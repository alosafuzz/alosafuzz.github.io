---
title: "Fuzzing EPICS pvAccess: a clean seam, an amplification that wasn't, and patch-and-refuzz"
date: 2026-10-28
project: fieldbusfuzzer
published: true
summary: "After fuzzing EPICS Channel Access I turned to its structured-data successor, pvAccess (PVXS). The protocol is richer — a recursive type-introspection decode followed by typed values — and, unlike Channel Access, the deserializer is cleanly isolatable: the harness needed zero IOC runtime setup. Within minutes a nine-byte message was making the decoder try to allocate eight gigabytes. The honest work was proving that is NOT the denial of service it looks like (it's a lazy allocation that never commits), and then getting past it: the allocation class masks everything underneath, so I patched the missing bound locally and re-fuzzed to show the decoder itself is memory-safe. This is a writeup about not promoting a scary-looking artifact into a finding, and about the hybrid-build sanitizer gap that a single question caught — twice."
---


This is the sequel to [fuzzing EPICS Channel Access](/writeups/fuzzing-epics-channel-access-reaching-the-parser/).
There, the lesson was that *reaching* the parser was the hard part — Channel Access's `camessage()` is welded
to the IOC runtime and took seven initialization fixes to stand up. pvAccess was the opposite: the hard part
wasn't reaching the parser, it was **not overclaiming the first thing it coughed up.**

## The clean seam

pvAccess (PVA) is EPICS's structured-data protocol — where Channel Access moves scalars, PVA moves arbitrary
typed structures: a message carries a `FieldDesc` type-introspection tree (nested structs, unions, arrays,
bitsets) followed by the value data. The modern C++ implementation is **[PVXS](https://github.com/epics-base/pvxs)**.

The novelty gate came back clean — no CVE on pvAccess/PVXS/pvAccessCPP, not on OSS-Fuzz, no shipped harness,
only academic fuzzing talks. And the decoder has a property Channel Access didn't:

```cpp
void from_wire_type_value(Buffer& buf, TypeStore& ctxt, Value& val);
```

It takes a `Buffer` (pointer + length) and output containers, with no event loop, no sockets, no IOC database.
That is a near-direct libFuzzer entry. My harness builds a `FixedBuf` over the fuzz bytes, a `TypeStore`, and an
empty `Value`, and calls it. **Zero initialization fixes** — the opposite of the Channel Access saga. (The build
was its own small adventure: PVXS bundles libevent as a submodule my shallow clone skipped, so `libpvxs.a`
wouldn't link until I pointed it at the system libevent; then I compiled the decode translation units with
clang+ASan and linked them against the gcc-built archive — the same hybrid trick I used for Channel Access.)

## Nine bytes, eight gigabytes

Within minutes the fuzzer produced a crash. A nine-byte input made the decoder attempt
`malloc(8,288,342,344)` — 8.3 GB — in `operator new[]`. The source is unsubtle (`pvaproto.h`):

```cpp
Size slen{};
from_wire(buf, slen);            // element count, read straight off the wire
shared_array<E> arr(slen.size);  // new E[count] — before a single element is read
```

`Size` is a variable-length encoding that reaches a 64-bit value, and nothing bounds the declared count against
the bytes actually remaining in the message. The same shape appears in the struct child-count `reserve()` and the
union/any array decoders. It looks exactly like a remote, unauthenticated, amplification denial of service: tiny
message in, gigabytes of allocation out.

It is very tempting to write that up. So I didn't — not until I'd measured it.

## The de-confound: a reservation is not an exhaustion

I ran the trigger with libFuzzer's allocation limits disabled and watched the real memory:

```
Executed trigger in 17 ms
Maximum resident set size (kbytes): 33484
```

33 MB. The 8.3 GB `malloc` never *committed*. On a 64-bit Linux with overcommit (a typical IOC), `new double[1e9]`
is a lazy virtual reservation — the pages aren't backed until touched, and the element-read loop only touches as
many bytes as the message actually carries, then frees. libFuzzer's `-malloc_limit_mb` flags the *request*, which
is a useful signal, but it is not the same as memory exhaustion.

So the honest severity is low. It's a real **CWE-770** (unbounded allocation from an attacker-controlled count,
no cap), and on a host with overcommit disabled or a tight ulimit the `new[]` throws `bad_alloc` — a
connection-level hiccup at worst. On a 32-bit build `count * sizeof(E)` could integer-overflow into a genuine
heap overflow, but I'm on 64-bit and won't claim what I didn't test. A hardening item worth a one-line fix —
*cap declared counts against remaining bytes* — not a denial-of-service I'm going to brand with a CVE.

## Patch-and-refuzz: getting past the artifact to the real question

The real question was still open: **is the decoder memory-safe?** And the allocation class was in the way of
answering it — nearly every count-bearing path hits the giant `new[]` first, the sanitizer aborts on it, and
`allocator_may_return_null` didn't suppress it. The fuzzer was drowning in one benign class and couldn't explore
underneath.

The fix is the same technique I'd use on an incomplete vendor patch: **patch-and-refuzz.** I added the missing
bound locally — clamp each declared count to the remaining buffer size, at all five allocation sites — rebuilt,
and re-fuzzed. This is, not coincidentally, the exact hardening the CWE-770 note recommends; here it doubles as a
fuzzing probe. The result:

- coverage jumped from ~6,000 to ~16,500 edges — the fuzzer was finally exploring the decode logic instead of
  bouncing off the allocator;
- tens of millions of executions under ASan + UBSan across the full decode path;
- **zero** memory-safety crashes, zero undefined behavior.

The anchor (planting a recursion-guard removal, and watching the harness catch the resulting runaway) says the
harness can see a real bug. It just didn't find one. The recursive introspection decode and the typed-value walk
are memory-safe.

## The sanitizer gap a single question caught — twice

One more honest note, because it's the most transferable lesson here. On both EPICS targets I was asked a plain
question — *are ASan, UBSan, and MSan all complete?* — and both times it caught a real gap in my own work.

On Channel Access, I'd written "ASan+UBSan" when my build flag was `-fsanitize=address,fuzzer-no-link` —
`fuzzer-no-link` is *coverage instrumentation for libFuzzer*, not UBSan. The binary even had `__ubsan_handle`
symbols (the linked ASan runtime ships them), so a glance at the symbol table lied. The check that tells the
truth is `nm` on the **object file**, not the binary.

On pvAccess, the trap was the hybrid build itself: I'd instrumented the two main decode translation units with
clang, but three decode-adjacent ones — the bitmask, type, and shared-array code — were sitting in the gcc-built
`libpvxs.a`, **uninstrumented**. ASan's malloc interceptors still catch heap errors globally, but precise
out-of-bounds in those files would have been invisible. Closing it meant compiling those three with clang too and
verifying each object carried `__ubsan_handle` / `__asan` call sites before trusting the result.

MSan I did not run on either, and I'll say why plainly: both harnesses link gcc-built EPICS archives MSan can't
see, so it would false-positive on every call into them. A real MSan pass needs a full clang rebuild of EPICS,
which its build system refused. That's a limitation, stated, not papered over.

## What I'd take away

A deserializer that allocates on a declared count before reading the data will hand a fuzzer a scary number in
the first minute. The discipline is to measure whether the number is real before it becomes a finding — a
reservation on an overcommit system is not an exhaustion, and saying so cost nothing but a `time -v`. Then, when
a benign-but-loud class is masking the surface you actually care about, patch it out locally and re-fuzz; the
clean run on the patched build is the honest basis for "the decoder is safe," and the patch you wrote to get
there is usually the fix worth suggesting anyway. And when someone asks whether your sanitizers are really all
on — check the object files, not the binary. Twice now that question has been worth more than the campaign.
