---
title: "Fuzzing bacnet-stack: a negative result worth keeping"
date: 2026-10-21
project: fieldbusfuzzer
published: true
summary: "A coverage-guided campaign against bacnet-stack's decoders — the surface behind a dense 2023–2026 CVE cluster — ran ~564 million executions under ASan/UBSan and MSan across four harnesses and found nothing new at the patched HEAD. The point of the piece isn't the zero; it's how you earn the right to report a zero: prove every harness reproduces a known CVE on the pre-patch version first — and watch one of them fail to, because a defensive guard I added made it more robust than the code it was testing."
---
BACnet runs the building you're sitting in — HVAC, lighting, access control, fire and
energy management — and it runs it over UDP port 47808, unauthenticated by design.
The dominant open-source implementation is Steve Karg's **bacnet-stack**, embedded in
a great many controllers and gateways. It is also **not on OSS-Fuzz**, and it has a
dense cluster of decoder CVEs from 2023 through 2026 — CVE-2023-51773 (an application-data
over-read), CVE-2026-41475 (WritePropertyMultiple decoding past the buffer), CVE-2026-41502
(a ReadPropertyMultiple out-of-bounds read), and more — **all in the service decoders, and
all found by manual code audit, not fuzzing.** That last detail is the whole reason to
show up: a surface that keeps yielding bugs to people reading code by hand is a surface a
coverage-guided fuzzer should be able to push further on.

So I built one. This is the write-up of what it found, which was nothing — and why that
nothing is, I think, worth publishing anyway.

## Where the shipped fuzzer stops

bacnet-stack ships its own libFuzzer/AFL harnesses (`apps/fuzz-libfuzzer`,
`apps/fuzz-afl`). Before writing a line of my own I read theirs, because the first job of
a new harness is to go where the existing one doesn't. Theirs enters at
`my_routing_npdu_handler` — the **NPDU** layer — which means it **bypasses the BVLC
framing layer entirely** (the 4-byte BACnet/IP header and its message dispatch), and it
registers handlers for ReadProperty, WriteProperty, ReadPropertyMultiple and a few
others but **not WritePropertyMultiple**, and it decodes into one shared `MAX_APDU`
buffer.

That last choice matters more than it looks. A single oversized shared buffer means an
over-read of a few bytes past the *logical* end of a message still lands inside the
*physical* buffer — no redzone, no crash, ASan none the wiser. So three gaps:

1. the **BVLC layer** (nobody fuzzes it);
2. the **WritePropertyMultiple** decoder (`wpm.c`), unregistered;
3. **in-buffer over-reads** the shared buffer masks.

## Four tight-buffer harnesses

Each harness copies the fuzz input into a `malloc(size)` buffer sized *exactly* to the
input, so an ASan redzone sits precisely at `buf[size]` — an over-read of even one byte
past the logical end is a hard crash, not a silent pass.

- **`harness-bacapp`** drives `bacapp_decode_application_data` — the primitive
  application-value decoder, the CVE-2023-51773 surface.
- **`harness-wpm`** reproduces the exact decode loop of `h_wpm.c`'s (static, un-linkable)
  `write_property_multiple_decode`, with the device-write callback nulled out so it's a
  pure parse — the CVE-2026-41475 surface.
- **`harness-rpm`** mirrors the request-decode loop of `h_rpm.c` — the RPM
  malformed-request DoS surface (the PR #1374 fix).
- **`harness-bvlc`** is the wire-realistic one: it mirrors `bvlc_bbmd_disabled_handler`'s
  dispatch over the real `bvlc_decode_*` functions, then chains any extracted NPDU through
  `bacnet_npdu_decode` and on into the APDU decoder — the full BVLC → NPDU → APDU path a
  real frame on UDP 47808 takes.

A note for anyone reproducing: libFuzzer over a read-only seed directory with leak
detection on spends a long fixed stretch in its initial corpus merge — long enough to
look like an ~11 exec/s decoder DoS. It isn't. Hand it a writable corpus dir as the first
argument and `-detect_leaks=0` and it settles at ~200K exec/s. (`-runs=0` init is 0.01s;
the one-shot driver runs every unit in 0.00s. The slowness was never in the decoder.)

## The campaign, and the zero

Pinned at the **post-fix HEAD** (`bacnet-stack` master at `e3e1d1c0`, 2026-10-13 — after
the 1.6.1 release, with the whole 2023–2026 decoder cluster patched) on purpose — I wanted
*new* bugs, not a re-run of the patched cluster. The numbers:

| Harness | ASan/UBSan execs | MSan execs | Crashes |
|---|---|---|---|
| bacapp | 138.5M | 25.5M | 0 |
| rpm    | 136.2M | 19.0M | 0 |
| wpm    | 2.84M  | 0.43M | 0 |
| bvlc   | 218.1M | 23.2M | 0 |

**~564 million executions. Zero crashes, zero timeouts, zero leaks, zero uninitialized
reads.** The MSan passes are separate builds (MSan and ASan can't coexist), origin-tracked,
over the grown corpora.

The honest reading of that is: the 2023–2026 decoder cluster was *just* patched, and at
the fixed HEAD these specific surfaces don't give up anything more to a coverage-guided
pass at this depth. Fine. But a table of zeros is worthless unless you can show the
harnesses weren't simply dead — that they'd have caught a bug if one were there.

## Earning the zero: reproduce the known CVEs

For each harness I checked out the **pre-fix parent commit** of its target CVE in a throwaway
`git worktree`, rebuilt the harness *unchanged* against that tree, and ran it over the same
seeds. If the harness is real, the known bug falls out immediately.

- **bacapp → CVE-2023-51773**, vulnerable commit `bbe5de7c~1`: ASan heap-buffer-overflow in
  ~263 iterations, straight through `bacapp_decode_application_data` (bacapp.c:445) into
  `decode_object_id_safe`. 
- **wpm → CVE-2026-41475**, `a70ce075~1`: ASan heap-buffer-overflow through
  `wpm_decode_object_id` (wpm.c:51) into the old unbounded `decode_tag_number_and_value`.
- **bvlc → the #1241 "secure the BVLC decoders" hardening**, `578f5071~1`: UBSan flags a
  signed-shift undefined-behavior in the deprecated primitive decoders that commit replaced.

Three for three. And then the fourth one didn't.

## The harness that was too good

**rpm → the RPM malformed-request DoS** (PR #1374, fix commit `48ed1aef`), vulnerable commit
`48ed1aef~1`: 8.3 million executions, no crash, no hang. The harness that mirrors the real RPM
handler loop failed to reproduce the known bug. (This DoS carries no CVE — it's the fix in
PR #1374, distinct from the RPM off-by-one *read* CVE-2026-41502, which is a separate issue in
`rpm_decode_object_id` fixed back in 1.4.3.)

This one is not a memory-safety bug — it's a **denial of service by infinite loop**.
On the vulnerable tree, `rpm_decode_object_property` returns `0` (not an error) when the
input is exhausted mid-parse; the handler's property loop treats "decoded zero bytes" as
progress and spins forever. The fix makes the function return a reject instead.

So why didn't my harness spin? Because when I wrote it, I had — reasonably, defensively —
added two `decode_len >= service_len` escape checks to the loop. The *real* `h_rpm.c`
handler has no such checks. My guards made the harness **strictly more robust than the code
it was supposed to be testing.** It could never observe the loop that is the entire bug.

That is the finding of this whole exercise, negative result and all: **a decode harness that
"mirrors" a handler but quietly hardens it will silently stop reporting the handler's own DoS
bugs.** The fix is a guard-free mirror — `harness-rpm-faithful.c`, the loop exactly as the
handler runs it — plus libFuzzer's `-timeout`. That version reproduces the DoS on the
first malformed input (a timeout artifact, stack parked in `rpm_decode_object_end`). Run on
the patched HEAD it does 12M executions and never hangs — so the fix holds and there's no
*new* loop DoS hiding behind my old guards either.

ASan/OOB findings are immune to this — the redzone fires no matter how the loop is written.
It's only the hang/DoS class that the guards can swallow, and it's exactly the class that
doesn't announce itself with a crash.

## Lessons

- **A zero is only publishable if the harness is proven live.** Check each harness out against
  the pre-patch parent of its target CVE and confirm the known bug reproduces. If it doesn't,
  you've learned something about your harness, not the target.
- **Don't harden a handler mirror.** Defensive progress guards that the real handler lacks turn
  a faithful DoS test into a robustness demo. For hang/loop classes, mirror the loop exactly and
  let `-timeout` do the detection.
- **Tight buffers earn their keep.** Sizing the input buffer to the input (redzone at the end)
  catches the small in-buffer over-reads a shared `MAX_APDU` buffer hides — the reason to write a
  focused harness even when an upstream one exists.
- **Go where the shipped fuzzer stops.** The BVLC layer and WritePropertyMultiple were unfuzzed
  because the upstream harness enters above the former and never registers the latter.

## Closing

No CVE came out of this. What came out is a clean, coverage-proven negative on four BACnet decode
surfaces at the current release — every application-type branch and every BVLC message decoder
demonstrably exercised — and a concrete reminder that the harness is part of the system under test.
The one that found nothing is only trustworthy because the other four, pointed at the vulnerable
past, found exactly what they were supposed to. The rigor lives in the retest, not the run.
