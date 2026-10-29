---
title: "Fuzzing EPICS Channel Access: reaching the parser was the hard part"
date: 2026-10-28
project: fieldbusfuzzer
published: true
summary: "EPICS Channel Access runs the control networks of particle accelerators, light sources, and telescopes — and the maintainers say outright that it 'was never intended to be used in a hostile environment' and 'never claimed to be hardened.' That is a standing invitation. But the interesting part of this campaign wasn't the result (the parser is memory-safe at the parse layer under more than a billion executions of ASan + UBSan). It was that reaching the real server parser in-process took seven separate initialization fixes, a hybrid clang/gcc build because EPICS refused to compile under clang, and learning that EPICS's assert() suspends the thread instead of crashing — so a tripped assertion looks like a hang, not a bug. This is how I earned a trustworthy negative, and the mistake I caught in my own sanitizer flags along the way."
---


The industrial-protocol stacks with big reputations are mostly picked over, so before building anything I
run a novelty gate. This round the standouts were saturated — RT-Labs **p-net** fuzzed to ten CVEs with
libFuzzer now in CI, **OpENer** shipping its own AFL harness behind two CVE waves, **lib60870** with a
fresh 2026 cluster in its information-object parser. The one that came back genuinely interesting was
**[EPICS](https://github.com/epics-base/epics-base) Channel Access**: no memory-safety CVE on the core
parser, not on OSS-Fuzz, only a 2021 student AFL attempt described as "not production-ready." And a
corroborating signal you rarely get this explicitly — the maintainers themselves, in a 2018 tech-talk
thread about a CA server loop triggered by a *port scan*, wrote that Channel Access "never claimed to be
hardened" and "was not intended for use in a hostile environment."

Widely deployed, admittedly unhardened, never systematically fuzzed. That is the setup you want. What I
did not expect was that the protocol parser would be the easy part, and the *harness* would be the project.

## The target: a parser welded to an IOC

Channel Access is the client/server protocol EPICS IOCs speak over TCP and UDP 5064 — read, write, and
monitor named process variables, no authentication, no encryption. The server-side parse lives in one
function, `camessage()` in the IOC's `rsrv` module: it reads a 16-byte header, handles a large-array
extension where a `0xFFFF` length field switches to a 3-word form (the classic declared-length-vs-actual
primitive), bounds the message size, and dispatches through a jump table to per-command handlers.

That function is exactly the attacker-reachable parse I wanted in a libFuzzer harness. The problem is that
`camessage()` is not a free-standing parser. It asserts on a global resource bucket, locks a global client
queue, walks an event subsystem, reaches into the record database, and operates on a `struct client`
that's threaded through mutexes, lists, and sockets. You don't call it; you stand up enough of an IOC
around it to let it run.

## EPICS would not build under clang

The first wall was the build. I wanted the parser compiled with `-fsanitize=fuzzer,address` and the rest
of EPICS instrumented too. EPICS has its own build system, and its toolchain probe is wired to gcc; my
attempts to force clang were rejected before a single object compiled, and `-fsanitize=fuzzer-no-link`
isn't a flag gcc accepts.

The way through was a hybrid. Build all of EPICS the normal way (gcc) to get the static archives, then
compile *only* `camessage.c` with clang + ASan + coverage instrumentation and link it against the
gcc-built `libCom` / `libdbCore` / `libdbRecStd`. Link order makes my instrumented object win over the
archive's copy. ASan's allocator interceptors still catch heap errors globally, and libFuzzer's coverage
comes from the one translation unit I actually care about. It's not a full-ASan build of EPICS — I'll say
so plainly below — but it puts the parser under instrumentation, which is the point.

## Seven ways the harness crashed before the fuzzer could

With the build sorted, every input — including a zero-byte one — hung. Not crashed. *Hung.* That led to
the single most useful thing I learned about fuzzing EPICS:

**`epicsAssert` does not call `abort()`. It suspends the failing thread.**

So a failed assertion inside the server doesn't produce a crash a fuzzer can catch — it produces a process
that sits there forever. The first hang was `assert(pCaBucket)` at the top of `camessage()`: the resource
bucket is created in the server's init routine, which I hadn't run. That is also a permanent lesson for
this target: **treat every libFuzzer timeout on EPICS as a candidate finding**, because a remotely
reachable assertion *is* a denial of service (a suspended CA server thread), and it is indistinguishable
from a hang until you look.

Then the de-confounding turned into a checklist. Each fix exposed the next uninitialized piece of IOC
state the parser or its handlers assumed:

1. `pCaBucket` — the resource-id bucket the parser asserts on.
2. `clientQlock` — the global client-queue mutex; without it, the channel lookup dereferenced a null lock.
3. `evuser` — a null event context made the version handler's priority path segfault.
4. The version priority path itself couples to an event task I never start — a no-op override of one
   function removed it (it's runtime plumbing, not parse logic).
5. `rsrvChanFreeList` — the channel allocator, needed once channel-claim succeeds.
6. `rsrvEventFreeList` — the event allocator, needed for monitors.
7. `rsrvCurrentClient` — the thread-private slot the handlers read.

None of these are EPICS bugs. They are the price of pulling a server parser out of its server. Seven
fixes in, the full command set ran clean.

## A mistake in my own flags

Here is the part worth being honest about. For most of this campaign my notes said I was running "ASan +
UBSan." I wasn't. My build line was `-fsanitize=address,fuzzer-no-link` — and `fuzzer-no-link` is
*SanitizerCoverage* for libFuzzer, not UndefinedBehaviorSanitizer. I had conflated the two.

The reason it slipped past a glance is instructive: the final binary *did* contain `__ubsan_handle`
symbols — because the linked ASan runtime ships the combined asan+ubsan runtime library. The symbols are
there; the *instrumentation* was not. The check that actually settles it is `nm` on the **object file**,
not the binary: `camessage_instr.o` had **zero** `__ubsan_handle` call sites. UBSan was never applied.

I rebuilt with `-fsanitize=address,undefined` (suppressing the alignment check, because the parser
intentionally reinterprets the unaligned receive buffer as the header — harmless on x86), confirmed the
object now carried UBSan call sites, and re-ran. The lesson I wrote down: *verify sanitizer instrumentation
on the object, never trust the symbol table of the fully-linked binary.*

## Reaching the deep handlers

A clean first campaign (TCP) and a second (adding the UDP search path, which nearly doubled coverage) left
one surface untouched: the channel operations — read, write, claim — which only run against a channel that
has actually been created in the database. With no database loaded, those handlers bail out early. To reach
their real parse (the DBR type/count validation and size math), I loaded a minimal database, registered
record support, initialized access security, and then **pre-claimed one channel by running a real
create-channel message through the parser at startup** — which handed back a server id the fuzzer could
then target with reads and writes.

That reached the handlers, and immediately hit the predicted wall: the actual value transfer
(`dbGet`/`dbPut`) hangs on a record that never went through full IOC initialization — record processing,
not message parsing. The clean move is to stub the leaf value I/O so the handlers run their *parse*
(validate the DBR type, clamp the count, compute the size, build the reply) and skip the record machinery
that needs a running IOC. The value transfer itself is out of in-process scope; the parse around it is not.

## The timeouts, and why none of them were real

The deep soak produced a couple hundred libFuzzer timeouts — and given the `epicsAssert`-suspends-as-hang
rule, I could not wave them off. Every one had to be triaged. Two sources, both artifacts:

- Under UBSan, larger inputs occasionally exceeded the ten-second limit purely on instrumentation
  overhead — the same inputs ran in tens of milliseconds on the ASan binary.
- Under ASan, the timeouts came from my own harness design: a real server gives each connection its own
  client that's torn down on disconnect, but my persistent test client never disconnects, so successful
  channel claims pile up across a long-lived fuzzing worker until one input's processing crosses the
  limit. Every such input completed *instantly* on a fresh process.

Per-input, the parse is fast and clean. The timeouts were a property of the harness's lifetime, not of
EPICS. Stated honestly so the next person doesn't chase them.

## The result, stated honestly

Across the campaigns — TCP, UDP, and the deep database-coupled handlers — more than a billion executions
under AddressSanitizer plus a UndefinedBehaviorSanitizer pass: **zero memory-safety crashes, zero
undefined behavior, zero genuine hangs.** The header parse, the `0xFFFF` length-lie handling, the
message-size bounding, the string handlers, and the UDP search path all hold up. The anchor — a planted
bounds bug that ASan caught cleanly — says the harness could see a real one.

Two honest limits. **MemorySanitizer was not run**, and it's impractical for this target: the hybrid build
links gcc-compiled archives MSan can't see, so it would false-positive on every call into them; a real
MSan pass needs the full clang rebuild EPICS wouldn't give me. And the **record value transfer** is out of
in-process scope. Within those limits, the Channel Access *parser* — the thing the maintainers called "not
hardened" — is memory-safe at the parse layer.

## What I'd take away

Three things. First, when a maintainer tells you a protocol was never meant to face a hostile network,
believe them about the *threat model* (isolate it) but check the *parser* anyway — "not hardened" is a
design statement, not a measurement, and here the measurement came back clean. Second, know your runtime's
failure mode: EPICS suspends on assert, so on this target a hang is a finding until proven otherwise.
Third, read your own build flags — the difference between coverage and UBSan is one token, the linker will
happily hide it in the symbol table, and only the object file tells the truth. A negative result is only
worth keeping if every part of how you got it is honest, including the parts where you were briefly wrong.
