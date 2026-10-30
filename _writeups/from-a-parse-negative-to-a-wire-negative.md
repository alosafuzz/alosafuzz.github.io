---
title: "From a parse negative to a wire negative: the second harness"
date: 2026-10-30
project: fieldbusfuzzer
published: true
summary: "An in-process harness can earn a trustworthy negative for a parser and still say nothing about the server that runs it. The parse harness stubs whatever is welded to the runtime, and it cannot see the whole-server failure classes: a spin loop, a reachable assert that suspends a thread, a connection lifecycle gone wrong. So after the in-process EPICS Channel Access parser came back clean, I built a second harness that drives a real softIoc over a real socket, with the two detectors a live server needs and a way to keep a valid session alive long enough to reach the code the parse harness had to stub. It came back clean too, which is the point: this is how a parse-level negative becomes a server-level one."
---

*Defensive security research. This describes a fuzzing method and a negative
result; it contains no exploit. The target is unmodified open-source software,
[epics-base](https://github.com/epics-base/epics-base) (EPICS Open License).*

---

An in-process parser harness is the right first move, and it has a blind spot. Both are true, and the gap
between them is where this post lives.

## What the in-process negative does and does not cover

The [EPICS Channel Access campaign](/writeups/fuzzing-epics-channel-access-reaching-the-parser/) fuzzed the
real server command parser, `camessage()`, in process under ASan and UBSan, more than a billion executions
across the soaks, TCP and UDP, with the deep command handlers reached by standing up a minimal database. The
parser is memory-safe on that surface. That is a real result and I stand by it.

It is also a result about the parser, not the server. Reaching `camessage()` in process meant stubbing the
record value transfer, `dbGet` and `dbPut`, because the real value path needs a fully initialized record and
hangs without one. The in-process harness never ran the actual copy of a value into or out of a record. It
also could not observe the failures that only exist at the level of a running server: a command that sends
the dispatch loop spinning, a malformed message that drives the connection state machine into a bad state,
or the EPICS habit of calling `assert()`, which suspends the calling thread rather than aborting, so a
tripped assertion presents as a hang and not a crash.

None of that is a criticism of the parse harness. It is the reason a second one is worth building.

## The second harness: drive the real server over the wire

The idea is plain. Start the real `softIoc`, talk to it over a real socket on TCP 5064, and treat the
process as the thing under test rather than one function inside it. Two details make it useful rather than a
demo.

The first is keeping a valid session alive. A CA server disconnects a client the moment a message violates
the framing, so a naive mutational fuzzer spends almost all its time being hung up on, never reaching the
command handlers behind the handshake. The harness holds two connections. A golden connection does the full
version and create-channel handshake once, learns a real server-side channel id, and from then on sends only
messages that are structurally valid on that channel: real read, write, write-notify, event-add, and
event-cancel, with the data type, element count, and payload tampered but the framing intact. Those reach
`dbGet` and `dbPut` for real, which is exactly what the in-process run had to stub. A second, disposable
connection carries the rest: the length-lie with the extended 0xffff header, bad data types, invalid channel
ids, truncated messages, and plain random bytes, the port-scan class that the server is meant to reject at
the door. When the junk connection gets dropped, which is often, only that throwaway is renewed and the
golden session keeps its reach.

The second detail is the detectors, because a live server fails in two different shapes.

## Earning the zero on a live server

A parse harness crashes or it doesn't. A server has a third state, alive but not answering, and for EPICS
that state is the interesting one: a reachable `assert()` suspends a thread, and a spin loop pegs a core,
and both look like silence on the wire. So the harness watches for two things. A crash is the child process
dying, which covers a real memory fault or an abort. A hang is the server still running but no longer
answering a fresh, valid CA exchange within a timeout, confirmed with a second probe to rule out a transient.
On either, the triggering message and the recent message history are saved and the server is restarted.

A detector you have not tested is a detector you do not have. Before trusting a clean run I anchored both
against ground truth: SIGSTOP on the server reads as alive and unresponsive, which is the hang classification;
SIGKILL reads as not alive, which is the crash classification; a healthy server reads as alive and responsive,
and a resumed one goes back to responsive. The crash path inherits the in-process anchor too, where a planted
over-read produced an ASan report in this same code. With the detectors proven, a zero means something.

## Adding a sanitizer to the live server

A stock server catches crashes and hangs, not a silent over-read that never faults. The record value path
was the one surface the in-process run could not reach, so it is exactly where a silent bug would hide, and
catching it needs a sanitizer on the live process. EPICS had refused to build under clang earlier in this
work, so the in-process harness used a hybrid clang-parser-over-gcc-archives build and could not run MSan.
For the live server the answer was simpler than the hybrid dance: rebuild the whole of EPICS with gcc's own
AddressSanitizer, which the EPICS build system accepts without complaint. The result is a `softIoc` that is
fully ASan-instrumented, confirmed by its linked libasan and its symbols, and clean on ordinary caget and
caput traffic.

Run with a sanitizer configured to abort on error, a silent corruption in the real `dbGet` or `dbPut` now
turns into a process death that the crash detector catches, with the ASan report waiting in the log.

## The result, and what it is worth

Channel Access held. The stock server took 381,059 messages, 155,724 of them on the golden session reaching
real record processing, with no crash and no hang. The ASan server took another 286,444 messages, 119,046 of
them deep, with no crash, no hang, and no ASan report. Across both, 667,503 messages over the wire, a quarter
of a million of them exercising the value path the parse harness had stubbed, and nothing fell over. The
server rejected the malformed traffic the way it should and kept serving.

So the parse-level negative now extends to a server-level negative on the covered paths, at this pinned
commit. That is a stronger claim than the parse harness alone could make, and it is still a bounded one: the
reach is the covered surface, the value path is now reached but a hybrid-free MSan on the live server is a
further step, and a negative at one commit is a statement about that commit. The historical Channel Access
port-scan loop did not reproduce here, which is worth saying plainly rather than quietly dropping.

The reusable part is the shape, not the target. When an in-process harness gives you a clean parser, you have
tested a function, not a server. A second harness that drives the real process over the wire, keeps a valid
session alive to reach what the first one stubbed, anchors a crash detector and a hang detector against
ground truth, and runs the live process under a sanitizer, turns a parser negative into a server negative, or
finds the thing that only the server could show you.

*Worked examples: [EPICS Channel Access](/writeups/fuzzing-epics-channel-access-reaching-the-parser/) and its
successor [pvAccess](/writeups/fuzzing-epics-pvaccess-the-amplification-that-wasnt/).*
