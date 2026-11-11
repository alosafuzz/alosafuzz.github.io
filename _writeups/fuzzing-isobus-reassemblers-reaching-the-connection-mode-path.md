---
title: "Fuzzing ISOBUS reassemblers: the frame that never reached the code"
date: 2026-11-10
project: fieldbusfuzzer
published: true
summary: "A tractor's implements reassemble multi-frame messages from eight-byte CAN frames, and those reassemblers are attacker-controlled input to the terminal and task controller. AgIsoStack++ has three of them — J1939 Transport Protocol, Extended TP, NMEA 2000 Fast Packet — and I fuzzed all three. The memory-safety result was clean, which the code earns: the reassembly write is bounded by construction. The part worth writing down is a harness mistake that looked fine. The connection-mode paths only run for messages addressed to our device, so every frame I fed as a broadcast was dropped before it reached the Extended TP reassembler, while coverage climbed on the easy half and said nothing was wrong. Fixing that, and reading an MSan report that turned out to be the standard library rather than the stack, is the real content here."
---

*Defensive security research. This describes a fuzzing method and a negative result; it
contains no exploit. The target is unmodified open-source software,
[AgIsoStack++](https://github.com/Open-Agriculture/AgIsoStack-plus-plus) (MIT).*

---

Everything on an agricultural implement bus is eight bytes at a time. A device descriptor, an
object pool for the cab display, a multi-section spray command — anything bigger than one CAN
frame is split up and reassembled on the other end, and the reassembler is reading bytes an
implement put on the bus. That is the surface: a malicious or malfunctioning ECU is untrusted
input to the terminal and the task controller. AgIsoStack++ is a maintained open-source
ISOBUS stack, and it has three reassemblers — the J1939 Transport Protocol, the Extended
Transport Protocol, and NMEA 2000 Fast Packet. I fuzzed all three. They held up, and I want
to be precise about both halves of that: why the code earns the clean result, and the two
ways the harness tried to lie to me about it.

## The target, and why the gate scoped it

Before building anything I gate a target, and AgIsoStack++ came back a qualified go. The
reason to be careful is that the project is unusually well-tended: it runs its unit tests
under AddressSanitizer and UBSan in CI, and the maintainers have been actively hardening the
server-side parsers — the virtual terminal and task-controller handlers and the object-pool
file parser — against truncated and short-frame input. Those are a crowded place to look,
with someone already auditing them. The three reassemblers were quiet on memory safety by
contrast, and a CI ASan job on a fixed set of unit tests is not a fuzzer: it never varies the
declared lengths and counts the way a length-lie attack does. So the scope was the
reassemblers, and the servers and object pool were left alone.

## Harnessing a reassembler

The entry point is clean. Each manager takes incoming CAN frames through a single
`process_message` call, so the harness constructs a source control function, builds
`CANMessage` objects from the fuzzer's bytes, and feeds a stream of them — a connection or
broadcast announce first, then data frames. The Transport Protocol's broadcast mode, BAM, is
the ideal starting point: one announce frame declares a total size and packet count, the
receiver sizes a buffer, and the data frames fill it. It is connectionless and
unauthenticated, which is both the realistic threat and the easy thing to drive. On that
harness, with the detector confirmed by a deliberately planted out-of-bounds read, the
Transport Protocol and Fast Packet reassemblers ran clean under ASan and UBSan across tens of
millions of executions.

And the data-transfer write earns it. Before copying a frame's payload into the reassembly
buffer, it checks that the current packet index has not reached the declared message length,
and it clamps the per-frame copy to the bytes that remain. Announce a size of 1785 and deliver
two frames, or announce a tiny size and flood data frames, and you get a rejected session, not
an overflow. That is what bounded-by-construction looks like, and it is the right answer.

## The frame that never arrived

The Extended Transport Protocol told a different story, and the story was about my harness.
ETP coverage sat low and would not climb. ETP has no broadcast mode — it is always
connection-mode — and I had been feeding every frame as a broadcast, the same way BAM wants.
The stack was doing exactly what it should: a connection-mode message addressed to the global
broadcast address is not for any particular device, so it was dropped before it reached the
reassembler. The check is one line — the destination has to be *our device*, an internal
control function, not a broadcast — and my frames failed it silently. Coverage still moved,
because the frames reached the dispatch and got rejected there, which is exactly the trap: the
harness looked like it was fuzzing ETP, and it was fuzzing the front door's reject path.

The fix was to give the harness a real internal control function as the destination and let
the fuzzer choose, per frame, between broadcast and addressed-to-us. One subtlety made it a
two-step fix. My first attempt faked it — a plain control function with its type field set to
"internal" — and UBSan caught the stack down-casting that object to the concrete internal
type, which is undefined behavior on an impostor. The stack is entitled to assume that a
destination marked internal really is the derived type the network manager creates, so the
harness has to create the real one. With that, ETP reached its connection-mode reassembly —
request-to-send, clear-to-send, the data-packet offset, and the data frames — and it, too,
came back clean.

The lesson generalizes past this stack: enumerating a target's parse entry points is step
one, and confirming each one actually reaches its deep code is step two. A gate in the
dispatch — an address check, a registration check, a state guard — will happily let your
harness run millions of executions against a reject path while coverage climbs enough to look
honest.

## The MSan report that was the standard library

MemorySanitizer is the tool that catches reads of uninitialized memory that ASan cannot see,
so a reassembler negative is not finished until it has run. It fired immediately, in the
transport manager's own update loop, and it was tempting to call it a finding. It was not.

The manager keeps its active sessions in a `std::list` and returns a copy of that list on
every update. The MSan origin trace pointed entirely into the standard library — a list node
allocated on the heap, read during the list's copy constructor, with no AgIsoStack field
anywhere in it. Without an instrumented libstdc++, MSan treats the list's own node bookkeeping
as uninitialized, and it fired only once the list was non-empty, which is to say only when
there was a node to copy. Copying a list of shared pointers does not read the objects they
point at, so there was no path from the session's fields to the report. It is the standard
library, not the stack. The same conclusion I reached fuzzing a large GNSS library a few days
earlier applies here: MSan on STL-heavy C++ without an instrumented standard library reports
the containers, and the only honest move is to read the origin before believing it.

## What the negative is worth

AgIsoStack++'s three multi-frame reassemblers are memory-safe on the fuzzed surface, with the
connection-mode paths reached and not just the connectionless ones, and the one MSan report is
the standard library rather than the code. The reassembly write is bounded by construction,
exactly as the gate predicted for a stack this carefully maintained. For software that sits
between an implement and the terminal a farmer trusts, a clean, well-covered negative — with
the one harness blind spot named rather than hidden behind a coverage number — is a result
worth keeping. The protocol details and the fuzz surface are in the companion
[ISOBUS transport guide](/guides/isobus/).
