---
title: "Fuzzing Java ICS protocol stacks: four that held up"
date: 2026-11-18
project: fieldbusfuzzer
published: true
summary: "A coverage-guided fuzzing pass over the Java libraries that speak IEC 60870-5-104, KNXnet/IP, SNMP, and M-Bus. All four held up against malformed input across tens to hundreds of millions of executions. This is the case for why, and the method that makes a clean fuzzing result mean something: in a memory-safe runtime the yield shifts from corruption to availability, and the harness only earns its result when its fidelity model matches what the production server actually catches."
---

I spent a stretch of November 2026 pointing a coverage-guided fuzzer at the Java libraries that speak
industrial protocols: IEC 60870-5-104, KNXnet/IP, SNMP, and M-Bus. This is the writeup for the ones
that came back clean. Further results from the same sweep are still in progress and will follow
separately.

A clean result is worth publishing. A fuzzing campaign that finds nothing, run with a harness that
actually reaches the parser and a fidelity model that matches the production server, is evidence the
code is sound against malformed input. Most negative fuzzing never gets written down, so the next person
repeats it. These four did not need a patch, and here is why I believe that.

## Java changes the target

The C side of this work hunts memory corruption: a declared length that outruns the buffer, an
out-of-bounds read, a write past an allocation. In pure Java none of that reaches the attacker. The JVM
bounds-checks every array access and throws instead of corrupting memory. Real corruption only appears
where the stack crosses into native code: a JNI call, a Netty off-heap buffer, `sun.misc.Unsafe`. None
of the four libraries here take that path for decoding, so the attack class narrows to availability:

- an unbounded allocation driven by a wire length field, which becomes `OutOfMemoryError` or
  `NegativeArraySizeException`
- deep recursion in nested structures, which becomes `StackOverflowError`
- a non-progress loop on a malformed field, which becomes a hang
- an uncaught runtime exception at a shared thread boundary, which can wedge an accept loop

That shift drives the whole method. I am no longer looking for a sanitizer trip. I am looking for the
one input the server's own try/catch cannot absorb.

## The method, briefly

Tooling is Jazzer 0.30 on JDK 21: a libFuzzer-style, bytecode-instrumented, coverage-guided fuzzer for
the JVM. The harness is a `fuzzerTestOneInput(byte[])` that drives the real decode entry point, with
instrumentation scoped to the library's own packages. OOM is made deterministic with a modest `-Xmx`
and an RSS limit; hangs with `-timeout`; recursion rides the default stack size.

Two decisions matter more than the tooling.

First, a novelty gate before any harness: does the library ship its own fuzzer, is it on OSS-Fuzz, does
it have a decode-DoS advisory, and does the issue tracker or the commit history on the decode file show
an active audit I would collide with. A target that fails the gate does not get built.

Second, and this is the one that separates a real Java finding from noise: harness fidelity is inverted
from C. In C the danger was a harness buffer that hid a crash the real code would suffer. In Java the
danger is the opposite. Most ICS servers wrap per-message parsing in a broad catch and keep serving, so
an `IllegalArgumentException` the parser throws on a bad frame is a dropped message, not a crash. If the
harness treats that as a finding, every campaign "finds" dozens of non-bugs. So the first thing I do on
each target is read the server's receive loop and find exactly what it catches. The harness then
swallows precisely those exceptions and lets only the ones the server cannot absorb escape: `Error`
(OOM, StackOverflow), a hang, or a Jazzer bug-detector sink. A finding has to survive the real server's
own handler to count.

## IEC 60870-5-104: OpenMUC j60870

`org.openmuc:j60870:1.8.0`, unauthenticated TCP/2404. The receive path is `ConnectionReader` ->
`APdu.decode` for the APCI framing, then for an I-format frame the ASDU buffer goes to `ASdu.decode` and
the per-type information-object decoders. Around 60 ASDU type decoders sit behind that entry, which is
the attacker-controlled surface.

Fidelity read: the reader's outer try is a broad `catch (Exception)` that closes the one connection. So
every exception the parser can throw, including the deliberate `throw new IOException(...)` framing
guards and any unchecked runtime exception, ends the same way: one connection dropped. Only an `Error`
escapes that catch to kill the reader thread or the JVM.

I ran two harnesses to cover both layers, the APCI frame and the ASDU body, for about 378 million
executions combined. No OOM, no StackOverflow, no hang, no uncaught `Error`. Peak memory stayed flat,
which rules out an allocation blow-up. One crash did surface in an early strict-parser run, an
`IllegalArgumentException` at `ASdu.java:559` on a frame declaring zero element sets where the parser
expects one. It is production-absorbed by the broad catch, so it is a robustness note (throw
`IOException` there for consistency), not a security bug. The one design observation worth passing to
the maintainer: j60870 tears down the connection on any malformed ASDU rather than mirroring and
continuing, so a single crafted I-frame drops the link. That is the library's chosen posture, not a
defect.

Verdict: the IEC-104 receiver parser is sound against malformed input.

## KNXnet/IP: Calimero

`io.calimero:calimero-core:3.0-M2`. KNXnet/IP routing is unauthenticated multicast on
224.0.23.12:3671, so the parse surface takes whatever any host on the segment sends. The faithful path
is `ReceiverLoop.onReceive` -> `KNXnetIPHeader.from` -> dispatch by service type -> cEMI decode. I
widened the harness past cEMI to the full unauthenticated service-type layer: the header, the
HPAI/CRI/CRD building blocks, the DIB-bearing description response, the connect and connectionstate and
disconnect requests, search request and response, and the routing messages.

Fidelity read: `onReceive` wraps the parse in `catch (KNXFormatException | RuntimeException)`, so any
parser exception is a dropped frame. Only `Error` and hangs matter.

About 18.8 million executions, 675 edges of coverage, clean. One OOM artifact appeared mid-run and did
not reproduce at the production `-Xmx1g` (it was Jazzer's own instrumentation allocating under a
pathologically low heap, not the parser), so it is an artifact, not a finding.

Verdict: the KNXnet/IP receive path holds up across the unauthenticated service-type surface.

## SNMP: SNMP4J

`org.snmp4j:snmp4j:3.13.2`, unauthenticated UDP/161 and /162. The dispatch path is
`MessageDispatcherImpl` -> the v1/v2c/v3 message-processing models -> `PDU.decodeBER` over the datagram.
The harness drives `PDU`, `PDUv1`, and `ScopedPDU` decode directly.

Fidelity read: the dispatcher wraps decode in a broad `catch (Exception)` plus specific
`IndexOutOfBoundsException` handlers, so every runtime exception the BER decoder throws is a dropped
datagram. About 85 million executions, clean, with flat memory.

SNMP4J is the interesting case because it shows the good-practice version of the control I care most
about in binary decoders. BER, like most tag-length-value encodings, lets a length field declare far
more than the message actually carries. A naive decoder reads the length and allocates that many bytes
before reading any content, so a few bytes claiming a two-gigabyte length force a two-gigabyte
allocation. SNMP4J does not. By default it checks the declared length against the bytes remaining in the
input before allocating. Feed it an object identifier that claims a length of 2,147,483,647 inside a
21-byte datagram and it rejects the frame cleanly:

    IOException: The encoded length 2147483647 exceeds the number of bytes left in input at position 21

That single check is the whole difference between a decoder that is a denial-of-service primitive and
one that is not. Not every ASN.1 or TLV library does it, and the check costs one comparison. SNMP4J is
a good example to point at.

Verdict: the SNMP4J BER decoder bounds wire lengths against the datagram and the dispatcher absorbs
parser exceptions; no availability finding.

## M-Bus: OpenMUC jMBus

`org.openmuc:jmbus:3.3.0`. The decode entry is `MBusMessage.decode` for the link-layer frame and
`VariableDataStructure.decode` for the DIF/VIF data records, which is the rich attacker-controlled part.
About 37.7 million executions focused on the DIF/VIF records, clean: no OOM, no negative array, no
recursion blow-up.

The one thing to fix is small. The link-layer header parser reads fixed offsets before it checks the
frame length, so a truncated frame (an empty buffer, or a one-byte long-frame start `0x68`) throws
`ArrayIndexOutOfBoundsException` from `MBusMessage.java` instead of a clean format exception. On the
wired transport an application reading from a socket or serial port would want to catch that, so it is
worth hardening: validate `length` before each header dereference. It is a robustness issue in the
CWE-20 family, not a memory-safety or DoS bug, and the record-level decoder behind it is clean.

Verdict: the DIF/VIF data-record decoder is sound; one short-frame hardening note on the header parse.

## The limits of a clean result

Each result is a strong first pass, not an exhaustive proof. In every case I drove the real decode entry
with a fidelity model read from the server's own catch blocks, made OOM and hangs deterministic, and ran
tens to hundreds of millions of executions without an escaping `Error`. That is good evidence the parser
is sound against malformed input.

It is not the same as formal absence of bugs. Coverage-guided fuzzing is blind to a bug that hides
behind a specific data value sharing an edge it already covers, so a per-type seed corpus with
degenerate length and count fields, checked with JaCoCo for degenerate-path coverage, would harden these
from strong negatives to near-exhaustive ones. And because all four are pure Java on the decode path,
this says nothing about a memory-corruption class, which does not exist here; a library that dropped into
JNI or an off-heap buffer would need an entirely different run with a native sanitizer.

The reusable part is the method. A Java ICS fuzzing harness earns its result only when its fidelity
model matches what the production server actually catches. Get that wrong in the lenient direction and
you miss real OOMs; get it wrong in the strict direction and you drown in dropped-message noise that was
never a bug. Reading the receive loop first is the whole game.
