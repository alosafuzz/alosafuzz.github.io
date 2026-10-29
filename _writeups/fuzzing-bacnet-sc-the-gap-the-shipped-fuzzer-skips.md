---
title: "Fuzzing BACnet/SC: the gap the shipped fuzzer skips, and a decoder that validates before it trusts"
date: 2026-10-29
project: fieldbusfuzzer
published: true
summary: "bacnet-stack ships its own fuzzers, but they never touch the BACnet/SC datalink. Fuzzing that gap under the full ASan+UBSan+MSan matrix comes back clean, and the reason is worth keeping: a set of option decoders that deliberately omit bounds checks, made safe by a strict validate-then-decode split."
---

*Defensive security research. This writeup describes a fuzzing methodology and a
negative result; it contains no exploit. The target is unmodified open-source
software, [bacnet-stack](https://github.com/bacnet-stack/bacnet-stack), GPL-2.0
with the GCC linking exception.*

---

## Why BACnet/SC, and why the gap

BACnet/SC (BACnet Secure Connect, ASHRAE 135 Annex AB) is the modern secure datalink for building
automation. It replaces classic BACnet/IP's UDP broadcast with a hub-and-spoke network of TLS 1.3
WebSocket connections, and it is being deployed as the fix for classic BACnet being unauthenticated.
The application layer above it is unchanged; what is new is the BVLC-SC framing that wraps every
message on the wire.

The reason it was worth a campaign is a gap, not a hunch. bacnet-stack is the de-facto open-source
BACnet implementation, and it already ships fuzzers (`apps/fuzz-libfuzzer` and `apps/fuzz-afl`). But
those harnesses only enter the BACnet/IP BVLC, NPDU, and APDU paths through `router-mstp/main.c`.
They include nothing from `src/bacnet/datalink/bsc/`. The entire BACnet/SC decoder is unit-tested
only, never fuzzed, and the stack is not on OSS-Fuzz. An earlier pass I did on the classic BVLC-IP
and NPDU core found it robust; BACnet/SC is a different, newer, untested datalink in the same stack.
That is the gaps-only doctrine working as intended: don't re-tread the fuzzed core, go to the layer
the shipped harness skips.

## A clean seam

BACnet/SC's decoder turned out to be one of the most harness-friendly targets I've built. The entry
point is `bvlc_sc_decode_message(uint8_t *buf, size_t buf_len, BVLC_SC_DECODED_MESSAGE *message,
...)`, and `bvlc-sc.c` includes only its own header. It compiles against libc alone, with no other
translation unit to link. That self-containment is also what makes MemorySanitizer feasible here,
the way it was for NMEA 2000 and unlike the hybrid EPICS builds where a gcc archive floods MSan with
false positives.

For seeds I didn't hand-craft frames. The library ships encoders, so I wrote a small generator that
calls them to emit one valid message per BVLC-SC type (Result, Encapsulated-NPDU, Address-Resolution
and ACK, Advertisement and Solicitation, Connect-Request and Accept, Disconnect, Heartbeat,
Proprietary), plus two option-bearing variants: an encapsulated NPDU carrying a secure-path data
option, and one carrying a proprietary destination option. Fifteen on-grammar seeds, which put the
corpus straight into the option-walk and per-function payload paths.

The harness copies each input into a tight `malloc(size)` buffer so a read one byte past the frame
is a hard ASan crash rather than a silent read into allocator slack, then consumes every pointer and
length the decoder hands back: the payload, the data and destination option lists, each proprietary
option's data, and the per-function union (the result's utf8 detail string, the encapsulated NPDU,
the address-resolution URI string, the connect VMAC and UUID, the proprietary data). A decoder that
sets a pointer or length walking past the buffer gets caught on consume. I anchor-validated the whole
path by planting a 1-byte over-read in a throwaway copy of `bvlc-sc.c` and confirming ASan fired a
heap-buffer-overflow at `bvlc_sc_decode_message`, with the real tree left untouched.

## The result, and the alarming comment that isn't a bug

The campaign came back clean: ASan+UBSan over 230 million executions, a separate MSan build over 187
million, zero memory-safety crashes, zero undefined behavior, zero uninitialized reads.

The interesting part is a comment I hit during the static sweep. The option decoders,
`bvlc_sc_decode_option_hdr` and `bvlc_sc_decode_proprietary_option`, say outright that they omit
sanity checks and must be called "on previously validated option list only." Read alone, that looks
like a finding waiting to happen: `bvlc_sc_decode_proprietary_option` reads a 2-octet length out of
the option and indexes by it with no bound in sight.

They are safe because they never run on raw input. `bvlc_sc_decode_hdr` first calls
`bvlc_sc_validate_options_headers`, and that pass does the real work: it walks the option list
against the remaining frame length, checks there are 2 octets left before reading each proprietary
option's declared length, and rejects any declared length that would run the walk past the buffer.
Then `bvlc_sc_decode_message` rejects a list carrying more options than `BVLC_SC_HEADER_OPTION_MAX`.
The VMAC reads and the payload offset are bounded against the message length in the same pass. Only
after all of that do the check-free decoders re-walk the list, now provably in bounds.

This is a deliberate validate-then-decode split. The strict pass up front is what lets the inner
decoders stay simple. It is the right pattern, and it is why the fuzzer and the sweep agree: a
comment that reads like a liability is load-bearing precisely because something else carries the
load. Worth internalizing before you spend a day chasing the over-read that the validation already
closed.

## Why a negative result is still worth publishing

This is a robustness-negative, like classic BACnet (post-fix), CANopen, ADS, NMEA 2000, and the
EPICS stacks: a surface that looked promising and held up under a real campaign. The deliverables
are the reusable parts:

- a **mapped gap** in a widely deployed stack: the BACnet/SC decoder that the shipped fuzzers skip,
  with the self-contained `bvlc_sc_decode_message` seam that makes it cheap to fuzz;
- an **encoder-driven seeding** pattern that puts a corpus on-grammar for free;
- the **validate-then-decode reading** of the option path, so the next researcher recognizes the
  design instead of misreading the "sanity checks omitted" decoders as a bug;
- the complete **ASan+UBSan+MSan matrix** on a self-contained C decoder.

And a scope note worth stating plainly: this covers the message decoder, not the `bsc-socket`,
`bsc-node`, and hub connection state machines above it. Those are stateful, would need a
session-driver harness, and are a separate target. For anyone deploying BACnet/SC: the protocol's
real security value is the TLS layer it adds over classic BACnet, so certificate and hub-trust
management is where the attention belongs, with network segmentation still worth keeping underneath.

*Companion: [A researcher's guide to BACnet/SC](/guides/bacnet-sc/).*
