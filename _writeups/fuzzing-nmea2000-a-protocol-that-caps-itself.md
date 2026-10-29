---
title: "Fuzzing NMEA 2000: a virgin marine stack, a sibling's CVE, and a protocol that caps itself"
date: 2026-10-29
project: fieldbusfuzzer
published: true
summary: "A full ASan+UBSan+MSan campaign over ttlappalainen/NMEA2000, covering all 55 PGN decoders and the fast-packet reassembly path, comes back clean. A robustness-negative, and a case study in why the sanitizer matrix is worth the setup cost: it caught two of my own harness bugs, and the one bug class that just took a CVE in a sibling stack turned out to be guarded here."
---

*Defensive security research. This writeup describes a fuzzing methodology and a
negative result; it contains no exploit. The target is unmodified open-source
software, [ttlappalainen/NMEA2000](https://github.com/ttlappalainen/NMEA2000), MIT.*

---

## The setup

NMEA 2000 is the control network on boats: GPS, depth, engine, autopilot, and AIS
vessel-tracking all sharing one CAN bus. It is unauthenticated by design, with every node
trusting every frame, which makes the realistic attacker a malicious or counterfeit device
on the bus and the attack surface a node's parser of the PGN messages other nodes send.
[ttlappalainen/NMEA2000](https://github.com/ttlappalainen/NMEA2000) is the de-facto
open-source N2K stack, embedded in a large fraction of marine gateways and devices.

It landed on my candidate board for one reason: a sibling implementation just took a CVE
for exactly this bug class. The N2K driver inside gpsd was hit by
[CVE-2025-67268](https://nvd.nist.gov/vuln/detail/CVE-2025-67268), a heap out-of-bounds
write in PGN 129540 (satellites-in-view), where the satellite count read off the wire was
not bounded against a fixed array, plus CVE-2025-67269, an integer underflow DoS. When a
protocol's parse class is demonstrably live in one implementation, the obvious question is
whether the other popular implementation has the same shape of bug. ttlappalainen has no
CVE, is not on OSS-Fuzz, and ships no fuzzer, so it is a virgin target by my pre-build
checklist. GO, full campaign.

## Reaching the parsers

The good news about an in-process N2K harness is that `tN2kMsg` is a plain struct. You
fill its `Data[]` with crafted bytes, set the PGN, and call the decoder. No CAN hardware,
no transport to stand up. The decoders live in `N2kMessages.cpp` as a family of
`bool ParseN2kPGN#####(const tN2kMsg&, ...)` functions that pull fields out through the
shared extractor primitives in `N2kMsg.cpp` (`GetByte`, `Get2ByteUInt`, `GetStr`,
`GetVarStr`, and so on), each reading at an advancing index.

I started with a hand-written harness over five high-value decoders: position, COG/SOG,
GNSS, AIS, and the satellites-in-view PGN that bit gpsd. It came back clean fast. But five
of ~55 decoders is not a result, because coverage-guided fuzzing is only honest about the
code it actually enters. So I auto-generated a harness over every `ParseN2kPGN*` in the
library. A small generator parses the prototypes out of the header
(`bool\s+(ParseN2kPGN\d+)\s*\(([^;{}]*)\)`), declares one scratch output per distinct
parameter type, pairs each `char*`/`size_t` string-out with a fixed 64-byte buffer, and
emits a `switch` that sets the right PGN and calls the decoder for each fuzzer-chosen
index. Fifty-five decoders, one entry point, the fuzzer picking which to hit and with what
bytes.

That broad harness also came back clean. But getting there, two of my own bugs fired
first, and that is really the story.

## The sanitizers caught me twice

I ran this target under the full matrix, AddressSanitizer plus UndefinedBehaviorSanitizer
plus MemorySanitizer, which was feasible here precisely because NMEA2000 is a
self-contained C++ build with minimal STL and no external gcc archive to link against. On
my hybrid-build targets like the EPICS stacks, MSan false-positive-floods on every call
into uninstrumented code, so it is out of scope there. NMEA2000 is the one target in this
series where all three ran cleanly end to end.

Both of the first "crashes" were in my harness, not the library.

The first was a UBSan hit during smoke-testing. I was consuming a decoder's
`double Latitude` output as `(unsigned long)Latitude` to feed a data sink. A negative
latitude is a negative double, and casting that to an unsigned integer is undefined
behavior. UBSan flagged it at once. The fix was to consume only integer outputs into the
sink. The lesson is that UBSan polices the harness as strictly as the target, and a
float-to-unsigned cast is easy to write without thinking.

The second was an MSan hit in the fast-packet harness. I declared `unsigned long id` (8
bytes) and filled it with `memcpy(&id, data, 4)` (4 bytes), then passed it to the CAN-ID
decoder. The high four bytes were uninitialized. ASan never saw it, because the decoder
masks the ID down to 29 bits, so the uninitialized bytes never affected an address. Only
MSan caught the uninitialized read. `unsigned long id = 0;` fixed it. This is the
canonical case for keeping MSan in the matrix even when ASan is already green: uninit reads
that get masked away are invisible to everything else.

Neither was a library bug. But each one is a reminder that a clean result is only as
trustworthy as the harness producing it, and the matrix is what keeps the harness honest.

## The fast-packet path, and a protocol that caps itself

The parser breadth covers the decode surface. The other half of N2K's attack surface is
the receive path: the fast-packet reassembly state machine
(`tNMEA2000::SetN2kCANBufMsg`) that stitches a sequence of CAN frames back into one
message. A fast-packet first frame declares a total byte length, and continuation frames
carry a rolling counter and 7 bytes each. A declared length that does not match what
actually arrives is the classic reassembly over-read or over-write primitive.

To fuzz it I subclassed `tNMEA2000` with a stub CAN layer (every `CANSend`/`CANGet`
overridden to a no-op), set listen-only mode, and fed the fuzzer's bytes as a stream of
13-byte synthetic CAN frames into the reassembler, consuming and freeing completed slots.
Anchor-validating this harness was itself instructive. Planting a "declared length too
large" did not overflow anything, because the protocol caps itself. A fast-packet message
maxes out at exactly 6 + 31*7 = 223 bytes, the reassembly buffer is `Data[223]`, and the
copy is independently length-bounded, so a declared length larger than the buffer never
completes (there are not enough continuation frames to fill it) rather than overflowing.
The field that looks like an over-read primitive is closed by the geometry of the protocol.
I only got the anchor to fire by writing far past the buffer (`Data[CopiedLen+100000]`),
which confirmed the harness genuinely reaches the copy and ASan genuinely watches it. The
library's arithmetic just never produces an out-of-bounds index.

With the anchor validated, the real run was clean: tens of millions of executions across
the reassembly path under ASan plus UBSan, and a separate MSan build over the same path.
Zero crashes, zero UB, zero uninitialized reads.

## The result

Across the whole campaign, all ~55 PGN decoders and the fast-packet reassembly path, under
ASan plus UBSan plus MSan:

| Harness | Sanitizers | Executions | Crash / Timeout / OOM |
|---|---|---|---|
| 5 high-value decoders | ASan+UBSan, MSan | ~190M | 0 / 0 / 0 |
| 55-decoder auto-generated | ASan+UBSan, MSan | ~410M | 0 / 0 / 0 |
| fast-packet reassembly | ASan+UBSan (55M), MSan (44M) | ~99M | 0 / 0 / 0 |

Clean. And specifically, the gpsd bug class is guarded here: `ParseN2kPGN129540` bounds
the satellite count before indexing, the extractors clamp the read index against the
message length, and the string paths clamp the declared length to the bytes remaining.
ttlappalainen/NMEA2000 is a carefully, defensively written stack.

## Why a negative result is still worth publishing

This is a robustness-negative, like my CANopen, post-fix BACnet, Beckhoff ADS, and EPICS
(Channel Access and pvAccess) campaigns: a virgin implementation of a protocol whose bug
class is live elsewhere, that holds up under a real campaign. The deliverables are the
reusable things:

- a mapped fuzz surface for the most-deployed open-source N2K stack, so the next
  researcher starts from the decoders and the reassembler rather than from zero;
- an auto-generation pattern for covering a large family of same-shaped decoders from one
  harness;
- the protocol-cap insight that closes the fast-packet declared-length primitive by design,
  worth knowing before you spend days hunting an overflow that cannot exist;
- a concrete demonstration that the ASan+UBSan+MSan matrix pays for itself. It caught two
  harness bugs that would otherwise have quietly biased the result, including one, the
  masked uninit read, that only MSan could see.

And a defensive takeaway for anyone running N2K gear: the bus is a trust domain. The
realistic attacker is a counterfeit or compromised device on the wire (`AV:A`), and
segmentation, not the parser, is the mitigation that matters. If you integrate a different
N2K stack than ttlappalainen, audit its count-bearing decoders against the gpsd class
before you trust it.

*Companion: [A researcher's guide to NMEA 2000](/guides/nmea2000/).*
