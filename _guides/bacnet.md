---
title: "A Researcher's Guide to BACnet/IP (ASHRAE 135)"
protocols: ["BACnet/IP"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["building"]
transport: ["bacnet-udp"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

BACnet (ANSI/ASHRAE/ISO 16484-5) is *the* building-automation protocol — HVAC,
lighting, access control, fire panels, metering — in commercial buildings,
hospitals, data centres, and campuses. BACnet/IP carries it over **UDP/IP**, which
shapes the whole threat model: connectionless, spoofable source, and
broadcast-heavy discovery (Who-Is / I-Am).

For a researcher the appeal is threefold: a **three-layer stack** (BVLL → NPDU →
APDU) each with parseable fields; a **tag-length-value (TLV) encoding** with
extended tags and lengths that is a classic parser-fuzz surface; and a set of
**unauthenticated control services** (ReinitializeDevice, DeviceCommunicationControl)
whose only gate is an optional, often-absent password.

- **Transport:** UDP port **47808** (0xBAC0). TCP 47808 is BACnet/SC (secure) and
  some legacy stacks. Spec ASHRAE 135-2020 (freely available).

## 2. Session & transport model

No connection, no handshake — every datagram is independent. A fuzzer just creates
a UDP socket and `sendto`/`recvfrom`. The NPDU control byte's
*message-expecting-reply* bit decides whether a reply is due; unconfirmed services
(Who-Is, I-Am, COV notifications) may draw no unicast reply on real networks (the
software responder below always replies for calibration determinism).

## 3. Wire format — BVLL → NPDU → APDU

**BVLL (4 bytes):** `0x81` type + function code + **big-endian total length**
(includes the 4-byte header — a length field to lie about). Function codes include
Original-Unicast-NPDU (0x0A), Original-Broadcast-NPDU (0x0B), Forwarded-NPDU
(0x04), Register-Foreign-Device (0x05), Distribute-Broadcast-To-Network (0x09),
Read/Write-BDT (0x02/0x01).

**NPDU (2+ bytes):** version `0x01` + control flags. The control byte signals
DEST-present (bit 2) and SRC-present (bit 0); when set, variable-length
network/address specifiers and a **HopCount** follow — HopCount=0 handling is a
known soft spot. Priority bits ride here too.

**APDU** — PDU type in the upper nibble: Confirmed-Request (0x0), Unconfirmed
(0x1), Simple-ACK (0x2), Complex-ACK (0x3), Error (0x5), Reject (0x6), Abort (0x7).
A Confirmed-Request carries segmentation flags, a max-segs/max-apdu byte, an
**invoke-ID** (must echo), and a **service-choice** byte.

**TLV tag encoding** — the fuzz-rich part: `[tag_number(4) | class(1) | len/type(3)]`.
`tag_number=15` escapes to an extended tag byte; `len/type=5` escapes to an
**extended length** (1–3 further bytes). Opening/closing context tags (6/7) bracket
constructed data. Object identifiers pack `(object_type<<22)|instance` into 4 bytes.

## 4. The fuzz surface

- **TLV tag/length parsing** — extended tag numbers (tag=15 + follow byte),
  **extended length escapes** (len/type=5 claiming 1–3 length bytes larger than the
  datagram), mismatched opening/closing context tags, deeply nested constructed
  data. This is the highest-yield generic surface on BACnet.
- **BVLL length field** vs. actual datagram size.
- **APDU type / service-choice dispatch** — undefined service choices; an ACK/Error
  PDU type sent *as a request*.
- **ReadProperty / WriteProperty** — unknown property-ids (→ Error, not crash),
  out-of-range present-value writes, large octet/char-string values (heap-overflow
  shaped), array-index extremes.
- **Unauthenticated control** — **ReinitializeDevice** (coldstart/warmstart) and
  **DeviceCommunicationControl** (disable comms) whose only gate is an optional
  password; test the no-password path.
- **Resource exhaustion** — **SubscribeCOV flood** (COV table is 16–32 slots),
  confirmed-request invoke-ID collision (TSM slot exhaustion), Who-Is storm (device
  floods I-Am → CPU starvation).
- **BBMD surface** — Register-Foreign-Device (FDT exhaustion / broadcast
  redirection), spoofed **Forwarded-NPDU** injection, Distribute-Broadcast relay.
- **NPDU HopCount=0** — discard vs. process/loop.

**Classification line:** Error (0x50), Reject (0x60), Abort (0x70) APDUs and a
non-zero BVLC-Result are **exceptions, not crashes**; Simple/Complex-ACK and
unconfirmed I-Am are clean; a BVLL type ≠ 0x81, a truncated header, or an
unrecognized APDU type is malformed (crash). The crash signal over UDP is a
**timeout** (no datagram) on an otherwise well-formed request.

**Structured vs. coverage-guided:** structured generation reaches the service and
BBMD semantics; the TLV/BER-like tag decoder is also a strong *coverage-guided*
target against an open-source stack (bacnet-stack / BACnet4J) under ASan — the
extended-tag/extended-length paths are where C-stack memory bugs concentrate.

## 5. Known vulnerabilities & bug classes

Durable, repeatedly-productive BACnet classes (field-level):
- **Large-payload WriteProperty** (string/octet-string) — heap overflow.
- **ReadProperty all-properties** — buffer overflow assembling an oversized response.
- **Unauthenticated ReinitializeDevice / DeviceCommunicationControl** — instant
  reboot / comms-brick with no password.
- **SubscribeCOV & invoke-ID exhaustion** — resource/TSM starvation.
- **BBMD FDT exhaustion and Forwarded-NPDU spoofing** — broadcast redirection /
  amplification.
- **TLV extended-length over-read** and **HopCount=0** — parser/loop faults.

(During the icsScanner port of this module's active fingerprint, a real encoder bug
was found in the *write-side* character-string builder — a spurious duplicate length
byte — a reminder that the TLV encoder, not just the decoder, is worth testing.)

## 6. Building a test harness

UDP robustness responder (`scripts/bacnet_responder.py`, port 47809): a
`handle_datagram(data, addr, sidecar, verbose) -> Optional[bytes]` that answers
Who-Is→I-Am, ReadProperty→Complex-ACK/Error, WriteProperty→Simple-ACK,
SubscribeCOV→Simple-ACK, DCC/ReinitDevice→Error(auth), and the BBMD ops
(Register-FD / Read-BDT/FDT / Forwarded-NPDU dispatch) → BVLC-Result/ACK.

Harness notes: use NPDU ctrl `0x00` for plain unicast (no routing fields), `0x04`
for DEST-present; no session/SEQ to patch. Classification exactly as §4.

**Calibration baseline (software responder, 189 cases): clean** — 63 crash
indicators, *all* ANOMALY_TIMEOUT, **0 malformed_response false positives**. The
timeouts are the no-reply-by-design cases (fuzzer-sent I-Am/Who-Has, Abort/Reject
PDUs, binary_corruption) plus 26 Error-APDU exceptions (DCC auth, read-only
WriteProperty). read_write_property and sequence categories were fully clean.

## 7. Open-source implementations & tooling

- **bacnet-stack** (Steve Karg) — the C reference; compilable → ASan/coverage-guided
  for the TLV decoder.
- **BACnet4J** — Java stack; good differential-testing target.
- Wireshark `bacapp` / `bvlc` / `npdu` dissectors; ASHRAE 135 (free).
- `BAC0` (Python) — quick interactive client for building valid seeds.

## 8. Spec references & sources

- ANSI/ASHRAE 135-2020 (freely available from ASHRAE).
- Wireshark BACnet dissectors.

## 9. Open questions / under-explored surface

- A coverage-guided ASan campaign on bacnet-stack's TLV/extended-length decoder —
  not yet run; the highest-value memory-safety surface.
- BACnet/SC (TCP 47808, the secure-channel variant) — a different, newer surface
  deserving its own guide.
- Differential behavior of bacnet-stack vs. BACnet4J vs. embedded controllers on
  the same TLV/service corpus.
- GOOSE-style amplification via BBMD Forwarded-NPDU on real multi-subnet networks.

*Worked example: `protocols/bacnet/fuzzer.py` (8 categories, 189 cases);
responder `scripts/bacnet_responder.py`.*