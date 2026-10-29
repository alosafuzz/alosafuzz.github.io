---
title: "A researcher's guide to BACnet/SC (BACnet Secure Connect)"
protocols: ["BACnet/SC", "BACnet Secure Connect", "BVLC-SC"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["building"]
transport: ["websocket", "tls", "tcp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
known bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

**BACnet/SC** (BACnet Secure Connect, ASHRAE 135 Annex AB) is the modern secure datalink for
BACnet, the dominant building-automation protocol. It replaces classic BACnet/IP's UDP broadcast
(port 47808) with a **hub-and-spoke network of TLS 1.3 WebSocket connections**: nodes dial a hub
over `wss://`, and the hub relays frames between them. It exists because classic BACnet is
unauthenticated and unencrypted, and it is being deployed as the fix for exactly that (vendors ship
it in newer controllers and management systems).

The important thing for a researcher: the BACnet application layer above it (NPDU, APDU, object
services) is **unchanged**. What is new is the **BVLC-SC framing layer** that wraps every message
on the wire. So BACnet/SC adds one new binary parser to the stack, and that parser runs on every
frame a node or hub receives, below the application logic.

- **Transport:** WebSocket over TLS 1.3 (`wss://`), hub-and-spoke. Two datalink roles: the **hub**
  (accepts node connections, relays) and the **node** (connects to a primary and failover hub).
- **Security model:** TLS gives authentication and confidentiality at the connection level. That
  matters for the threat model (below), but it does not make the BVLC-SC decoder's job any safer:
  the decoder runs on whatever bytes a connected peer sends.
- **Role:** every participant parses BVLC-SC messages from its peers.

## 2. The BVLC-SC message model

A BVLC-SC message (ASHRAE 135 AB.2.2) is a binary frame:

- **BVLC function** (1 octet): the message type.
- **Control flags** (1 octet): bits for whether an originating VMAC, destination VMAC, data
  options, and destination options are present.
- **Message ID** (2 octets).
- **Originating / Destination Virtual Address** (0 or 6 octets each, VMAC, presence per control
  flags).
- **Destination options** and **data options** (variable, a walked list, presence per control
  flags). Each option is secure-path or proprietary; a proprietary option carries a 2-octet length
  then its data.
- **Payload** (the rest of the frame), interpreted per the BVLC function.

Message types: BVLC-Result, Encapsulated-NPDU, Address-Resolution (and ACK), Advertisement (and
Solicitation), Connect-Request, Connect-Accept, Disconnect-Request (and ACK), Heartbeat-Request
(and ACK), and Proprietary-Message.

The researcher's hooks: the **VMAC-present flags** (do the 6-octet reads stay in the frame?), the
**option list walk** (does a proprietary option's declared length walk past the buffer?), and the
**per-function payload** (variable-length strings and NPDU bodies pointed at by offset and length).
These are the classic length-lie and offset-walk surfaces.

## 3. The fuzz surface, mapped to bacnet-stack

[bacnet-stack](https://github.com/bacnet-stack/bacnet-stack) (GPL-2.0 with the GCC linking
exception) is the de-facto open-source BACnet stack and implements BACnet/SC in
`src/bacnet/datalink/bsc/`. The key point for a researcher: **the stack ships its own fuzzers
(`apps/fuzz-libfuzzer`, `apps/fuzz-afl`), but they only enter the BACnet/IP BVLC, NPDU, and APDU
paths. They include nothing from `bsc/`.** The BACnet/SC decoder is unit-tested only, never fuzzed,
so it is a genuine gap in an otherwise partially-fuzzed stack.

- **PRIME, the message decoder:** `bvlc_sc_decode_message(uint8_t *buf, size_t buf_len,
  BVLC_SC_DECODED_MESSAGE *message, ...)` in `bvlc-sc.c`. It is a **pure in-process decoder**: bytes
  in, a decoded struct out, no WebSocket or TLS stack required. `bvlc-sc.c` includes only its own
  header, so a harness compiles it against libc alone.
- **The sub-decoders it drives:** `bvlc_sc_decode_hdr` (header + VMAC + option-list validation),
  `bvlc_sc_validate_options_headers` (the up-front option-length validation pass), and the
  per-type decoders for result, advertisement, connect-request, connect-accept, and proprietary.
- **The layer above (separate, larger surface):** the `bsc-socket` / `bsc-node` / hub-function /
  node-switch **connection state machines**. These are stateful and would need a session-driver
  harness; the pure decoder above is the cheap, high-value seam.

Role is peer-side: the decoder parses what a connected node or hub sends.

## 4. Known bug classes

BACnet/SC itself has no CVE, and the `bsc/` code is not on OSS-Fuzz. But the BACnet BVLC-and-length
class is live in the classic (IP) datalink, which is the right prior:

- **[CVE-2020-36872](https://nvd.nist.gov/vuln/detail/CVE-2020-36872)**: a BACnet Test Server
  failed to validate the BVLC Length field against the received UDP frame, a denial of service. The
  classic length-lie.
- **[CVE-2018-10238](https://opencve.alliance.unm.edu/cve/CVE-2018-10238)**: a buffer overflow in
  BACnet/IP BVLC forwarded-NPDU handling.
- The NDSS 2026 paper
  [*BACnet or BadNet*](https://www.ndss-symposium.org/ndss-paper/bacnet-or-badnet-on-the-insecurity-of-implicitly-reserved-fields-in-bacnet)
  (BACsFuzz) found 26 issues across BACnet and KNX tied to implicitly reserved fields, in the
  classic datalink, not BACnet/SC.

So the question for BACnet/SC is the same, moved up one layer: does the BVLC-SC decoder bound every
VMAC read, option length, and payload offset against the actual received length?

## 5. A robustness note: bacnet-stack's BACnet/SC decoder holds up

I fuzzed `bvlc_sc_decode_message` in-process under **AddressSanitizer + UndefinedBehaviorSanitizer +
MemorySanitizer**, all three, feasible because the decoder is a self-contained C build. Seeds were
generated by the library's own encoders (one valid message per type, plus option-bearing variants),
and the harness used a tight `malloc(size)` buffer so any read past the frame is a hard crash, not a
silent read into allocator slack. The harness was anchor-validated: a planted 1-byte over-read
produced the expected ASan heap-buffer-overflow.

**Result: clean.** Hundreds of millions of executions, zero memory-safety crashes, zero undefined
behavior, zero uninitialized reads.

The interesting part is *why* it holds. The option decoders (`bvlc_sc_decode_option_hdr`,
`bvlc_sc_decode_proprietary_option`) carry a comment saying they omit sanity checks and must be
called on a "previously validated option list only." Read in isolation, that is alarming: they read
a proprietary option's 2-octet length and index by it with no bound. But they never run on raw
input. `bvlc_sc_decode_hdr` first calls `bvlc_sc_validate_options_headers`, which walks the option
list against the remaining frame length, checks there are 2 octets to read before reading each
proprietary length, and rejects any declared length that would run past the buffer. Then
`bvlc_sc_decode_message` rejects a list with more options than `BVLC_SC_HEADER_OPTION_MAX`. The VMAC
and payload offsets are all bounded against the message length in the same pass. It is a deliberate
**validate-then-decode** split: the strict pass up front lets the inner decoders stay simple without
being unsafe.

This is a robustness-negative of the same kind as classic BACnet (post-fix), CANopen, ADS, NMEA
2000, and the EPICS stacks. The value is the mapped gap and the methodology, not a CVE, and for a
security-oriented transport layer a clean decoder is the result you want.

## 6. Defensive notes

- **The real BACnet/SC security story is the TLS layer**, certificate issuance and rotation, and
  hub access control. BACnet/SC fixes classic BACnet's lack of authentication; keep the certificate
  and trust-store management disciplined, because that is the control the protocol actually adds.
- **The BVLC-SC decoder runs before any connection-level trust decision**, on whatever a peer sends.
  A compromised or malicious node (or a hub) is the realistic attacker against it. If you integrate
  a different BACnet/SC stack, audit its decoder for the VMAC-read, option-walk, and payload-offset
  bounds described above.
- **Segment the automation network.** TLS and SC do not remove the value of keeping building-control
  systems off general-purpose networks.

## 7. Further reading

- bacnet-stack (BACnet/SC in `src/bacnet/datalink/bsc/`):
  [github.com/bacnet-stack/bacnet-stack](https://github.com/bacnet-stack/bacnet-stack).
- Classic BACnet BVLC/length CVEs:
  [CVE-2020-36872](https://nvd.nist.gov/vuln/detail/CVE-2020-36872),
  [CVE-2018-10238](https://opencve.alliance.unm.edu/cve/CVE-2018-10238).
- [*BACnet or BadNet* (NDSS 2026)](https://www.ndss-symposium.org/ndss-paper/bacnet-or-badnet-on-the-insecurity-of-implicitly-reserved-fields-in-bacnet).
- Companion guide: [BACnet/IP](/guides/bacnet/).
- Writeup: *Fuzzing BACnet/SC: the gap the shipped fuzzer skips* (alosafuzz).

*Caveat on reachability: the decoder result is proven in-process against the real
`bvlc_sc_decode_message`; the connection state machines above it (bsc-socket/node/hub) are a
separate stateful surface not covered here.*
