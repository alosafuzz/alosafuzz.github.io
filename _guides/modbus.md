---
title: "A Researcher's Guide to Modbus/TCP"
protocols: ["Modbus/TCP"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["cross"]
transport: ["modbus-tcp"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

Modbus is the oldest and most widely deployed industrial protocol — PLCs, RTUs,
drives, meters, I/O blocks across every vertical. Modbus/TCP wraps the original
serial PDU in a 7-byte MBAP header and runs over **TCP port 502**. It is governed
by the Modbus Organization (there is **no IETF RFC**; the authoritative docs are
the modbus.org spec V1.1b3 and the TCP/IP implementation guide).

For a researcher Modbus is deceptively simple — a 1-byte function code and a tiny
data model — which is exactly why it rewards fuzzing: the protocol has **no
authentication, no encryption, no integrity** (TCP carries no CRC), so every
bug is reachable from any client, and the interesting failures are in how
implementations handle *malformed or boundary* requests, gateway broadcast
semantics, and length-field lies.

## 2. Session & transport model

No handshake — connect to 502 and send an ADU. Requests are correlated by a
**Transaction ID** the server echoes, so multiple requests can be pipelined on one
connection. Max ADU over TCP is **260 bytes** (7 MBAP + 253 PDU).

## 3. Wire format — MBAP + PDU

**MBAP header (7 bytes, big-endian):**
| Field | Bytes | Note |
|---|---|---|
| Transaction ID | 2 | echoed by server |
| Protocol ID | 2 | **always 0x0000** |
| Length | 2 | byte count of Unit ID + PDU (≤ 0x00FF) |
| Unit ID | 1 | serial slave addr; 0xFF ≈ "no slave" on TCP; **0x00 = broadcast on a TCP→serial gateway** |

**PDU:** `FunctionCode(1) | Data(0..252)`. Exception response: `FC|0x80 | ExceptionCode`.

Function-code ranges: 0x01–0x40 public (many unassigned), 0x41–0x48 and 0x64–0x6E
user-defined, 0x80–0xFF exception space. Per-request limits are spec-defined
(FC01/02 ≤ 2000 coils; FC03/04 ≤ 125 registers; FC0F ≤ 1968 coils; FC10 ≤ 123
registers; FC05 value must be exactly 0xFF00 or 0x0000). Exceeding a limit must
return Exception 03.

## 4. The fuzz surface

- **Function-code dispatch** — sweep 0x00–0x7F: unassigned gap codes (0x09, 0x0A,
  0x0D, 0x0E, 0x12, 0x13, 0x19–0x2A, …) must return Exception 01 (Illegal
  Function); a silent drop or crash is non-compliant and interesting.
- **MBAP Length field vs. actual** — declare N, send M: N > M = **starvation**
  (server blocks waiting for bytes that never arrive); N < M = **truncation**. The
  highest-value framing lever.
- **Protocol ID ≠ 0x0000** — undefined behavior.
- **Per-request count/quantity boundaries** — FC03 qty=126, FC0F qty=1969,
  address near 0xFFFF with a count that straddles the ceiling, byte-count
  inconsistent with quantity (FC0F/FC10 where the declared byte_count disagrees
  with qty — a length-lie inside the PDU). A notable real-world finding on an ESP32
  stack was a **truncated FC0F exception** (missing exception-code byte) on
  large-quantity writes.
- **FC05 value abuse** — any value other than 0xFF00/0x0000.
- **Unit-ID / broadcast semantics** — on a TCP→serial **gateway**, Unit ID 0x00 +
  a write FC (05/06/0F/10) is a **broadcast write to every downstream slave** —
  high impact; reserved UIDs 0xF8–0xFE are undefined on TCP.
- **Transaction-ID handling** — duplicate TIDs across pipelined requests, TID=0,
  wraparound 0xFFFF→0x0000 (a device that misroutes by TID).
- **Coil/register aliasing** — write via one data type, read back via another;
  PLCs that share physical storage flip unexpected bits.
- **Pipelining / stacked PDUs** — multiple ADUs in one TCP segment (multi-ADU
  response handling is a real harness concern — see §6).
- **Secondary (downstream) injection** — register *values* flow into HMIs,
  historians, CSV/SQL exports; format-string / XSS / CSV-formula / SQL fragments
  written via FC10 surface bugs one layer past the PLC. Secondary to protocol
  fuzzing; opt-in via an injection wordlist.

**Classification line:** `FC|0x80` exception responses are **spec-compliant, not
crashes**. The crash signal is timeout/reset/no-response, a TID/proto/length
mismatch in the reply, or a truncated response.

**Structured vs. coverage-guided:** Modbus is a textbook structured-generator
target — the surface is semantic (FC dispatch, count/length validation, gateway
broadcast) and shallow. A coverage-guided campaign is better spent on the embedded
C stacks (libmodbus, FreeMODBUS, esp-modbus) where the memory-safety bugs live.

## 5. Known vulnerabilities & bug classes

Modbus's durable, repeatedly-productive classes (the base protocol has no CVE of
its own — the bugs are per-implementation):
- **Illegal-function / gap-code crashes** on embedded stacks (should be Exception 01).
- **Length-field starvation** — a declared length larger than the payload hangs the
  reader (connection/thread exhaustion).
- **Count/byte-count overflows** — qty or byte_count beyond spec limits driving
  over-reads/over-writes (e.g. the truncated-FC0F-exception class above).
- **Gateway broadcast write** — unauthenticated mass write via Unit ID 0x00.
- **Connection exhaustion** — most devices cap at 1–16 concurrent TCP connections.
- **Downstream injection** — register values rendered/logged unsanitized.

## 6. Building a test harness

Robustness responder (`scripts/modbus_responder.py`, port 5020): returns Exception
0x02 for assigned FCs, 0x01 for unknown, one writable coil at 0x0001; validates
proto-id, length (≤260), truncation; sidecar JSONL.

Harness lessons (these are the ones that bite):
- **Multi-ADU drain.** A pipelined / coil-aliasing payload gets *one response per
  ADU*. Read only the first and the next case reads a stale response → false
  TID-mismatch cascade. Count ADUs, drain N−1, compare the Nth response's TID
  against the **Nth** ADU (not the first).
- **Reconnect after *every* broken-socket anomaly** — not just timeout/reset, but
  also clean EOF (no_response) and malformed_response, or every subsequent case
  false-positives into a dead socket.

**Calibration baseline (software responder, 978 cases): clean** — 71 crash
indicators, all expected (46 connection_reset: bad proto_id/oversized/truncated; 19
timeout: starvation/truncation; 6 no_response), **0 malformed_response false
positives** after the multi-ADU TID fix. Live runs against esp-modbus / OpenPLC
reproduced known per-stack behavior with no new false signal.

## 7. Open-source implementations & tooling

- **libmodbus** (C), **FreeMODBUS**, **esp-modbus** (ESP-IDF), **modbus-esp8266**
  (Arduino) — embedded C targets for coverage-guided/ASan campaigns (where the real
  memory bugs are).
- **pymodbus** (Python) — reference client for valid seeds and a spec-compliance
  differential oracle.
- Wireshark `mbtcp` dissector; modbus.org spec V1.1b3 + TCP/IP guide.

## 8. Spec references & sources

- MODBUS Application Protocol Specification V1.1b3 (modbus.org, 2012).
- MODBUS Messaging on TCP/IP Implementation Guide V1.0b (2006).
- MODBUS Security Protocol V3.6 (2021) — the TLS/cert-auth wrapper (rarely deployed).

## 9. Open questions / under-explored surface

- Which embedded stacks crash (vs. Exception 01) on gap function codes — the ESP32
  truncated-FC0F result suggests the embedded tier is where the live bugs are.
- Device-specific string-register conventions for the downstream-injection surface.
- A coverage-guided ASan sweep of libmodbus/FreeMODBUS PDU handling — complementary
  to the structured generator.

*Worked example: `protocols/modbus/fuzzer.py` (9 categories, 978 cases) — the
project's original and largest module; responder `scripts/modbus_responder.py`.
(Prior published prose: `blog-post-ics-fuzzing.md`.)*