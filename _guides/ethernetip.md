---
title: "A Researcher's Guide to EtherNet/IP & CIP"
protocols: ["EtherNet/IP", "CIP"]
vendor: ["rockwell"]
vendor_group: "Rockwell / Allen-Bradley"
sector: ["manufacturing"]
transport: ["ethernet-ip"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

EtherNet/IP carries the **Common Industrial Protocol (CIP)** over TCP/IP and
UDP/IP. It is the dominant protocol of **Rockwell/Allen-Bradley** automation
(ControlLogix, CompactLogix, MicroLogix) and is spoken by thousands of ODVA-member
devices — drives, I/O blocks, HMIs, gateways. Two messaging styles: *explicit*
(request/response, TCP 44818) and *implicit* I/O (cyclic, UDP 2222).

For a researcher EtherNet/IP is a two-layer target with a lot of depth: a
fixed 24-byte **ENIP encapsulation** header (session, length, status) wrapping a
**CIP** request whose richness — a path of logical segments addressing
class/instance/attribute, a service-code space, and the Connection Manager's
Forward_Open / Unconnected_Send routing — is where the interesting bugs live. The
CIP **path** and the **Unconnected_Send** embedded-message are the two highest-value
surfaces, and both have recent (2026) Rockwell CVEs.

- **Transport:** TCP **44818** (explicit messaging — this guide), UDP 2222 (I/O).
  Spec: ODVA EtherNet/IP + CIP Vol. 1/2.

## 2. Session & transport model

```
TCP connect → RegisterSession (0x0065) → session handle → Send RR Data (0x006F) → …
```

A session handle is assigned by the target in RegisterSession and must ride in the
ENIP header of subsequent commands (`Unregister Session` and `Send RR Data` require
it). A fuzzer completes RegisterSession in `connect()`, stores the handle, and
patches it into outgoing frames — *except* where the test is a wrong/zero handle.
Some commands (NOP, List Identity/Services/Interfaces) need no session.

## 3. Wire format — ENIP encapsulation + CIP

**ENIP header (24 bytes, little-endian):** Command (2) | Length (2) | Session
Handle (4) | Status (4) | Sender Context (8, echoed) | Options (4, must be 0) |
Data. Commands: NOP 0x0001 (no response), List Services 0x0004, List Identity
0x0063, Register 0x0065, Unregister 0x0066, Send RR Data 0x006F, Send Unit Data
0x0070.

**Common Packet Format (CPF)** inside Send RR Data: Interface Handle (4) | Timeout
(2) | Item Count (2) | items `{Type(2), Length(2), Data}`. Unconnected explicit
messaging = a Null Address Item (0x0000, len 0) + an **Unconnected Data Item**
(0x00B2) carrying the CIP request.

**CIP request:** `Service(1, bit7=0) | PathSize(1, in WORDs) | Path(PathSize×2) |
Data`. Response: `Service|0x80 | 0x00 | GeneralStatus(1) | AddlStatusSize(1) |
AddlStatus… | Data`.

**CIP path** = logical segments `0x20|type|format` — Class (0x20), Instance (0x24),
Attribute (0x30), Connection Point (0x2C), with 1/2/4-byte formats (the 2/4-byte
forms carry a pad byte). Common targets: Identity `20 01 24 01`, Message Router
`20 02 24 01`, **Connection Manager `20 06 24 01`**.

**Key CIP services:** Get/Set_Attribute_Single (0x0E/0x10), Get/Set_Attributes_All
(0x01/0x02), Multiple_Service_Packet (0x0A), **Forward_Open (0x54)**,
**Forward_Close (0x4E)**, **Unconnected_Send (0x52)**, **Large_Forward_Open (0x5E)**.
Forward_Open carries connection parameters (RPI, network connection params with a
10-bit size field) and a **Connection Path Size** + path; Unconnected_Send carries
an **embedded message length** + embedded CIP request + a route path.

## 4. The fuzz surface

- **CIP path segments** — the richest surface. `PathSize` lying about the segment
  bytes that follow; oversized ANSI-symbol segments (`0x91`/`0xAF` + length); bogus
  logical-segment formats; truncated 2/4-byte segments missing the pad byte. Recent
  Rockwell CVEs (2026-9621/9622/9624/9625) are **path-size and embedded-length lies**.
- **Forward_Close path-size lie** and **Unconnected_Send embedded-message-length
  lie** — the two specific 2026 CVE shapes: a length field (path size / embedded
  message length) that disagrees with the bytes actually present.
- **Connection parameters** (Forward_Open) — RPI=0 or 0xFFFFFFFF, the 10-bit
  connection-size field at extremes; **Large_Forward_Open (0x5E)** 4-byte size
  params up to 65535; concurrent Forward_Opens exhausting a fixed pool (4–8).
- **Service-code dispatch** — undefined/vendor service codes; a response-bit-set
  service as a request.
- **ENIP header** — Length vs. actual CPF bytes, bad Options (must be 0), invalid
  session handle (session fixation: some devices accept any handle), oversized
  Sender Context.
- **Unconnected_Send routing** — route path to unintended backplane modules (path
  traversal across the backplane).
- **Allen-Bradley extensions** — Logix symbolic tag read/write (0x4C/0x4D) with a
  0x91 symbolic segment (empty/max/odd-length names, element-count extremes,
  fragmented 0x4E/0x4F), and Execute PCCC (0x4B) CMD/FNC sweeps.
- **State / NOP** — NOP (0x0001) has *no* response (skip the recv or every NOP case
  false-positives as timeout — a real harness pitfall); RegisterSession replay.

**Classification line:** ENIP status non-zero or CIP general status non-zero →
**exception, not crash** — *except* ENIP 0x0001 (invalid command) / 0x0003
(malformed) which disconnect and are crash-worthy. The crash signal is
timeout/reset on a well-formed, session-valid request.

**Structured vs. coverage-guided:** heavily structured — the bugs are CIP-semantic
(path-size/embedded-length lies, connection-manager state, service dispatch) reached
through a real session. The recent Rockwell path/embedded-length CVEs were found by
*structured* length-mismatch generation, exactly this module's forte.

## 5. Known vulnerabilities & bug classes

- **CVE-2026-9621/9622/9624/9625** (Rockwell, 2026) — **Forward_Close path-size
  lie** and **Unconnected_Send embedded-message-length lie**: a length field that
  exceeds the bytes present drives an over-read. The icsFuzzer EtherNet/IP module
  added explicit cases for both.
- **Oversized CIP path string** — buffer overflow in path parsing on some PLCs.
- **Connection-parameter extremes** (RPI=0/0xFFFFFFFF; connection-size field) —
  integer/allocation faults.
- **Session fixation** — devices accepting any session handle unverified.
- **Forward_Open amplification** — target streams large I/O to an attacker-chosen
  UDP destination.
- **Unconnected_Send backplane traversal** — reach modules not meant to be routable.
- **Malformed security-object (class 0xAC) service** — crashes on some Rockwell PLCs.

## 6. Building a test harness

Robustness responder (`scripts/ethernetip_responder.py`, port 44819): module-level
`_next_session_handle()` for unique per-connection handles; handles Register/
Unregister, List Identity/Services/Interfaces, NOP, Send RR Data; CIP Get/Set
attribute, Forward_Open/Close, Large_Forward_Open, Multiple_Service_Packet,
Unconnected_Send; a fake Identity object; sidecar JSONL.

Harness notes:
- **Patch the session handle** (ENIP bytes 4:8) for all categories *except*
  binary_corruption and state_machine (which test wrong sessions); never patch
  RegisterSession (session=0 by spec).
- **NOP has no response** — detect it and skip the recv, or every NOP case times out
  (100% false-positive). The general "no-response command" lesson.
- No application CRC (TCP handles integrity).

Live target reality: **OpenPLC's EtherNet/IP is a minimal I/O stub** — only
RegisterSession + Forward_Open/Close are implemented; List Identity / Send RR Data /
Unconnected_Send / Large_Forward_Open all **silently time out** (not crashes — the
server is healthy, verified by a fresh RegisterSession after each category). The
*implemented* Forward_Open/Close path took 36 malformed cases with 0 crashes (a real
negative result). **A meaningful CIP-object/unconnected-messaging assessment needs a
full-stack device** (ControlLogix, Moxa MGate), not OpenPLC — an important targeting
lesson: confirm the stack *implements* the surface before trusting a "clean" run.

## 7. Open-source implementations & tooling

- **cpppo** (Python) and **pycomm3** — clients for building valid seed requests.
- **OpENer** (ODVA's open-source EtherNet/IP adapter, C) — compilable →
  ASan/coverage-guided target for the CIP parser.
- Wireshark `enip` / `cip` dissectors; ODVA CIP Vol. 1/2.
- Real full-stack targets for the interesting surface: Rockwell ControlLogix,
  Moxa MGate.

## 8. Spec references & sources

- ODVA EtherNet/IP Specification; CIP Vol. 1 (Common) + Vol. 2 (EtherNet adaptation).
- Rockwell advisories for CVE-2026-9621/9622/9624/9625.
- Wireshark ENIP/CIP dissectors.

## 9. Open questions / under-explored surface

- A coverage-guided ASan campaign against OpENer's CIP path/segment parser — the
  path-size-lie class suggests memory-safety bugs beyond the known Rockwell ones.
- Confirming the 2026 Rockwell CVE shapes against a live RSLinx/ControlLogix target
  (no full-stack device was available during the module's build).
- Implicit I/O (UDP 2222) and the Forward_Open amplification path — out of scope
  here; a separate guide.
- Backplane-traversal reach via Unconnected_Send on real multi-module chassis.

*Worked example: `protocols/ethernetip/fuzzer.py` (10 categories incl. Logix tag +
PCCC + the 2026 path/embedded-length CVE cases); responder
`scripts/ethernetip_responder.py`.*