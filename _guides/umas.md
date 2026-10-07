---
title: "A Researcher's Guide to Schneider UMAS (Modbus fn 0x5A)"
protocols: ["UMAS", "Modbus"]
vendor: ["schneider"]
vendor_group: "Schneider Electric"
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

UMAS (Unified Messaging Application Services) is **Schneider Electric's**
proprietary engineering protocol for the Modicon line — M221, M340, M580, Quantum,
Premium. It is how EcoStruxure Control Expert / Unity Pro / Machine Expert read PLC
identity, read/write variables and memory, take an exclusive **reservation** of the
controller, and upload/download the control program.

The researcher's hook: UMAS is **not** a separate protocol on a separate port — it
rides *inside* standard Modbus/TCP on **port 502** as a single Modbus function code,
**`0x5A`**. Allow Modbus to a Modicon PLC and you allow UMAS. That means a UMAS
fuzzer can **layer directly on an existing Modbus transport** (reuse the MBAP
machinery, swap the PDU to fn 0x5A) — and the interesting surface is a sub-function
dispatch table, a reservation/session state machine, and length-prefixed
name/nonce/signature fields riding on a transport you already have.

## 2. Session & transport model

```
TCP connect (502) → READ_ID (unauth) → [optional: TakeReservation → session key] → …
```

No UMAS-specific handshake over the Modbus transport. READ_ID (identity) is
unauthenticated across the whole Modicon line. A **reservation** (UMAS fn 0x10)
returns a 1-byte **session key** that privileged operations must then carry in the
PDU's session byte; on newer PLCs the reservation is gated by a nonce +
SHA256-signed message, on older ones (M221) it is effectively ungated
(CVE-2018-7790/7791). A fuzzer should **not** auto-reserve — a held reservation
exclusively locks out a live engineer.

## 3. Wire format

Modbus/TCP MBAP (7 bytes) + UMAS PDU:
```
MBAP: TID(2) | Proto=0x0000(2) | Length(2) | Unit(1)
UMAS PDU: 0x5A | session/pairing(1) | UMAS-function(1) | body…
```
- Session/pairing byte is `0x00` before a reservation, the device-issued key after.
- READ_ID request is ten bytes: `00 01 00 00 00 04 00 5a 00 02`.

**Response shape nuance (important for a classifier):**
- READ_ID / plain replies: `MBAP + 0x5A + status + data` — status at **offset 8**.
- Reservation replies: `MBAP + 0x5A + session-echo + status + new-key` — status at
  **offset 9**.
- Status `0xFE` = success, `0xFD` = error; Modbus-layer rejection = fn `0x5A|0x80` =
  **`0xDA`**.

**UMAS function codes (sourced subset):** 0x01 INIT_COMM, **0x02 READ_ID**, 0x03
READ_PROJECT_INFO, 0x04 READ_PLC_INFO, **0x10 TAKE_RESERVATION**, 0x11
RELEASE_RESERVATION, 0x12 KEEP_ALIVE, 0x20 READ_MEMORY_BLOCK, 0x22/0x23 READ/WRITE_
VARIABLES, 0x30/0x31 INIT/UPLOAD, 0x33/0x34 INIT/DOWNLOAD, 0x40/0x41 START/STOP_PLC,
0x50 MONITOR, 0x58 CHECK. (Labels for rarer codes are best-effort; the full 0x00–0xFF
space is swept regardless.)

## 4. The fuzz surface

UMAS is flagged the richest parser target of the Schneider/Modicon set:

- **UMAS function-code dispatch** — sweep the sub-function byte 0x00–0xFF (the
  single richest surface); undefined codes should return 0xFD, not crash.
- **Reservation / session state machine** — release-before-take, double-take,
  KEEP_ALIVE with no reservation, a **forged session byte** on a privileged op
  (e.g. STOP_PLC) with no reservation held, TakeReservation with a zero-length name
  or a **length-prefix that lies** about the name bytes that follow.
- **Length-field boundaries** — reservation name length-prefix vs. actual bytes,
  READ_MEMORY_BLOCK address/size extremes, READ_VARIABLES count extremes.
- **Nonce / signed-message parsing** (M340/M580) — nonce-length and
  **signature-length field lies** (over-read / under-read), truncated/over-long
  signatures — the signed-reservation parser.
- **Binary corruption** over the canonical READ_ID and TakeReservation frames
  (incl. the 0x5A function byte, session byte, and name-length prefix).
- **Sequence** — pipelined / interleaved UMAS requests, duplicate session bytes
  (rides the inherited Modbus multi-ADU handling).

**Classification line:** a UMAS `0xFD` status (or a Modbus `0xDA`) is an
**exception, not a crash**. The crash signal is timeout/reset/no-response, or a
0x5A reply with a status at neither offset 8 nor 9 (state confusion →
`UNEXPECTED_DATA`).

**Structured vs. coverage-guided:** firmly structured — the surface is semantic
(sub-function dispatch, the reservation state machine, nonce/signature length
handling) layered on the Modbus transport, with no public Schneider stack to
instrument. Black-box structured generation against a real Modicon (or the
responder below) is the path.

## 5. Known vulnerabilities & bug classes

- **CVE-2018-7790 / CVE-2018-7791** (Modicon M221, SEVD-2018-235-01) — the
  reservation / password-overwrite mechanism grants without real authentication
  (replay, and overwrite-without-knowing-the-old-password).
- **CVE-2018-7842** (Modicon M580, Cisco Talos TALOS-2018-0741) — corroborates the
  0x5A wrapper and the 0xFE/0xFD status convention from an independent team.
- Durable classes to drive a generator: **sub-function dispatch**, the
  **reservation/session state machine**, and **length-prefixed name/nonce/signature**
  fields (the length-lie family).

Unauthenticated READ_ID identity disclosure is a design exposure (CWE-306/CWE-200)
rather than a parser bug — useful as a liveness/fingerprint oracle, not the fuzz
*finding*.

## 6. Building a test harness

Robustness responder (`scripts/umas_responder.py`, port 5021): a safe UMAS state
machine — READ_ID → `5A FE` + fake identity; TakeReservation → allocate a session
key (avoiding 0x00/0xFD/0xFE so it can't be mistaken for a status), mark reserved;
Release → `5A FE`; KEEP_ALIVE → ok-if-reserved; unknown fn → `5A FD`; non-0x5A fn →
a Modbus illegal-function exception; malformed MBAP → close. Sidecar JSONL.

Because UMAS rides Modbus, the fuzzer **subclasses the Modbus module** and inherits
the MBAP send/recv, multi-ADU drain, TID, and reconnect logic verbatim — the
classifier just adds the 0xFE/0xFD/0xDA status semantics (accepting the status at
offset 8 *or* 9 to cover both reply shapes). `establish_presence()` is a no-op
(never auto-reserve); reservation-state cases are device-state-changing and gated
by the CLI confirmation flow.

**Calibration baseline (software responder, 432 cases): clean** — 51 crash
indicators, *all* in binary_corruption (33 connection_reset + 14 timeout + 4
no_response, i.e. corrupt/truncated frames), 278 exception_responses (sweep/
refusal paths), and **0 crash indicators from the other five categories**
(boundary / function_sweep / reservation_state / nonce_signed / sequence) — no
false positives.

## 7. Open-source implementations & tooling

- `kushfj/se-umas` — UMAS Wireshark dissector + function table.
- `0xedh/schneider_plc_exploit` — `modicon_exploit.py` (fn 0x5A, READ_ID 00 02).
- Redpoint `modicon-info.nse`; Orange-Cyberdefense *awesome-industrial-protocols*
  `umas.md`.
- No open-source Schneider UMAS *server* exists — black-box against real Modicon or
  the EcoStruxure/Unity simulator.

## 8. Spec references & sources

- Kaspersky ICS-CERT, *"The secrets of Schneider Electric's UMAS protocol"* (2022)
  — byte-exact transport reference.
- Cisco Talos TALOS-2018-0741 (M580); Schneider SEVD-2018-235-01 (M221).

## 9. Open questions / under-explored surface

- Live validation against a real Modicon PLC or the EcoStruxure/Unity simulator —
  no free UMAS stack is known, so calibration is software-responder only (the
  live-validation gap).
- Exact sub-function numbering for the nonce-exchange / signed-reservation path
  varies by firmware; the signed-message cases model the Kaspersky-documented
  length/signature fields rather than a specific firmware's dispatch.
- The READ_ID response field layout (model vs. firmware vs. device name) — only
  heuristically parsed; refine against a real capture.

*Worked example: `protocols/umas/fuzzer.py` (`UmasFuzzer(ModbusFuzzer)`, 6
categories, 432 cases) with `scripts/umas_responder.py`. Derived from the
icsScanner → icsFuzzer handoff `decompiled-protocols-for-icsfuzzer.md` §3.*