---
title: "A Researcher's Guide to Omron FINS"
protocols: ["FINS"]
vendor: ["omron"]
vendor_group: "Omron"
sector: ["manufacturing"]
transport: ["fins-udp"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

FINS (Factory Interface Network Service) is **Omron's** PLC protocol — CJ/CS/CP
and NJ/NX series controllers across packaging, automotive, and general discrete
manufacturing. It carries memory read/write, CPU run-state control, clock, and
status. FINS/UDP (this guide) runs on **UDP port 9600**; a FINS/TCP variant adds a
small framing header on top of the same commands.

For a researcher FINS is the simplest target in the set — a **12-byte fixed
header, fully stateless, no authentication** — which makes it a clean place to
study memory-area addressing bugs and CPU-control authorization: every command is
a single self-contained datagram, and the whole surface is reachable from one
`sendto`.

## 2. Session & transport model

Stateless UDP: no handshake, no session. Each request is an independent datagram;
the response echoes the routing header (with source/destination swapped) plus a
**2-byte end code**. A **SID** (service id) byte correlates request and response —
but because UDP ordering isn't guaranteed, a SID mismatch is *unexpected data*, not
a crash.

## 3. Wire format

**12-byte FINS header:**
| Off | Field | Note |
|---|---|---|
| 0 | ICF | info-control (0x80 request, response 0xC0) |
| 1 | RSV | reserved (0x00) |
| 2 | GCT | gateway count (0x02) |
| 3–5 | DNA / DA1 / DA2 | destination network / node / unit |
| 6–8 | SNA / SA1 / SA2 | source network / node / unit |
| 9 | SID | service id (request/response correlation) |
| 10–11 | MRC / SRC | **main + sub command code** (the dispatch pair) |

Command body follows MRC/SRC. **Response** = ICF 0xC0 + swapped routing + SID +
MRC/SRC + **MRES/SRES end code at offset 12–13** (0x0000 = normal) + data.

**Key command codes (MRC,SRC):** Memory Area Read `01 01`, Write `01 02`, Fill
`01 03`; Run `04 01`, Stop `04 02`; Clock Read/Write; Controller Status Read.
**Memory-area codes** (in the Read/Write body): CIO word 0x82 / bit 0x80, DM word
0x02 / bit 0x30, EM0 word 0x0A, HR word 0x52, Timer PV 0xB0, Counter PV 0xB1 — the
address is area + 3-byte address + element count.

## 4. The fuzz surface

- **Command (MRC/SRC) dispatch** — sweep the main/sub command space; undefined
  pairs should return an end code, not crash.
- **Memory-area code** — sweep the area byte (valid vs. undefined); area/width
  confusion (word code at a bit address and vice versa); read-only areas (Timer PV,
  Counter PV, CIO bit) written to.
- **Address + element count** — address near the top of an area with a count that
  straddles the ceiling; count=0; count=0xFFFF (over-read / over-serve); count vs.
  actual data bytes mismatch in a Write (a length lie).
- **Fill** (`01 03`) — large fill ranges into read-only or out-of-range areas.
- **CPU control (Run/Stop/Reset)** — unauthenticated run-state change: FINS has no
  auth, so a Stop is accepted by design; the *finding* is any stack that crashes or
  mishandles the control body, not the by-design control (gate/label these).
- **Header fields** — ICF values other than 0x80, GCT extremes, DNA/DA1/DA2 routing
  to non-existent nodes (gateway-relay behavior), SID edge values.
- **Framing / binary corruption** — truncated header (< 12 bytes), bad ICF,
  oversized/short bodies.
- **State / sequence** — duplicate SID, rapid command flood, interleaved
  read/write to one address.

**Classification line:** a non-zero **end code (MRES/SRES)** is a spec-compliant
error — **exception, not a crash**. A **SID mismatch** is `UNEXPECTED_DATA` (UDP
reordering), not a crash. The crash signal over UDP is a timeout (no datagram) on a
well-formed request, or a truncated/malformed reply.

**Structured vs. coverage-guided:** FINS is a pure structured-generator target —
the surface is the command/area/count semantics, and it's shallow and stateless.
There is little open-source Omron-stack code to instrument, so coverage-guided
fuzzing isn't readily available; black-box structured generation against a real CJ/
CP PLC (or the responder below) is the path.

## 5. Known vulnerabilities & bug classes

FINS has no auth and no integrity, so the durable classes are:
- **Unauthenticated CPU Stop/Run** — a single datagram halts the controller (by
  design; an operational exposure, and a robustness test for the control-body
  parser).
- **Memory-area over-read** — count/address beyond an area's bounds; area-code
  confusion serving the wrong width.
- **Write length-lie** — declared element count disagreeing with the data present.
- **Routing abuse** — DNA/node/unit values exercising gateway-relay paths.
- **Header-field validation** — ICF/GCT handling on malformed headers.

(No single headline CVE is cited; FINS findings are per-device and the protocol's
lack of auth is the dominant exposure.)

## 6. Building a test harness

Robustness responder (`scripts/fins_responder.py`, port 9610, UDP): a single-
threaded `recvfrom` loop; writable areas CIO/DM/EM0/HR word + DM bit; read-only
rejection for Timer PV, Counter PV, CIO bit; CPU Run/Stop/Reset all rejected
(safety); response header built by swapping DA1/SA1; sidecar JSONL.

Harness notes:
- **End code at offset 12–13** drives the exception-vs-clean decision.
- **SID mismatch → UNEXPECTED_DATA**, never a crash (UDP ordering).
- Sidecar vocabulary: read_ok/bad_area/bad_address/bad_count, write_ok/bad_area/
  write_reject, fill_ok/bad_area, run_reject/stop_reject/reset_reject, clock_ok/
  status_ok, cmd_unknown/cmd_malformed.

**Calibration (software responder):** ~180 cases across 8 categories (boundary,
binary_corruption, sequence, state_machine, memory_read, memory_write, cpu_control,
command_sweep); 62 tests. (No standalone research note — this guide is built from
the module.)

## 7. Open-source implementations & tooling

- **omron-fins** (Python, e.g. `pyfins`/`fins` libraries) — clients for building
  valid seeds.
- Wireshark `omron` / FINS dissector — field-level reference.
- A real Omron CJ/CP/NJ PLC or the CX-Programmer simulator — the realistic target
  (no widely-used open-source FINS *server* exists to instrument).

## 8. Spec references & sources

- Omron FINS Command Reference Manual (W227) — command/area/end-code tables.
- Omron CS/CJ-series Communications Commands reference.
- Wireshark FINS dissector.

## 9. Open questions / under-explored surface

- FINS/TCP framing (the small header atop the same commands) — a separate, minor
  surface this UDP module doesn't cover.
- Gateway-relay behavior (DNA/node/unit routing across networks) on multi-node
  Omron topologies.
- Which real Omron CPUs crash (vs. end-code) on area-code confusion or over-count
  reads — needs device-level testing; no open stack to coverage-guide.

*Worked example: `protocols/fins/fuzzer.py` (8 categories, ~180 cases) with
`scripts/fins_responder.py` (UDP robustness mock).*