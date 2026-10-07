---
title: "A Researcher's Guide to S7comm (Siemens S7)"
protocols: ["S7comm"]
vendor: ["siemens"]
vendor_group: "Siemens"
sector: ["manufacturing"]
transport: ["iso-on-tcp"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and a
confirmed bug class described at the field/CWE level; no weaponized exploit or DoS
code.*

---

## 1. What it is & where it runs

S7comm is the native protocol of Siemens **SIMATIC S7-300/400** PLCs (and, in a
newer "S7comm-plus" variant, S7-1200/1500). It carries CPU configuration, program
up/download, and variable read/write. Classic S7comm (the subject of this guide)
has **no authentication and no encryption** — the security layer only arrived with
S7comm-plus / TIA Portal. Many deployed devices, and most open-source emulations,
speak the classic dialect.

Open-source server implementations exist and are widely deployed via **snap7**
(bundled into OpenPLC v3 *and* v4 for S7 server emulation), which makes classic
S7comm unusually testable — you can fuzz a real, inspectable server on a Pi.

- **Transport:** TCP port **102**, as ISO-on-TCP: **TPKT (RFC 1006) → ISO COTP
  Class 0 → S7 PDU**.

## 2. Session & transport model

```
1. TCP connect (102).
2. COTP CR → CC   (connection request/confirm; carries src/dst TSAP).
3. S7 Setup Communication (PDU negotiation: max AMQ, max PDU length).
   ← ROSCTR=0x03 Ack_Data  → session ready.
4. S7 Read/Write Variable, SZL read, PI service, PLC stop, etc.
```

TSAP values src=0x0100 / dst=0x0200 correspond to S7-300 rack/slot 0/0 (snap7
accepts others, including invalid ones). A fuzzer must complete COTP + Setup Comm
before its S7-layer cases are reachable.

## 3. Wire format

**TPKT (4 bytes):** `03 00` + big-endian uint16 total length (includes the header).
**COTP DT:** `02 F0 80` (LI=2, type=DT 0xF0, EOT). COTP CR carries TPDU-size and
TSAP parameters.

**S7 PDU** (after COTP DT):

| Off (in S7) | Field | Note |
|---|---|---|
| 0 | `0x32` | S7 protocol id (magic) |
| 1 | ROSCTR | 0x01 Job / 0x02 Ack / 0x03 Ack_Data / 0x07 Userdata |
| 2–3 | redundancy id | zeros |
| 4–5 | PDU reference | request/response correlation |
| 6–7 | param length | |
| 8–9 | data length | |
| 10+ | parameter | function code + function-specific params |
| … | data | |

Key function codes (in the parameter): 0x04 Read Var, 0x05 Write Var, 0xF0 Setup
Comm; Userdata (ROSCTR 0x07) carries SZL reads and the diagnostic subfunctions.
Read/Write Var parameters encode **area** (0x81 I / 0x82 Q / 0x83 M / 0x84 DB /
0x1C counters / 0x1D timers), DB number, start address, and a **count** field.

### S7comm SZL / userdata (extension surface)

SZL (System Status List) reads ride a Userdata PDU (ROSCTR 0x07) with parameter
`00 01 12 04 11 44` (CPU functions, Read-SZL) and data `SZL-ID (2) + SZL-INDEX (2)`
— e.g. SZL-ID `0x001C` is module identification. The **SZL-ID / SZL-INDEX enum
space** and the userdata subfunction dispatch are a modest but real additional
parser surface (see the icsScanner handoff `decompiled-protocols-for-icsfuzzer.md`).

## 4. The fuzz surface

- **`count` in Read/Write Var.** The confirmed snap7 bug lives here (see §5): a
  count exceeding the negotiated PDU size. This is *the* field to probe — element
  counts at 0x7FFF, 0xFFFF, and across the negotiated-PDU boundary.
- **Area / DB-number enums.** snap7 returns *success* for invalid area codes
  (0x00, 0xFF, 0x1D) — a spec-compliance gap that signals the area dispatch is a
  soft validation surface worth sweeping.
- **ROSCTR / function-code dispatch.** Values outside the defined set; a client
  sending Ack/Ack_Data ROSCTR codes.
- **The `0x32` magic.** snap7 ignores it (responds to 0x00/0x31/0x33/0xFF) — a
  reminder that "does the parser even check its own protocol id?" is a real
  question on these stacks.
- **SZL-ID / SZL-INDEX sweep** (userdata) — enumerate the list ids; some return
  data, some error, some are unimplemented.
- **COTP / TPKT layer.** TPKT length lies (claim more than sent → reader starves),
  truncated COTP, COTP CR replay on an established connection (snap7 correctly
  re-confirms — a negative control), bad Setup Comm.
- **State machine.** Read/Write before Setup Comm; malformed Setup Comm;
  wrong/invalid TSAP.

**Structured vs. coverage-guided:** both apply here, and S7comm is a good case for
*combining* them. The structured generator finds the semantic bugs (count/area
validation, ROSCTR dispatch) and reaches them through the real COTP+Setup
handshake; because snap7 is open source, its server path can *also* be
compiled under ASan and coverage-guided-fuzzed for memory-safety bugs the
black-box generator won't localize.

## 5. Known vulnerabilities & bug classes

**Confirmed via icsFuzzer:** a single S7 Read Variable with **`count=0xFFFF`**
(after Setup Comm) crashes **snap7** within ~100 ms — the process exits and port
102 becomes unreachable until a manual restart (reproduced 5/5). Spec behavior
would be an Ack_Data with error class 0x05/0x06; crashing is **CWE-20 improper
input validation**. Root cause (confirmed by source read) is a **signed/unsigned
PDU-guard bypass** in snap7's `TS7Worker::ReadArea` read path. Unauthenticated,
single-step DoS, **CVSS 7.5 HIGH** — affects snap7 as bundled in OpenPLC v3 and v4
(v4 vendors identical source). CVE pending; see the project's snap7 disclosure.

The bug is in **snap7's server code**, not OpenPLC's own logic — OpenPLC is a
consumer of the snap7 server API. A useful reminder when attributing ICS findings:
fuzz the device, but locate the bug in the *library*.

Context: classic S7comm's lack of auth means unauthenticated **PLC stop** and PI
services are accepted by design (not bugs — protocol-design behavior). Keep those
cases gated/labelled; the *finding* is the crash, not the by-design control.

## 6. Building a test harness

Two options, both valuable:
1. **snap7 on OpenPLC** (a real, open-source server on a Pi) — the live target that
   produced the confirmed finding. Fuzz it directly on port 102.
2. **A robustness responder** (`scripts/s7comm_responder.py`, port 10200) that does
   COTP CR/CC + Setup Comm, then answers Read/Write/SZL/PI/Stop, rejecting
   read-only areas and unknown SZL ids, with a sidecar JSONL. Use it for
   calibration before touching hardware.

**Response classification:** S7 magic at resp[7]=0x32, ROSCTR at resp[8],
error_class/code at resp[17:19]. A non-zero S7 error is an **exception, not a
crash**; silent drop on a malformed PDU is standard defensive behavior (snap7
dropped 25/36 binary_corruption cases — not findings). The crash signal is
timeout/connection-reset *on a well-formed request*, matching the count=0xFFFF
shape.

**Harness note:** the crash is asynchronous — a probe within a few ms of the
trigger can still succeed before snap7 exits, which once produced a misleading
"still up" reading. Verify the target a short delay after the trigger, and apply a
reconnect backoff (icsFuzzer retries 3× at 0.3/1.0/2.0 s) so a crash cascade is
distinguishable from transient resets.

## 7. Open-source implementations & tooling

- **snap7** (`github.com/SCADACS/snap7`) — S7-300/400 server + client; the testable
  reference, and the one with the confirmed DoS. Compilable → ASan/coverage-guided.
- **OpenPLC** v3/v4 — bundles snap7 for S7 server emulation.
- Wireshark `s7comm` dissector — field-level reference for ROSCTR/param/data.

## 8. Spec references & sources

- Siemens S7comm documentation (ROSCTR, Read/Write Var, Userdata/SZL).
- RFC 1006 (TPKT), ISO 8073 (COTP).
- Wireshark S7comm dissector wiki.

## 9. Open questions / under-explored surface

- Which other Read/Write parameter combinations (area × DB × address × count) reach
  the same signed/unsigned guard — the confirmed crash used count=0xFFFF, but the
  guard bypass may have siblings.
- The full SZL-ID space and userdata subfunction dispatch on real S7-300/400 vs.
  snap7's partial implementation.
- S7comm-plus (S7-1200/1500) is a different, authenticated protocol — out of scope
  here, but the natural next target.

*Worked example: `protocols/s7comm/fuzzer.py` (8 categories) + the confirmed snap7
finding in `lab-notes/s7comm-research.md`; responder `scripts/s7comm_responder.py`.*