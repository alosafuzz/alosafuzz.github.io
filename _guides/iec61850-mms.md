---
title: "A Researcher's Guide to IEC 61850 MMS"
protocols: ["IEC 61850 MMS"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["electric"]
transport: ["iso-on-tcp"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: protocol stack, fuzz surface, and
bug classes only; no weaponized exploit or DoS code. Covers the MMS-over-TCP
surface; GOOSE/SV (L2) are noted but out of scope.*

---

## 1. What it is & where it runs

IEC 61850 is the international standard for substation communication — the data
model (logical nodes, data objects) and the services that move it. In electric
utilities it is the backbone protocol between protection relays, bay controllers,
and the station HMI. Three transports share the standard:

- **MMS over TCP (port 102)** — the client/server config + data-access surface.
  **This is the fuzzing target** of this guide.
- **GOOSE** — raw Ethernet multicast, EtherType 0x88B8, L2 only (needs CAP_NET_RAW;
  hardware-phase work).
- **Sampled Values (SV)** — raw Ethernet 0x88BA; out of scope.

What makes MMS a rich research target is its **deep, layered ASN.1/BER stack**:
every message traverses TPKT → COTP → (Session/Presentation/ACSE) → MMS, and the
BER encoding itself (indefinite lengths, long-form lengths, nested constructed
tags) is a classic parser-bug surface independent of the MMS semantics on top.

## 2. Session & transport model — the full stack

```
TCP 102
├── TPKT (RFC 1006)       4-byte framing: 03 00 + BE uint16 total length
├── ISO COTP Class 0      CR / CC / DT / DR / DC
├── ISO Session (SPDU)    CONNECT (0x0D) ... (often folded into the handshake)
├── ISO Presentation (PPDU) CP / CPA
├── ACSE (ISO 8650)       AARQ (0x60) / AARE (0x61) association
└── MMS (ISO 9506)        confirmedRequest/Response/Error, initiate, etc.
```

A working connection must complete **COTP CR/CC → Session CONNECT → Presentation
CP → ACSE AARQ/AARE → MMS initiate** before any MMS service request is reachable.
This is a notorious implementation pitfall: a fuzzer that sends a bare ACSE AARQ
straight after COTP (skipping Session + Presentation) is rejected by the ISO
Session parser (it sees a non-CONNECT SPDU, 0x60 instead of 0x0D) and never reaches
MMS. The practical fix is to carry a **captured, full Session+Presentation+ACSE
AARQ** as the handshake and wrap MMS PDUs in the Session DATA SPDU
(`01 00 01 00`) + Presentation FULLY-ENCODED-DATA layers.

**Port 102 is shared** with S7comm — they use the same ISO-on-TCP lower layers but
diverge at ACSE. A quick disambiguation: COTP CR→CC succeeds for both; an ACSE AARQ
drawing an AARE means MMS, whereas S7's Setup Comm drawing ROSCTR=0x03 means
S7comm. (snap7 resets on an AARQ.) Fingerprint before fuzzing.

## 3. Wire format — MMS PDUs and BER

**MMS outer PDU tags:** 0xA0 confirmedRequest, 0xA1 confirmedResponse, 0xA2
confirmedError, 0xA3 unconfirmed, 0xA8 initiate-Request, 0xA9 initiate-Response.

**ConfirmedRequest:** `A0 [len] 02 01 <invoke_id> <service_choice…>` where the
service CHOICE tag selects the operation:

| Tag | Service | Tag | Service |
|---|---|---|---|
| 0xA1 | getNameList | 0xA5 | write |
| 0xA2 | identify | 0xA6 | getVariableAccessAttributes |
| 0xA3 | rename | 0xAD | defineNamedVariableList |
| 0xA4 | read | 0xAF | deleteNamedVariableList |

Object names follow the IEC 61850 convention
`<LogicalDevice>/<LogicalNode>$<FC>$<DataObject>$<DataAttribute>` (e.g.
`.../XCBR1$ST$Pos$stVal`), carried as VisibleStrings inside the read/write
variable-access specification.

**BER encoding — the length field is the star of the show:**
- short form: one byte 0x00–0x7F;
- long form: `0x81 <len>` (128–255), `0x82 <hi> <lo>` (256–65535);
- **indefinite form: `0x80` + content + `00 00`** — legal BER (not DER); some
  parsers mishandle or hang on it.

## 4. The fuzz surface

Two superimposed surfaces — ASN.1/BER structure and MMS semantics:

- **BER length abuse** (`asn1_ber_corruption`): indefinite-length `0x80` forms,
  long-form lengths that claim more than present, length-overflow claims. The
  highest-yield generic surface — it stresses the decoder below the MMS logic.
- **MMS service dispatch** (`mms_service_sweep`): sweep CHOICE tags across
  0xA0–0xBF and 0x80–0x8F, including undefined service tags — does the dispatcher
  handle an unknown service gracefully?
- **TPKT length vs. actual** (`pdu_fragmentation`): claim a larger TPKT length than
  bytes sent → the reader allocates/awaits (up to 65535) and **starves**; split
  frames across segments.
- **Object-name / address parsing** (`mms_address_sweep`): path traversal shapes,
  null bytes, overlong identifiers in the domain/item VisibleStrings.
- **getNameList recursion**: deeply nested `continueAfter` pagination chains.
- **Association state machine** (`state_machine`): bad COTP CR class, wrong TSAP,
  bad TPKT version byte, sending AARE instead of AARQ mid-handshake.
- **invoke_id handling**: rollover / monotonicity assumptions.

**Structured vs. coverage-guided:** MMS rewards *both*, more than most ICS
protocols. The BER layer is a deep byte-parser — an ideal coverage-guided /
libFuzzer target against an instrumented open-source stack (libiec61850,
below). The MMS service semantics and the multi-layer association handshake are a
structured-generator target (reach the service dispatcher through a real
association, then sweep). icsFuzzer does the structured half black-box; the BER
decoder is a strong candidate for a separate coverage-guided campaign.

## 5. Known attack-surface classes

No single headline CVE is cited here; the durable, repeatedly-productive classes
on MMS stacks are:
1. **TPKT length field** — over-claim → reader starvation/hang.
2. **COTP CR TSAP mismatch** — association rejection quirks.
3. **ACSE AARQ/AARE confusion** — PDU injected out of handshake order.
4. **MMS getNameList recursion** — deep `continueAfter` nesting.
5. **BER indefinite length** — non-DER parsers hang/mishandle.
6. **Large TPKT allocation** — allocate-then-wait on a 65535 claim.
7. **MMS invoke-id rollover** — monotonic-tracking assumptions.
8. (GOOSE) **stNum rollover** at 2^32−1 — receivers must accept wrap (L2 surface).

These are the field-level shapes to turn into a generator; the BER-length and
TPKT-length items are where memory-safety bugs in C stacks concentrate.

## 6. Building a test harness

**libiec61850** (`mz-automation/libiec61850`) is the reference open-source MMS
stack and the ideal target: build the example server, move it off port 102 (shared
with snap7 on a shared Pi) to e.g. 10102, and fuzz it. Being open source, it is
*also* the stack to instrument under ASan for a coverage-guided BER campaign.

A **robustness responder** (`scripts/iec61850_responder.py`, port 10202) handles
the full 7-layer handshake (it must accept the Session CN SPDU 0x0D and locate the
AARQ 0x60 within the packet) and returns well-formed error PDUs for bad input, with
a sidecar JSONL.

**Response classification:** after stripping the Session/Presentation wrapper,
read the MMS tag: 0xA1 confirmedResponse = clean; **0xA2 confirmedError and 0xA4
rejectPDU = exception, not a crash**; a bad APCI / short frame = malformed (crash).

**Calibration baselines (both clean, 0 false-positive malformed_response):**
- Software responder (173 cases): 37 crash indicators (23 connection_reset + 14
  timeout), 76 confirmedError exceptions, 60 clean.
- **Live run vs. libiec61850 on real hardware (173 cases, 0 real crashes):** the
  reference stack held up — 42 connection_reset (server closes on malformed
  session/presentation/ACSE), 90 exceptions, 16 timeout, 17 clean, 8 genuine
  malformed-response anomalies. An honest "robust implementation" result, and a
  good baseline for differential testing against *other* MMS stacks.

## 7. Open-source implementations & tooling

- **libiec61850** — reference server+client; build with `-DBUILD_EXAMPLES=ON`;
  compilable → ASan/coverage-guided for the BER layer.
- Wireshark `mms` / `cotp` / `tpkt` dissectors — field-level reference.
- Other stacks (OpenIEC61850, commercial relays) — differential-testing targets.

## 8. Spec references & sources

- IEC 61850-8-1 (MMS mapping), 61850-7-2 (ACSI).
- RFC 1006 (TPKT); ISO 8073 (COTP); ISO 8650 (ACSE); ISO 9506 (MMS).

## 9. Open questions / under-explored surface

- Differential behavior across MMS stacks on the same BER-length and
  service-sweep corpus (libiec61850 was robust — are the others?).
- GOOSE/SV (L2) fuzzing — requires raw Ethernet; a separate hardware-phase guide.
- The exact Session/Presentation layer handling across stacks (the captured-AARQ
  shortcut works but masks per-stack differences worth probing).
- A coverage-guided BER campaign against libiec61850 under ASan — not yet run.

*Worked example: `protocols/iec61850/fuzzer.py` (8 categories, 173 cases),
live-validated against libiec61850; responder `scripts/iec61850_responder.py`.*