---
title: "A Researcher's Guide to DNP3 (IEEE 1815)"
protocols: ["DNP3"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["electric"]
transport: ["dnp3-tcp"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

DNP3 (Distributed Network Protocol, IEEE Std 1815-2012) is the dominant SCADA
protocol of **North American electric utilities** — substations, RTUs, IEDs — and
is heavy in water and oil/gas too. A master polls outstations for telemetry and
issues control (open/close a breaker, set an analog output).

For a researcher, DNP3's defining trait is its **three independent layers, each
with its own framing and its own bugs**: a Data Link Layer (DLL) with a CRC on
*every* block, a Transport Layer (TL) that fragments, and an Application Layer (AL)
with a rich Group/Variation object model. That stacking multiplies the parser
surface — and the CRC-per-block rule is itself a fault-injection target (does the
device actually check it?). An optional Secure Authentication layer (SAv2/5/6) sits
on top.

- **Transport:** TCP port **20000** (UDP 20000 for broadcast, rarer).
- **No session handshake** — unlike IEC 104, the master can send a READ
  immediately after TCP connect. (Some stacks want a DLL `RESET_LINK_STATES`
  first; treat that as an optional, testable pre-step.)

## 2. Session & transport model

```
TCP connect → (optional DLL RESET_LINK_STATES → ACK) → DLL USER_DATA(+TL+AL) → RESPONSE
```

No STARTDT equivalent. Application-layer sequence numbers are **loosely enforced**
unless the request sets CON=1 (confirmation requested) — which is itself a knob:
set CON=1 and withhold the confirm, or replay a sequence number.

## 3. Wire format — the three layers

**DLL frame:**
```
05 64 | LEN | CTRL | DST_lo DST_hi | SRC_lo SRC_hi | CRC_lo CRC_hi   (header)
[ up to 16 user bytes + 2-byte CRC ] × N                            (data blocks)
```
- Start bytes **always `05 64`**. `LEN` = 5 + len(user_data), 5..255 (so ≤250 user
  bytes). `DST`/`SRC` little-endian, `0xFFFF` = broadcast.
- **CRC-16/DNP** (poly 0x3D65 reflected = 0xA6BC, init 0, final XOR 0xFFFF, LE
  output) on the 6-byte header *and* on every 16-byte data block.
- **CTRL** byte: DIR | PRM | FCB | FCV | FC(4). Master request typically `0xC4`
  (DIR=1,PRM=1,FC=4 unconfirmed user data); FC=3 is *confirmed* user data and
  requires the FCB bit to alternate per frame.

**TL header (1 byte):** FIR | FIN | SEQ(6). Single segment = `0xC0`. Multi-segment
reassembly (FIR=1/FIN=0 … never FIN=1) is a memory-exhaustion lever.

**AL message:** `AC | FC | objects`. The **AC** byte is FIR|FIN|CON|UNS|SEQ(4) —
CON requests app confirmation, UNS marks unsolicited. FCs include READ (0x01),
WRITE (0x02), SELECT/OPERATE (0x03/0x04, the two-step SBO interlock),
DIRECT_OPERATE (0x05), COLD/WARM_RESTART (0x0D/0x0E), ENABLE/DISABLE_UNSOLICITED
(0x14/0x15), AUTH_REQUEST (0x20).

**Object model:** `GROUP | VARIATION | QUALIFIER | RANGE… | DATA…`. The
**qualifier** nibble pair selects range/index encoding — including limited-count
forms (0x07 1-byte count, 0x08 2-byte count) that declare how many objects follow.

## 4. The fuzz surface

DNP3 pays off layer by layer:

- **DLL CRC handling** (binary_corruption): send a frame with a *bad* header or
  block CRC but a plausible `LEN`. A compliant stack closes; embedded stacks that
  "never check" and parse anyway are the finding. This is the signature DNP3
  fault-injection test.
- **`LEN` vs. actual** and block-count math — truncation, over-claim (starvation).
- **AL function-code dispatch** — the defined and reserved FC space; unsolicited
  (UNS=1) requests sent *to* an outstation.
- **Object Group/Variation + qualifier** — unknown G/V (must return IIN2.OBJ_UNKNOWN,
  not crash), and **limited-count qualifiers (0x07/0x08) with count > configured
  objects** — the classic over-read/overflow lever.
- **CROB (G12V1) control codes** — `Code=0` (NUL), reserved TCC values; some
  implementations misbehave on NUL control.
- **Analog output (G41V1) float edges** — NaN/±Inf into an analog-output driver.
- **Multi-fragment AL** (TL FIR without FIN) — buffer exhaustion on partial
  reassembly.
- **SAv5 (Group 120)** — challenge replay, **HMAC truncation** (short HMAC), key
  status mismatch, algorithm confusion (declare SHA-256, send AES-GMAC length),
  32-bit sequence wrap, **aggressive mode (G120V3) without prior auth**.
- **State / sequence** — FCB non-alternation on FC=3, SBO bypass (DIRECT_OPERATE
  with no SELECT), broadcast (DST=0xFFFF) control without auth, COLD_RESTART right
  after connect (restart-auth enforcement).

**Classification line:** `IIN2.FUNC_NOT_SUPP / OBJ_UNKNOWN / PARAM_ERROR` are
spec-compliant exceptions, **not** crashes (same role as Modbus FC|0x80). The crash
signal is timeout/reset/no-response — especially on a frame with *valid* CRCs.

**Structured vs. coverage-guided:** DNP3 is primarily a structured-generator target
(semantic object/qualifier/SAv5 bugs reached without deep byte-parsing), and the
CRC-per-block rule means a mutation fuzzer that doesn't fix CRCs mostly tests "does
it reject bad CRC." For a coverage-guided campaign you'd instrument an open-source
stack — but note **opendnp3 is archived** (see §7), which limits that path.

## 5. Known vulnerabilities & bug classes

No single headline CVE is cited here; DNP3's durable, repeatedly-productive classes:
- **CRC bypass** — embedded stacks that parse frames with bad CRC if `LEN` looks
  plausible.
- **Large object count** (qualifier 0x07/0x08 count > configured) — buffer overflow.
- **Partial AL fragment buffering** — memory exhaustion.
- **Unauthenticated COLD_RESTART / broadcast control** — SAv5 should gate these;
  some devices don't.
- **SAv5 aggressive-mode-without-auth and HMAC-truncation** — authentication-layer
  logic bugs.
- **G41V1 NaN/Inf / G12V1 NUL CROB** — driver-level input-validation faults.

## 6. Building a test harness

Robustness responder (`scripts/dnp3_responder.py`, port 20001): no DLL handshake,
validates start bytes / `LEN≥5` / header CRC / block CRCs / truncation; FC=READ →
RESPONSE (FC=0x81, IIN=0x0000); unknown AL FC → IIN2.FUNC_NOT_SUPP; unknown G/V →
IIN2.OBJ_UNKNOWN; sidecar JSONL.

Harness notes:
- **No SEQ patching needed** (unlike IEC 104 SSN) — app-layer SEQ with CON=0 isn't
  enforced by most outstations; send verbatim.
- **Multi-frame drain** — `app_layer_frag` cases concatenate DLL frames; compute
  wire length = `10 + user_len + ceil(user_len/16)*2` and drain N−1 responses.
- **CRC validity rule** — every category *except* binary_corruption uses valid
  CRCs; binary_corruption's bad-CRC / bad-start / truncation cases are *expected*
  to draw `close_bad_header_crc` / `close_bad_block_crc` / `close_bad_start_byte` /
  `close_truncated`.

Live target: **confirmed robust** — DNP3 vs. OpenPLC (opendnp3) across 4 runs,
228 cases, **0 findings**; SAv5/SAv6 bypass cases all rejected. A good robustness
baseline and a template for differential testing against weaker stacks.

## 7. Open-source implementations & tooling (and a landmine)

- **opendnp3** (`dnp3/opendnp3`) — the historical reference stack, **now archived
  (last push 2022-05-18)**. Still the object-model reference, but don't build new
  coverage-guided work on dead upstream. Its master API also exposes only
  `SelectAndOperate` / `DirectOperate` — **no bare Select** — so it can't express a
  Select-only case (relevant for SBO/authorization tests).
- `dnp3/dnp3-simulator` — GPL GUI master+outstation on opendnp3; stale, VS2013/x86.
- **`CommunicationTools/DNPScopSlave`** (BSD-2) — hand-rolled stack, *no* opendnp3
  dependency; but binary-only, Windows/GUI-only, no headless mode — a manual
  cross-validation target, not a CI harness.
- Commercial (FreyrSCADA) looks open but is licensed — do not mistake for free.

## 8. Spec references & sources

- IEEE Std 1815-2012 (DNP3).
- Wireshark `dnp3` dissector (field-level reference).

## 9. Open questions / under-explored surface

- A genuinely scriptable, cleanly-licensed, *maintained* outstation target for
  automated cross-validation — the survey above found none ideal (archived or
  GUI-only). A fork or raw-APDU harness is the gap.
- Which embedded/vendor stacks actually skip CRC validation (the highest-value DNP3
  bug class) — needs device-level testing.
- A coverage-guided ASan campaign against a *live* DNP3 stack — blocked by opendnp3's
  archival; an alternative stack is needed.

*Worked example: `protocols/dnp3/fuzzer.py` (8 categories, 228 cases),
live-validated against opendnp3/OpenPLC; responder `scripts/dnp3_responder.py`.*