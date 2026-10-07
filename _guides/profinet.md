---
title: "A Researcher's Guide to PROFINET (DCP + PNIO-CM)"
protocols: ["PROFINET"]
vendor: ["siemens"]
vendor_group: "Siemens"
sector: ["manufacturing"]
transport: ["dce-rpc", "raw-ethernet"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

PROFINET is the dominant **Siemens-ecosystem** industrial Ethernet protocol —
PLCs, distributed I/O (ET 200), drives, and field devices across discrete
manufacturing and process automation. It is actually a family of sub-protocols at
different layers; two matter most for a network fuzzer:

- **DCP (Discovery and Configuration Protocol)** — raw Ethernet, **EtherType
  0x8892**, L2 multicast. How an engineering tool discovers devices and sets their
  name/IP before any IP config exists. **Requires CAP_NET_RAW / layer-2 access** —
  a hardware/privileged-interface phase.
- **PNIO-CM (Context Manager)** — **DCE/RPC over UDP, port 34964**. The
  acyclic connect/read/write channel used to establish an Application Relation (AR)
  and read/write device records. This is the IP-reachable surface and the main
  structured-fuzz target.

(Real-time cyclic I/O — PNIO-RT, EtherType 0x8892 with a FrameID — is L2 and
latency-bound; out of scope here.) **PROFINET p-net was heavily fuzzed by Nozomi in
2025** (10 memory-corruption CVEs in the UDP-RPC layer), so new work should target
*other* stacks or *other* sub-surfaces rather than re-run that campaign.

## 2. Session & transport model

**DCP:** connectionless L2 — Identify-All multicast → devices reply with their
name/IP/role; Set services change name/IP/reset.

**PNIO-CM:** DCE/RPC over UDP. The DCE/RPC layer carries a **Bind** then a
**Request** (often concatenated in one datagram — a fuzzer must split them into
separate UDP sends). The CM interface UUID is
`DEC401D0-A91B-11D0-96E1-00A024517A00`. Operations: **Connect** (establish an AR),
**Read**/**Write** (device records by Index), Control, Release. The AR must be of a
valid type before records are accessible.

## 3. Wire format

**DCP frame (L2):** Ethernet (dst = PROFINET multicast, EtherType 0x8892) +
frame-ID + DCP header (ServiceID / ServiceType / Xid / ResponseDelay / DataLength)
+ DCP blocks (`Option / Suboption / BlockLength / BlockInfo / value`). Device
name/IP live in option/suboption blocks.

**PNIO-CM (DCE/RPC over UDP):** the DCE/RPC header (version, packet type Request/
Response, flags, object UUID, interface UUID, activity UUID, opnum) + an NDR body.
For Read/Write, the body is an **IODReadReq/IODWriteReq** block carrying a
**sequence number, AR UUID, API, slot/subslot, and an Index** (the record selector)
plus a length and data. Device-management indices live in the **0xF000–0xF8FF**
range (e.g. 0xF000 real-identification, 0xF020/0xF040 records).

## 4. The fuzz surface

**PNIO-CM (IP, the main target):**
- **Index dispatch (Read/Write)** — sweep the record Index space, especially
  0xF000–0xF8FF; writes to read-only indices (0xF000) must be refused, not crash.
- **AR type / Connect block** — invalid AR types (valid set observed: 0x0001,
  0x0002, 0x0004, 0x0006), malformed Connect blocks, record lengths that disagree
  with the data present (a block-length lie).
- **DCE/RPC framing** — Bind/Request split boundaries, wrong interface/object UUID,
  opnum sweep, fragment/segment flags, NDR length fields.
- **Record write length** — block_len beyond 0xFFFF / disagreeing with payload
  (the module caps block_len at 0xFFFF to avoid its *own* overflow — a reminder that
  the *generator* must not create unrepresentable frames).
- **State machine** — Read/Write before Connect (no AR); Release then continue;
  duplicate Connect.

**DCP (L2, privileged phase):** option/suboption sweep, BlockLength lies,
oversized Set-name values, malformed Identify filters — TLV-abuse territory, but
L2-gated and therefore conceptual until run with raw-socket access.

**Classification line:** a PNIO error status / IODReadRes/IODWriteRes with a
non-zero error is an **exception, not a crash**. Timeout/reset on a well-formed,
AR-valid request is the crash signal. (DCP cases generate bytes even without
scapy; without L2 access they're emitted but not sent — `anomaly=None`.)

**Structured vs. coverage-guided:** PNIO-CM is a structured-generator target (AR
state, Index dispatch, DCE/RPC framing). The memory-safety surface of the UDP-RPC
layer is exactly what Nozomi coverage-guided-fuzzed in p-net (RT-Labs) in 2025 —
so a coverage-guided campaign should pick a *different* stack (Siemens'
proprietary, or another open implementation) to avoid re-walking patched ground.

## 5. Known vulnerabilities & bug classes

- **Nozomi vs. p-net (RT-Labs), May 2025** — a full libFuzzer campaign found **10
  memory-corruption CVEs** (incl. CVE-2025-32399, CVE-2025-32405) in the **UDP-RPC
  (PNIO-CM) layer**; RT-Labs patched in 1.0.2 and folded libFuzzer into their CI.
  The lesson: the CM record/connect parser is where the memory bugs are — and p-net
  specifically is now picked-over.
- **DCP spoofing / name-takeover** — unauthenticated Set-name/Set-IP on the L2
  discovery plane (by design; an operational-security exposure more than a parser
  bug).
- Durable classes to carry to other stacks: **record-length lies** in IODWrite,
  **AR-Connect block** parsing, **DCE/RPC NDR** length handling.

## 6. Building a test harness

Robustness responder (`scripts/profinet_responder.py`, port 34965, UDP): stateless
`handle_datagram()` — Bind→BindACK, Request→dispatch by opnum; Connect checks AR
type (valid 0x0001/0x0002/0x0004/0x0006), Read serves known indices
0xF000–0xF040, Write rejects 0xF000 (read-only); sidecar JSONL.

Harness lessons:
- **Split concatenated PDUs** — a Bind+Request packed in one buffer must be sent as
  separate UDP datagrams (`_split_pdus`), or the responder sees one malformed blob.
- **Index offset** — the record Index sits at a specific body offset (34 in this
  module's IODRead/Write builder, not 18 — an easy off-by-N that silently breaks
  every record case).
- **DCP is generate-but-don't-send without scapy** — emit the bytes for audit/
  export, skip the raw-socket send, mark `anomaly=None` (so L2 cases don't
  false-positive as timeouts in a non-privileged run).

**Calibration (software responder):** 161+ cases across 8 categories (boundary,
binary_corruption, state_machine, sequence, dcp_discovery, dcp_configuration,
pnio_connect, record_rw); 97 tests pass. (No standalone research note — this guide
is built from the module and its calibration.)

## 7. Open-source implementations & tooling

- **p-net** (RT-Labs, C) — the reference device stack; **already Nozomi-fuzzed**
  (target other stacks for *new* memory-safety work, or use p-net ≥1.0.2 as a
  robustness oracle).
- **Wireshark** `pn_dcp` / `pn_io` / `dcerpc` dissectors — essential for PNIO-CM
  and DCP field decoding.
- Siemens TIA Portal / a real ET 200 device — the realistic AR/record target.

## 8. Spec references & sources

- IEC 61158/61784 (PROFINET); PROFIBUS & PROFINET International (PI) specifications.
- Wireshark PROFINET dissectors (pn_dcp, pn_io).
- Nozomi Networks p-net fuzzing disclosure (2025).

## 9. Open questions / under-explored surface

- A coverage-guided campaign against a *non-p-net* PNIO-CM stack — p-net is done.
- The DCP L2 plane under real raw-socket access (name/IP takeover + block TLV
  fuzzing) — generated but not yet sent in this module.
- PNIO-RT cyclic frames (FrameID/IOCS/IOPS) — a separate L2, latency-bound surface.
- Full AR lifecycle fuzzing (Connect → parametrization → ApplicationReady) against
  a real device, which the software responder only approximates.

*Worked example: `protocols/profinet/fuzzer.py` (8 categories, 161+ cases, DCP
generate-only) with `scripts/profinet_responder.py` (UDP PNIO-CM robustness mock).*