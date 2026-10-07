---
title: "A Researcher's Guide to GE SRTP"
protocols: ["GE SRTP"]
vendor: ["ge"]
vendor_group: "GE / Emerson"
sector: ["manufacturing"]
transport: ["srtp"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: this documents the wire format,
the fuzz surface, and published bug classes so researchers can build their own
test harnesses. It contains no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

SRTP is the native network protocol of GE/GE-Fanuc **Series 90-30 and 90-70**
PLCs and their successors, the **PACSystems RX3i / RX7i / CRU320**. It carries
configuration, programming, and raw memory read/write. The design assumption is a
trusted network: **no authentication, no encryption, no session token.** Any host
that can reach the port can read or write PLC memory, start/stop the CPU, or
overwrite the ladder program — by architecture, not by bug.

That makes SRTP a high-yield research target: the interesting bugs are not
*authorization* bypasses (there is nothing to bypass) but **parser and
input-validation** failures reachable with a single unauthenticated packet, which
is exactly what both published CVEs are.

- **Transport:** bare TCP, port **18245** (a secondary listener sits on 18246).
- **Siblings on the same hardware:** EGD (18246/UDP), Modbus/TCP (502). EtherNet/IP
  (44818) is **PACSystems-only** — not present on 90-30/90-70.

## 2. Session & transport model

A 4-packet lifecycle on one TCP connection:

```
Client → Server:  pkt_type 0x0000  INIT      56 bytes, all zeros
Client ← Server:  pkt_type 0x0001  INIT_ACK
Client → Server:  pkt_type 0x0002  REQ       56-byte header (+ payload for writes)
Client ← Server:  pkt_type 0x0003  REQ_ACK   56-byte header (+ data for reads)
```

The PLC **silently drops** any REQ that arrives before INIT is acknowledged — so a
fuzzer must complete INIT/INIT_ACK before its cases reach the request parser.
After the handshake the connection accepts a continuous stream of REQ/REQ_ACK.
(This "silent drop before handshake" is itself a state-machine case worth testing:
send REQ first, duplicate INIT, send INIT_ACK *from* the client, etc.)

## 3. Wire format — the 56-byte header (all multi-byte fields little-endian)

| Off | Size | Field | Researcher's note |
|----|----|----|----|
| 0 | 2 | pkt_type | 0x00 INIT / 0x01 INIT_ACK / 0x02 REQ / 0x03 REQ_ACK |
| 2 | 2 | index | sequence counter |
| 4 | 2 | size | **payload length** — a lying length field; in REQ_ACK doubles as status (0=ok) |
| 6 | 20 | reserved | zeros in practice — fuzz as opaque "session context" |
| 26 | 3 | time | HH:MM:SS |
| 29 | 1 | msg_seq | per-message counter |
| 30 | 1 | msg_type | 0xC0 SHORT / 0xD4 SHORT_ACK / 0xD1 SHORT_ERR / 0x80 EXTENDED / 0x94 EXTENDED_ACK |
| 32 | 4 | mbox_src | source mailbox; 0x00010000 |
| 36 | 4 | mbox_dst | dest mailbox; normal 0x000E1000 |
| 40 | 1 | pkt_num | 1-based index in a multi-packet sequence |
| 41 | 1 | total_pkt_num | total packets in the sequence |
| 42 | 1 | **svc_req_code** | service code (the dispatch byte — see §4) |
| 43 | 1 | **seg_selector** | memory type/segment |
| 44 | 2 | target_index | start register/bit address |
| 46 | 2 | target_count | element count — a size field the reader trusts |
| 48 | 6 | data/pad | inline write data or zero-pad |

Caveat from the sources (Palatis dissector vs. TheMadHatt3r client disagree on
sub-byte alignment in offsets 26–41): treat **26–41 as opaque session-context
bytes to fuzz independently** rather than as firmly-typed fields.

## 4. The fuzz surface

This is where SRTP pays off for a structured generator — the header is small,
fixed-width, and has several enum/dispatch/size fields the firmware must validate:

- **Service-code dispatch (byte 42).** Documented codes span 0x00–0x44 with large
  gaps. The undocumented ranges — **0x01, 0x02, 0x10–0x1F, 0x26–0x37, 0x3A–0x3E,
  0x41, 0x42, 0x45–0xFF** — are prime: sweep every byte with an otherwise-valid
  frame and watch for anything that is not a clean SHORT_ERR. (Read-only sweep:
  keep to svc ≤ 0x06 to stay safe; the write/control codes mutate the device.)
- **Memory-segment enum (byte 43).** Documented selectors are sparse (0x08–0x1E
  word/byte areas, 0x46–0x56 bit-addressed variants). Sweep 0x00–0xFF for
  undocumented segments and off-by-one width confusion (word selector used where a
  byte selector is expected).
- **target_index / target_count (bytes 44–47).** Address and element-count
  extremes (0, 1, 0xFFFF, boundary straddles). `target_count` is the classic
  "read N elements the device will try to serve" field — the shape behind CWE-20
  overflow/over-read bugs.
- **Multi-packet (EXTENDED) framing (bytes 40–41, msg_type 0x80).** `pkt_num >
  total_pkt_num`, `pkt_num = 0`, overlapping sequences — reassembly logic is
  rarely hardened.
- **Mailbox routing (bytes 32–39).** Sweep `mbox_dst` around the documented
  0x000E1000; routing handlers are a known soft spot.
- **State machine.** REQ-before-INIT, duplicate INIT, INIT with the wrong
  pkt_type, client-sent INIT_ACK, malformed INIT size field.

**Structured vs. coverage-guided:** a structured generator (what icsFuzzer does)
is the right tool here — the bugs live in *semantic* field validation (enum
dispatch, count/size handling, reassembly) reachable from a valid session, not in
deep byte-level parsing a coverage-guided fuzzer would need. There is no
open-source SRTP *server* to instrument, so coverage-guided fuzzing isn't readily
available; black-box structured generation against real hardware (or the
robustness responder below) is the practical path.

## 5. Known vulnerabilities & bug classes

| CVE | CVSS | Class | Effect |
|---|---|---|---|
| CVE-2018-8867 (ICSA-18-137-01) | 7.5 | CWE-20 improper input validation | device reboot / unavailability (PACSystems RX3i ≤ 9.30) |
| CVE-2019-13524 (ICSA-20-014-01) | 7.5 | CWE-20 improper input validation | **CPU halts — physical battery removal to recover** (RX3i/RX7i/CRU320, EOL, no fix) |

Both are unauthenticated, single-malformed-packet DoS; neither advisory disclosed
the exact trigger field — which is precisely why a field-by-field structured sweep
(service code × segment × count × framing) is the way to re-derive and extend the
surface. The EOL "no fix" status of CVE-2019-13524 keeps this relevant on
still-deployed hardware.

## 6. Building a test harness

There is no open-source SRTP server, so calibration uses a **robustness
responder** that implements the session + a read-only memory model and refuses
everything else cleanly:

- Handshake INIT→INIT_ACK; then dispatch REQ by service code.
- READ_SYS_MEM returns zeroed data for documented segments; unknown
  segments/services → **SHORT_ERR (msg_type 0xD1)**; writes/control → SHORT_ERR
  (read-only responder).
- Sidecar JSONL records every decision so a fuzzer crash indicator can be matched
  to an expected close.

**Response classification** (the finding-vs-noise line): timeout / connection
reset → crash indicator (this *matches the CVE behavior*, so it is the signal to
watch on real hardware); response < 56 bytes or `pkt_type ≠ 0x0003` → malformed
(crash); `msg_type = 0xD1` SHORT_ERR or non-zero size on an expected-success read →
**exception, not a crash** (the device correctly refused).

**icsFuzzer calibration baseline** (software responder, 603 cases): 76 crash
indicators, **0 false-positive malformed_response** — 67 timeout + 1 reset in
binary_corruption, 244 SHORT_ERR exceptions across memory_selector_sweep (all
undocumented segments), 82 exceptions across service_code_sweep; boundary /
sequence / extended_msg / mailbox all clean. On real hardware, any crash indicator
**without** a matching responder close is a finding candidate.

Gate the device-mutating cases (SET_PLC_RUN 0x23, WRITE_SYS_MEM 0x07,
TOGGLE_FORCE 0x44) behind an explicit flag — they stop the PLC or force I/O.

## 7. Open-source implementations & tooling

- `Palatis/packet-ge-srtp` — Wireshark Lua dissector; best field-level reference.
- `TheMadHatt3r/ge-ethernet-SRTP` — Python client (INIT + READ_SYS_MEM).
- `automayt/ICS-pcap` (GE-SRTP/) — captured sessions for study.
- No server implementation exists to instrument — black-box only.

## 8. Spec references & sources

- Abbasi & Hollick (2017), *Leveraging the SRTP protocol for over-the-network
  memory acquisition of a GE Fanuc Series 90-30*, Digital Investigation 22, S26–S38.
- GE Fanuc TCP/IP Communications Manual **GFK-1541B**.
- CISA ICSA-18-137-01, ICSA-20-014-01.

## 9. Open questions / under-explored surface

- Exact sub-byte layout of header offsets 26–41 (sources disagree) — a clean
  capture against known hardware would resolve it.
- Which specific field each published CVE's malformed packet abused — undisclosed;
  the undocumented service-code and segment ranges are the first place to look.
- EXTENDED multi-packet reassembly (`pkt_num`/`total_pkt_num`) is barely documented
  and almost certainly under-tested.
- Mailbox routing (`mbox_dst`) behavior for values far from 0x000E1000.

*Worked example: `protocols/ge_srtp/fuzzer.py` in the icsFuzzer project implements
all eight categories above, with `scripts/ge_srtp_responder.py` as the robustness
testbed.*