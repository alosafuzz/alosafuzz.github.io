---
title: "A Researcher's Guide to CANopen (and CANopenNode)"
protocols: ["CANopen", "SDO", "PDO", "NMT", "LSS", "EMCY"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["manufacturing", "cross"]
transport: ["can"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes, so you can test your own devices.*

CANopen (CiA 301, with CiA 305 for node configuration) is the application layer that sits on top of
raw CAN in a huge share of motion controllers, drives, I/O modules, and medical/rail subsystems. If a
device has a DB9/screw-terminal CAN port and an object dictionary, it almost certainly speaks CANopen.
The dominant open-source stack is [CANopenNode](https://github.com/CANopenNode/CANopenNode); RT-Labs
C-Open and CANfestival are the other notable ones.

## 1. What it is & where it runs

Every CANopen message is a plain CAN frame: an 11-bit (or 29-bit) identifier plus **0–8 data bytes**.
There is no IP, no TCP — reachability means "a node on the same CAN segment," and that segment is a
shared bus with no authentication. The threat model is a malicious or compromised node (a swapped
drive, a counterfeit I/O block) that can put any frame on the wire the master will parse.

## 2. The object model & COB-IDs

A device exposes an **object dictionary** (16-bit index + 8-bit sub-index). Communication is split by
*function code* encoded in the CAN identifier (the COB-ID):

| Function | Default COB-ID | Direction |
|---|---|---|
| NMT control | `0x000` | master → all |
| SYNC / TIME | `0x080` / `0x100` | master → all |
| EMCY | `0x080 + nodeId` | node → bus |
| PDO (process data) | `0x180..0x500 + nodeId` | cyclic I/O |
| **SDO** (service data) | **rx `0x600 + nodeId`**, tx `0x580 + nodeId` | config/transfer |
| Heartbeat / NMT err | `0x700 + nodeId` | node → bus |
| LSS | `0x7E5` (master→slave), `0x7E4` (reply) | node configuration |

## 3. The fuzz surface

Each object has a tiny receive handler that reads the frame's DLC and data. In descending order of
interest:

- **SDO server — the richest surface.** SDO moves arbitrary-length data to/from the object dictionary
  in three modes: *expedited* (≤4 bytes in one frame), *segmented* (7 bytes/frame with a toggle bit),
  and **block** (sub-blocks of up to 127 segments accumulated into a server-side buffer, with a CRC).
  Block transfer is the most suspicious: it is stateful, multi-frame, and accumulates attacker bytes
  into a fixed buffer — exactly the shape of a buffer-accounting bug. Note it is frequently a
  *compile-time option* (off by default in CANopenNode) and requires a ≥900-byte buffer + CRC16.
- **LSS (CiA 305).** Node-id / bit-rate configuration and *fastscan* identity matching — bit-manipulation
  on unconfigured nodes.
- **RPDO mapping**, **NMT**, **heartbeat consumer**, **EMCY consumer**, **TIME** — shallower, but all
  parse bus-supplied bytes.

## 4. Known vulnerabilities & bug classes

- **RT-Labs C-Open, 2026:** CVE-2026-82358 (SDO write-protection bypass — upload a read-only OD entry
  then write it via download segments) and CVE-2026-82357 (LSS NULL-pointer dereference on a missing
  identity sub-index). Proof that the SDO-server and LSS surfaces carry real, recent bugs.
- **General classes to probe:** integer over/underflow in SDO buffer accounting (`bufOffset`
  arithmetic across sub-blocks, segment `count` and block `noData` fields), toggle/sequence-number
  state confusion, OD size-vs-transfer-size mismatches, and uninitialized reads on truncated frames.

## 5. Building a test harness

CANopenNode abstracts the CAN controller behind a thin driver (`CO_CANrxMsg_read{Ident,DLC,Data}` and
`CO_CAN*`). That is the in-process seam: implement those accessors against a `{ident,DLC,data[8]}`
struct and, rather than calling each static receive handler directly, dispatch frames through
`CO->CANmodule->rxArray` by matching the identifier — the same thing the real interrupt does. One
harness then covers the whole receive surface. Two fidelity requirements bite:

- The SDO server **discards every frame** unless the node's NMT state is pre-operational/operational
  and the server object is valid — so your init must pump `CO_process()` until the node is operational.
- Stateful transfers (block INITIATE → response → sub-block) need **several `CO_process()` ticks
  between frames**; one tick per frame leaves segments arriving before the state machine is ready.

A coverage-guided run that looks "saturated" may simply not have compiled the block path in — verify
you reached it (re-plant a bug and replay the corpus) before trusting a clean result. See the writeup
[*Fuzzing CANopenNode: the surface your fuzzer skips*]({{ '/writeups/fuzzing-canopennode-the-surface-your-fuzzer-skips/' | relative_url }}).

## 6. Open-source implementations & tooling

- [CANopenNode](https://github.com/CANopenNode/CANopenNode) — the reference C stack (Apache-2.0).
- RT-Labs C-Open; CANfestival — alternative stacks.
- `python-can` + `canopen` (Python) and SocketCAN `vcan` for a hardware-free bus on Linux.

## 7. Spec references & sources

- CiA 301 (application layer & communication profile), CiA 305 (LSS).
- CiA 1301 (CANopen FD) for the FD variant.

## 8. Open questions / under-explored surface

- CANopen **FD** (longer frames, different framing) in the stacks that support it.
- The SDO **block-upload** retransmit path (client ack with an earlier sequence number).
- Multi-node / gateway (CiA 309) deployments where frames cross segments.
