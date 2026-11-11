---
title: "A researcher's guide to ISOBUS transport (and AgIsoStack++)"
protocols: ["ISOBUS", "ISO 11783", "J1939 TP", "ETP", "NMEA 2000 Fast Packet"]
vendor: ["cross"]
vendor_group: "Agriculture (ISOBUS)"
sector: ["agriculture", "cross"]
transport: ["can"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
known security posture only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

A modern tractor and its implements — planters, sprayers, balers — talk over **ISOBUS**
(ISO 11783), a CAN-based stack built on J1939. The virtual terminal in the cab, the task
controller, and every implement ECU exchange configuration, commands, and telemetry on the
same bus. Because CAN frames carry only eight data bytes, anything larger than a single
frame — an object pool, a device descriptor, a multi-section command — is split across many
frames and reassembled, and the reassemblers are the interesting attack surface: an implement
on the bus is attacker-controlled input to the terminal and task controller.

The stack fuzzed here is **[AgIsoStack++](https://github.com/Open-Agriculture/AgIsoStack-plus-plus)**
(Open-Agriculture, C++11, MIT), a maintained open-source ISOBUS implementation.

## 2. Three reassemblers, three framing models

ISOBUS carries multi-frame messages three ways, and each is a separate reassembler worth
fuzzing on its own:

- **J1939 / ISO 11783 Transport Protocol (TP)** — up to 1785 bytes. Two modes:
  - **BAM** (Broadcast Announce Message): connectionless and unauthenticated. One
    `TP.CM_BAM` frame declares the total size and packet count; the receiver sizes a
    reassembly buffer; `TP.DT` data frames fill it by sequence number. No handshake, so any
    node can announce an arbitrary length and stream frames. This is the cleanest
    length-lie-into-a-heap-buffer on the bus.
  - **RTS/CTS**: connection-mode, destination-specific. The sender requests to send, the
    receiver answers with clear-to-send, then data flows. Reaching this path in a harness
    needs the receiver side to actually respond (see §5).
- **Extended Transport Protocol (ETP)** — larger transfers, connection-mode only (no
  broadcast). Adds a Data Packet Offset message so batches of packets can be placed at an
  offset into the buffer. The offset and the declared sizes are the fields to push.
- **NMEA 2000 Fast Packet** — a lighter scheme for up to ~223 bytes: the first frame carries
  a sequence/length byte, subsequent frames a frame counter, and the payload is reassembled
  by counter. Connectionless; a registered PGN is all it needs.

## 3. The fuzz surface, mapped to AgIsoStack++

Each reassembler ingests frames through one entry point — feed raw CAN frames there:

- **`TransportProtocolManager::process_message(const CANMessage &)`** — dispatches to
  `process_connection_management_message` (BAM/RTS parse: total size at bytes 1–2, packet
  count at byte 3) and `process_data_transfer_message` (the reassembly write).
- **`ExtendedTransportProtocolManager::process_message`** — RTS / CTS / DPO / DT for ETP.
- **`FastPacketProtocol::process_message`** — Fast Packet, after a PGN is registered.

Fields to seed to extremes: the **declared total size** and **packet count** in the
announce, the **sequence numbers** on data frames (gaps, duplicates, out-of-order), and the
**ETP data-packet offset**. The classic bug shape is a mismatch between the announced length
and the frames actually delivered.

## 4. Known security posture (not a CVE list)

AgIsoStack++ has **no published CVE**, and the project is unusually well-tended for its
class: a CI job builds the unit tests under ASan and UBSan, and the maintainers have been
landing truncation and short-frame hardening on the server-side parsers (the virtual
terminal and task-controller message handlers, and the object-pool/DDOP file parser). That
is worth knowing two ways. Those server and object-pool parsers are *actively being audited*,
so they are a crowded place to look. The three **reassemblers**, by contrast, have a quiet
memory-safety history — which is exactly why they were the target here.

## 5. A robustness note — the reassemblers hold up

Fuzzed at the frame level under AddressSanitizer and UBSan across all three reassemblers —
tens of millions of executions, with the connection-mode ETP path reached as well as the
connectionless BAM and Fast Packet — the reassembly is **memory-safe**: no out-of-bounds, no
use-after-free. The data-transfer write is bounded by construction: it rejects a packet index
that reaches the declared message length and clamps the per-frame copy to what remains, so a
length lie produces a rejected session rather than an overflow. A clean, well-covered
negative on the multi-frame surface.

Two harness lessons carry over to any CAN-stack target:

**Reaching a reassembler is not the same as harnessing its entry point.** The connection-mode
paths (TP's RTS, all of ETP) only run when the message is addressed to *our device* —
`is_destination_our_device()` requires the destination to be an internal control function,
not a broadcast. A harness that feeds every frame as a broadcast silently has its RTS frames
dropped at the door and never reaches the connection-mode reassembly, while coverage looks
plausible. Driving those paths means giving the harness a real internal control function as
the destination (a faked base object with the "internal" type set is not enough — the stack
down-casts it to the concrete internal type, which is undefined behavior on an impostor).
Enumerating the entry points is step one; confirming each actually *reaches* its deep code is
step two.

**MemorySanitizer on an STL-heavy C++ stack reports the standard library, not your target.**
Here the transport manager copies its `std::list` of active sessions on every update, and
without an instrumented libstdc++, MSan flags the list's own node bookkeeping as
uninitialized — a report whose origin trace is entirely in the standard-library headers, with
no stack field in it, and which fires only once the list is non-empty. Read the origin before
believing an MSan hit on this kind of target; a genuine finding points at your code, not at
`std::list`'s copy constructor.

## 6. Further reading

- AgIsoStack++ source: [github.com/Open-Agriculture/AgIsoStack-plus-plus](https://github.com/Open-Agriculture/AgIsoStack-plus-plus)
- ISO 11783 (ISOBUS) and SAE J1939 define the transport protocols; NMEA 2000 defines Fast Packet.
- The companion writeup — the full ASan/UBSan campaign, the connection-mode reachability fix,
  and the MSan std::list story — is at
  [/writeups/fuzzing-isobus-reassemblers-reaching-the-connection-mode-path/](/writeups/fuzzing-isobus-reassemblers-reaching-the-connection-mode-path/).
