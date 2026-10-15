---
title: "A Researcher's Guide to EtherCAT (and SOEM)"
protocols: ["EtherCAT", "SoE", "CoE", "EoE", "FoE"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["manufacturing", "cross"]
transport: ["ethernet", "eoe"]
project: fieldbusfuzzer
status: published
cve: ["CVE-2026-70388", "CVE-2026-82943", "CVE-2026-82944", "CVE-2026-82945", "CVE-2026-82946", "CVE-2026-82947"]
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

EtherCAT (Ethernet for Control Automation Technology, IEC 61158) is a **real-time
fieldbus** that runs directly on standard Ethernet (EtherType **`0x88A4`**),
originated by Beckhoff and managed by the EtherCAT Technology Group. It is
pervasive in **motion control, robotics, CNC, packaging, and semiconductor
tooling** — anywhere a controller must clock many I/O nodes with microsecond
determinism.

**The single most important thing for a researcher:** EtherCAT is strongly
**master-centric**. One master drives the segment; slaves only ever respond.
Frames are forwarded slave-to-slave "on the fly," each node reading and writing
its slice as the frame passes. That design decides where the attack surface is:
the **master's parser of slave-supplied data**, not the slave firmware. On a bus
with one malicious, counterfeit, or compromised device, every byte the master
reads back is attacker-influenced.

- **Transport:** raw Ethernet, EtherType `0x88A4` (no IP underneath on the bus
  itself); optionally tunneled as **EoE** (Ethernet-over-EtherCAT) for IP traffic.
- **No authentication or encryption** at the bus layer — by design, for determinism.
- **Threat model:** adjacent/on-segment (`AV:A`), a malicious slave or a MITM node.

## 2. Frame & datagram model

An EtherCAT frame carries one or more **datagrams**, each with a command (read/write
to a logical/physical/auto-increment address), an address, a length, and a **working
counter (WKC)** that slaves increment to prove they processed it. A fuzzer reaching
the master exercises: WKC/offset handling in frame processing, and the **mailbox**.

## 3. The mailbox — the richest surface

Acyclic, larger exchanges use the **mailbox**, a length-prefixed envelope that
multiplexes several protocols over the same framing:

| Sub-protocol | Purpose |
|---|---|
| **CoE** (CANopen-over-EtherCAT) | SDO object dictionary read/write — config, parameters |
| **SoE** (Servo/Sercos-over-EtherCAT) | servo drive parameters (IDNs) |
| **FoE** (File-over-EtherCAT) | firmware/file transfer, segmented |
| **EoE** (Ethernet-over-EtherCAT) | tunneled Ethernet/IP, incl. a set-IP request |

Each sub-protocol carries its **own length field**, supplied by the slave, and each
handler computes a payload size from it. That shared shape — *slave-supplied length,
minus a fixed header, used to size a copy* — is the recurring fuzz target.

## 4. The fuzz surface, mapped to SOEM

[SOEM](https://github.com/OpenEtherCATsociety/SOEM) (RT-Labs) is the open-source
master most products embed. The surface a researcher drives:

- **Frame receive / `inframe`** — WKC offset and frame-length handling.
- **Mailbox receive (central)** — the one function every mailbox message passes
  through before dispatch; the right place to both *attack* and *fix*.
- **Per-protocol handlers** — `ecx_SoEread`, CoE SDO read, `ecx_FOEread`,
  `ecx_EOErecv`, `ecx_EOEgetIp` — each parsing its own length.
- **Cyclic mailbox mode** — an optional mode whose size comes from slave config.

In-process libFuzzer + ASan/UBSan reaches all of these; a `veth` two-process setup
(a real master vs. a minimal malicious-slave) confirms reachability on the wire.

## 5. Published bug classes (SOEM, ≤2.0.0; fixed in 2.0.1)

RT-Labs advisory **RRTL-260921-1** consolidated multiple researchers' reports into
six CVEs, all `AV:A`, all fixed in **SOEM 2.0.1**:

- **CVE-2026-70388** (HIGH) — **integer-underflow OOB write** (`CWE-191`/`195`/`787`).
  The SoE/CoE/EoE/FoE handlers subtract a fixed header from a slave-supplied length
  in *signed* arithmetic; a length below the header goes negative and is used as a
  huge positive copy size. The canonical fieldbus bug class: **a length field trusted
  into a size computation.**
- **CVE-2026-82944** (HIGH, `8.8`) — **buffer overflow in CoE SDO multi-segment upload**
  (`CWE-787`/`131`/`120`): the master validates the declared total size once at the start
  but never tracks the cumulative bytes written; a slave declares a small total, then
  streams segments past the buffer. The stateful cousin of the length-trust bug.
- **CVE-2026-82947** (HIGH) — **OOB reads in frame processing** (`CWE-125`): an
  unvalidated working-counter offset, plus cyclic-mailbox and EoE-timestamp read paths.
- **CVE-2026-82943** (MEDIUM) — **OOB read via unchecked length** (`CWE-125`/`200`): a
  slave claiming a large length while sending a short message reads adjacent memory
  back to the caller — up to ~64 KB information disclosure.
- **CVE-2026-82945** (`6.5`) — **FMMU configuration-table overflow** (`CWE-787`/`129`/`120`):
  an unchecked table index during slave scan lets a device presenting more than
  `EC_MAXFMMU` config blocks write past the array — reached automatically at scan time,
  before operational state, driven by the slave's on-chip EEPROM.
- **CVE-2026-82946** (MEDIUM) — **NULL-pointer dereference** in mailbox error handling
  (`CWE-476`): an error response clears the buffer pointer, the retry loop reuses it.
  Two messages (an error, then anything) crash the master.

**The fix is instructive:** a single validation in the central mailbox-receive
function — check each message's length against the per-protocol minimum and the
physical mailbox size before any parser runs — closes the underflow across all four
sub-protocols. One guard in the shared path beats four per-parser patches.

## 6. Defensive notes

- **Upgrade to SOEM 2.0.1+**; audit embedded masters for their vendored SOEM version.
- **Segment isolation** is the real mitigation: keep EtherCAT off shared/routable
  networks; treat the bus as a trust domain and control what devices join it.
- **Supply chain**: a counterfeit or second-hand slave is the realistic `AV:A` actor.

## 7. Further reading

- RT-Labs security information — [rt-labs.com/cyber-security](https://rt-labs.com/cyber-security/)
- Writeup: *Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers* (alosafuzz).

*GPIB-style caveats don't apply here: EtherCAT is genuinely on the wire, and the
master is genuinely reachable from any device on the segment.*
