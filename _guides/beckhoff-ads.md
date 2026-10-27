---
title: "A Researcher's Guide to Beckhoff ADS/AMS (and AdsLib)"
protocols: ["ADS", "AMS"]
vendor: ["beckhoff"]
vendor_group: "Beckhoff (TwinCAT)"
sector: ["manufacturing", "cross"]
transport: ["tcp", "udp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

**ADS** (Automation Device Specification) is Beckhoff's application protocol for
**TwinCAT**, the soft-PLC/motion runtime that drives a very large share of European
industrial automation — CNC, robotics, packaging, semiconductor and building
automation. ADS messages ride inside **AMS** (Automation Message Specification)
routing envelopes. Every TwinCAT tool, HMI, and the AdsLib client library you embed
in your own code speaks ADS to reach PLC symbols, registry, I/O, licensing and system
services.

**The single most important thing for a researcher:** ADS is **router-mediated and
client-heavy**. A client doesn't talk to a PLC directly; it talks to a local **AMS
router** that forwards AMS packets to the destination `AmsNetId`. The richest
*library-side* attack surface is therefore the **client's parser of the responses** a
(malicious, compromised, or spoofed) PLC/router sends back — not just the PLC's
request handler. And because **ADS is cleartext** (no encryption, no message
authentication — [CVE-2017-16726](https://nvd.nist.gov/vuln/detail/CVE-2017-16726)), a
man-in-the-middle or a rogue device on the route can supply those response bytes.

- **Transport:** **TCP 48898** (AMS/ADS) and **UDP 48899** (discovery / add-route).
- **Addressing:** `AmsNetId` — six bytes, usually the IP plus `.1.1` — and a 16-bit
  **AMS port** (e.g. `851` = TC3 PLC runtime, `0x4000+` = system services).
- **No authentication or encryption** on the protocol itself; access control is a
  route table, and routes are added over the same cleartext UDP.
- **Threat model:** network (`AV:N`) for the PLC-side request handlers; for the
  client library, a malicious/compromised PLC or AMS router the client connects to,
  or a cleartext MITM supplying response bytes.

## 2. Frame model — the length-lie primitive

Every ADS/TCP exchange begins with a **6-byte AMS/TCP header**: two reserved bytes
and a **32-bit length** of everything that follows. Inside sits the **AMS header**
(target/source `AmsAddr`, command id, state flags, a **`cbData` payload length**,
error code, invoke id), then the command payload.

That is two independent declared lengths — the AMS/TCP `length` and the AMS
`cbData` — each supplied by the peer and each used to decide how many bytes to read
and copy. **Declared-vs-actual length handling is the canonical fieldbus bug class**,
and ADS has it twice in the header before any command even dispatches. The receiver
reads the 6-byte header, trusts its `length`, then reads the AMS header + `cbData`
bytes of payload.

## 3. The fuzz surface, mapped to AdsLib

[AdsLib](https://github.com/Beckhoff/ADS) is Beckhoff's own open-source C++ client
library (MIT), embedded in countless tools and integrations. The response-parse
surface a researcher drives, ranked by reachability:

- **UDP discovery / add-route response (lowest bar).** The client **broadcasts** on
  48899 and parses whatever any device on the LAN answers (`AddRemoteRoute`,
  `GetRemoteAddress` in `AdsLib.cpp`): a cookie/invoke/service header, then a
  `while (count--)` **tag-walk** — `uint16 tag; uint16 len; …` — where `len` drives
  further consumption of the response frame. Any device can reply; spoofing is trivial
  on a cleartext broadcast.
- **Symbol-upload response (`SymbolAccess.cpp`).** `SymbolEntry::Parse(data, len)`
  reinterpret-casts an `AdsSymbolEntry` header over the response, then slices
  **nested lengths** — `entryLength` / `nameLength` / `typeLength` / `commentLength` —
  into `std::string`s. `FetchSymbolEntries()` walks many entries, advancing
  `data += entryLength` across a slave-supplied count.
- **Registry-dump response (`RegistryAccess.cpp`).** The "…from network" key/value
  parser: `strnlen` string walks, type/`bytesLeft` accounting, and dword/qword hex
  decoding over attacker bytes.
- **Transport / notification layer (`AmsConnection`, `NotificationDispatcher`).** The
  `AmsTcpHeader` / `AoEHeader` receive path and the notification-sample ring parser —
  where the two header length-lies above are consumed.
- **Secondary services** — RTime, EtherCAT-access, master-DC-stat, license, system —
  mostly fixed-size responses behind strict `bytesRead != sizeof()` checks.

In-process libFuzzer + ASan/UBSan reaches the four application-layer parsers directly
(they take `(data, len)` / buffer entries, and they *copy* attacker bytes into
`std::string`/`std::vector`, so an over-read trips ASan on the copy — no "consume the
descriptor" step needed). The transport path needs a **rogue-router rig**: a real
AdsLib client over a loopback socket fed crafted AMS frames (a real socket, no
`--wrap`), which proves the deployed client reaches the parser.

## 4. Published bug classes (the protocol & product, not AdsLib)

The ADS CVEs to date are **protocol/product** issues, and they define the threat
model that makes the client-parse surface interesting:

- **[CVE-2017-16726](https://nvd.nist.gov/vuln/detail/CVE-2017-16726)** — ADS is
  **cleartext**: traffic can be eavesdropped and **forged** (`CWE-319`). This is the
  linchpin: it makes a MITM or spoofed-response threat model realistic, which is
  exactly what a client-side response parser must survive.
- **[CVE-2019-16871](https://nvd.nist.gov/vuln/detail/CVE-2019-16871)** — remote code
  execution as **SYSTEM** on embedded-Windows (CE) PLCs via the ADS protocol — the
  high-water mark for ADS request-handler impact.
- **[CVE-2017-16718](https://nvd.nist.gov/vuln/detail/CVE-2017-16718)** — a
  **fixed-key** weakness in the route-add path (`CWE-321`), reachable over that same
  cleartext UDP 48899 discovery channel.
- **[CVE-2014-5414](https://nvd.nist.gov/vuln/detail/CVE-2014-5414)** — ADS password
  brute-force (`CWE-307`).

Note what is **not** on this list: a memory-safety CVE in **AdsLib** itself. There
isn't one, and that is a finding of its own kind (next section).

## 5. A robustness note — AdsLib's response parsers hold up

I ran a coverage-guided ASan/UBSan campaign (clang-18 libFuzzer, fork mode,
value-profile, boundary-value seeding) across AdsLib's client-reachable response
parsers at master `24e598a`: the symbol and registry parsers (~210M executions,
including explicit per-field boundary seeds at `{0, 1, limit±1, UINT16_MAX,
UINT32_MAX}`) and the UDP discovery tag-walk (~255M executions). Each harness was
**anchor-validated** with a planted over-read first — e.g. weakening
`SymbolEntry::Parse`'s `nameLength` bound produced an immediate ASan
heap-buffer-overflow READ — so the harnesses demonstrably *can* fire.

**Result: zero crashes.** AdsLib is a **virgin but deliberately defensively-written**
codebase. The hot parsers carry real bounds *and* security-audit comments ("every
bound below is taken from `fullLength`, never from the ring itself"; "`Parse()` bounds
`entryLength` by the bytes we handed in … must not walk by whatever that older entry
announced"). `SymbolEntry::Parse` checks `sizeof(header) <= lengthLimit` before it
reads a single field; the multi-entry walk maintains `bytesRead <= remaining` every
iteration; the UDP tag-walk uses only bounded `Frame` primitives (`pop<T>()`
size-checks, `remove()` clamps via `std::min`). This is the same class of credible
**robustness-negative** as CANopen (CANopenNode) and post-fix BACnet (bacnet-stack):
a clean result that reflects the quality of the code, not a dead harness.

**Lesson for researchers:** don't assume a virgin fieldbus library is naive. The
cheap wins (an unclamped declared length copied straight into a buffer) are exactly
what a security-minded maintainer guards first. On a hardened target, the residual
surface moves to the **least-commented** parsers and to the **transport/notification
layer** reached only via a rogue-router rig — higher harness cost, lower yield.

## 6. Defensive notes

- **Treat ADS as a trust domain, not a protected one.** It is cleartext by design;
  there is no message authentication. Segment it off routable networks and tightly
  control which devices can add routes over UDP 48899.
- **Pin the route table.** Route-add over cleartext UDP is the soft underbelly
  (`CVE-2017-16718`); restrict who can reach 48899 and audit the route list.
- **Patch the product, not just the library.** The high-impact ADS CVEs are TwinCAT /
  embedded-Windows issues — keep the runtime current (`CVE-2019-16871`).
- **If you embed AdsLib**, track upstream `Beckhoff/ADS`; it is actively maintained and
  the response parsers are already hardened — but you still own the transport exposure.

## 7. Further reading

- Beckhoff information system — ADS protocol & TwinCAT documentation.
- `Beckhoff/ADS` (AdsLib) — [github.com/Beckhoff/ADS](https://github.com/Beckhoff/ADS).
- FH-Aachen (2017), *Security Analysis of the ADS Protocol of a Beckhoff CX2020 PLC*
  — protocol-level analysis predating any library fuzzing.

*Caveat on reachability: the application-layer parser findings are proven at the
library level in-process; the client-side threat model (malicious/compromised PLC or
router, or a cleartext MITM) is what carries them to a deployed client. The transport
parse path requires a rogue-router rig to reach on the wire.*
