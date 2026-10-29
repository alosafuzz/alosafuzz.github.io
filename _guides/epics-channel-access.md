---
title: "A Researcher's Guide to EPICS Channel Access"
protocols: ["Channel Access", "CA", "pvAccess"]
vendor: ["epics"]
vendor_group: "EPICS (Argonne / collaboration)"
sector: ["science", "cross"]
transport: ["tcp", "udp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
known security posture only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

**EPICS** (Experimental Physics and Industrial Control System) is the distributed
control framework behind a huge share of big science: particle accelerators,
synchrotron light sources, radio telescopes, neutron sources, fusion experiments,
and plenty of industrial test stands. Its original and still-dominant wire protocol
is **Channel Access (CA)** — a client/server protocol for reading, writing, and
monitoring named "process variables" (PVs) exposed by an **IOC** (Input/Output
Controller). A newer protocol, **pvAccess** (PVA), carries structured data but CA is
what most of the installed base speaks.

**The single most important thing for a researcher:** the EPICS maintainers are *on
record* that Channel Access **"was never intended to be used in a hostile
environment"** and "never claimed to be hardened," and there is a long-documented CA
server loop that could be provoked by a plain port scan. CA has **no authentication
and no encryption** by design — access control is a host/user allow-list the server
trusts the client to report. So the threat model is explicit: anything that can reach
the IOC's port can talk to the parser.

- **Transport:** **TCP 5064** (CA virtual-circuit) and **UDP 5064** (name resolution /
  search and beacons); the CA Repeater uses **UDP 5065**.
- **No authentication / no encryption** on the protocol itself.
- **Role:** the IOC is the **server** — it parses unauthenticated client requests.
  That's the highest-value surface: no rogue-server rig needed, just a socket.

## 2. Frame model — the length-lie primitive

Every CA message starts with a fixed **16-byte header** (`caHdr`):

| field | size | meaning |
|---|---|---|
| command | u16 | message type (jump-table index) |
| payloadSize | u16 | size of the payload that follows |
| dataType | u16 | DBR type of the operation |
| count | u16 | element count |
| parameter1 | u32 | usually the channel id (cid/sid) |
| parameter2 | u32 | command-dependent (version, dbr available, …) |

The researcher's hook is the **large-array extension**: when `payloadSize` (or
`count`) is `0xFFFF`, protocol version ≥ 4.9 switches to a **3-word form** where the
real 32-bit payload size and count follow the header. That is the classic
*declared-length-vs-actual-bytes* primitive — the message's own length field drives
how many bytes the server consumes. The server computes `msgsize = payloadSize +
header` and must bound it against the bytes actually received before dispatching.

## 3. The fuzz surface, mapped to epics-base

[epics-base](https://github.com/epics-base/epics-base) is the reference implementation
(C/C++). The server-side CA parse lives in the IOC's `rsrv` module. Ranked by
reachability:

- **TCP command dispatch (PRIME) — `rsrv/camessage.c` `camessage()`.** Reads the
  `caHdr` off the circuit, handles the `0xFFFF` extended form, bounds `msgsize`, then
  dispatches via `tcpJumpTable[command]`. Handlers include version, echo, host/client
  name, event add/cancel, and the channel operations (create/claim, read, read-notify,
  write). An unauthenticated client on TCP 5064 reaches all of this.
- **UDP search / beacon (SECONDARY, lowest bar) — `rsrv/cast_server.c`.** The same
  `camessage()` runs with the UDP jump table (`udpJumpTable`), whose live entries are
  *version* and **search** — the datagram name-resolution path that *any* host on the
  broadcast domain can hit. This is the class the historical port-scan loop lived in.
- **The channel operations go into the database** — `dbChannel_create` /
  `dbChannel_get` / `dbChannel_put` and the DBR size math (`dbr_size_n(dataType,
  count)`). Note the read path is defensively written: it validates the DBR type and
  **clamps** `count` to the channel's element count before computing sizes.
- **pvAccess (`modules/pvAccess`, and PVXS)** — the newer structured-data protocol; a
  separate, larger surface for another campaign.

## 4. Known security posture (not a CVE list)

Unlike most targets in this series, Channel Access has **no memory-safety CVE** on the
core parser, and `epics-base` is **not** on OSS-Fuzz. What exists:

- The maintainers' own framing that CA is **unhardened by design** and a documented
  **CA-server loop reachable via a port scan** — i.e. the robustness of the parse layer
  was never the design goal; network isolation was.
- Only **academic / incomplete** prior fuzzing (a 2021 student AFL effort on
  `softIoc`, described as "not production-ready"; ongoing conference talks on
  state-machine fuzzing of CA / pvAccess). Nothing shipped or continuous.

That combination — admittedly-unhardened, widely deployed, never systematically fuzzed —
is exactly why the parse layer is worth a rigorous look.

## 5. A robustness note — the CA parser holds up (reaching it is the hard part)

I built an in-process libFuzzer harness around the **real** `camessage()` server
parser (both the TCP and UDP dispatch paths) and ran it under AddressSanitizer and
UndefinedBehaviorSanitizer — well over a billion executions across the campaigns,
anchor-validated by planting a bounds bug and confirming the harness caught it.

**Result: zero memory-safety crashes, zero undefined behavior, zero genuine hangs**
(every libFuzzer timeout de-confounded — some were sanitizer-instrumentation slowness,
the rest a harness artifact where a never-disconnecting test client accumulated
channel state; all completed instantly on a fresh process). The header parse, the
`0xFFFF` length-lie handling, the message-size bounding, the string handlers, and the
UDP search path are all robust at this depth.

**The real story was reachability, not the zero.** `camessage()` is deeply coupled to
the IOC runtime: it `assert()`s on a resource bucket, locks a global client queue,
walks an event subsystem, and dispatches into the database. Standing up just enough of
that to reach the parser took **seven** separate initialization fixes — and a crucial
EPICS-specific gotcha: **`epicsAssert` suspends the failing thread instead of calling
`abort()`**, so a tripped assertion shows up to a fuzzer as a **hang, not a crash**.
If you fuzz EPICS, treat every timeout as a candidate finding until you've proven
otherwise. On this target, the lesson is the inverse of a bug: the code the maintainers
called "not hardened" is memory-safe at the parse layer — the hard part was building a
harness honest enough to say so.

## 6. Defensive notes

- **Treat CA as a trust domain, not a protected one.** It is unauthenticated and
  cleartext *by design*. Keep IOCs off routable/hostile networks; segment the control
  network; firewall UDP/TCP 5064 and the repeater 5065.
- **Use the access-security layer** (host/user allow-lists) and keep it restrictive —
  but remember the client self-reports identity, so it's a policy control, not a
  cryptographic one.
- **For exposed deployments, front CA with a gateway** (e.g. the CA gateway / PV
  Access gateway) rather than exposing IOCs directly.
- **Patch the framework** — track `epics-base` releases even absent CVEs; robustness
  fixes land without advisories.

## 7. Further reading

- EPICS Base — [github.com/epics-base/epics-base](https://github.com/epics-base/epics-base);
  Channel Access Protocol Specification (EPICS docs).
- Writeup: *Fuzzing EPICS Channel Access: reaching the parser was the hard part* (alosafuzz).

*Caveat on reachability: the parser-level result is proven in-process against the real
`camessage()` on both transports; the record value-transfer path (`dbGet`/`dbPut`)
needs a fully-initialized IOC and was out of in-process scope.*
