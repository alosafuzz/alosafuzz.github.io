---
title: "A Researcher's Guide to KNX / KNXnet/IP (and knxd)"
protocols: ["KNX", "KNXnet/IP", "cEMI", "TP1"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["building-automation", "cross"]
transport: ["knxnet-ip-udp", "tp1"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes, so you can test your own devices.*

KNX runs the building you're in — HVAC, lighting, access control, blinds, energy. The field bus is
usually twisted-pair (TP1); IP reachability is via **KNXnet/IP** over UDP port 3671 (unicast tunneling
and management, plus multicast routing on 224.0.23.12). The dominant open-source daemon is
[knxd](https://github.com/knxd/knxd) (the EIBd successor); calimero (Java) and thelsing/knx (embedded)
are the other common stacks. KNXnet/IP plain has **no authentication** — anyone who can reach UDP 3671
can send frames the gateway will parse.

## 1. The layered shape

KNXnet/IP is four nested layers, and knowing where each ends is the whole map:

```
KNXnet/IP header : 06 10 | service-type(2) | total-length(2)      (6 bytes)
  service body   : SEARCH / DESCRIPTION / CONNECT / TUNNEL / ROUTING / DEVICE_CONFIG ...
    cEMI         : message-code | add-info-len | add-info | <L_Data>   (tunnel/routing payloads)
      TP1 frame  : ctrl | src(2) | dst(2) | len | <LSDU> | chk        (the bus-level telegram)
        APDU/TPDU: transport + application service + data
```

## 2. The fuzz surface

- **The envelope is shallow.** `fromPacket` enforces `byte0..1 == 06 10` and `total-length == size`,
  so top-level length-lies bounce immediately; the per-service `parse*` functions mostly copy the
  payload out without deep parsing. Don't expect much here.
- **The depth is in cEMI → TP1 → APDU.** The L_Data/busmonitor decoders parse addressing, length, and
  application services from attacker bytes — this is where the memory-safety surface lives.
- **Transport matters for reachability.** A malformed TP1 frame reaches the decoders via the real KNX
  bus (TP-UART/NCN5120 serial adapters), via multicast routing, or via a busmonitor tunnel. The serial
  path applies a length-gated frame assembler (`in_check`) that rejects some shapes; the KNXnet/IP
  busmonitor tunnel path (`CEMI_to_Busmonitor`) has **no such length gate** — a reachability
  distinction worth tracing per finding.

## 3. Known vulnerabilities & bug classes

- **knxd #665 (2026):** NULL-pointer dereference in `L_Busmon_PDU::Decode` — the busmon decode path
  dereferenced `CM_TP1_to_L_Data`'s return without a null check. Fixed.
- **knxd [#666](https://github.com/knxd/knxd/issues/666) (2026):** integer overflow in
  `CM_TP1_to_L_Data` — `uint8_t len = c[6] + 1` wraps to 0 on `c[6]==0xFF`, yielding a zero-length LSDU
  that trips `assert(lsdu.size() >= 1)` (a reachable assertion abort). Reported; fix queued upstream.
  See [*A signed/unsigned slip*… not — the knxd writeup]({{ '/writeups/fuzzing-knxd-a-minute-to-crash-a-day-to-earn-the-reach/' | relative_url }}).
- **Protocol/auth (older):** CVE-2015-8299 (buffer overflow in ETS/Falcon via a crafted KNXnet/IP
  packet), CVE-2023-4346 (Connection Authorization lockout), and the general fact that plain KNXnet/IP
  is unauthenticated. KNXnet/IP Secure exists but is unevenly deployed.
- **General classes:** signed/unsigned length arithmetic on frame fields, assertions on
  network-controlled data, and cEMI additional-info / length handling.

## 4. Building a test harness

knxd's `EIBNetIPPacket::fromPacket(CArray&, …)` is the top-level entry; the per-service `parseEIBnet_*`
functions and the cEMI/TP1/APDU decoders (`CM_TP1_to_L_Data`, `APDU::fromPacket`,
`L_Busmon_PDU::Decode`) are the deeper targets. Mirror the real gate (magic + length) exactly and add
no progress guards the handler lacks. For busmonitor decode, note it only runs when a text-busmonitor
client is attached — reachability is conditional and worth proving on a real daemon.

## 5. Open-source implementations & tooling

- [knxd](https://github.com/knxd/knxd) (C++, GPL) — daemon/router; the broadest surface.
- calimero-core (Java), thelsing/knx (embedded C++).
- `KNXnet/IP` Wireshark dissector; `knxtool` / the EIB client API for driving a running knxd.

## 6. Spec references & sources

- KNX 03_08_0x (KNXnet/IP core, tunneling, routing, device management).
- KNX 03_03_0x (cEMI, TP1 data link).

## 7. Open questions / under-explored surface

- KNXnet/IP **Secure** (session/auth framing) — newer, thinner prior art.
- The cEMI **additional-information** fields and LTE-HEE (E-mode) addressing.
- Routing (multicast) vs tunneling reachability differences for the deep decoders.
