---
title: "A Researcher's Guide to EPICS pvAccess (PVXS)"
protocols: ["pvAccess", "PVA", "PVXS"]
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

**pvAccess (PVA)** is EPICS's second-generation control protocol — the structured-data
successor to [Channel Access](/guides/epics-channel-access/). Where Channel Access moves
scalars and simple arrays, pvAccess moves **arbitrary typed structures**: a message
carries a *type introspection* (a `FieldDesc` describing nested structs, unions, arrays,
and bitsets) followed by the value data. It is how EPICS carries NTTable, NTNDArray
(detector images), and other composite data across accelerators, light sources, and
telescopes. **PVXS** is the modern C++ implementation, actively developed and expected
to supplant the older `pvDataCPP`/`pvAccessCPP`.

**The single most important thing for a researcher:** pvAccess inherits Channel Access's
posture — **no authentication or encryption by design** (optional "anonymous"/"ca"
identity the client self-reports), isolation is the intended control — but it has a
*much richer* parser. The type-introspection decode is recursive, the value decode
walks attacker-described structures, and arrays/strings carry **declared counts** that
drive allocation. That makes the deserializer the interesting surface.

- **Transport:** **TCP 5075** (virtual circuits) and **UDP 5076** (search / beacons).
- **No auth / no encryption** on the wire; the decode runs before/around optional auth.
- **Role:** the IOC/PVA server is the **server** — it parses unauthenticated client
  messages. Highest-value surface, no rogue-server rig needed.

## 2. Frame & serialization model — the count-lie primitive

A PVA message has a small header (magic `0xCA`, version, flags incl. **byte-order**,
command, payload size) and then a command-specific body. The bodies that matter carry
**typed data**, encoded in two parts:

1. **Type introspection** — a `FieldDesc` tree: a type code, and for structures a child
   count followed by each child's name + recursive `FieldDesc`.
2. **Value data** — the field values, laid out per the introspection.

The researcher's hooks:
- **Variable-length `Size`** encodes counts as 1 / 5 / 9 bytes (up to a 64-bit value) —
  so a tiny message can declare an enormous array/child count. That declared count
  drives `new[]` / `reserve()` **before** the elements are read: the *count-lie*
  (declared size ≫ actual bytes), the pvAccess analogue of the length-lie.
- **Recursion** — nested structs/unions make the introspection decode recursive
  (depth-guarded in PVXS).
- **Byte-order flag** — the payload endianness is negotiated per message; a decoder
  must handle both.

## 3. The fuzz surface, mapped to PVXS

[PVXS](https://github.com/epics-base/pvxs) (C++). Ranked by reachability and isolation:

- **PRIME (cleanly isolatable) — the typed-data deserializer, `src/dataencode.cpp`:**
  `pvxs::impl::from_wire_type_value(Buffer&, TypeStore&, Value&)` decodes the FieldDesc
  introspection (recursive) **and** the value, driving the whole struct/union/array/
  bitset/var-length decode. It takes a `Buffer` (ptr+len) with **no server-runtime
  coupling** — a near-direct `(data, len)` libFuzzer entry. The recursive
  `from_wire(Buffer&, vector<FieldDesc>&, TypeStore&, depth)` and the array decode in
  `pvaproto.h` (`shared_array<E> arr(count)`) are the hot spots.
- **SECONDARY — server message framing, `src/serverconn.cpp`:** the TCP virtual-circuit
  loop that frames messages and dispatches per command (connect / create-channel / get /
  put / monitor / introspect), each pulling `sid`/`ioid`/type-value off the wire.
- **TERTIARY — UDP search / beacon, `src/udp_collector.cpp`:** the datagram collector
  that parses search requests — reachable by *any* host on the broadcast domain.

## 4. Known security posture (not a CVE list)

Like Channel Access, pvAccess/PVXS has **no memory-safety CVE** on the parser, is **not**
on OSS-Fuzz, and ships **no fuzz harness**; prior fuzzing is **academic/incomplete**
(conference talks on state-machine fuzzing of CA/pvAccess). The protocol's design
assumption is network isolation, not a hardened parser — the same "not meant for hostile
networks" heritage as CA.

## 5. A robustness note — the decoder is memory-safe; watch the counts

I built an in-process libFuzzer harness around `from_wire_type_value` and ran it under
AddressSanitizer + UndefinedBehaviorSanitizer across the full decode path
(`dataencode` / `data` / `bitmask` / `type` / `sharedarray`), anchor-validated by
planting a recursion-guard removal.

**Two findings worth separating:**

1. **The decoder is memory-safe.** Tens of millions of executions after neutralizing the
   allocation class (below) — **zero** memory-safety crashes, zero undefined behavior.
   The recursive introspection decode and the typed-value walk hold up.

2. **An unbounded-allocation class (CWE-770), low severity.** The array/struct decoders
   read a `Size` count from the wire and immediately `new E[count]` / `reserve(count)`
   **before** reading element data, with no bound of the declared count against the
   remaining message bytes. A ~9-byte message can request a multi-gigabyte allocation.
   **But de-confound it before calling it a DoS:** on a 64-bit, overcommit Linux (a
   typical IOC) that `new[]` is *lazy* — the element-read loop only touches the bytes the
   message actually contains, so real RSS stays tiny and there is no exhaustion. On a
   no-overcommit host or under a ulimit it throws `bad_alloc` (connection-level at worst).
   It's a legitimate hardening item — **cap declared counts against remaining bytes** —
   not a CVE-grade denial of service, and I don't claim it as one.

**Method note (how #1 was earned):** the allocation class *masked* deeper fuzzing — the
sanitizer aborts on the giant `new[]` on nearly every count-bearing path. The way to a
trustworthy "the decoder is safe" is **patch-and-refuzz**: cap the counts locally (the
same hardening #2 recommends), rebuild, and re-fuzz. Coverage roughly doubled and the
campaign came back clean — which is the honest basis for the memory-safe claim.

## 6. Defensive notes

- **Isolate it.** pvAccess is unauthenticated and cleartext by design; keep PVA servers
  off hostile/routable networks and firewall TCP 5075 / UDP 5076.
- **Front exposed deployments with a gateway** rather than exposing IOCs directly.
- **Patch the framework** — track PVXS releases even absent CVEs; robustness and
  hardening fixes land without advisories.
- **If you embed PVXS**, be aware of the declared-count allocation behavior on
  no-overcommit / memory-constrained hosts.

## 7. Further reading

- PVXS — [github.com/epics-base/pvxs](https://github.com/epics-base/pvxs); EPICS pvAccess
  protocol specification (EPICS docs).
- Companion: [A Researcher's Guide to EPICS Channel Access](/guides/epics-channel-access/).
- Writeup: *Fuzzing EPICS pvAccess: a clean seam, an amplification that wasn't, and patch-and-refuzz* (alosafuzz).

*Caveat on reachability: the decoder result is proven in-process against the real
`from_wire_type_value`; the `serverconn` TCP framing state machine and `udp_collector`
search path sit above it and are a separate (server-coupled) increment.*
