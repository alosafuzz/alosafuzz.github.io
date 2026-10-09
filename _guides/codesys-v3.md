---
title: "A Researcher's Guide to the CODESYS V3 Name Service"
protocols: ["CODESYS V3"]
vendor: ["codesys"]
vendor_group: "CODESYS (OEM runtime)"
sector: ["cross"]
transport: ["codesys-udp"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: this documents the wire format,
the fuzz surface, and published bug classes so researchers can build their own
test harnesses. It contains no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

CODESYS V3 is not a single vendor's PLC — it is the **OEM soft-PLC runtime
embedded inside hundreds of PLC/HMI brands**: WAGO, Beckhoff, Eaton, Festo,
Berghof, ABB, Schneider, and many more all ship a licensed CODESYS Control
runtime. That is what makes it a disproportionately valuable research target: a
single parser bug in the *shared* runtime has a blast radius across the entire
OEM ecosystem, not one product line.

The **name service** is CODESYS's unauthenticated discovery layer. It is how the
CODESYS IDE and gateway find runtimes on a network: a client sends a broadcast or
unicast *NameServiceRequest* and a runtime answers with an *Identification* reply
carrying its node name, device name, vendor, and target type/version. No
authentication, no session, no token — by design, discovery predates any auth.

- **Transport:** **UDP 1740** (the block-driver / name-service port; the family
  also binds 1741–1743). The embedded gateway uses **TCP 11740** (older/Windows
  setups used TCP 1217). This guide targets the UDP 1740 name service.
- **Connectionless:** no handshake, no session. One datagram in, (historically)
  one datagram out.

> **Reachability caveat — read this before you plan a campaign.** On a *modern*
> CODESYS runtime (tested: CODESYS Control for Linux SL 4.22 / SDK 3.5.22.30) the
> UDP 1740 name service **binds but stays silent** — it does not answer the
> classic rapid7-era NameServiceRequest at all, even sent unicast, to the
> interface broadcast, or to 255.255.255.255, and even after the default
> *enforced* security policy is relaxed. See §5 and §9. The legacy "unauth UDP
> 1740 identity read" assumption still holds on older OEM runtimes and many
> fielded PLCs, but on current CODESYS the live discovery path has moved to the
> TCP gateway / OPC UA. Plan your reachability check first.

## 2. Session & transport model

There is no session. The name service is a single connectionless request/reply:

```
Client → Runtime (UDP 1740, bcast or unicast):  service_id 0x03  NameServiceRequest
Client ← Runtime:                                service_id 0x04  Identification reply
```

A healthy endpoint **silently drops** any datagram it does not like (bad magic,
unknown service, truncated body). That silent-drop behavior is central to how you
instrument the fuzzer (see §6): on UDP, *a timeout is the normal refusal, not a
crash*.

The embedded gateway on **TCP 11740** carries the same identification payload
inside a length-prefixed, framed block-driver protocol (`CmpBlkDrvTcp`). It is
reachable where the UDP NS is silent, but its frame grammar is not publicly
documented — reaching the deep name-TLV parser through it is a reverse-engineering
task (§9).

## 3. Wire format

The frame is a small block-driver **header (big-endian)** followed by a
**little-endian payload**. The byte oracle below is reproduced from the rapid7
`codesys3.lua` dissector and verified byte-for-byte by the icsFuzzer builder.

**Header (big-endian):**

| Off | Size | Field | Researcher's note |
|----|----|----|----|
| 0 | 1 | magic | `0xC5` |
| 1 | 1 | hopinfo | `(hop_count << 3) \| header_length`; **header_length = low 3 bits**, counted in 16-bit *words* |
| 2 | 1 | packetinfo | `(priority<<6)\|(signal<<5)\|(addr_type<<4)\|(data_length & 0xF)` |
| 3 | 1 | **service_id** | `0x03` NameServiceRequest / `0x04` Identification reply — the dispatch byte |
| 4 | 1 | message_id | per-message id |
| 5 | 1 | **address_lengths** | `(sender_words << 4) \| receiver_words` — two nibbles, each a count of 16-bit words |
| 6 | 2 | broadcast_id | big-endian |
| 8 | var | sender address | `sender_words * 2` bytes (big-endian words) |
| .. | var | pad | zero-pad up to a 4-byte boundary (faithful to the source's `len % 4` pad) |

**Payload (little-endian):** `package_type(H) version(H) request_id(I)`, then — in
the **Identification reply only** — the identity TLVs:

```
maxChannels(H) byteorder(B) addrDiff(B) parentAddrSize(H)
node_len(H) dev_len(H) vend_len(H)
target_type(I) target_id(I) target_version(I) target_flags(I)
ser(B) oem(B) blk(B) + pad
parentAddr[parentAddrSize] bytes
node[node_len] / device[dev_len] / vendor[vend_len]  strings
```

**The offset math is the whole game.** The device locates the payload at:

```
pos = header_length*2 + (sender_words + receiver_words)*2, re-aligned up to a 4-byte boundary
```

So `header_length` and the two `address_lengths` nibbles are **attacker-controlled
inputs to a pointer computation**. Over- or under-declare them and the parser
reads the payload from an offset you chose — the classic length-vs-offset
confusion surface.

**Locked seed (NameServiceRequest, sender 192.168.1.50/24, bcast id 0x1234) — 20 bytes:**

```
c5 7c 40 03 00 10 12 34 00 32 00 00 02 c2 00 04 69 69 20 04
```

This is the golden oracle: the icsFuzzer `build_name_request()` reproduces it
byte-for-byte with default args, asserted in both the module's unit test and
icsScanner's discovery smoke test.

## 4. The fuzz surface

The header is tiny and fixed-width, with several enum/dispatch/size fields the
runtime must validate before it can even decide to drop a packet — a good fit for
a **structured generator**. icsFuzzer splits it into five categories (524 cases):

- **Service dispatch (byte 3).** Sweep `service_id` `0x00–0xFF` with an otherwise
  valid body (icsFuzzer: `codesys_service_sweep`, 256 cases). `0x03`/`0x04` are
  documented; everything else exercises the dispatch table's handling of unknown
  service codes.
- **Header length / address nibbles (byte 1, byte 5).** The offset-computation
  inputs: over-/under-declared `header_length`, sender/receiver word counts that
  disagree with the real bytes, 4-byte-pad edge cases, header/payload truncation
  (icsFuzzer: `boundary`, 53 cases). This is where length-vs-offset confusion
  lives.
- **Identity-reply TLV length lies (`codesys_name_tlv`, 32 cases).** `node_len` /
  `dev_len` / `vend_len` and `parentAddrSize` set to `0 / 0xFF / 0x0100 / 0x7FFF /
  0xFFFF` while the real string/field bytes are *short* — a **declared-length ≠
  actual-length lie**, the shape behind OOB-read/CWE-125. Note: this is a *lie in
  the length field*, not a literal 64 KB datagram; also covered are embedded NUL /
  high-bit / format-string bytes and a reply truncated mid-TLV.
- **Binary corruption (`binary_corruption`, 177 cases).** Single-bit flips across
  the whole 20-byte seed, structural byte substitutions, empty / all-`0x00` /
  all-`0xFF`, and doubled frames.
- **Sequence / state (`sequence`, 6 cases).** Concatenated or repeated datagrams,
  request+reply mixes, a second `0xC5` magic mid-payload.

The service sweep is deliberately held to **48%** of the corpus (under a 50%
single-category guideline) so no one dimension drowns the others.

**Structured vs. coverage-guided.** The interesting bugs are *semantic* — offset
computation, declared-vs-actual length, dispatch of unknown enums — reachable from
a single well-formed-enough datagram, which is exactly what a structured generator
targets. A coverage-guided in-process fuzzer would be the stronger tool **if** you
can compile a CODESYS component with sanitizers, but the runtime is closed-source;
black-box structured generation against a real runtime (or the robustness
responder in §6) is the practical path. The `0x04` reply-TLV parser in particular
may live on the *client/gateway* side rather than the runtime's request handler —
see §9 before assuming your TLV cases reach the device.

## 5. Known vulnerabilities & bug classes

CODESYS V3's runtime has a long advisory history in exactly these layers — name
service, block driver (`CmpBlkDrvTcp` / `CmpBlkDrvUdp`), channel/name server, and
tag-handling parsers. Representative clusters:

- The **2022 CODESYS Control runtime cluster** (CERT@VDE / CODESYS Security
  Advisories) covering `CmpBlkDrvTcp`, `CmpChannelServer`, and `CmpNameServiceServer`
  memory-safety and improper-input-validation bugs — multiple CVEs, several
  remotely reachable pre-auth.
- Earlier single-packet runtime bugs in the `CmpWebServer` / block-driver family.

> **Verify exact CVE IDs and affected-version ranges at publish time.** The
> clusters above are recorded from internal research notes and should be confirmed
> against the CODESYS Security Advisory portal and CERT@VDE before you cite specific
> identifiers.

**Bug classes this surface rewards:**

| Class | CWE | Where |
|---|---|---|
| Length/offset confusion | CWE-125 / CWE-787 | `header_length`, `address_lengths` → payload pointer |
| Declared-length-vs-actual overrun | CWE-125 | `node_len` / `dev_len` / `vend_len` / `parentAddrSize` |
| Dispatch of unknown enum | CWE-20 | `service_id`, `package_type` |

**A posture finding, not just a parser finding.** On the modern tested runtime the
UDP name service is *silent by default* because CODESYS 3.5.17+ ships an
**enforced security policy** (`CmpSecurityManager`: `UserLogin_AuthenticationType =
ONLY_ASYMMETRIC`, `UnsignedApplicationFileTransfer = DENY`, "Enforce signed
communication"). That gates the legacy unauthenticated reply off — so *current
CODESYS is not discoverable/attackable via the old rapid7 UDP path out of the
box*. Relaxing the comm-security keys on a disposable demo runtime did **not**
restore the reply, which points to NS grammar drift from the ~2015-era frame as
well as the policy. That silence is itself worth reporting as a defensive
improvement, and it reframes where the live attack surface now is (TCP gateway /
OPC UA).

## 6. Building a test harness

There is no open-source CODESYS runtime to instrument, but — unusually for ICS —
there **is a free, official runtime to validate against**: *CODESYS Control for
Linux SL* (store.codesys.com, runs ~2 h in demo mode without a license). The
`.package` is a ZIP containing `codesyscontrol_linux_<ver>_amd64.deb`; extract and
run `codesyscontrol.bin` directly. It opens UDP 1740, TCP 11740 (gateway), and TCP
4840 (OPC UA). This closes the "no free stack" gap that plagues most ICS fuzzing.

For calibration without a device, use a **robustness responder** modeling a
*healthy* endpoint: it answers a valid NameServiceRequest and **silently drops
everything else**, writing a sidecar JSONL of each drop reason (bad magic / unknown
service / bad package / truncated header / truncated payload).

**Response classification — the finding-vs-noise line, UDP edition.** Because a
healthy name service drops malformed datagrams silently, *treating every timeout
as a crash would make this module over-report massively*. The fix is a **liveness
heuristic**:

- On a case timeout, send one canonical NameServiceRequest. Escalate to a crash
  indicator (`no_response`) **only if that known-good probe also fails** — i.e. the
  device actually stopped answering. Otherwise it is a benign `timeout`.
- Tune the receive timeout: every dropped case otherwise burns a full timeout, so
  a sweep against a silent-drop device is slow.

This is the same calibration lesson first learned on LwM2M, baked into the CODESYS
module from day one rather than discovered live.

**Calibration baseline** (icsFuzzer, software responder, 524 cases): **0 crash
indicators, 0 false positives** — 397 malformed drops → timeout →
liveness-confirmed-alive → benign; 127 valid replies classified clean. Against a
device that stays up, the module is silent, which is the property you want before
pointing it at real hardware.

**Live validation against the free runtime** (CODESYS Control 3.5.22): the runtime
**survived** the full corpus (524), a 5× soak (2620 datagrams), and a TCP-gateway
fuzz pass (533 frames) — process alive throughout, gateway reachable post-run,
clean log = a **robustness result**. Because the UDP NS is silent on this build, a
reply-based liveness oracle can't work, so the live harness falls back to a
**survival oracle**: send the corpus raw to UDP 1740 and use a TCP connect to the
gateway (11740) as the alive/crash signal, pinpointing the first case-block after
which the gateway never recovers. Honest scope: survival is confirmed; because the
NS is silent, each case reaching the *deep* name-TLV (`0x04`) parser is **not**
confirmed (the early header parser is exercised — the component must parse it to
decide to drop).

## 7. Identifying CODESYS over TCP (when UDP 1740 is silent)

Because modern runtimes answer nothing on UDP 1740, asset identification should
lean on TCP. All of these are passive-connect or unauthenticated reads
(identification, not exploitation):

- **TCP 11740 open, banner-less** — the embedded gateway (`CmpBlkDrvTcp`). A strong
  CODESYS-V3 indicator. (TCP **1217** is the classic Windows gateway port — absent
  on Linux SL but worth probing on older/Windows setups.)
- **TCP 4840 (OPC UA) — the richest unauth identity vector.** CODESYS Control
  embeds an OPC UA server; an unauthenticated **GetEndpoints** returns the
  `ApplicationUri` / `ProductUri` / application name (vendor + product, e.g.
  "CODESYS Control for Linux SL") and the endpoint URL **leaks the hostname**.
  GetEndpoints works even under the enforced security policy. The deeper
  `Server/ServerStatus/BuildInfo` read (ProductName / SoftwareVersion /
  BuildNumber) is a *session* read and is often gated by `ONLY_ASYMMETRIC`.
- **UDP 1740 bind fingerprint** (if observable from a span port): CODESYS binds the
  name service per-interface on **both the unicast and broadcast address** — a
  distinctive pattern even when it never replies.

To recover the full identity the silent UDP NS would otherwise give
(node/device/vendor/target_version), two routes, both scoped follow-ons: OPC UA
Server node reads (4840), or the gateway `CmpBlkDrvTcp` scan request (11740, needs
the frame RE'd).

## 8. Spec references & sources

- rapid7 Metasploit `codesys3.lua` / CODESYS discovery module — the byte oracle for
  the name-service frame used here.
- CODESYS Security Advisories (CODESYS GmbH portal) and CERT@VDE coordinated
  advisories — the authoritative CVE list for the runtime/block-driver layers.
- CODESYS Control for Linux SL (store.codesys.com) — the free demo runtime used for
  live validation; component list (`CmpBlkDrvUdp`, `CmpBlkDrvTcp`,
  `CmpNameServiceServer`, `CmpSecurityManager`) is logged at startup.
- Wireshark CODESYS dissector / community captures for frame study.

## 9. Open questions / under-explored surface

- **Current discovery grammar.** The stock 3.5.22 runtime did not answer the
  rapid7-era NameServiceRequest even with security relaxed. Is the modern NS frame
  simply drifted (different magic/field layout), or has discovery moved entirely to
  the gateway's own scan path? A captured CODESYS IDE "scan network" exchange would
  resolve it and re-seed the fuzzer against a *replying* device.
- **`CmpBlkDrvTcp` gateway grammar (TCP 11740).** Reverse-engineering the framed
  gateway protocol is the path to (a) reading identity over TCP and (b) reaching
  the `codesys_name_tlv` fuzz category against a real modern device.
- **Where the `0x04` reply-TLV parser actually runs.** Confirm whether the runtime's
  request handler shares the reply-parse code path, or whether only the IDE/gateway
  *client* parses identification replies — this determines whether the TLV
  length-lie cases hit the device at all.
- **The enforced-policy default as a research axis.** How far back does the silence
  go (3.5.17? 3.5.19?), and which OEM runtimes ship the policy *disabled* for
  backward compatibility — i.e. where the legacy UDP surface is still live.

*Worked example: `protocols/codesys_v3/fuzzer.py` in the icsFuzzer project
implements all five categories above, with `scripts/codesys_v3_responder.py` as the
robustness testbed and `scripts/validate_codesys_live.py --liveness-tcp` as the
survival oracle for a silent device.*
