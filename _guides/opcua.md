---
title: "A Researcher's Guide to OPC-UA (Binary / UA-TCP)"
protocols: ["OPC-UA"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["iiot"]
transport: ["ua-tcp"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code. Covers the binary
UA-TCP transport (opc.tcp://, port 4840).*

---

## 1. What it is & where it runs

OPC-UA (IEC 62541) is the successor to OPC Classic and the de-facto integration
protocol of modern OT — on nearly every DCS, SCADA historian, PLC gateway, and
data concentrator. The **binary UA-TCP transport (port 4840)** is what embedded
stacks and most SCADA servers actually speak (the XML/JSON-over-HTTPS binding on
4843 is comparatively rare).

For a researcher OPC-UA is the deepest binary target in the ICS set: a layered
model (**UA-TCP → SecureChannel → Session → Services**), an all-little-endian
encoding with variable-length Strings/ByteStrings carrying **signed Int32 length
fields**, a **NodeId** type with six encoding variants, and multi-chunk message
reassembly. Crucially, **SecurityMode=None reaches all of the service logic with
zero crypto** — and the richest bugs historically sit *pre-session*, in the
HEL/OPN framing before any auth exists.

## 2. Session & transport model

```
TCP connect → HEL → ACK → OPN(OpenSecureChannel, SecurityMode=None) → OPN resp
  → MSG CreateSession → MSG ActivateSession(anonymous) → MSG Read/Browse/Write/… → CLO
```

A fuzzer must track, across messages: `SecureChannelId` + `TokenId` (from OPN
resp), a monotonic `SequenceNumber`, a per-request `RequestId`, and the
`AuthenticationToken` (from CreateSession). Every one of these is a fuzz knob (see
§4). SecurityMode=None (value 1) + the None policy URI avoids all certificate /
signing / encryption work.

## 3. Wire format

**8-byte transport header:** 3-char MessageType (`HEL`/`ACK`/`ERR`/`OPN`/`CLO`/
`MSG`) + 1-char ChunkType (`F` final / `C` chunk / `A` abort) + **MessageSize
uint32 LE (includes the header)**.

**HEL/ACK** negotiate buffer sizes. **OPN** carries an *asymmetric* security header
(SecurityPolicyUri string, SenderCertificate/Thumbprint ByteStrings — null under
None) + a sequence header + the OpenSecureChannelRequest body. **MSG** carries a
*symmetric* security header (SecureChannelId + TokenId) + sequence header +
`TypeId NodeId` + RequestHeader + service params.

**Encoding primitives (all LE):** fixed-width ints/floats; **String / ByteString =
`Int32 length (−1 = null)` + bytes** (the signed length is a prime fuzz target);
DateTime = Int64 100-ns ticks since 1601. **NodeId** encoding byte selects:
0x00 TwoByte, 0x01 FourByte, 0x02 Numeric, 0x03 String, 0x04 Guid, 0x05 ByteString
— service NodeIds are FourByte `01 00 lo hi`.

Services are addressed by NodeId: Read i=631, Write i=673, Browse i=527,
CreateSession i=461, ActivateSession i=467, CreateSubscription i=787,
OpenSecureChannel i=446, etc.

## 4. The fuzz surface

- **Pre-session framing (HEL/OPN)** — the historically richest surface, reachable
  with no auth. Malformed HEL (buffer-size fields, EndpointUrl length); malformed
  OPN asymmetric header (SecurityPolicyUri length, cert/thumbprint ByteString
  lengths). Multiple real CVEs were triggered here before any session existed.
- **Signed Int32 string/bytestring lengths** — −2 … INT_MIN, and huge positive
  lengths that exceed the datagram. The single most productive OPC-UA primitive.
- **NodeId variant abuse** — invalid encoding bytes (0x06–0xFF), ExpandedNodeId
  flag bits (0x40/0x80) on a TwoByte form, Numeric with ns=0xFFFF / id=UINT32_MAX,
  String NodeId with 64 KB or null identifier, arrays of 0 / 1 / 1000 NodeIds in
  one Browse.
- **Chunk reassembly** (`C`/`F`/`A`) — many `C` chunks with no `F` (reassembly
  buffer exhaustion), `A` with a mismatched SequenceNumber, SequenceNumber gaps,
  two interleaved `C` series on alternating RequestIds, a `MessageSize` smaller or
  larger (UINT32_MAX) than the bytes written.
- **Service NodeId sweep** — TypeId i=400..1000 incl. undefined IDs, null NodeId as
  TypeId, String/Guid NodeId forms as TypeId.
- **Sequence/Request IDs** — SequenceNumber 0 / UINT32_MAX / backward / duplicate;
  RequestId 0 / duplicate for concurrent in-flight; RequestHandle mismatch.
- **Session state machine** — MSG before HEL, before OPN, before ActivateSession;
  replay an old TokenId after renew; OPN RequestType=RENEW with no prior ISSUE; CLO
  then keep sending; two simultaneous OPNs; HEL twice.
- **Resource exhaustion** — CreateSubscription until BadTooManySubscriptions then
  one more; PublishingInterval = 0.0 / negative; LifetimeCount = 0 / UINT32_MAX;
  10 000 MonitoredItems on root; 1000 back-to-back Publishes.
- **Dangerous (gate behind a flag)** — Write Value attribute (modifies PLC I/O),
  Call methods, Add/DeleteNodes (mutates address space), HistoryUpdate.

**Classification line:** an `ERR` message or a non-zero `ServiceResult` in the
ResponseHeader is an **exception, not a crash**. A MessageSize < 8 or > 16 MB, an
unknown MessageType, or an unexpected response TypeId is malformed (crash). Confirm
a crash by reconnecting with a fresh HEL.

**Structured vs. coverage-guided:** OPC-UA strongly rewards *both*. The service and
session semantics are a structured-generator target; the binary decoder (string
lengths, NodeId variants, chunk reassembly) is an ideal **coverage-guided/ASan**
target against open62541 or UA-.NETStandard — which is exactly where the CVE record
below concentrates.

## 5. Known vulnerabilities & bug classes

A dense, well-documented CVE landscape — the pattern *is* the lesson:

| Stack | CVE | CWE | Shape |
|---|---|---|---|
| Unified Automation C++ | CVE-2019-13549 / 13550 | 835 / 125 | infinite loop & OOB read via malformed MSG/NodeId — **pre-session** (Claroty, ICSA-19-274-03) |
| UA-.NETStandard | CVE-2018-7559 / 2023-27321 | 119 / 121 | buffer overflow in TCP message processing |
| UA-.NETStandard | CVE-2021-27432 | 400 | uncontrolled resource consumption DoS |
| Prosys SDK | CVE-2022-25761 / 29862 / 29864 | 119 / 835 / 400 | heap overflow in binary decode; infinite loop in **chunk reassembly**; SecureChannel resource exhaustion (Claroty "OPC UA Deep Dive") |
| KEPServerEX | CVE-2022-43520 / 2023-29444 | 476 / 20 | NULL deref / input-validation crash |
| open62541 | CVE-2023-28150 / 2022-25634 | 125 / 476 | OOB read in **string decoding**; NULL deref via crafted DataValue |
| asyncua | CVE-2024-27354 | 400 | DoS via malformed Browse/Read |

Pattern summary (the fuzzer's targeting map): (1) malformed pre-session HEL/OPN
framing; (2) oversized/negative Int32 string/ByteString lengths; (3) chunk
reassembly; (4) NodeId variant abuse; (5) subscription/publish flood; (6) infinite
reference graphs in Browse; (7) RequestedLifetime = 0 / UINT32_MAX in OPN.

## 6. Building a test harness

Robustness responder (`scripts/opcua_responder.py`, port 4841): HEL/ACK, OPN,
CreateSession, ActivateSession; Read→Good DataValue, Browse→empty result,
Write→BadNotWritable, CreateSubscription→sub_id; unknown service →
BadServiceUnsupported; sidecar JSONL.

Harness lesson (a real one from this module): the generator must build each case
**from live session state** (current SecureChannelId/TokenId/auth_token) and patch
a fresh **SequenceNumber** per request — a module tested only against its own
responder passed, but against a *real* asyncua server 99% of cases timed out until
(1) per-request SequenceNumber patching and (2) a spec-correct QualifiedName
DataEncoding (≥6 bytes, not a 2-byte null NodeId) were fixed. Validate against a
real stack, not just the mock.

**Calibration baseline (software responder, 581 cases): clean** — 32 crash
indicators (17 timeout from binary_corruption truncations + chunk abuse, 7
connection_reset from ERR/CLO, 8 malformed = expected wrong-type/size), 428
BadServiceUnsupported exceptions from the service sweep, 121 clean; **0
false-positive malformed_response**.

## 7. Open-source implementations & tooling

- **open62541** (C) — amalgamation build, embedded in many PLCs; the prime
  coverage-guided/ASan target (two CVEs above).
- **UA-.NETStandard** (OPC Foundation reference), **asyncua** (Python; best for
  building/patching seeds), **node-opcua** (JS).
- Wireshark `opcua` dissector (fully decodes SecurityMode=None); UaExpert for
  manual exploration.

## 8. Spec references & sources

- IEC 62541 Part 4 (Services), Part 6 (binary mappings), Part 8 (Data Access) —
  free from opcfoundation.org.
- Claroty/Vedere Labs "OPC UA Deep Dive" (2022); CISA ICSA-19-274-03,
  ICSA-18-212-03.

## 9. Open questions / under-explored surface

- A sustained coverage-guided ASan campaign on open62541's decoder (string length /
  NodeId variant / chunk reassembly) — the CVE pattern says more bugs remain.
- Differential testing across open62541 / UA-.NETStandard / asyncua on one
  pre-session HEL/OPN corpus.
- The HTTPS/JSON binding (4843) — a different, under-fuzzed surface.
- SecurityMode=Sign/SignAndEncrypt message-layer logic (reachable only with a
  certificate flow the fuzzer doesn't emulate today).

*Worked example: `protocols/opcua/fuzzer.py` (8 categories, 581 cases),
live-validated and bug-fixed against a real asyncua server; responder
`scripts/opcua_responder.py`. (Prior published prose: `blog-addendum-opcua-anon-write.md`.)*