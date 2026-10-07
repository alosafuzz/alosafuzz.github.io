---
title: "A Researcher's Guide to LwM2M & CoAP"
protocols: ["LwM2M", "CoAP"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["iiot"]
transport: ["coap"]
project: icsfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

LwM2M (OMA SpecWorks Lightweight M2M) is the device-management protocol for
**constrained IIoT devices** — smart metering, utility/telemetry gateways, remote
RTU-class sensors, asset tracking. A client (the managed device) registers with a
server and exposes a tree of **Objects/Instances/Resources** by URI path (`/3/0/0`
= Device object, instance 0, Manufacturer). It is a *scope-expansion* for an ICS
fuzzer — adjacent to OPC-UA/BACnet's IIoT lean, not a classic floor protocol.

**The single most important finding for a researcher:** LwM2M adds almost **no new
wire format of its own** — LwM2M messages *are* CoAP messages (RFC 7252). A "LwM2M
fuzzer" is ~90% a **CoAP parser fuzzer** plus a thin semantic layer (which URI
paths/content-formats/interfaces mean what). So the byte-level attack surface is
shared with *every* CoAP product, and the verified CVE record (§5) lands exactly
where that implies: CoAP option parsing, block-wise reassembly, and DTLS.

- **Transports:** plain **CoAP/UDP 5683** (`coap://`), **DTLS/UDP 5684**
  (`coaps://`), and **CoAP-over-TCP/TLS (RFC 8323)**. Versions 1.0/1.1/1.2.

## 2. Session & transport model

Three transports, three framings, one CoAP semantic core:
- **Plain CoAP/UDP 5683** — no handshake; `sendto` a datagram, `recvfrom` the
  reply. The sweet spot: zero crypto, all service logic reachable.
- **DTLS/UDP 5684** — a full **DTLS-PSK (or RPK/cert) handshake** must complete
  before one CoAP byte is accepted. Many production devices mandate it, so a
  plain-5683 fuzzer may not reach them — but the handshake is a real harness lift
  and its own bug surface.
- **CoAP-over-TCP/TLS (RFC 8323)** — the UDP 4-byte header is replaced by a
  **length-prefixed** framing (Len/TKL byte + extended length + Code + Token +
  options + payload), **no Message ID, no Type**; a CSM exchange opens the session.

LwM2M interfaces on top: Bootstrap, **Registration** (`POST /rd?ep=<name>&lt=<lt>`
with a CoRE-link body), Device Management (Read/Write/Execute/Create/Delete on
object URIs), and Information Reporting (Observe/Notify).

## 3. Wire format — CoAP (the real target)

**4-byte CoAP/UDP header:** `Ver(2) | T(2) | TKL(4) | Code(8) | Message-ID(16)` +
Token (TKL bytes) + options + `0xFF` payload marker + payload.
- **Ver** must be 1; **T** = CON/NON/ACK/RST; **TKL** 0–8 (**9–15 reserved — must
  be rejected**; a parser that over-reads the token is the bug); **Code** =
  class.detail (0.01 GET … 0.04 DELETE, + FETCH/PATCH).

**Options — the dominant bug surface.** Each option byte = `delta(4) | length(4)`
with **escape nibbles**: 13 → +8-bit extension byte (+13), 14 → +16-bit extension
(+269), **15 → reserved** (legal only as the whole `0xFF` payload marker; a 15 in
either nibble otherwise is a format error the parser must reject). This
delta/length nibble encoding with extension bytes is historically the richest CoAP
parser-bug source.

**Sub-surfaces with their own cases:** **Block-wise transfer (RFC 7959)** —
Block1/Block2 options (`NUM/M/SZX`), reassembly of out-of-order/overlapping/
oversized-total blocks (a known memory-safety sink, and the path for LwM2M's
Firmware Update object 5); **Content-Format/Accept** steering the body;
**Observe** state machine.

**LwM2M payload parsers (the thin semantic part, each its own sub-surface):**
**LwM2M-TLV** (content-format 11542, custom type-length-value — length fields are a
separate integer surface), **SenML-CBOR** (1.1+, CBOR: indefinite-length items,
deep nesting, huge declared lengths), SenML-JSON, plain/opaque, and CoRE Link
(the registration body).

## 4. The fuzz surface

- **CoAP header** — Ver≠1, **TKL 9–15** (token over-read), reserved Code classes.
- **Option delta/length encoding** — 13/14 extension bytes truncated or oversized,
  running option-number accumulation overflow, repeated critical options, unknown
  **critical (odd) option numbers**, a `15` nibble outside the payload marker,
  Uri-Path/Uri-Query segment explosions.
- **Block-wise reassembly** — overlapping/out-of-order blocks, oversized total,
  incrementing Block1 PUTs that drive unbounded allocation (a real, recent CVE —
  see §5), reachable over **plain CoAP, no DTLS**.
- **Content-format body parsers** — LwM2M-TLV length lies; SenML-**CBOR**
  indefinite-length/deeply-nested/huge-length items.
- **LwM2M semantics** — Execute on a read-only resource, Write wrong value type,
  **firmware-update object (5)** Package-URI abuse (the Zephyr CVE), double-register,
  notify-before-observe, bootstrap-sequence abuse.
- **State / sequence** — Message-ID/Token reuse and correlation confusion, duplicate
  CON flooding.
- **DTLS (phase-2 surface)** — handshake-state and resumption bugs (the Californium
  cluster), PSK identity/key handling.

**Classification line:** a CoAP error response code (4.xx/5.xx) is a
spec-compliant exception, not a crash. **But over UDP, "timeout" is NOT by itself a
crash** — see the liveness heuristic in §6; this is the single most important
calibration lesson of the module.

**Structured vs. coverage-guided:** both, strongly. The CoAP option/block/CBOR
decoders are ideal **coverage-guided/ASan** targets against Wakaama / libcoap /
Zephyr (all open C). The LwM2M *semantic* layer (firmware-object Write, interface
state machine) and the stateful DTLS/registration flows are the **structured
black-box** niche — and that niche is exactly where the recent 2024–26 semantic/
block-wise CVEs landed *despite* OSS-Fuzz coverage of the parsers.

## 5. Known vulnerabilities & bug classes (verified)

Every confirmed bug sits in a surface §3/§4 names in advance — strong validation:

- **Zephyr LwM2M client — CVE-2026-10672** (GHSA-rf6j-4mpp-j9mf, **CVSS 8.2**,
  **CWE-125 OOB read**): a server-supplied firmware-pull **Package URI** is
  `memcpy`'d into a fixed 128-byte buffer with no length check / no NUL; a 128–254-
  byte URI leaves it unterminated and later C-string reads walk off the end.
  Reachable via a **Write to firmware object (5)** — the LwM2M *semantic* niche.
  Present v3.0.0–v4.4.0, fixed v4.5.0.
- **Eclipse Wakaama — CVE-2026-58465** (**CVSS 8.7**): **Block1 handler** — a
  sequence of incrementing-block PUTs drives **unbounded allocation** → DoS,
  **unauthenticated, plain CoAP**. Confirms the block-wise category. Also
  CVE-2019-9004 (invalid-option memory leak → OOM — confirms the option surface)
  and CVE-2021-41040 (generic CoAP-parse sanitization, CVSS 7.5).
- **libcoap — CVE-2024-46304** (`coap_handle_request_put_block`, block-wise DoS —
  a *second*, independent block-wise confirmation) and CVE-2025-34468 (stack
  overflow in proxy address resolution, CVSS 9.8, proxy-path-gated).
- **Eclipse Californium (Leshan's substrate) — DTLS cluster** CVE-2022-39368 /
  2022-2576 / 2021-34433 / 2020-27222: handshake cleanup, resumption amplification,
  signature-verification bypass, state corruption — validates DTLS as its own rich
  (phase-2) surface.

## 6. Building a test harness

A framing-only software responder exists (`scripts/lwm2m_responder.py`, UDP), but
LwM2M is lucky: **mature open-source stacks are the real oracle** — Eclipse Leshan
(demo server), **Eclipse Wakaama** and AVSystem Anjay (example server/client),
Zephyr's client. The module was **live-validated against a real Wakaama stack**
(built from source): plain-CoAP 80-case corpus, server survived all 80, 36 real
interop responses, and the 5.00-Internal-Server-Error responses concentrated in the
**block-wise** cases — the fuzzer puts signal on the historically right surface.

Two harness lessons that generalize:
- **UDP timeout ≠ crash — add a liveness re-probe.** The first calibration
  over-reported (44 "crash indicators," 0 real crashes) because every UDP timeout
  was treated as a crash. The fix: on a timeout/no-response, fire a
  **liveness probe** (empty-CON CoAP ping → expect RST on UDP/DTLS; `GET
  /.well-known/core` on TCP) and only flag a crash if the probe *also* fails. This
  dropped 44→0 false positives with **zero loss of real signal** (same anomaly
  profile, server confirmed alive) — the highest-value outcome of the live work.
- **`--source-port`** — a real LwM2M *client* drops packets from an unknown source,
  so device-management cases can't reach it unless the fuzzer binds the expected
  local port; binding it let real 4.00/4.01 client responses come back.

DTLS-PSK transport is wrapped via a persistent `openssl s_client -dtls1_2 -psk`
session (CPython has no DTLS; libcoap's coap-client is one-shot and unusable for a
fuzzing session) — socket-duck-typed so the send path is unchanged.

## 7. Open-source implementations & tooling

- **Eclipse Wakaama** (C client/server) — live-validated here; the CoAP/block-wise
  reference and a coverage-guided/ASan target.
- **libcoap** (C) — substrate for many embedded stacks; block/proxy CVEs above.
- **Zephyr LwM2M** (C) — the on-device, plant-relevant client (CVE-2026-10672).
- **Eclipse Leshan** (Java, on Californium) — public demo server; JVM → DoS/
  resource/parser-exception class, inherits the DTLS cluster.
- **AVSystem Anjay** (C) — vendor-fuzzed; no public SDK CVE located.
- Wireshark `coap` dissector; `aiocoap` (Python) for building valid seeds.

## 8. Spec references & sources

- RFC 7252 (CoAP), RFC 7959 (block-wise), RFC 7641 (Observe), RFC 8323
  (CoAP-over-TCP/TLS), RFC 8132 (FETCH/PATCH).
- OMA SpecWorks LwM2M 1.0/1.1/1.2 (TS-Core, registry); SenML (RFC 8428) + SenML-CBOR.

## 9. Open questions / under-explored surface

- A coverage-guided ASan campaign on Wakaama/libcoap option + block + SenML-CBOR
  decoders — complements the structured black-box work and targets the exact
  CVE surfaces.
- DTLS validated only vs. an `openssl` echo peer, **not** vs. a real DTLS *LwM2M*
  stack (Leshan has no plain DTLS demo; the Moxa DLM Bootstrap 5684 target was
  unrunnable) — a real DTLS-LwM2M oracle is the gap.
- The full LwM2M-TLV and SenML-CBOR body parsers on real stacks (beyond framing).
- Emulating enough server-side registration/auth that a real client authorizes 2.05
  reads — would deepen client-side device-management fuzzing.

*Worked example: `protocols/lwm2m/fuzzer.py` (8 categories × 80 cases × 3
transports), with the liveness-confirmation heuristic and `--source-port`;
live-validated vs. Eclipse Wakaama. Responder `scripts/lwm2m_responder.py`
(framing-only).*