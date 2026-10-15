---
title: "A Researcher's Guide to SCPI & LXI Test Instruments"
protocols: ["SCPI", "VXI-11", "HiSLIP", "GPIB"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["iiot", "cross"]
transport: ["raw-socket", "vxi-11", "hislip"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

SCPI (Standard Commands for Programmable Instruments, SCPI-99, layered on
IEEE-488.2) is the **text command language** spoken by bench and rack test &
measurement gear — oscilloscopes, DMMs, spectrum/logic analyzers, power supplies,
signal generators, source-measure units. It shows up in RF/EW labs, power and
calibration labs, semiconductor test, and increasingly on **automated production
lines** wired into the plant network — a *scope-expansion* for an ICS fuzzer, the
test-instrument/IIoT neighbor of OPC-UA's IT-ward lean, not a classic floor bus.

**The single most important finding for a researcher:** "GPIB" is largely a red
herring for a *network* fuzzer. Raw GPIB/IEEE-488 is a parallel **hardware bus**
(needs a controller card) — not reachable over IP. Modern instruments carry SCPI
over **LAN** (the LXI standard), and *that* is the attack surface. And across all
three LAN transports, the bytes converge on **one place: the instrument's SCPI
command parser.** A "SCPI fuzzer" is overwhelmingly a **command-parser fuzzer**
plus thin transport framing — exactly where the public CVE record lands (§5).

- **Transports:** raw-socket SCPI **TCP 5025** (+ a control variant 5024);
  **VXI-11** (ONC-RPC over TCP + portmapper **111**); **HiSLIP** **TCP 4880**.
- **No authentication or encryption** in the base protocols — by design. HiSLIP
  2.0 is the first to add TLS/auth, and almost nothing ships it.

## 2. Session & transport model

Three transports, three framings, one SCPI semantic core:

- **Raw-socket SCPI (TCP 5025)** — no framing, no handshake, no auth. Open a
  socket, send newline-terminated command lines, read replies. The sweet spot: all
  command-parser logic reachable with zero protocol overhead. (TCP 5024 is a
  "control"/telnet-style variant on many instruments.)
- **VXI-11 (TCP + portmapper 111)** — ONC-RPC. The client hits the **portmapper**
  to find the Device Core channel, then `create_link` → `device_write` (carries the
  SCPI string) → `device_read` (reply) → `destroy_link`, with an async/abort channel
  and an interrupt channel. **VXI-11.2** is the GPIB-gateway control path (the
  standards-based "GPIB over LAN"). Framing surface = ONC-RPC record marking +
  opcode/argument decode; payload surface = the same SCPI string.
- **HiSLIP (TCP 4880)** — **two TCP sockets** (synchronous data + asynchronous
  control), message-header framed (prologue `HS` + message-type + control-code +
  parameter + 64-bit payload length). Carries SCPI in Data messages. v2.0 adds
  TLS + client/server auth.
- **GPIB-over-LAN gateways** (Prologix GPIB-ETHERNET, HP/Agilent E2050/E5810, ICS
  Electronics 9065/9099) add small proprietary layers: Prologix = plain ASCII over
  **TCP 1234** with `++`-prefixed control commands (otherwise the line is forwarded
  to the GPIB instrument), plus a **NetFinder discovery service on UDP 3040**. These
  gateways are the real "GPIB over LAN" boxes — and several ship a **control web page
  with no authentication** that relays an arbitrary command string straight to the
  attached GPIB instrument or Modbus RTU device (§5). Closed firmware.

## 3. Wire format — SCPI (the real target)

SCPI is line-oriented ASCII, newline-terminated, but the parser is richer than it
looks — and the parameter grammar is where the length/overrun bugs live.

- **Command tree & pattern matching** — keywords in short/long form
  (`MEAS`/`MEASure`), **optional `[]` keywords**, `:` hierarchy and `;` compounding
  of multiple commands per line, `*`-prefixed **IEEE-488.2 common commands**
  (`*IDN?`, `*RST`, `*CLS`, `*ESR?`), and **numeric suffixes** on keywords
  (`OUTPut2:VOLTage`). Query (`?`) vs. set forms.
- **Parameter types** (each its own parser, each a sub-surface):
  - **Arbitrary block data** — `#<ndigits><length><bytes>`: one digit giving the
    number of length digits, then the length, then the payload (e.g. `#12AB` = 1
    length-digit, length 2, bytes `AB`), **plus the indefinite form `#0…`**. This is
    the textbook **length-lie**: the declared length vs. the bytes actually present.
  - **Numeric list** `(1,2:50,80)` and **channel list** `(@1!2:3!4,5!6)` — range,
    dimension, and nesting parsing; huge counts; malformed ranges. In `libscpi` these
    live in a separate **expression** module (`SCPI_Expr*`), distinct from the scalar
    parameter readers — its own entry surface.
  - **Numbers with units/suffix** (`1.5 KOHM`, `MAX`/`MIN`/`DEF`/`INF`), **radix**
    forms `#H` hex / `#Q` octal / `#B` binary, quoted strings (`"…"`/`'…'`),
    program expressions `(…)`, and character data (`MINimum`, `DEFault`).

**VXI-11 framing sub-surface:** ONC-RPC fragment/record marking (the continuation
bit + 31-bit length), `create_link`/`device_write`/`device_read` argument structs
(link IDs, flags, lengths), and portmapper `GETPORT`. **HiSLIP framing sub-surface:**
the fixed 16-byte message header, especially the **64-bit payload length** field vs.
bytes delivered, message-type/control-code enums, and the two-socket
sync/async correlation.

## 4. The fuzz surface

- **SCPI command parser (primary, transport-agnostic):**
  - **Arbitrary block `#` parser** — length-digit count out of range, declared
    length ≫ / ≪ bytes present, indefinite `#0` never terminated, length overflow.
  - **Numeric/channel lists** — unbounded counts, inverted/huge ranges, deep
    nesting, missing close paren, `@` channel syntax edge cases.
  - **Pattern matcher** — pathological `:`/`;` compounding depth, overlong keywords,
    numeric-suffix overflow, optional-keyword ambiguity, unterminated strings,
    mismatched quotes, radix digits out of range.
  - **Input buffering** — the byte-intake path before a terminator (partial lines,
    missing terminator, oversized line vs. the instrument's input buffer).
- **VXI-11 RPC framing** — record-mark length lies, truncated/oversized
  `device_write` data-length vs. payload, bogus link IDs, portmapper abuse.
- **HiSLIP framing** — 64-bit payload-length vs. delivered bytes, message-type/
  control-code enum fuzzing, async-channel state confusion, oversized headers.
- **Gateway layers** — Prologix `++` control-command parser and the NetFinder UDP
  3040 discovery responder (structured-generator, closed firmware).

**Classification line:** a SCPI **error pushed onto the Standard Event
Status / error queue** (e.g. `-113 "Undefined header"`, `-108 "Parameter not
allowed"`), or a VXI-11/HiSLIP protocol error reply, is a **spec-compliant
exception, not a crash**. A dropped/hung connection is only a crash if a **liveness
re-probe also fails** (§6).

**Structured vs. coverage-guided:** both. The one broadly-reused open-source
parser, **`j123b567/scpi-parser` (`libscpi`)**, is an ideal **coverage-guided/ASan**
target — in-process, deterministic, no hardware, and *transport-agnostic* (the
parsed string is identical whether it arrived via raw-5025, VXI-11, or HiSLIP). The
**raw-socket (5025) wire rig** and the **VXI-11/HiSLIP framing** are the
**structured black-box** niche against real (closed) instrument firmware, which is
exactly where the Siglent product CVEs landed.

## 5. Known vulnerabilities & bug classes (verified)

Every confirmed bug sits in a surface §3/§4 names in advance:

- **Siglent SDS1104X-E cluster (2023, Bret McDanel)** — SCPI on TCP 5024/5025, **no
  auth**:
  - **CVE-2023-25367** — **unfiltered SCPI input → RCE, CVSS 9.8.** The canonical
    "command parser trusts the wire" outcome.
  - **CVE-2023-25369** — **DoS via a malformed SCPI command** — precisely the
    parser-crash class a fuzzer finds.
  - CVE-2023-25366 — an undocumented `WEB:PSW?` / `WEB:PSW <new>` command on 5025
    discloses/changes the web-UI password (also reachable unauth through the web
    `/device_read_write.php` SCPI bridge) — CWE-284 improper access control.
  - CVE-2023-25368 — unauthenticated firmware overwrite.
- **Trend Micro, 2020 — "Security Analysis of Devices That Support SCPI and VISA
  Protocols."** Keysight/Agilent and other instruments found internet-exposed via
  Shodan, unauthenticated by design; the paper's conclusion is that the exposure is
  a *protocol-design* property ("a fix is not available") — firewalling is the only
  control. Establishes the surface is live and widely reachable.
- **GPIB-over-LAN gateway, no auth (ICS Electronics 9065/9099).** The 9065
  (Ethernet-to-GPIB) and 9099 (Ethernet-to-Modbus RTU) serve a `control.html` whose
  `cmd` field **relays an arbitrary command to the attached GPIB instrument / Modbus
  field device with no authentication challenge at all** — confirmed from the
  vendor's own shipped firmware HTML, which contains zero password/login mechanism
  anywhere in the whole 90xx product line. A gateway turns one exposed, auth-free
  web endpoint into command access to whatever bench or field device hangs off it.
- **LXI default web password, firmware-verified (Keysight Truevolt / keysight-lxid).**
  The modern Keysight LXI web UI ships **password-enabled-by-default with a known
  factory password `"Keysight"`** (carved from a Truevolt DMM image and confirmed by
  cracking the shipped default hash against the firmware's own salt+SHA256 scheme);
  the `keysight-lxid` PHP framework is shared family-wide (DMMs, DAQ970A, …). A
  vendor-documented default, not a backdoor — but it means the "authenticated" web
  path is often a one-guess wall, and the SCPI ports behind it stay unauthenticated.
- **Gap:** **no coverage-guided fuzzing campaign against `scpi-parser` exists** — no
  OSS-Fuzz entry, no CVE, no sanitizer CI in the repo. The parser that sits behind
  the product CVEs above has never been systematically fuzzed in the open. (For
  context, the *kernel* GPIB staging driver is separately under-hardened —
  CVE-2026-31769 UAF, CVE-2025-22052, CVE-2025-38613 — but those are local-ioctl,
  not network-reachable, so out of this model.)

## 6. Building a test harness

Two complementary rigs, mirroring the suite's coverage-guided + wire-reachability pattern:

- **Coverage-guided, in-process (primary):** link `libscpi` and drive its parse
  entry point under **libFuzzer + ASan/UBSan**. Entry points, verified against
  `libscpi/inc/scpi/parser.h`:
  - `scpi_bool_t SCPI_Input(scpi_t *context, const char *data, int len)` — byte
    intake + terminator buffering (the natural `LLVMFuzzerTestOneInput` sink: feed
    the raw fuzz bytes here).
  - `scpi_bool_t SCPI_Parse(scpi_t *context, char *data, int len)` — one command
    line. Note the **non-const `char *`**: the parser tokenises/rewrites the buffer
    in place, so the harness must pass a **writable copy** of each input, not the
    libFuzzer-owned const buffer.
  - Sub-surface readers: `SCPI_ParamArbitraryBlock` (the `#` length-lie),
    `SCPI_ParamArrayInt32/UInt32/Int64/UInt64/Float/Double` (numeric arrays), and
    the `SCPI_Expr*` expression module (numeric/channel lists).

  Register a minimal `scpi_command_t` table + a stubbed `scpi_interface_t`
  (write/flush/error/reset no-ops) so the harness is pure buffer-in; re-init the
  `scpi_t` context (`SCPI_Init`) or clear its error queue between iterations.
  BSD-2-Clause, builds with make; expect minor clang `-include`/feature-macro
  workarounds (it targets embedded C89; `strncasecmp` and friends), like hipserver needed.
- **Over-the-wire (reachability / structured):** a raw-socket **TCP 5025** sender is
  trivial (seed `*IDN?`, `*RST`, a block-data write) and confirms whether a parser
  crash is reachable against a real or emulated instrument. VXI-11 and HiSLIP
  framing wrap the same SCPI payload — add them when targeting those transports.

**Harness lessons that generalize (from the suite):**
- **Timeout ≠ crash — add a liveness re-probe.** A robust instrument that drops or
  resets a malformed line will trip a naive "timeout = crash" oracle on every case
  (this over-reporting bit both the LwM2M and OPC-UA modules). On a
  timeout/reset/no-response, fire a **stateless** liveness probe (reconnect + a
  known-good `*IDN?` on a throwaway socket) and flag a crash only if *that* also
  fails. Keep the probe **stateless** — a VXI-11 `create_link` per probe can exhaust
  the instrument's link table and manufacture false positives (the OPC-UA
  session-exhaustion lesson).
- **Spec-compliant error ≠ crash** — drain and classify the SCPI error queue
  (`SYSTem:ERRor?`) / the VXI-11/HiSLIP error replies as benign exceptions.

## 7. Open-source implementations & tooling

- **`j123b567/scpi-parser` (`libscpi`)** — C, BSD-2-Clause, ~598★, active, 93%+ unit
  coverage, no prior fuzzing. **The recommended coverage-guided target** and the
  de-facto grammar reference. (Forks in real products: OWON, PumpkinSpace, others.)
- **`liblxi` / `lxi-tools`** (lxi-tools org, C) — client/CLI for discovery + VXI-11 +
  raw socket + HiSLIP; fuzz angle is the **client-side response/discovery** parsing,
  not the instrument parser. No CVEs found.
- **`lxi-tools/libhislip`** (C, client+server) — **PRE-ALPHA / "not functional,"**
  HiSLIP 1.0 only; a server to mature into or hand-build from the IVI spec.
- **VXI-11 clients** — `python-vxi11` (pure Python), `PyVXI11` (Cython, rpcgen on
  `VXI11.rpcl`), `Lab::VXI11` (Perl). **No mature OSS C *server*** located (ONC-RPC;
  glibc sunrpc deprecated ≥2.26 → needs libtirpc) — the VXI-11-framing fuzz target
  needs one built/ported first.
- **Wireshark** has full **VXI-11** and **HiSLIP** (TCP 4880) dissectors — framing
  ground truth. `python-ivi` and `pyvisa` drive live rigs for seed capture.
- **icsScanner's own VXI-11 probe** (`core/fingerprint.py:probe_lxi_vxi11_identity`)
  is a ready, dependency-free discovery + seed source: a single ONC-RPC portmapper
  (TCP 111) `PMAPPROC_GETPORT` for the VXI-11 Device Core program (**program
  `395183` / `0x0607af`, vers 1, IPPROTO_TCP**), constants verified against
  python-vxi11 — reusable verbatim as the VXI-11 wire rig's portmapper/`create_link`
  bootstrap (the scanner↔fuzzer handoff pattern used for the SLMP/XGT/CODESYS modules).

## 8. Spec references & sources

- **SCPI-99** + **IEEE-488.2-2004** (command grammar; `scpi-parser` is de-facto
  ground truth for the parse rules).
- **VXI-11** — VXIbus Consortium (VXI-11, .2 GPIB gateway, .3 instrument); ONC-RPC
  (RFC 1057/1831). Reference scans on bitsavers.
- **HiSLIP** — IVI Foundation **IVI-6.1 HiSLIP 2.0** (public download,
  ivifoundation.org).
- **LXI** — LXI Consortium device specification. Prologix GPIB-ETHERNET manual
  (`++` command set, NetFinder UDP 3040).
- Siglent CVE write-ups (Bret McDanel); Trend Micro 2020 SCPI/VISA research.

## 9. Open questions / under-explored surface

- **The headline gap:** a coverage-guided ASan/UBSan campaign on `libscpi`'s block /
  numeric-list / channel-list / pattern surfaces — never done in the open, and the
  parser sits behind shipped-product CVEs.
- **Library-bug → product reachability:** a `libscpi` crash is a hardening finding
  unless shown reachable in a shipped instrument; map which instruments actually
  embed `libscpi`, and pair in-process findings with a raw-5025 wire repro.
- **VXI-11-framing fuzzing** is blocked on an OSS C server — recheck GitHub before
  committing; VXI-11.2 (GPIB-gateway) is the genuinely "GPIB over LAN" path.
- **HiSLIP** framing (64-bit length field) once `libhislip` matures or a minimal
  server is built from IVI-6.1.
- Gateway surfaces: Prologix `++` parser and the NetFinder UDP 3040 responder
  (structured-generator, closed firmware).

*This guide is written from the 2026-10-08 GPIB/SCPI gap survey
(`fieldbus-fuzzer/lab-notes/scpi-gpib-gap-survey.md`) — forward-looking, ahead of a
worked module. The recommended first build is a `libscpi` coverage-guided target
(`SCPI_Input`/`SCPI_Parse` under libFuzzer+ASan) with a raw-socket (TCP 5025)
wire-reachability rig; `libscpi` API signatures above verified against upstream
`parser.h`.*
