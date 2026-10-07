---
title: "A Researcher's Guide to FactoryTalk Linx RNA"
protocols: ["RNA"]
vendor: ["rockwell"]
vendor_group: "Rockwell / Allen-Bradley"
sector: ["manufacturing"]
transport: ["rna"]
project: icsfuzzer
status: draft
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and
published bug classes only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

RNA is the live-data / messaging layer of Rockwell Automation's **FactoryTalk
Linx**, implemented in `RnaDaSvr.dll` inside `RSLinxNG.exe`. It runs on
Windows-based FactoryTalk servers and engineering stations — the data-broker that
sits between HMIs/historians and the plant network.

It is interesting to a researcher precisely because it is **not** a classic binary
TLV protocol like CIP or Modbus. RNA is a **thin binary envelope wrapping XML text
payloads** (and, on a sibling service, COM-Automation-style typed records). That
mix — a lying binary length field on the outside, attacker-controlled XML
attributes on the inside — produces two distinct bug families in one protocol.

- **Transport:** TCP, port **4241** (FactoryTalk Linx). A separate service,
  FTDiagnosticsViewer, listens on **5241** with the *same envelope but a different
  header and a binary VARIANT record format* — treat it as a separate target.
- **No public specification exists.** Everything below was derived by reading
  Tenable's four PoC scripts byte-for-byte
  (`github.com/tenable/poc/.../RockwellAutomation/FactoryTalk/`), not from a spec.

## 2. Session & transport model

```
1. TCP connect (4241).
2. Client → OpenNamespace  (command=XmlCommand, transid=1, session-id= empty)
                            + XML <OpenNamespace> data block.
3. Server → same envelope; response header carries session-id=<N>.
4. Client → subsequent requests set session-id=<N>, increment transid.
```

The session id is recovered from the **first response** by scanning the header
block for `session-id=<N>` — so a fuzzer's connect phase must parse the response
envelope, not assume a fixed offset.

## 3. Wire format

**Envelope** (same for request and response):

```
Offset 0:   magic        4 bytes   b'rna\xF2'
Offset 4:   header block  variable  length-prefixed (pad=True)
Offset 4+N: data block    variable  length-prefixed (pad=False)
```

**`block(data)`** = `struct.pack('<L', len(data))` + `data`. A subtlety worth
getting right in a generator: when padding is on, the **length field reflects the
padded length** (the pre-pad `dlen` is dead code in the PoC) — verified by reading
the raw source, not a summary. This is the lying-length knob for the
`binary_corruption` category.

**Header block** — *not* fixed binary fields. It is flat text: `key=value` pairs,
**sorted by key**, each null-terminated, concatenated:

```
"command=XmlCommand\x00session-id=\x00transid=1\x00"
```

Observed keys: `command`, `transid` (increments per request), `session-id` (empty
on the first message, numeric after assignment). Whether the server actually
*requires* sorted order is unverified — itself a header-fuzz question.

**Data block** — raw XML text for `OpenNamespace` / `ConfigureItems`. (The 5241
FTDiagnosticsViewer service instead carries a binary VARIANT-style record —
`wstr()` UTF-16LE length-prefixed strings, `vt_str()`/`vt_i4()` typed wrappers — a
materially different grammar, out of scope for the 4241 generator.)

## 4. The fuzz surface

RNA's two bug families map cleanly onto two layers:

**Layer A — the binary envelope.** Wrong magic (`rna\xF2`), **lying block-length
fields** (declared length ≠ bytes present), truncated blocks. This is the same
"length field disagrees with payload" pattern that drives parser over-reads
everywhere.

**Layer B — the XML and header text.**
- **XML attribute-value extremes** (`boundary`, but string-encoded): `count`,
  `sampleRate`, `sampleDepth`, `leaseTime` as `0`, `-1`, `0x7FFFFFFF`,
  `0xFFFFFFFF` in both signed and unsigned string forms. CVE-2020-5802 is exactly
  this — a `count` the server passes to `operator new`.
- **Session state machine** (`sequence`/`state_machine`): re-send `OpenNamespace`
  with an already-valid session id (CVE-2020-5801's shape); `ConfigureItems`
  before any `OpenNamespace`; a `session-id` from a different/closed connection;
  rapid `transid` reuse.
- **XML well-formedness** (protocol-specific category): unclosed tags, wrong
  namespace URI, missing required attributes, entity expansion — a text-XML
  protocol makes XXE/entity-bomb-shaped cases relevant where binary protocols
  don't.
- **Header text fuzz** (protocol-specific): missing `command`/`transid`,
  non-numeric `transid`/`session-id`, extra keys, wrong sort order, oversized
  key/value strings.

**Structured vs. coverage-guided:** RNA is a structured-generator target — the
known bugs are *semantic* (a session-state misuse; an XML count used as an
allocation size), not deep byte-parser bugs. There is no open-source server to
instrument for coverage-guided fuzzing.

## 5. Known vulnerabilities & bug classes

| CVE | Port | Message | Class |
|---|---|---|---|
| CVE-2020-5801 | 4241 | double `OpenNamespace` on a valid session | state-machine / unhandled exception |
| CVE-2020-5802 | 4241 | `ConfigureItems` with `count="1073741812"` | CWE-789/CWE-20 attacker-controlled allocation size (`operator new`) |
| CVE-2020-5806 | 127.0.0.1:7153 | `LoadIconStream` | local-only per advisory (binding uncertain) |
| CVE-2020-5807 | 5241 | oversized wide-string log field | buffer bug in the *different* VARIANT grammar |

Tenable advisory **tra-2020-71** is the CVE-level summary; the PoC scripts carry
the actual bytes. Three of the four are network-reachable; CVE-2020-5806's
loopback binding is asserted by the advisory but not confirmed in the PoC (which
takes an arbitrary host) — an open question.

## 6. Building a test harness

With no spec and no test device, the responder is explicitly **framing-only**: it
accepts `OpenNamespace`, hands back a `session-id`, accepts `ConfigureItems`, and
returns a well-formed envelope — enough to prove cases connect and parse, **not**
enough to reproduce the real allocator/exception crashes (that needs Rockwell's
server-side logic). Label this limitation loudly so "cases get a well-formed
response from the mock" is never mistaken for "confirmed against RSLinxNG.exe."

Two implementation lessons from building the icsFuzzer module, both caught by the
test suite rather than by inspection — generally useful for any *text-in-binary-
envelope* protocol:
- **Parse-mutate-re-encode beats in-place byte substitution.** Patching a
  session-id by raw substring replacement inside an already length-prefixed
  envelope desyncs the header's own length field whenever the replacement differs
  in length. Parse the envelope, mutate the header dict, re-encode.
- A state-machine filter that keyed on the same placeholder marker used to flag a
  case for patching silently *deleted* the case it meant to keep — assert that
  distinguishing cases survive generation.

**Calibration:** 56 cases across 6 categories — reported honestly, below the
project's usual 150–600 density because `sequence`/`state_machine` turned out
smaller once written concretely. Framing-only, so there is no crash baseline to
compare against real hardware yet.

## 7. Open-source implementations & tooling

- Tenable PoC scripts (`tenable/poc`, RockwellAutomation/FactoryTalk) — the only
  public byte-level source; read `block()`, `OpenNamespace`, `ConfigureItems`,
  `FTDiagViewer` directly.
- No open-source RNA server exists — black-box / framing-mock only.

## 8. Spec references & sources

- Tenable advisory **tra-2020-71** and the four PoC scripts (fetched 2026-09-26).
- CISA advisories for CVE-2020-5801/5802/5806/5807.

## 9. Open questions / under-explored surface

- The `rna` magic's full meaning and RNA's command set beyond the four
  PoC-documented messages are unknown.
- Whether the server enforces header sort order, and whether `securityToken="Token"`
  (a literal placeholder in the PoCs) is actually validated.
- CVE-2020-5806's real binding (loopback vs. network).
- The 5241 FTDiagnosticsViewer VARIANT grammar is a separate, under-documented
  target deserving its own guide.

*Worked example: `protocols/factorytalk_rna/fuzzer.py` (6 categories, 56 cases)
with `scripts/factorytalk_rna_responder.py` as the explicitly framing-only testbed.*