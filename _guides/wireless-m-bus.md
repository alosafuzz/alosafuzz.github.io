---
title: "A researcher's guide to wireless M-Bus (wM-Bus / OMS)"
protocols: ["wM-Bus", "wireless M-Bus", "OMS", "EN 13757-4"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["smart-metering", "iiot", "cross"]
transport: ["radio-868mhz", "radio-169mhz"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes, so you can test your own devices.*

Wireless M-Bus (EN 13757-4) is the radio sibling of wired [M-Bus](/guides/m-bus/). It is how heat,
water, gas, and electricity meters report over the air to a concentrator, and it is the metering layer
underneath the OMS (Open Metering System) profile used across much of Europe. A receiver decodes
whatever a meter transmits, so the interesting parser is the host side, and a spoofed or malicious
meter, or anything that can inject a telegram into the receiver, is the threat model.

## 1. What it is & where it runs

Meters transmit short telegrams on licence-free bands, commonly 868 MHz (modes S, T, C) and 169 MHz
(mode N). A concentrator, gateway, or self-hosted SDR setup listens, decodes, and forwards the
readings. The link is one-way for most meters: they wake, send, and sleep. Payloads may be AES-128
encrypted (OMS security modes 5, 7, and 9), but encryption is keyed per meter and is not
authentication of the sender at the radio layer, so an attacker can still put well-formed framing on
the air without any key. The dominant open-source decoder is
[wmbusmeters](https://github.com/wmbusmeters/wmbusmeters); SDR front-ends like rtl-wmbus feed it.

## 2. Wire format

A telegram is a stack of layers, each of which the host must parse before it reaches the meter values:

```
DLL  (data link)        : L | C | M(2) | A(6: id,ver,type)   + format A/B CRCs
ELL  (extended link)    : optional; CI 0x8c/0x8d/0x8e/0x8f, may carry encryption
NWL  (network)          : optional
AFL  (auth/fragmenting) : optional; CI 0x90, fragment control, variable-length MAC
TPL  (transport)        : CI selects header (none/short/long), access no., status,
                          config word (encryption mode + encrypted block count)
  -> AES-128 decrypt (modes 5/7/9) over the encrypted block count
  -> data records: [DIF (+DIFE...)] [VIF (+VIFE...)] [data]   (same as wired M-Bus)
```

- The `CI` (control information) byte at the head of each optional layer selects which layer and
  header variant follows. A decoder is a `CI`-driven dispatch, which is a classic place for a missing
  case or an unchecked length.
- The **difvif** data records are shared with wired M-Bus: DIF encodes coding and length, VIF encodes
  unit and scaling, both chain extension bytes (DIFE/VIFE). Values appear as integer, BCD, real, or
  variable-length.
- **Compact frames** send only the difvif values and refer to a previously seen format, so the decoder
  reconstructs the record layout from a stored template. That reconstruction path is attacker-reachable
  and less travelled than the full-frame path.

## 3. The fuzz surface

The whole decode is reachable from raw bytes with no radio and no key. In wmbusmeters the chain is
`Telegram::parse` -> `parseWMBUS` -> the per-layer parsers -> `parseTPL` / `parse_TPL_78` -> decrypt
-> `parseDV`. The places worth seeding toward:

- **Length fields versus bytes remaining.** Every layer carries a length that must be checked against
  what is left in the frame before any byte is read. The variable-length AFL MAC and the short
  data-link and auth-layer headers are the obvious candidates.
- **The decrypt helper.** A length derived from the telegram sizes a buffer for the AES block count;
  seed it to zero and to very large values.
- **The compact-profile reconstruction.** Malformed templates and base values reach code the
  full-frame path does not.
- **difvif chains.** Long DIFE/VIFE chains drive shift amounts and multiply-accumulate conversions;
  seed boundary digit values and deep chains.

## 4. Known vulnerabilities & bug classes

A 2026 campaign against wmbusmeters (see the [companion writeup](/writeups/fuzzing-wmbusmeters-the-dos-afl-counts-as-a-clean-exit/))
found and had fixed:

- **Reachable process exit on wire data (availability).** The decoder called an error helper that
  terminates the process on a malformed compact-profile telegram. One telegram, one outage. The
  general lesson: a telegram parser must never call `error()`/`exit()`/`abort()` on attacker bytes;
  it should return a failure and skip the record.
- **Out-of-bounds reads** from length fields trusted before they are bounded against the frame (the
  data-link C field, the auth-layer length, and the auth-layer MAC copy).
- **Attacker-sized stack allocation** in the decrypt helper.
- **Signed-shift and signed-overflow undefined behavior** in the difvif decoder (long DIFE chains and
  BCD-to-integer conversion).

These generalize to any wM-Bus decoder: unchecked per-layer lengths, allocations sized from the
telegram, and integer handling in the difvif conversions.

## 5. Building a test harness

- Target `Telegram::parse(frame, MeterKeys*, warn)` (or the equivalent entry in another decoder) with
  in-process libFuzzer, not the shipped AFL targets alone. AFL counts a deliberate `exit()` as a clean
  exit, and `AFL_HARDEN` is not a sanitizer, so build with clang under **ASan + UBSan**.
- Set a fixed test key so the AES decrypt path is reachable from fuzz input.
- Copy each input into a tight `malloc(size)` buffer so a one-byte over-read is a hard ASan crash, not
  a silent read into allocator slack.
- If UBSan aborts early on a dominant undefined-behavior class (the difvif shift), rebuild with that
  class made non-fatal to reach the code it masks.
- **MSan is impractical here**: the C++ decoder pulls in enough of an uninstrumented libstdc++ to flood
  MSan with false positives. Seed from the real telegrams in the project's driver test cases.

## 6. Open-source implementations & tooling

- [wmbusmeters](https://github.com/wmbusmeters/wmbusmeters) (GPL-3.0): the reference decoder; ships
  AFL fuzzers for difvif and a whole-binary telegram run.
- rtl-wmbus / rtl_433: SDR front-ends that demodulate telegrams off the air for a decoder to parse.
- The difvif layer is shared with wired M-Bus, so [rscada/libmbus](https://github.com/rscada/libmbus)
  is a useful cross-reference for the record parser even though it does not do the radio layers.

## 7. Spec references & sources

- EN 13757-4 (wireless M-Bus radio and link layer), EN 13757-3 (application layer, difvif records).
- OMS (Open Metering System) specification, volume 2 (primary communication) for the security modes
  and TPL header handling.

## 8. Open questions / under-explored surface

- The stateful layers above the message decoder (the SDR driver state, any session or gateway logic)
  need a driver harness and are a separate target from the pure byte-to-tree parser.
- Other wM-Bus parsers, including vendor concentrator firmware and the SDR demodulators themselves,
  are largely unfuzzed in the open.
- Mode N (169 MHz) framing and the less-common CI dispatch cases get less corpus coverage than the
  868 MHz S/T/C modes.
