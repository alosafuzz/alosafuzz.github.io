---
title: "A researcher's guide to SML (Smart Message Language)"
protocols: ["SML", "Smart Message Language", "EDL21"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["smart-metering", "iiot", "cross"]
transport: ["optical-ir", "serial", "tcp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes, so you can test your own devices.*

SML (Smart Message Language) is the data format German electricity meters push over their optical
interface. It is what an EDL21/EDL40 smart meter emits on its infrared port, what a USB IR read head
hands to software like volkszaehler, Tasmota, or ESPHome, and what then gets relayed onward over MQTT
or TCP. The parser that matters is the receiver, and a malicious or spoofed meter, injected IR, or a
relay feeding SML onward is the threat model.

## 1. What it is & where it runs

Most consumption meters are one-way: the meter wakes on a schedule and transmits an SML file; nothing
is sent back. A read head on the optical port (or a serial/TCP bridge) delivers the bytes to a host
that decodes them into meter readings. There is no transport authentication; SML carries an optional
`valueSignature` per entry, but receivers rarely verify it, so an attacker who can put bytes on the
wire is unauthenticated against the parser.

## 2. Wire format

An SML file is a sequence of SML messages, wrapped by an escape-based transport frame:

```
transport:  1b1b1b1b 01010101            escape + version start
            <SML file: one or more SML messages>
            1b1b1b1b 1a PP CRC16         escape + end, PP = pad count, CRC16 over the frame
  (a literal 1b1b1b1b inside the payload is escaped by doubling it)

SML message: list( transactionId, groupNo, abortOnError, messageBody, crc16, endOfMessage )
messageBody: a tagged choice; the interesting one is GetListResponse, whose valList is a
             list of SML_ListEntry( objName, status, valTime, unit, scaler, value, valueSignature )
```

- Every field is a **TL (type-length) byte**: the high bits select the type (octet string, boolean,
  signed integer, unsigned integer, or list), bit 7 means more TL bytes follow (length extension), and
  the low nibble is the length, counting the TL byte(s) itself. For a list the length is the element
  count. This is a nested, length-prefixed TLV, which is the whole parse surface.
- **Integers** are 1 to 8 bytes, two's complement for the signed type.
- **objName** is a 6-byte OBIS code identifying the quantity (for example `1-0:1.8.0` is total imported
  active energy); `scaler` and `unit` turn the raw `value` into a reading.
- The transport layer (escape framing plus CRC16) is a separate parser from the message decoder, and
  the two are worth fuzzing independently.

## 3. The fuzz surface

- **TL length versus bytes remaining.** Each field's declared length must be checked against the buffer
  before the bytes are read. Length-extension TL bytes and the per-type length are the obvious targets.
- **Nested list depth and element counts.** A list's declared element count drives the walk; deep or
  inconsistent nesting is where recursion limits and list accounting get tested.
- **Integer decode.** The 1-to-8-byte signed and unsigned decode is small but a classic spot for
  signed-shift and sign-extension undefined behaviour.
- **The escape/CRC transport.** The `1b1b1b1b` escape scanner and the doubling rule are a distinct
  byte-level surface from the message decoder.

## 4. Known vulnerabilities & bug classes

There is no public CVE for either dominant open-source SML parser. A 2026 campaign across both
(see the [companion writeup](/writeups/fuzzing-sml-a-novelty-gate-miss-and-capping-to-reach-deeper/)):

- **volkszaehler/libsml (C)** already ships its own libFuzzer harness on `sml_file_parse` under
  ASan+UBSan, so it is partially fuzzed rather than virgin. Re-running it with MSan added on current
  HEAD came back clean.
- **olliiiver/sml_parser (C++, embedded)** had never been fuzzed. The result was a memory-safety
  robustness-negative (no out-of-bounds despite values that point into the parse buffer, MSan clean)
  with two low-severity undefined-behaviour items: a **signed left-shift of a negative value** in the
  signed-integer decode, and an **invalid enum load** where a raw type byte was read into a state enum.
  Both are hardening, fixed upstream.

The general classes to expect in any SML parser: TL length fields trusted before bounds, list-count
and nesting accounting, and integer-decode undefined behaviour.

## 5. Building a test harness

- **libsml**: entry `sml_file_parse(unsigned char *buf, size_t len)` is a self-contained C bytes-to-tree
  parser, so the full ASan+UBSan+MSan matrix is feasible (MSan is cheap here). It links `-luuid`. Note
  it already ships `test/src/fuzzer.c` on this exact entry, so check that before building a duplicate.
- **olliiiver/sml_parser**: entry `sml_states_t smlState(unsigned char byte)` is a byte-by-byte state
  machine; feed the input one byte at a time, and on `SML_LISTEND`/`SML_FINAL` consume `smlOBISEntry`,
  whose `.bytes`/`.length` point into the parser's buffer (so consuming them forces over-read
  detection). Reset the global parser between inputs. Self-contained C++, so MSan is feasible.
- Copy the input into a tight `malloc(size)` buffer so a one-byte over-read is a hard ASan crash.
- Seed from the real dumps in [devZer0/libsml-testing](https://github.com/devZer0/libsml-testing), or
  from the embedded telegrams the parsers ship for their examples.

## 6. Open-source implementations & tooling

- [volkszaehler/libsml](https://github.com/volkszaehler/libsml) (C, GPL-3.0): the reference host-side
  parser; ships a fuzzer and a `sml_file_write` encoder useful for seed generation.
- [olliiiver/sml_parser](https://github.com/olliiiver/sml_parser) (C++, LGPL-2.1): a low-memory
  parser for Arduino/ESP32 and native builds.
- [devZer0/libsml-testing](https://github.com/devZer0/libsml-testing): a corpus of real meter dumps,
  the natural seed set and regression suite.

## 7. Spec references & sources

- The SML specification (BSI TR-03109-1 Annex / the VDE SML document) for the message structure, TL
  encoding, and the CRC16 and escape framing.
- IEC 62056-21 for the optical interface SML rides on; the OBIS code list (IEC 62056-6-1) for the
  object identifiers in `objName`.

## 8. Open questions / under-explored surface

- The transport escape/CRC layer gets less attention than the message decoder; the `1b1b1b1b` scanner
  and the doubling rule are worth a dedicated harness.
- Embedded parsers compiled at -O2 without sanitizers hide the integer undefined-behaviour classes; a
  sanitizer build is the only way to see them.
- Meter-to-head read-head firmware and the serial/MQTT relays that forward SML are largely unfuzzed in
  the open.
