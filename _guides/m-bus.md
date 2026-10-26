---
title: "A Researcher's Guide to M-Bus (Meter-Bus)"
protocols: ["M-Bus", "EN 13757"]
vendor: ["cross"]
vendor_group: "Cross-vendor"
sector: ["smart-metering", "iiot", "cross"]
transport: ["m-bus-serial", "m-bus-tcp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and bug
classes, so you can test your own devices.*

M-Bus (Meter-Bus, EN 13757) is the European standard for reading heat, water, gas, and electricity
meters. Wired M-Bus runs over a two-wire bus; deployments increasingly tunnel it over TCP via
converters. A concentrator polls meters and parses whatever they return — so the interesting parser is
the **master/host side** decoding meter-supplied frames, and a malicious or spoofed meter is the threat
model. The dominant open-source library is [rscada/libmbus](https://github.com/rscada/libmbus).

## 1. What it is & where it runs

A master sends short request frames; a meter replies with a long frame carrying a variable-length set
of **data records**. Over TCP the same frames ride a thin wrapper (converter-dependent). There is no
authentication at the wired-M-Bus layer.

## 2. Wire format

```
Long/Control frame: 68 L L 68 | C | A | CI | <user data> | CHK | 16
  user data (variable-data structure, CI=0x72/0x76):
    fixed header: ident(4 BCD) | manuf(2) | version | medium | access-no | status | signature(2)
    data records: [DIF (+DIFE...)] [VIF (+VIFE...)] [data]   -- repeated
```

- `L` is the length; the `68 .. 68` framing and the trailing checksum/`0x16` bound the frame.
- **DIF** (Data Information Field) encodes the data *coding/length*; **VIF** (Value Information Field)
  encodes the *unit/scaling*. Both can chain extension bytes (DIFE/VIFE).
- Values appear as integers, **BCD**, real, or variable-length LVAR strings.

## 3. The fuzz surface

The host decoder walks the data records using attacker-controlled length/coding fields — the classic
length-lie surface:

- **`mbus_parse()` / the frame parser** (`mbus/mbus-protocol.c`): the `L` length vs actual bytes, the
  `68..68` framing, checksum handling.
- **DIF/VIF record walking:** a DIF/VIF that claims more data (or more extension bytes) than the frame
  contains — bounds on each record vs the remaining buffer.
- **BCD / LVAR decoding:** variable-length and nibble-packed fields where a declared length drives a
  read or a buffer index.
- **Fixed-data vs variable-data** headers and the manufacturer-specific blocks.

## 4. Known vulnerabilities & bug classes

libmbus has historically had **no OSS-Fuzz presence and no CVE cluster** — a comparatively
under-tested host decoder. The bug classes to probe are the standard meter-decoder ones: length-field
vs buffer over-reads in the DIF/VIF record walk, BCD/LVAR length mishandling, and unchecked record
counts. (Always confirm against the current `master`; the project is maintained.)

## 5. Building a test harness

libmbus is plain C — drive `mbus_parse()` (or the frame/record decoders) in-process with libFuzzer +
ASan/UBSan, feeding fuzz bytes where a meter's reply enters the host. A tight, exact-size input buffer
(no shared oversized scratch) keeps an in-buffer over-read from being masked. Phase-1 needs no hardware;
a phase-2 wire repro uses a cheap USB M-Bus master/slave converter (or the TCP-wrapper path).

## 6. Open-source implementations & tooling

- [rscada/libmbus](https://github.com/rscada/libmbus) (BSD-3) — the reference C library + CLI tools.
- `libmbus`'s `mbus-serial-*` / `mbus-tcp-*` utilities for live reads.
- Wireshark has an M-Bus / wM-Bus dissector.

## 7. Spec references & sources

- EN 13757-2 (physical/link), EN 13757-3 (application layer, DIF/VIF data records).
- OMS (Open Metering System) profiles for the metering-specific encodings.

## 8. Open questions / under-explored surface

- **Wireless M-Bus (wM-Bus, EN 13757-4)** — a distinct radio stack (encryption, frame formats) with
  its own decoders (e.g. wmbusmeters).
- Manufacturer-specific VIF extension blocks and the long-tail of coding types.
