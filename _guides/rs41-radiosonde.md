---
title: "A researcher's guide to RS41 radiosonde telemetry"
protocols: ["RS41", "Vaisala RS41", "radiosonde", "SondeHub"]
vendor: ["Vaisala", "cross"]
vendor_group: "Weather / upper-air observation"
sector: ["meteorology", "aviation"]
transport: ["rf"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
bug classes only; no exploit, no trigger bytes.*

---

## 1. What it is & where it runs

The Vaisala **RS41** is the radiosonde on most weather balloons launched today. Twice a day from
hundreds of stations it climbs to ~30 km and transmits temperature, humidity, pressure, and GNSS
position back to the ground on a narrow FM channel in the 400-406 MHz met-aids band. The transmission
is one-way: the sonde broadcasts, the ground receives, and there is no uplink and no authentication of
any kind.

The receivers are open-source. **`rs1729/RS`** is the reference decoder collection, and
**`projecthorus/radiosonde_auto_rx`** is the widely deployed automatic receiver that feeds the
community **SondeHub** tracking network; it vendors the RS decoder byte-for-byte and rebases from it.
So the code that turns RF into parsed fields is the same handful of C files in both, and a parser bug
is a bug across the whole hobbyist and semi-operational receiver ecosystem.

For a researcher the trust model is the starting point, and it is worth stating plainly because it
sets the severity ceiling. The input is a broadcast radio frame. The realistic source of a malformed
frame is a **weak or noisy signal**, not an adversary: a sonde at the edge of range, multipath, a
collision between two sondes on the same frequency. A deliberately crafted transmitter is possible --
anyone with an SDR and a few watts in the met-aids band can send whatever bytes they like, and the
frame CRCs are keyless so a crafted frame can carry a valid checksum -- but there is no commercial or
operational incentive, and no device state to steal or pivot into. Treat findings here as robustness
against malformed and short frames, and reserve "attacker" for the specific case where it genuinely
applies.

## 2. The frame model

An RS41 frame, once demodulated and bit-synced, is a fixed-layout byte block:

- **Header / sync**, then the payload carried under **Reed-Solomon RS(255,231)** forward error
  correction. The RS code is keyless: it corrects bit errors, it does not authenticate. A decoder can
  be run with ECC on (correct, then parse) or with ECC off (parse the raw bytes as if they had already
  passed correction) -- the second mode is the one a fuzzer wants, because it models every frame that
  the RS stage would hand upward.
- **A sequence of typed sub-blocks**, each introduced by a one-byte type code and carrying its own
  length or count fields: the measurement block, the GNSS block, the **calibration/config block**
  (`FrameConf`, keyed by an 8-bit calibration-fragment counter `calfr`), and an optional **xdata**
  block (type `0x7E`) with its own `auxlen` byte and trailing CRC-16.
- Each sub-block is checked with a **CRC-16** before its fields are trusted.

The decoder reads the whole thing into one fixed buffer, `gpx->frame[FRAME_LEN]` (518 bytes in the
RS41 path), which is a member near the front of a large per-sonde state struct, `gpx_t`.

The researcher's hooks are the length and index fields: `calfr`, the xdata `auxlen`, the per-packet
`crclen`, and the running cursor `pos`. Each is taken from the frame. The question for every one is
whether it is bounded against `FRAME_LEN` before it is used to index or copy.

## 3. The fuzz surface, mapped to rs1729/RS

The decoder is `demod/mod/rs41mod.c`. A faithful harness writes the fuzz bytes into `gpx->frame[]`,
runs the real top-level path (`print_frame` -> `print_position` -> the per-block decoders), builds
with `ecc = 0` so the bytes stand in for a post-ECC frame, and compiles under AddressSanitizer and
UndefinedBehaviorSanitizer. The length-driven entry points:

- **`get_FrameConf`** -- reads the calibration counter `calfr = frame[pos_CalData]` and uses it to
  index the `calfrchk[]` and `calibytes[]` calibration arrays, including a 16-byte copy into
  `calibytes[calfr*16 + i]`. Valid `calfr` is `0x00..0x32`; the field is a raw byte.
- **`check_CRC`** -- reads `frame[pos]` / `frame[pos+1]` at a cursor that can sit at the frame
  boundary, to pick up a packet type and length before validating them.
- **`get_Aux`** -- the `0x7E` xdata walk: reads the trailing CRC bytes at `frame[pos+2+auxlen]` using
  the attacker-supplied `auxlen`.

## 4. Known bug classes

RS41 and these decoders have no CVE on record and are not on OSS-Fuzz, so the prior is the bug class,
not a list. This is a length-and-index parser over a fixed buffer, so the class to check is a frame
field used before it is bounded:

- **Index from the frame, used before a range check.** A counter or offset read from the frame
  (`calfr`, `auxlen`, a cursor near the end) indexes or copies against `frame[FRAME_LEN]` or a
  fixed-size table before anything confirms it is in range.
- **Guard after the read.** The right bounds check exists but runs one step too late -- the field is
  read, then checked -- so a short or malformed frame reads past the buffer before being rejected.

There is a second question that decides impact rather than presence, and it is specific to this
layout: **what does the over-read actually reach?** `frame[]` sits early in the large `gpx_t`, and
more decoder state follows it in memory. An index that runs off the end of `frame[]` therefore lands
on an adjacent struct field, not past the allocation. The same defect is a hard crash in a build that
puts the buffer at the end of its allocation, and a few corrupted internal fields in the real decoder
that keeps one persistent `gpx_t`. A researcher who stops at the sanitizer report will over-state it;
the honest reading needs the allocation shape.

## 5. Research status and disclosure

I fuzzed the `rs1729/RS` RS41 decoder in-process under ASan and UBSan and found a family of these
frame-index over-reads (and one small over-write in the calibration path), all of the class above.
Measured against the real `gpx_t`, they stay inside the struct: no crash, no denial of service, no
out-of-process disclosure. I reported them to `rs1729/RS` as a hardening change with three one-line
bounds checks, framed as short/malformed-frame robustness rather than an attack, and the maintainer
merged it and refined the style. The companion writeup has the method and the de-confounding that
established the intra-struct impact. Nothing here is a proof of concept.

## 6. Defensive notes

- **Bound every length and index taken from the frame before using it**, and put the check before the
  read, not after. The fields to watch are `calfr`, the xdata `auxlen`, and any cursor that can reach
  the frame boundary.
- **Vendored copies inherit the bug and the fix.** `radiosonde_auto_rx` carries this decoder
  byte-identical and rebases from `rs1729/RS`, so a fix upstream propagates on the next sync; a
  receiver operator pinned to an older copy does not get it automatically.
- **Keep the severity honest.** The frame CRCs are keyless, so a checksum gates noise but not a
  deliberate transmitter; and the deployment is passive reception with no device to compromise. These
  are robustness fixes for malformed input, worth making, and not a remote-code-execution surface.

## 7. Further reading

- `rs1729/RS` (the reference decoders):
  [github.com/rs1729/RS](https://github.com/rs1729/RS).
- `projecthorus/radiosonde_auto_rx` (the deployed receiver + SondeHub feed):
  [github.com/projecthorus/radiosonde_auto_rx](https://github.com/projecthorus/radiosonde_auto_rx).
- Writeup: *Fuzzing an RS41 decoder: the over-reads that stayed inside the struct* (alosafuzz).

*Caveat on reachability: the decoder runs on bytes recovered from a one-way radio broadcast with no
authentication, so the realistic source of a malformed frame is a weak or noisy signal; a crafted
transmitter is possible but has no incentive and no device state to reach, which keeps the ceiling at
robustness of the receiver software.*
