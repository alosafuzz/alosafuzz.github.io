---
title: "Fuzzing an RS41 decoder: the over-reads that stayed inside the struct"
date: 2026-11-17
project: fieldbusfuzzer
published: true
summary: "The Vaisala RS41 is the radiosonde on most weather balloons, and the open decoders that turn its broadcast into parsed telemetry (rs1729/RS, and radiosonde_auto_rx feeding SondeHub) are un-fuzzed receiver-side C. Fuzzing the RS41 path under ASan and UBSan surfaced a family of frame-index over-reads and one calibration over-write, all from a length or index field used before it is bounded against the fixed frame buffer. The part worth writing down is the de-confounding step: the fixed frame[] sits early in a large per-sonde struct, so every one of these lands on an adjacent struct field rather than past the allocation, which turns an alarming sanitizer report into a low-severity hardening fix. It reproduces, it is real, and it does not crash. Reported and merged upstream."
---

*Defensive security research. This writeup describes a fuzzing method and the hardening
issue it found; it contains no exploit, no trigger bytes, and no proof of concept. The
target is unmodified open-source software, [rs1729/RS](https://github.com/rs1729/RS)
(GPL-3). The change was reported and merged upstream.*

---

## Why this one

A radiosonde is about as passive a target as exists. The sonde transmits, the ground receives, there
is no uplink, and the decoder runs on whatever the FM demodulator recovers. That makes it easy to
under-rate as a fuzz target and easy to over-rate once a sanitizer fires, and both mistakes are worth
avoiding. The reason it is worth any attention at all is reach: the Vaisala RS41 is the most common
sonde flying, and the open decoder that parses it, `rs1729/RS`, is vendored byte-for-byte into
`radiosonde_auto_rx`, the receiver that feeds the community SondeHub network. One decoder, a lot of
listeners, and no coverage-guided fuzzing or OSS-Fuzz history on it.

The novelty check was clean on every axis: no shipped fuzzer, no OSS-Fuzz target, no CVE or advisory,
and a parser whose commit history is features and format support rather than a cluster of bounds
fixes.

## The harness

The receive path, once past error correction, is a sequence of per-block decoders hung off
`print_frame` / `print_position`, all reading one fixed buffer `gpx->frame[FRAME_LEN]`. The harness
writes the fuzz bytes straight into that buffer and runs the real top-level path.

One build choice did the useful work: `ecc = 0`. The RS41 payload is carried under Reed-Solomon
RS(255,231), which is keyless framing -- it corrects bit errors, it does not authenticate. Running the
decoder with ECC off means the fuzz bytes stand in for a frame that has already passed correction, so
the fuzzer spends its time on the parse logic instead of on satisfying a Reed-Solomon code. Every byte
string the harness feeds is a frame the RS stage could legitimately hand upward.

## What fell out

A 20-minute fork-mode campaign under AddressSanitizer and UndefinedBehaviorSanitizer produced 48 crash
inputs, and they resolved to three sites of one class: a length or index field taken from the frame
and used before it is bounded against `frame[FRAME_LEN]`.

- **`get_FrameConf`** reads the calibration-fragment counter `calfr = frame[pos_CalData]`, whose valid
  range is `0x00..0x32`, and uses it unchecked to index `calfrchk[51]` and to write sixteen frame
  bytes into `calibytes[calfr*16 + i]`. A frame with `calfr >= 0x33` indexes past both arrays. This
  one includes an out-of-bounds write, and it is gated by a CRC-16 that an attacker can compute.
- **`check_CRC`** reads `frame[pos]` and `frame[pos+1]` to pick up a packet type and length before the
  `pos + crclen + 4 > FRAME_LEN` guard, so a cursor at the frame boundary reads one or two bytes past
  it.
- **`get_Aux`** reads the xdata CRC bytes at `frame[pos+2+auxlen]` before its own
  `pos + auxlen + 4 <= FRAME_LEN` check, and `auxlen` is a frame byte, so the read can reach a couple
  of hundred bytes past the declared length. It is gated only by a `frame[pos] == 0x7E` match, no CRC.

Three functions, one mistake repeated: the bound exists but the read comes first, or the bound is
missing because the index was assumed to be in its valid range.

## The de-confounding, which is the actual finding

Forty-eight ASan reports looks like a serious result. It is not, and establishing that was the point of
the exercise rather than a footnote to it.

`frame[]` is declared near the front of `gpx_t`, and `gpx_t` is large: the Reed-Solomon tables, an
`ecdat` block with its own `frm_bytescore[526]`, and two `int[518]` index arrays all sit after the
frame buffer in the same object. So an access that runs off the end of `frame[]` lands on an adjacent
field of the same struct, not past the allocation. Whether that shows up as a crash depends entirely
on where the buffer sits in its allocation, which is a property of the harness, not the bug.

I checked it directly. Rebuilt with AddressSanitizer only and `gpx_t` heap-allocated, every one of the
48 inputs runs clean: zero past-allocation errors. Only UndefinedBehaviorSanitizer, which checks each
access against its own declared array bounds regardless of what is next to it, still flags them. So the
reports are genuine out-of-bounds accesses by the language, and in the real decoder -- which keeps one
persistent `gpx_t` for the life of a sonde -- they read and corrupt decoder-internal neighbouring
fields and nothing more. No segfault, no denial of service, no read outside the process object.

That is the honest severity: a real memory-safety defect, reachable from a transmitted frame, with
impact bounded to intra-struct corruption. It is worth fixing and it is not a crash. The lesson
generalises, and it is the same one a fixed-buffer parser keeps teaching: a tight or end-of-allocation
harness buffer turns a contained over-read into a hard crash the production layout never has, so the
allocation shape has to be checked before the sanitizer report is believed.

## The sanitizer matrix

AddressSanitizer and UndefinedBehaviorSanitizer together gave the split that mattered: ASan (with the
faithful allocation) said nothing crosses the object, UBSan said every one is an out-of-bounds array
access. MemorySanitizer ran on the same path and was clean -- there is no uninitialized-read finding
here, the defect is purely the unbounded index. I verified instrumentation on the object files, not
the linked binary.

## Reporting and outcome

Neither `rs1729/RS` nor `radiosonde_auto_rx` has a SECURITY.md or private reporting, and the severity
is low, so the report went as an ordinary public pull request: three one-line bounds checks, with the
impact stated plainly as hardening against short and malformed frames rather than an attack. Bound
`calfr < 51` before the calibration index and copy; reject `pos + 1 >= FRAME_LEN` at the top of
`check_CRC`; and in `get_Aux`, loop while `pos + 1 < FRAME_LEN` and take the CRC-byte read only once
`pos + auxlen + 4 <= FRAME_LEN` holds. No behaviour change for valid frames; every flagged input is
clean on the patched build and a fresh re-fuzz found nothing new.

The maintainer took it, and the exchange is the part worth passing on. The first draft of the title
leaned on "attacker-controlled frame indices," and the maintainer's reaction was that a weak signal is
the more likely source than an attacker -- which is correct for a passive broadcast receiver, and the
reframe to short/malformed-frame hardening is the accurate one. He merged the change under that
framing, kept his own code comment and the local variable the patch had reworked, and then refined the
xdata CRC handling himself so the sentinel value read more cleanly. Defer to the maintainer's structure
on their own file, and frame a passive-reception decoder as robustness rather than a threat; both were
the right call and both made the fix land.

The transferable part needs none of the specifics: when a decoder reads a length or an index out of
the frame, find where it is bounded and check that the bound comes first; and before you believe the
crash, put the buffer where production puts it and see whether the over-read still leaves the object.
