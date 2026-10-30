---
title: "Fuzzing SML: a novelty-gate miss, and capping one bug to reach the next"
date: 2026-10-30
project: fieldbusfuzzer
published: true
summary: "Smart Message Language looked like a virgin metering target. The first candidate, libsml, turned out to already ship a fuzzer on the exact entry point I had picked, a miss my own novelty gate should have caught. The pivot to a second parser, olliiiver/sml_parser, was genuinely unfuzzed and came back a memory-safety robustness-negative with two undefined-behaviour items, one of which only showed up after I capped the other to reach past it. Both are fixed upstream."
---

*Defensive security research. This writeup describes a fuzzing methodology and a
mostly-negative result; it contains no exploit. The targets are unmodified
open-source software: [volkszaehler/libsml](https://github.com/volkszaehler/libsml)
(GPL-3.0) and [olliiiver/sml_parser](https://github.com/olliiiver/sml_parser)
(LGPL-2.1).*

---

## Why SML, and the gate I almost fumbled

SML (Smart Message Language) is what German smart meters push over their optical port: a nested,
length-prefixed TLV that a read head delivers to software like volkszaehler or ESPHome, often relayed
onward over MQTT. The receiver parses bytes from a device it does not control, which is the shape this
suite looks for, and the record said no SML parser had a CVE or an OSS-Fuzz presence.

The first candidate was libsml, the reference C parser. Entry point `sml_file_parse(buf, len)`, a
self-contained bytes-to-tree decoder, ideal for the full sanitizer matrix. I ran the novelty gate,
called it virgin, and started on a harness.

On clone I found `test/src/fuzzer.c`: a libFuzzer harness on `sml_file_parse`, the exact entry I had
chosen, with the same ASan+UBSan recipe, seeded from the same corpus I was about to use. libsml is not
virgin, it is partially fuzzed, and my gate had missed it because the tree grep that was supposed to
catch this got truncated before it reached the `test/` directory. The lesson is the same one that bit
me on other targets: grep the whole tree, including test directories, for a shipped harness before
calling anything virgin. The only defensible gap left on libsml was adding MemorySanitizer, which the
shipped recipe lacks; re-running the current HEAD under MSan came back clean, so there was nothing new
there.

## The pivot that was actually virgin

olliiiver/sml_parser is a different codebase: a low-memory C++ parser for Arduino, ESP32, and native
builds, with no shipped fuzzer, no OSS-Fuzz, and no CVE. This time the full-tree check was clean. The
entry is `smlState(byte)`, a byte-by-byte state machine; the harness feeds one byte at a time and, on
list or file completion, consumes `smlOBISEntry`, whose decoded entries hold a pointer and length into
the parser's internal buffer. Consuming those forces any over-read to show up. The input goes into a
tight `malloc(size)` buffer so a one-byte over-read is a hard ASan crash, and the global parser is
reset between runs.

## Capping one bug to reach the next

The first run tripped UBSan almost immediately on a real meter telegram from the seed corpus: a signed
left-shift of a negative value in the signed-integer decoder, where the accumulator is seeded to all
ones for a negative number and then shifted. With `-fno-sanitize-recover` the run aborts there, which
means that one shallow site was all the fuzzer could see.

To get past it I rebuilt with that one undefined-behaviour class made non-fatal, keeping the rest of
ASan and UBSan. The fuzzer then walked deeper and hit a second site, hard: thousands of aborts, all at
the same line, where each element's type byte is read straight into a state enum that only defines
nineteen values. Any byte outside that range is an invalid enum load. It looked like a swarm of
crashes, but de-confounding it was one root cause reached by many inputs, not many bugs. This is the
same capping trick that gets you past a dominant undefined-behaviour class into the code it was
masking, run here on a parser rather than on a patched tree.

## The result, and fixing it

Memory safety held. Across the capped ASan+UBSan campaign and a separate MSan build there were zero
out-of-bounds reads and zero uninitialized reads, despite the entries that point into the parse
buffer. The low-memory design, with the parser accounting for its own list bounds, carried the load.
What came out were the two undefined-behaviour items, both benign at -O2 without a sanitizer and
neither memory-unsafe: the signed-shift in the integer decode, and the invalid enum load on the type
byte.

Low severity, but cheap to make correct, so I sent a fix upstream. The shift becomes an unsigned
accumulation with an identical two's-complement result, and the state enum gets a fixed `unsigned char`
underlying type, which makes any byte a valid representation and, as a bonus on an embedded target,
shrinks the state fields from four bytes to one. I verified it the way a hardening change should be
verified: all thirty-seven real-meter dumps in the test corpus parse byte-for-byte identically before
and after, and the sanitizer build no longer reports either case.

## Why a thin result is still worth writing up

Two parsers, one already fuzzed and one a robustness-negative with hardening-only findings, is not a
dramatic haul. The durable parts are the method, not the bugs:

- the **full-tree novelty gate**, and a concrete reminder of what a truncated grep costs: a near-
  duplicate of a harness that already exists;
- the **cap-to-reach-deeper** technique, which turns a single dominant undefined-behaviour abort into a
  path toward whatever sits behind it;
- the **de-confounding** that turns thousands of look-alike aborts back into one root cause;
- and the **regression-diff discipline** for a hardening fix, proving the change is bit-for-bit inert
  on real data before asking a maintainer to take it.

*Companion: [A researcher's guide to SML](/guides/sml/).*
