---
title: "Fuzzing gnsstk BINEX: a clean parser and a fight with MSan"
date: 2026-11-10
project: fieldbusfuzzer
published: true
summary: "BINEX is the compact binary format GNSS receivers and geodesy software use to exchange data, and the decoder reads attacker-influenceable records off files and network streams. gnsstk's BINEX reader looked like a strong unfuzzed target: a binary length-lie format, no CVE, quiet source history, next to a RINEX parser someone was already filing crashes against. It came back memory-safe under ASan and UBSan, and the over-read I expected did not fire for a tidy reason. The interesting half was MemorySanitizer, which on a large C++ library fights you twice — unrelated static initializers that abort at load, and exception machinery that drowns the signal — and getting a trustworthy MSan negative meant working around both. A clean result on a reference GNSS parser, and the techniques for MSan-ing a parser buried in a big C++ codebase."
---

*Defensive security research. This describes a fuzzing method and a negative result; it
contains no exploit. The target is unmodified open-source software,
[SGL-UT/gnsstk](https://github.com/SGL-UT/gnsstk) (LGPL-3.0).*

---

GNSS reference networks exchange receiver data in a few binary formats, and BINEX is the
compact one. The decoder sits in front of data that comes off base stations and network
streams, parsed without any authentication in the format itself, which is the kind of
surface worth a look. gnsstk's BINEX reader was a good candidate on paper: a binary
length-lie format, no CVE on the library or its GPSTk predecessor, source that had been
quiet since a 2016 fix, and — the part that made it interesting — a neighbor. Someone had
recently filed crash and heap-over-read issues against gnsstk's RINEX header parsers, a
different format in the same file-handling tree, so the library's parsers were already
under outside scrutiny. BINEX had escaped it.

It held up. The story is partly why it held up, and mostly what it took to prove it with
MemorySanitizer.

## The over-read that wasn't

A BINEX record is a sync byte, then two variable-length integers for the record ID and
the message length, then the message, then a CRC. The variable-length integer, UBNXI, is
where I expected trouble: its decode routine checks only that the starting offset is
within the buffer, then reads forward while each byte's high bit says "more to come," up
to four bytes. Read a truncated varint near the end of a buffer and that looks like a
short-buffer over-read.

It is not, and the reason is worth keeping. The decoder reads from a `std::string`, and a
`std::string` always has an accessible null terminator at index `size()`. That null has
its high bit clear, so it ends the continuation on its own, and the four-byte cap bounds
the rest. The signed variant, MGFZI, bounds-checks its declared length against the buffer
before reading. I confirmed it the direct way — a one-byte continuation byte fed straight
into the decoder does not fault — and then across a fuzzing campaign. Under ASan and
UBSan, both the full record reader, `getRecord`, and the two varint decoders are
memory-safe: no out-of-bounds, no use-after-free. The only sanitizer flag is benign, a
record that declares a zero-length message taking the address of an empty vector's first
element, which is a zero-length read rather than a real access.

That is a genuine negative on the surface a fuzzer reaches cheaply. But ASan and UBSan do
not see reads of uninitialized memory — the read-before-length-check class — and a parser
negative is not finished until MemorySanitizer has run. On a small self-contained target
that is a quick second build. On gnsstk it was most of the work.

## MSan, round one: the library aborts before the fuzzer starts

gnsstk is a large C++ library, and the BINEX decoder pulls in its file-handling
framework, time classes, and utilities. The practical way to fuzz one parser inside it is
to build the library's own CMake with the sanitizer flags and link a small harness
against the result, rather than hand-pick translation units and chase undefined symbols
through the time and math modules.

Built that way under MSan, the harness never reached its first input. Loading the shared
library runs every module's static initializers, and gnsstk's RINEX code — a different
format, not on the BINEX path at all — constructs global objects whose members are left
uninitialized, and uses them at load time. MSan is right to complain, in the narrow sense
that the values are uninitialized, but it is noise for this target: it aborts at library
load, before any BINEX code runs. A source ignorelist for the RINEX files did not fully
silence it, because the offending constructor is a header-inlined function that gets
emitted into an instrumented translation unit regardless of which source you exclude.
Runtime suppressions did not catch it either, since it fires during static initialization.

The fix that worked was to stop linking the unrelated code at all. Instead of the whole
library, I built a minimal object set with MSan — the BINEX files, the file-handling
framework, the utilities, the time classes, and the one math type they need — and left
RINEX and the other formats out entirely. With no unrelated global objects in the binary,
there is nothing to construct at load, and the harness starts clean.

## MSan, round two: the exception path is not a finding

Now it ran, and it reported a use of uninitialized value in the MGFZI decoder. Every
sampled crash pointed at the same line. It is tempting to call that a finding and move on,
and it would have been wrong.

The line is a throw. gnsstk signals a malformed record — here, an MGFZI whose declared
length exceeds the buffer, exactly the length lie I was hoping to break it with — by
constructing an exception and throwing it. The origin trace is clear that the
uninitialized value is a compiler temporary created inside the throw macro, which builds a
source-location string for the exception, not anything derived from the input bytes. The
decoder is doing the right thing: it rejects the lie by throwing. MSan is flagging the
library's own exception-location machinery on the handled error path. At most it is a
latent hygiene nit in gnsstk's throw macro; it is not a security bug, and it is not in the
BINEX logic. It dominates the run — coverage barely moves, because every malformed input
takes that throw and halts there — which is itself the tell: a real data-flow bug does not
land on precisely the error path the parser uses for every bad input.

So the honest MSan result is "no finding," reached by recognizing two kinds of noise: the
unrelated static-init aborts, worked around by linking a minimal target, and the
exception-machinery reports, read correctly by following the origin trace.

## What the negative is worth

gnsstk's BINEX record decoder is memory-safe and free of attacker-controlled
uninitialized-data flow on the fuzzed surface — the record framing and the UBNXI and
MGFZI varints. The suspected over-read is bounded by the string null terminator and the
varint cap, and the code rejects length lies by throwing cleanly. The gate that flagged
this as a strong unfuzzed target read it right; the code is simply robust, which for a
parser next to one that was already yielding crashes is a result worth recording.

The reusable part is the method for MemorySanitizer on a parser buried in a big C++
library: build the library its own way for ASan and UBSan, but for MSan link a minimal
object set that excludes the unrelated modules whose static initializers will otherwise
abort you at load, and when the run lights up on a throw, read the origin before believing
it. The BINEX wire format and the full fuzz surface are in the companion
[BINEX guide](/guides/binex/).
