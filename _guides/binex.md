---
title: "A researcher's guide to BINEX (GNSS binary exchange)"
protocols: ["BINEX", "UBNXI", "MGFZI"]
vendor: ["cross"]
vendor_group: "GNSS (geodesy)"
sector: ["science", "cross"]
transport: ["file", "tcp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series, written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
known security posture only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

GNSS reference networks move receiver data, orbits, and clock products around in a
handful of binary formats, and **BINEX** (Binary EXchange) is the compact one receivers
and processing software speak when they do not want the bulk of ASCII RINEX. It carries
observations, ephemerides, site metadata, and receiver state as self-describing binary
records. Where it shows up for a researcher: geodesy post-processing tools and receiver
software read BINEX from files and from network streams coming off base stations, so the
decoder sits in front of attacker-influenceable data with no authentication in the
format itself.

The decoder this guide and its companion writeup fuzzed is the BINEX reader in
**[SGL-UT/gnsstk](https://github.com/SGL-UT/gnsstk)** (the maintained successor to
GPSTk), `core/lib/FileHandling/Binex/BinexData.cpp`.

## 2. Frame model — records and two variable-length integers

A BINEX record is a short, regular structure:

```
[ sync byte ][ record ID ][ message length ][ message bytes... ][ CRC ]
```

- **Sync byte** — one byte of record flags (endianness, forward/reverse readability,
  CRC variant). The reader validates it before anything else, which is the gate a fuzzer
  has to get past first; it is a one-byte space, so a coverage-guided fuzzer finds a
  valid sync quickly.
- **Record ID and message length** are each a **UBNXI** — an unsigned variable-length
  integer, 1 to 4 bytes, each byte's high bit flagging "more to come." This is the
  format's length-lie primitive: the declared message length is attacker-chosen and
  drives how many bytes the reader then consumes.
- **Message bytes** are the record payload, parsed per record ID by the application.
- **CRC** closes the record.

Inside the message, signed values use **MGFZI**, a signed variable-length integer whose
first nibble carries a sign flag and a 1-to-8 byte length. Both UBNXI and MGFZI are the
small decoders where a length or bounds mistake would live, so they are where to aim.

## 3. The fuzz surface, mapped to gnsstk

- **`BinexData::getRecord(std::istream&)`** — reads one record off a stream: sync
  validation, the two UBNXI varints, the message bytes, the CRC. Driveable directly with
  a `std::istringstream` over fuzzer bytes (it is a public method; no FFStream wrapper
  needed).
- **`BinexData::UBNXI::decode(const std::string&, offset, littleEndian)`** and
  **`MGFZI::decode(...)`** — the varint decoders, public and string-based, so a second
  harness can hit them straight on. These are the obvious length-lie targets: feed a
  truncated varint and see whether the decoder reads past the buffer.
- Fields to seed to extremes: the UBNXI continuation chains (`0x80 0x80 0x80 0x80`), the
  MGFZI length nibble (claim 8 bytes with 1 byte present), the declared message length
  versus the bytes actually supplied.

## 4. Known security posture (not a CVE list)

There is **no published CVE** on gnsstk or its predecessor GPSTk for BINEX. The one
adjacent signal worth knowing: in early 2026 an external researcher filed crash and
heap-over-read issues against gnsstk's **RINEX** header parsers (a different file format
in the same library), so someone is fuzzing the file-handling code. The BINEX decoder
itself showed no such history — its source has been quiet since a 2016 record-length fix
and a 2022 static-analysis pass — which is what made it a worthwhile, genuinely unfuzzed
target.

## 5. A robustness note — the BINEX decoder holds up

Fuzzed under AddressSanitizer and UBSan across both `getRecord` and the UBNXI/MGFZI
decoders, the BINEX reader is **memory-safe** on this surface: no out-of-bounds, no
use-after-free. The tempting bug — UBNXI's decode checks only the starting offset before
reading, which looks like a short-buffer over-read — does not actually fire, for a reason
worth internalizing: reading a `std::string`, the implicit null terminator at `[size()]`
has its high bit clear, so it ends the varint continuation, and the 4-byte cap bounds the
rest. MGFZI bounds-checks its declared length against the buffer. The one thing a
sanitizer flags is benign: a record declaring a zero-length message makes the reader take
the address of an empty vector's first element, a zero-length read, not a real access.

## 6. Fuzzing a decoder buried in a large C++ library

BINEX is a good example of the real cost of fuzzing one small parser inside a big C++
codebase, and two techniques carry over to any similar target.

**Build the library's own way, then link a tiny harness.** gnsstk is CMake, and the
BINEX path pulls in the file-handling framework, the time classes, and utility code. Hand
-picking translation units turns into a game of chasing undefined symbols; configuring the
project's CMake with the sanitizer flags and building its library target resolves the
dependency graph for you. Point the harness at `getRecord` and the public varint decoders
and you are fuzzing the real code.

**MemorySanitizer needs the unrelated modules kept out.** MSan is the tool that catches
the read-before-length-check class ASan cannot see, and on a library like this it fights
back twice. First, loading the shared library runs the static initializers of every
module, and gnsstk's RINEX code constructs global objects with uninitialized members at
load time, so MSan aborts before your harness runs. A source ignorelist does not fully
help, because the offending constructor is header-inlined into an instrumented
translation unit. The clean fix is to stop linking the unrelated modules at all: build a
minimal object set — the BINEX files, the file-handling framework, utilities, time, and
the one math type they need — with MSan, and leave RINEX and the other formats out
entirely, so there is no unrelated global to trip over.

Second, once it runs, MSan on this decoder reports only the library's exception machinery.
gnsstk signals malformed input by throwing, and its throw macro builds an exception with a
source-location string from a compiler temporary that MSan considers uninitialized. Every
length-lie input takes that handled error path, so the reports pile up on the throw, not on
any data flow — noise, not a finding, but it will dominate an MSan run until you recognize
it. The lesson: on a library that uses exceptions for input validation, expect MSan to
light up the throw path, and read the origin trace before believing it.

## 7. Further reading

- gnsstk source and BINEX reader: [github.com/SGL-UT/gnsstk](https://github.com/SGL-UT/gnsstk)
- The BINEX format is documented by UNAVCO/EarthScope.
- The companion writeup — the full ASan + UBSan + MSan campaign and the big-C++-library
  fuzzing lessons — is at
  [/writeups/fuzzing-gnsstk-binex-a-clean-gnss-parser/](/writeups/fuzzing-gnsstk-binex-a-clean-gnss-parser/).
