---
title: "Fuzzing Open-C37.118: the parser with no length"
date: 2026-11-11
project: fieldbusfuzzer
published: true
summary: "Open-C37.118 is the open C++ reference for the synchrophasor protocol that carries PMU measurements into grid wide-area monitoring. Its receiver parsers take a raw buffer and no length, and validate neither the frame size nor the per-station counts, so one crafted frame walks a cursor off the end, a remote and unauthenticated denial of service of the concentrator. The writeup covers the harness, the three-sanitizer matrix, a correction to when MemorySanitizer is actually feasible on C++, and why an unmaintained but forked reference library still deserves a coordinated report."
---

*Defensive security research. This writeup describes a fuzzing methodology and the
issue it found; it contains no exploit, no trigger bytes, and no DoS code. The
target is unmodified open-source software,
[Open-C37.118](https://github.com/marsolla/Open-C37.118) (GPL-3.0). The finding was
reported to the maintainer under coordinated disclosure; the fix is merged and the
advisory published ([GHSA-h97w-jg62-9qhg](https://github.com/marsolla/Open-C37.118/security/advisories/GHSA-h97w-jg62-9qhg)).*

---

## Why this one

IEEE C37.118 is how the power grid sees itself in real time: phasor measurement units in substations
stream time-stamped voltage and current phasors to concentrators, which feed the wide-area monitoring
systems operators watch for stability. The protocol authenticates nothing; a concentrator parses
whatever frames arrive from the field. Open-C37.118 is the open C++ reference implementation, and
vendor products fork it, so a bug in its parser is a bug in a lineage, not one program.

The novelty check was clean in a way that is worth stating, because C37.118 parser bugs do exist and
it would be easy to mistake them for prior work on this library. The C37.118 CVEs on record are in
*other* codebases: a heap overflow and a leak in Wireshark's dissector, memory problems in OSIsoft's
PI interface. The one piece of academic fuzzing, PhasorSec, built its *own* hardened parser with
parser combinators, precisely because the verbose spec makes a hand-written parser error-prone -- it
did not fuzz this library. Open-C37.118 itself ships no fuzzer, is not on OSS-Fuzz, has no CVE, and
its parsing code has not changed since the 2014 initial commit. Virgin, by every axis I checked.

## The harness

The receiver seam is `CONFIG_Frame::unpack`, the configuration-frame parser. The reference calls it
straight off the socket (`read(sock, buffer_rx[80000])` then `unpack(buffer_rx)`), so the harness
is almost nothing: copy the fuzz bytes into a buffer and call `unpack`. The one deliberate choice is
the buffer. `unpack` takes no length argument, so to find reads past the frame I used a tight
`malloc(size)` buffer, where any over-read is a hard sanitizer error, rather than the 80000-byte
stack buffer the reference uses, where a modest over-read would hide in the slack.

The signature is the whole story in miniature. `void unpack(unsigned char *buffer)`, a parser for
attacker-controlled network frames that is structurally incapable of knowing where the frame ends.

## What fell out

The first crash came in about twenty seconds, and the deeper one followed from reading the code.

The configuration parser reads `pmu_count` from the frame, then for each station a 16-byte name, a
format word, and the channel counts `PHNMR`, `ANNMR`, `DGNMR`, then walks two cursors through the
per-channel names and conversion factors. Nothing is checked against the received length. Three
manifestations of the one defect:

- A frame shorter than the common header runs the fixed header reads straight past the buffer. There
  is no minimum-length check.
- Inside the per-station loop, the 16-byte name reads and the channel-factor reads run past a short
  frame -- the parser trusts that the bytes the counts promise are present.
- The sharpest one: a station that declares a phasor count near its maximum makes the parser compute
  a channel-block offset of about a megabyte and then dereference it. That is well past the 80000-byte
  receive buffer, so it is a hard segfault in the field, not only under the tight-buffer harness. One
  configuration frame crashes the concentrator.

The data-frame parser has the same shape: it reads measurements according to the counts in a
previously received config, so an inflated config followed by a short data frame reaches the same
over-read by a second path. This is one architectural defect (a parser family that takes no length
and validates no count) expressed across every frame type, so the fix is one design change (give
the parsers the received length and bound every read and every count against it), not a point patch.

Scored conservatively: an out-of-bounds read and a crash, a one-frame denial of service of a grid
concentrator, remote and unauthenticated. The over-read also pulls memory next to the frame into the
parsed station names and values, but I did not demonstrate that reaching the attacker, so I claim no
information disclosure; I saw no out-of-bounds write, so no code execution.

## The sanitizer matrix, and a correction about MemorySanitizer

AddressSanitizer plus UndefinedBehaviorSanitizer gave the deterministic result: three reproducible
over-read sites, including the megabyte-jump segfault. The interesting part was MemorySanitizer.

My standing note had been that MSan is impractical on STL-heavy C++ because an uninstrumented
standard library floods it with false positives, and I nearly skipped it here on that basis. That
note was wrong about the cause. The flood is specific to `-stdlib=libc++`: libc++'s headers are
inlined into your instrumented translation unit, so the sanitizer sees libc++'s own uninitialized
small-string and allocator reads and reports them. With the **default libstdc++**, the standard
library lives out-of-line in an uninstrumented shared object, the parser's own code is the only thing
instrumented, and MSan runs clean on well-formed input. So MSan was feasible here with nothing more
than `-fsanitize=fuzzer,memory` and no `-stdlib` flag, and it corroborated the finding, reporting the
over-reads as use-of-uninitialized values. The lesson, which I've folded back into the pre-build
checklist: for an `std::string`/`std::vector` C++ target, try the MSan build with the default
libstdc++ before declaring MSan infeasible.

## Reporting an unmaintained reference

The awkward part of this one is the channel. The repository is effectively dormant: the parsing code
has not changed since 2014, and an open pull request and an open issue have sat unanswered since 2022.
But the maintainer's account is active, so the first move is still a direct, private email with the
fix written out, which is what I did. If that goes unanswered, an unmaintained but widely-forked
reference is exactly the case where a public record matters more than an upstream merge: a CVE through
the coordinator-of-last-resort gives the downstream forks and the scanners something to track, and the
active forks get notified directly. The fix is portable enough that a fork can carry it regardless of
whether upstream ever moves.

The transferable parts need none of the specifics: a parser whose signature cannot express a length is worth a second look, the
tight-buffer harness is what turns a quiet over-read into a crash you can see, and MemorySanitizer on
C++ is a default-libstdc++ build away, not a lost cause.
