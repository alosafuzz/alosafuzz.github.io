---
title: "Fuzzing wmbusmeters: the denial of service AFL counts as a clean exit"
date: 2026-10-30
project: fieldbusfuzzer
published: true
summary: "wmbusmeters already ships AFL fuzzers, but they only reach the difvif parser and run the whole binary under AFL_HARDEN, never a sanitizer-instrumented pass on the telegram decoder. An in-process libFuzzer harness on Telegram::parse under ASan and UBSan found seven issues, headed by an unauthenticated one-telegram process exit that AFL structurally cannot see. The maintainer fixed every one the same day, which turned the writeup into a short lesson on reporting paths and on refuzzing a patch."
---

*Defensive security research. This writeup describes a fuzzing methodology and
the issues it found; it contains no exploit. The target is unmodified open-source
software, [wmbusmeters](https://github.com/wmbusmeters/wmbusmeters), GPL-3.0. All
issues below were reported to the maintainer and fixed before publication.*

---

## Why wmbusmeters, and the gap

wmbusmeters is the open-source daemon most self-hosted setups run to read wireless M-Bus meters off
an SDR or a USB dongle and forward them to MQTT, a file, or a database. It decodes whatever a meter
puts on the air, which makes the realistic attacker a spoofed or malicious meter, or anything that
can inject a telegram into one of the non-radio inputs (a simulate file, stdin, an MQTT bridge). None
of it needs a configured meter key to reach the parser.

The reason it was worth a campaign is a gap, not a hunch. The project already fuzzes itself: `src/fuzz.cc`
drives the difvif record parser under AFL, and a `run_fuzz_telegrams` target runs the whole binary over
telegrams with `AFL_HARDEN`. Neither of those is a sanitizer-instrumented in-process pass on the
telegram decode path. That is the seam this suite looks for: don't re-tread what the shipped harness
covers, go at the layer it skips.

## The harness

The entry point is `Telegram::parse(frame, MeterKeys*, warn)`, the function that takes raw bytes and
walks the whole chain: the data link header, the extended and network layers, the authentication and
fragmentation layer, the transport layer, AES decryption, and finally the difvif data records. The
harness is about twenty lines: build a `vector<uchar>` from the fuzz input, set a fixed test key so
the decrypt path is reachable, and call `parse`. I built it with clang under AddressSanitizer and
UndefinedBehaviorSanitizer. MemorySanitizer is impractical here, because the decoder pulls in enough
of libstdc++ that an uninstrumented standard library floods it with false positives, the same wall I
hit on other heavy-STL C++ targets and unlike the self-contained C decoders where MSan is cheap.

Two structural facts explain why the in-tree fuzzing had not found these. AFL treats a call to
`exit()` as a clean exit, so a parser that deliberately terminates the process never registers as a
crash. And `AFL_HARDEN` is not ASan or UBSan, so out-of-bounds reads and integer undefined behavior
are invisible to it. Change the harness to in-process libFuzzer under sanitizers and both of those
blind spots light up.

## What fell out

Seven issues, all reachable from the bytes of a received telegram, all scored conservatively on
demonstrated impact. I claimed no write, no corruption, and no code execution.

The headline is an availability bug. On a malformed compact-profile telegram, the decode path reaches
`DVEntry::extractLong`, which calls the library's `error()` helper, and that helper is marked
no-return and calls `exit()`. One crafted telegram therefore terminates the whole process. For a
central decoder serving a site over MQTT or a shared feed, that is a one-telegram outage, and it is
exactly the bug AFL reads as a clean exit.

The rest are memory-safety and hardening:

- Three out-of-bounds reads where a length field is read or trusted before it is checked against the
  bytes actually remaining in the frame: the data-link C field, the authentication-layer length byte,
  and the authentication-layer MAC copy, which could run up to sixteen bytes past the buffer. Bounded
  over-reads, low severity on their own, but real.
- An attacker-sized stack allocation in the decrypt helper, where a length derived from the telegram
  sizes a variable-length array. A fuzz input drove it to zero, which is undefined on its own; the
  larger worry is a big value turning into an unbounded stack allocation.
- Two undefined-behavior sites in the difvif decoder: a signed left shift driven past its width by a
  long DIFE chain, and a signed integer overflow in the BCD-to-integer conversion. Neither is memory
  unsafe, both are easy to make defined.

One build note that generalizes. On the plain sanitizer build, UBSan aborts on the difvif shift
before the deeper code runs, which hides the exit and the allocation bugs behind it. Rebuilding with
those two undefined-behavior classes made non-fatal (keeping the rest of ASan and UBSan) lets the
fuzzer walk past them and reach what they were masking. The exit bug also reproduces on the plain
build, because it is hit before any shift fires.

## The reporting path

Before contacting anyone I work out how the maintainer wants to hear about this: a SECURITY.md,
GitHub's private vulnerability reporting toggle, a security contact in the repo. wmbusmeters had none
of those, and private reporting was off, so I sent a plain email and set a ninety-day clock. That is
the conservative default when the policy is unknown, and it is also the wrong shape for a maintainer
who would rather just get a patch.

The reply, in substance, was: why send a private report instead of a pull request with the fix? The
maintainer then added a SECURITY.md saying so directly, that nothing here is secret, that reports
should be public, and that if a tool found the bug the finder should spend the time to fix it and
open a PR. Had that file been there when I started, my opening move would have been a fix-and-harness
PR rather than an email and a wait. A current SECURITY.md is the cheapest signal a project can give:
it tells a researcher whether step one is a quiet report or a pull request. The missing file cost a
round-trip, and the report is what produced it. For more on choosing that first move, see
[the disclosure spectrum after the fuzzer](/writeups/the-disclosure-spectrum-after-the-fuzzer/).

## The fix, and refuzzing it

The maintainer fixed all seven the same day: the exit became a returned error, the length reads got
their checks, the decrypt length was bounded, and the difvif accumulator was widened. That is about as
good as coordinated disclosure gets.

Refuzzing a patch is still part of the job, so I rebuilt the harness against the fixed tree and
replayed the inputs. The memory-safety and availability set is confirmed resolved: those telegrams
now parse cleanly. The two difvif undefined-behavior cases still trip UBSan on the current tree,
because the fix widened the accumulator while the intermediate shift and the BCD arithmetic are still
evaluated in `int`. These are hardening items, not memory-safety bugs, and how far to chase them is
the maintainer's call. I noted it and moved on.

The durable deliverable is the harness itself. I opened it as a pull request so the sanitizer-driven
pass on `Telegram::parse` lives in the tree alongside the existing AFL targets, with the reported
inputs as a regression corpus. The whole exchange, from first email to merged-ready harness, is a
small argument for the gaps-only doctrine: the shipped fuzzer was real and useful, and the bugs were
sitting in the one layer and the one failure mode it was built not to see.

*Companion: [A researcher's guide to wireless M-Bus](/guides/wireless-m-bus/).*
