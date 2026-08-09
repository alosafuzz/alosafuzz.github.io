---
layout: post
title: "Fuzzing the time: coverage-guided testing of PTP, gPTP, and NTS across four implementations"
date: 2026-08-09 08:00:00 -0600
---
Almost everything that has to agree on *when* leans on a small set of network time protocols. NTP is
the famous one, and it has been fuzzed to death — Project Zero's AFL campaign, AmpFuzz, and continuous
OSS-Fuzz coverage on ntpsec. So I went looking for the parts of the time ecosystem that *haven't* had
that attention: the Precision Time Protocol (PTP / IEEE 1588) that underpins telecom, finance, and
industrial timing; its automotive/TSN cousin gPTP (802.1AS); and Network Time Security (NTS, RFC 8915),
the TLS-authenticated layer that finally makes NTP trustworthy.

This is a writeup of a structured fuzzing campaign against those four implementations —
**linuxptp** and **ptpd** for PTP, **chrony** and **ntpsec** for NTS. The headline result is not a
string of CVEs. It's the opposite, and I think that's worth saying plainly: across roughly **840
million executions**, under AddressSanitizer and UndefinedBehaviorSanitizer, against every part that I
could reach, **I found no memory-safety or undefined-behavior defects.** These are mature, careful
codebases, and they held up. A robust result, rigorously arrived at, is a legitimate outcome — and the
interesting story is in *how* you make a "nothing broke" claim trustworthy.

## The method, briefly

I fuzzed these targets **in-process and coverage-guided** (libFuzzer + ASan/UBSan), not black-box over
the wire. Every target here is open source, so I compiled it with instrumentation and drove its real
parsing and handling code directly. A few techniques did the heavy lifting:

- **Structure-aware mutation.** Length-prefixed, TLV-heavy grammars (PTP messages, NTS-KE records)
  bounce random bytes off the first length check. Custom mutators that keep type/length fields
  consistent are the difference between shallow and deep coverage.
- **Genuine state, not forced state.** Many handlers only run in a specific protocol state (a PTP port
  must be SLAVE to process Sync). I reached those states by driving the implementation's *own* state
  machine (feeding a better-master Announce, running the real BMCA), so the state — and any bug found
  in it — is real, not an artifact of me poking a struct.
- **Valid crypto envelopes for crypto-gated parsers.** An NTS server only parses the inner extension
  fields *after* decrypting an authenticated request. Random bytes never get there. So I used the
  implementation's own key material to build genuinely valid cookies and authenticators wrapping the
  fuzz input as the decrypted plaintext — the only honest way to reach the inner parser.
- **Cross-implementation differentials.** For two protocols I ran a second implementation's parser
  against the first on identical bytes, looking for disagreements that would signal a spec-parsing
  divergence.

## Coverage matrix

The point of a "nothing broke" result is the reach behind it. Rows where the target simply held up are
collapsed; the numbers are function/region coverage of the *reachable* attack surface (whole-file
percentages are lower and misleading — they include transmit/build, servo, and timer code a receive-path
fuzzer structurally cannot reach).

| Attack Surface | Implementation | What was fuzzed | Reach | Executions | Result |
|---|---|---|---|---|---|
| PTP message parser | linuxptp v4.4 | `msg_post_recv` + all TLV sub-parsers, incl. structure-aware mutator passes | **100% of reachable** | 251M+ | held up |
| PTP header decode (differential) | linuxptp vs ptpd | 6 common-header fields | — | 72.7M | 0 divergences |
| PTP handlers / state machine | linuxptp v4.4 | management, sync, delay, signaling, unicast | management 90%, sync 85%, unicast-service 47% | ~90M | held up |
| gPTP / 802.1AS (L2) | linuxptp v4.4 | `has_prp_trailer` (L2 frame parse) | 95% | 60.2M | held up |
| NTS-KE record parser | chrony 4.8 | framing + client + server dispatch | framing 100%, server 100%, client 86% | 131.6M | held up |
| NTS NTP-path EF parser (request) | chrony 4.8 | `NEF_ParseField` (extension-field structural parse) | **100%** | 54.6M | held up |
| NTS-KE inner (crypto-gated) | chrony 4.8 | decrypted request EFs | **100%** | 26.8M | held up |
| NTS-KE (real 2nd impl) | ntpsec | `nts_ke_process_receive` under ASan | 94.7% | 101.4M | held up |
| NTS client response (hostile server) | chrony 4.8 | decrypted response EFs | 87% | 27.5M | held up |
| NTS-KE framing (differential) | chrony vs ntpsec | record type/length/critical + bounds | — | 24.7M | 0 divergences |

Two independent PTP implementations agree on header decoding; two independent NTS implementations agree
on record framing. Nothing crashed.

## A few things worth reading

Most of the campaign is "held up fine," so here are only the parts I found genuinely interesting.

**When 100% coverage isn't reachable — and that's the answer.** linuxptp's management-message parser
sat stubbornly at 98% of lines, with a handful of `if (data_len < 2) goto bad_length` guards I couldn't
hit. It turns out they're *provably unreachable*: the field is a 2-byte id, the only caller invokes the
parser solely when the TLV length exceeds 2, and odd lengths are rejected upstream — so `data_len` is
always ≥ 2. The guards are dead code by construction: good defensive programming that a caller invariant
makes impossible to trigger. Proving a branch unreachable is as valuable as covering it.

**gPTP is mostly the code you already fuzzed.** I expected 802.1AS to be a distinct target. It isn't:
in linuxptp, gPTP reuses the same message/TLV parser and handlers as L3 PTP — the "profile" is a config
flag and a modified best-master comparison, not a new parser. The only genuinely new attacker-reachable
code is the L2 frame wrapper (`has_prp_trailer`, a small PRP-trailer detector), which I fuzzed clean.
Scoping the *delta* of a protocol variant, instead of re-fuzzing shared code, is a result in itself.

**Reaching the crypto-gated parsers.** The most interesting harness work was for NTS. An NTS server
parses a client's inner extension fields only after decoding an authenticated cookie and decrypting the
request; a random packet dies at the cookie. So I held the server keys myself, generated valid cookies
and authenticators with the implementation's own routines, and made each fuzz input the *decrypted*
inner content. That took the inner extension-field parser from 0% to full coverage on the server side
(100%, parsing a client's decrypted request) and to 87% on the client side (parsing a hostile server's
decrypted response). This is the right way to fuzz authenticated protocols: don't fight the crypto, use it.

**Catching your own false positives.** Twice the harness "crashed" and twice it was the harness, not
the target. A NULL-dereference in linuxptp's unicast timer fired only because I manually triggered a
timer the real daemon only arms when the feature is configured — unreachable in production. And several
`Assertion 'initialised' failed` aborts in chrony were just missing module-init calls in my setup. The
discipline that makes a "0 findings" claim credible is the same one that rejects a false finding:
before believing a crash, prove the trigger is reachable in the real program.

## Disclosure status

Nothing to disclose. I want to be precise about what that does and doesn't mean, because "we fuzzed it
and found nothing" is easy to say and hard to justify:

- **What it means:** across the parsing and message-handling surfaces I could reach — PTP message and
  TLV parsing, the linuxptp state machine, the L2 frame wrapper, and NTS record + extension-field
  parsing in two implementations including the crypto-gated inner parsers — no input triggered a
  memory-safety or undefined-behavior fault, over hundreds of millions of executions.
- **What it does not mean:** I did not test the transmit/build paths, the servo and clock-discipline
  math, timer-driven logic, or the TLS library itself (I fuzz *above* the completed handshake, by
  design). Some reachable code I chose not to drive for diminishing returns — the unicast renewal state
  machine, one gPTP follow-up path — and I've documented those as untested-but-reachable rather than
  pretending they're covered. A clean result is only as good as its honesty about its edges.

## Lessons

- **A robustness result is a real result.** Framed honestly — with coverage numbers, the reachable
  surface named, and the untested edges listed — "it held up" is a legitimate and useful finding.
- **Coverage is the metric, not crash count.** Raw crash count measures your harness's hygiene. Edge
  coverage of the target, and proof of what you reached, measures the test.
- **Function coverage beats file coverage for handlers.** Whole-file percentages are dragged down by
  out-of-scope transmit/servo/timer code; the reachable-function figure is the honest one.
- **Use the implementation against itself.** Its own state machine gets you genuine states; its own
  crypto gets you past authenticated gates; its own init order gets a real object standing up.
- **Verify before believing — a crash or a "clean."** The same reachability check rejects a false
  finding and validates a robustness claim.

## Closing

I set out to find bugs in under-tested time protocols and instead spent most of the time proving I
couldn't. That's an anticlimax for a bug hunter and a good day for anyone whose clocks depend on this
code. The deployed reality is that the maintainers of linuxptp, chrony, and ntpsec have written parsers
that survive structured, coverage-guided, sanitizer-backed fuzzing across their reachable attack surface — and
that two independent implementations of each protocol agree on how to read the wire. That is a quieter
story than a CVE, but it is the one the evidence supports, and I'd rather publish the result the data
actually shows.

## Glossary

**Protocols & standards**
- **PTP** — Precision Time Protocol (IEEE 1588); synchronizes clocks to sub-microsecond accuracy over
  packet networks.
- **IEEE 1588** — the standard defining PTP.
- **gPTP** — Generalized PTP (IEEE 802.1AS); the PTP profile used in automotive and industrial
  Time-Sensitive Networking, carried directly over Ethernet (L2) instead of IP/UDP.
- **802.1AS** — the IEEE standard defining gPTP.
- **TSN** — Time-Sensitive Networking; the family of IEEE 802.1 Ethernet standards (including 802.1AS)
  for deterministic, low-latency networking.
- **NTP** — Network Time Protocol; the original and most widely deployed time-sync protocol.
- **NTS** — Network Time Security (RFC 8915); adds TLS-based authentication and integrity to NTP.
- **NTS-KE** — NTS Key Establishment; the TLS sub-protocol of NTS that negotiates cookies and keys
  before authenticated NTP exchanges begin.
- **RFC 8915** — the IETF standard defining NTS.
- **TLS** — Transport Layer Security; the protocol NTS-KE runs over (this campaign fuzzes above the
  completed handshake, not the TLS library itself).

**Fuzzing & tooling terms**
- **TLV** — Type-Length-Value; a self-describing binary encoding (a type tag, a length field, then a
  body) used throughout PTP messages and NTS-KE records.
- **BMCA** — Best Master Clock Algorithm; the PTP/gPTP algorithm ports run to elect which clock on the
  network is the authoritative time source.
- **ASan** — AddressSanitizer; compiler instrumentation that detects memory-safety errors (buffer
  overflows, use-after-free) at runtime.
- **UBSan** — UndefinedBehaviorSanitizer; compiler instrumentation that detects undefined-behavior
  violations (integer overflow, misaligned access, etc.) at runtime.
- **libFuzzer** — the in-process, coverage-guided fuzzing engine (part of LLVM) used to drive every
  harness in this campaign.
- **Edge / region coverage** — a measure of which control-flow paths in the compiled code were
  exercised; the progress metric used here instead of raw crash count.
- **L2** — OSI Layer 2, the Ethernet/data-link layer; gPTP frames are sent directly at L2.
- **CVE** — Common Vulnerabilities and Exposures; the public identifier scheme for disclosed
  vulnerabilities.
- **OSS-Fuzz** — Google's continuous fuzzing service for open-source projects, referenced here as prior
  art already covering NTP/ntpsec.

**Implementations fuzzed**
- **linuxptp** — the reference Linux implementation of PTP/gPTP (`ptp4l`), pinned at v4.4.
- **ptpd** — an independent, second PTP implementation, used here only for the header-decode
  differential.
- **chrony** — a widely deployed NTP/NTS daemon; the primary NTS-KE target (client, server, and
  NTP-path extension-field parsing).
- **ntpsec** — a second, independent NTS implementation, used for both the real-parser ASan fuzzing and
  the NTS-KE framing differential against chrony.

*Tooling: [timeFuzzer on GitHub](https://github.com/alosafuzz/timeFuzzer). Reach me at alosafuzz@proton.me.*
