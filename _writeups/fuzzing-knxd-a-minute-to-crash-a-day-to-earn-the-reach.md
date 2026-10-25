---
title: "Fuzzing knxd: a minute to crash, a day to earn the reach"
date: 2026-10-25
project: fieldbusfuzzer
published: true
summary: "A coverage-guided campaign against knxd — the open-source KNX/EIB daemon, with no prior fuzzing history — found a crash in under a minute: a one-byte integer overflow that hands the frame decoder a zero-length payload and trips an assertion. The bug was the easy part. The rest of the writeup is about what the fuzzer can't tell you: whether the crash is memory corruption or just an abort, and whether anything on the wire can actually reach it. Both answers came out smaller than the first impression — and getting them right is the whole job."
---


[knxd](https://github.com/knxd/knxd) is the daemon that most non-proprietary KNX/EIB installations run
to bridge a KNX bus to IP — the building-automation equivalent of a protocol gateway. It parses frames
from the bus (TP-UART/NCN5120 serial adapters) and from the network (KNXnet/IP), it has 600-odd stars
and a long deployment tail, and — per the novelty gate this suite runs before building anything — it
has **no OSS-Fuzz presence, no shipped fuzz harnesses, and no memory-safety CVE history**. The KNX CVE
record is all ETS (the Windows config tool), hardware routers, and protocol-auth logic; the open-source
C++ parsers themselves were untouched by sanitizer-driven fuzzing. That makes knxd a genuine virgin
target, which is exactly what this suite looks for.

This is the writeup of that campaign. The headline isn't the bug — the fuzzer found that in about a
minute. The headline is everything I had to do *after* the crash to say something true about it.

## Earning the right to trust a clean result

Before a single harness is trusted, it has to prove it can catch a bug it already knows about. knxd
handed me a perfect anchor: the pinned HEAD commit was literally *"Fix segfault in busmon PDU decoding
code"* (#665), a NULL-dereference in the busmonitor decode path fixed days earlier. So the plan wrote
itself — `git worktree` the pre-fix parent, build the deep-decode harness against it, and confirm it
reproduces that NULL-deref. It did, cleanly (`L_Busmon_PDU::Decode`, SEGV on a null `L_Data` pointer).
Rebuild against patched HEAD, same input runs clean. Now a *clean* result from the harness means
something, instead of being the silence of a harness that never reached the code.

That is the difference between "the fuzzer found nothing" and "the fuzzer looked and there was nothing
there." Only the second one is worth writing down.

## Three harnesses, one parse unit

KNXnet/IP has a layered shape: a 6-byte envelope, a service dispatch (SEARCH / CONNECT / TUNNEL /
ROUTING / DEVICE_CONFIG…), and underneath it the cEMI / TP1 / APDU decoders that actually chew on
addressing and payload bytes. I split the surface in two:

- an **envelope** harness driving `EIBNetIPPacket::fromPacket` and the eight request parsers, and
- a **deep** harness driving the TP1 frame decoder (`CM_TP1_to_L_Data`), the busmonitor PDU decode, and
  the application-layer `APDU::fromPacket`.

A useful early result was negative: the envelope parsers are *shallow*. Coverage plateaued at ~200
edges because `parseEIBnet_TunnelRequest` and friends just copy the cEMI blob out without parsing it —
`fromPacket` even enforces `len == size`, so the top-level length-lies every fuzzer tries get rejected
immediately. The interesting memory lives one layer down, and the deep harness confirmed it: ~10× the
coverage, and within a minute, a crash.

## The bug: one byte, one overflow, one dead daemon

The crash is an assertion abort in `L_Data_PDU::Decode`:

```
src/libserver/lpdu.cpp:31: Assertion `lsdu.size() >= 1' failed.
```

The root cause is a textbook integer overflow in the extended-frame branch of `CM_TP1_to_L_Data`:

```c
uint8_t len = c[6] + 1;          // c[6] is attacker-controlled
if (len + 8 != c.size())         // length-consistency check
  ...
else
  l->lsdu.set(c.data() + 7, len);
```

`len` is a `uint8_t`. When `c[6] == 0xFF`, `c[6] + 1` wraps to **0**. An 8-byte frame then satisfies
`len + 8 == c.size()` (`0 + 8 == 8`), and the LSDU — the actual payload — is set to length **zero**.
`CM_TP1_to_L_Data` returns a perfectly non-NULL `L_Data` object whose payload is empty, every later
consumer assumes payloads are non-empty, and the first one to look (`L_Data_PDU::Decode`) asserts and
the process is gone. A nine-byte input does it: `1C FF 58 B3 FF FF FF 66` behind a selector byte.

Notice this slips *past* the #665 fix. That fix added a NULL-check because `CM_TP1_to_L_Data` can return
`nullptr`; here it returns a valid pointer to a malformed object. Same function, adjacent mistake, not
covered by the previous patch — which is the honest framing for the report.

## What the fuzzer can't tell you, part 1: corruption or just a crash?

An out-of-bounds write and an `assert()` both look like "SIGABRT" to a fork-mode fuzzer. They are not
the same severity. `assert` is compiled out under `-DNDEBUG`, so the first question is whether a real
build even has it — and knxd's default `./configure` does **not** define `NDEBUG`, so the assertion is
live and the abort is real.

But the scarier possibility is that the assert is merely hiding an out-of-bounds read: with asserts
*off*, does the empty LSDU flow downstream into something that indexes `lsdu[0]`? So I built a third
variant with `-DNDEBUG` (asserts compiled out, confirmed by the absence of `__assert_fail`) and fed it
the trigger. It ran clean. The empty payload is handled gracefully once you get past the assertion;
there is no OOB read hiding behind it. So the honest classification is **integer overflow → reachable
assertion (a denial of service), not memory corruption** — CWE-190 feeding CWE-617, full stop. Scoring
it as a write primitive would have been a lie the tooling would happily have let me tell.

And the rest of the surface? Across the full sweep — ASan+UBSan over roughly **6.9 billion** envelope
executions and **~500 million** deep-decode executions, a **247-million-run** NDEBUG pass to explore
*past* the assertion, a LeakSanitizer pass, and a MemorySanitizer pass whose only reports were the
well-known libstdc++ `std::string` false-positive floor — there was exactly **one** finding. The TP1,
cEMI, and APDU decoders held up. That zero is the one I earned the right to report.

## What the fuzzer can't tell you, part 2: can anything reach it?

This is where the writeup turns, because the in-process harness is a liar by construction: it calls the
decoder directly with any bytes it likes. The real question is whether a frame on an actual transport
can arrive at `CM_TP1_to_L_Data` as an 8-byte payload with byte 6 = `0xFF`. So I stood up a real knxd
daemon, a pseudo-terminal pretending to be an NCN5120 serial adapter, and a real text-busmonitor client
over the knxd API, and tried to deliver the frame end to end.

It didn't crash. And the reason is the good part. The serial receive path assembles frames in
`TPUARTwrap::in_check`, which only hands a frame up once `in.size() >= in[6] + 9`. For `in[6] == 0xFF`
that's 264 bytes — and at 264 bytes the frame no longer satisfies the overflow condition, so
`CM_TP1_to_L_Data` returns `nullptr` instead of an empty-LSDU object. **The serial path cannot
construct the trigger.** The in-process repro was real; the serial wire repro proved it unreachable
*there*.

So is it reachable anywhere? Yes — one path. The KNXnet/IP busmonitor tunnel handler converts a cEMI
blob to a busmonitor PDU through `CEMI_to_Busmonitor`, which has **no length gate** and copies the
payload bytes straight in. That path lives in knxd's role as a *tunnel client* — a knxd that connects
out to a KNXnet/IP server in busmonitor mode, with a local text-busmonitor client attached. The
attacker there is the remote KNXnet/IP server. That is a real, but narrow and client-side, exposure:
not an unauthenticated server-side crash, which is what a careless reading of the in-process crash would
have implied.

So the reachability claim walked back twice — serial (none) and KNXnet/IP (client-side only) — and
landed somewhere far more modest than "knxd crashes on a malformed frame." That walk-back *is* the
finding's real shape. Writing the first version would have been easy and wrong.

## Disclosure

Because this is a narrow, conditional, availability-only robustness bug — not a weaponizable
vulnerability — I reported it the way knxd's maintainer handles this class: a plain, technical GitHub
issue, [knxd#666](https://github.com/knxd/knxd/issues/666), referencing #665, with the reproducer, the
root cause, the honest reachability note, and a one-line fix:

```diff
-  uint8_t len = c[6] + 1;
+  unsigned len = (unsigned) c[6] + 1;   // avoid the uint8_t wrap; 0xFF -> 256, frame then rejected
```

No CVE, no embargo, no drama — the right weight for the finding. *(Status: reported; fix offered.
This section will be updated when it's resolved upstream.)*

## What I'd take away

- **Fuzz the layer that reads bytes.** The KNXnet/IP envelope was shallow; the value was in the cEMI/TP1
  decoders underneath. Coverage told me that in the first minute — listen to it.
- **An assert is not an overflow.** Rebuild with `-DNDEBUG` before you call a SIGABRT "memory
  corruption." Here it demoted the finding from a write primitive to a DoS, correctly.
- **Reachability is the finding.** The in-process crash took a minute; establishing that the serial path
  can't reach it and only a client-side KNXnet/IP path can took the rest of the day — and it's the
  difference between an honest report and an inflated one.
- **Earn your zeros.** Reproducing the already-fixed #665 bug on the pre-patch tree is what makes "the
  decoders held up across billions of executions" a statement instead of a hope.

*Built with the fieldbusFuzzer coverage-guided suite (libFuzzer/ASan/UBSan/MSan). By Shad Malloy
(alosafuzz) — alosafuzz@proton.me.*
