---
title: "Fuzzing CANopenNode: the surface your fuzzer skips"
date: 2026-10-27
project: fieldbusfuzzer
published: true
summary: "CANopenNode is the de-facto open-source CANopen stack, and it had no fuzzing history — a clean virgin target. A multi-hundred-million-execution campaign under ASan/UBSan/LeakSanitizer found nothing: the receive stack is robust. But the story isn't the zero. It's that my first clean run silently never touched the richest surface — SDO block transfer — because it's compiled out by default, and a coverage number that looks saturated can be hiding an entire protocol feature you never built. This is how I found that out, and why an honest negative result is mostly about proving you looked where it matters."
---


The industrial-protocol stacks with the big reputations are mostly picked over. Before building anything
I run a novelty gate, and this round it was unanimous: RT-Labs **p-net** (PROFINET) is saturated — Nozomi
fuzzed it to ten 2025 CVEs and RT-Labs now runs libFuzzer in CI; **OpENer** (EtherNet/IP) ships its own
AFL harness and has two CVE waves behind it; **lib60870** (IEC-104) has a fresh cluster of GitHub
advisories in its information-object parser. All three: don't re-tread.

The one that came back genuinely virgin was **[CANopenNode](https://github.com/CANopenNode/CANopenNode)** —
the CANopen (CiA 301/305) stack that a very large share of open-source CAN devices embed. No OSS-Fuzz, no
shipped harness, no CVE, permissive license. And a useful corroborating signal that the protocol class is
real: a *sibling* stack (RT-Labs C-Open) took two SDO CVEs in 2026. Proven-buggy protocol, untouched
implementation. That's the setup you want.

This is the writeup of that campaign. It found nothing — and getting to a *trustworthy* nothing took three
tries and taught me more than a crash would have.

## Fuzzing a stack that abstracts its own hardware

CANopen isn't an IP protocol; every input is a CAN frame — an identifier plus up to eight data bytes.
CANopenNode is written to be portable, so it talks to the CAN controller through a thin driver layer
(`CO_CANrxMsg_read{Ident,DLC,Data}`, a few `CO_CAN*` functions). That abstraction is the harness seam. I
wrote a mock driver whose read accessors pull from a `{ident, DLC, data[8]}` struct I control, and then —
rather than call each parser directly — I fed frames through the stack the way the real interrupt does:
match the ident against `CO->CANmodule->rxArray` and invoke the registered `CANrx_callback`. One harness,
and every ident routes itself to the right object: SDO server, RPDO, NMT, heartbeat, EMCY, TIME, LSS. After
each frame I tick `CO_process()` so the state machines advance. That's the whole receive surface behind a
single `LLVMFuzzerTestOneInput`.

## The crash that wasn't (de-confounding the harness)

The first thing the fuzzer did was crash — a stack-use-after-return in `CO_LSSslave_receive`. The address
pointed back into my own harness's init frame. `CO_LSSinit` stashes pointers to the LSS address and the
pending node-id/bitrate, and in the real application those live in `main()`, which never returns. I'd put
them in a function that did. Moving them to file scope fixed it, and the "finding" evaporated.

That is the tax on in-process fuzzing, and it is worth paying attention rather than filing a bug: a harness
that lies about object lifetimes manufactures crashes that no device can reproduce. The flip side is that it
proved the plumbing works — ASan plus this harness genuinely catches memory errors on the receive path,
which is exactly the assurance you need before you trust a clean result later.

A second, quieter fidelity issue: the SDO server silently drops every frame unless the node is in
pre-operational/operational NMT state and the server object is valid. My init never pumped the NMT state
machine, so for the first stretch of any run the SDO server was inert. The real node runs `CO_process`
continuously; the harness has to as well.

## The zero I didn't trust

So I ran it. Hundreds of millions of executions, ASan + UBSan + LeakSanitizer, fork mode, value-profile.
Coverage climbed to about twelve thousand edges and plateaued. Zero crashes, zero leaks. By every surface
reading, a clean robustness result.

Then I did the step that actually matters for a negative: I checked whether the campaign had *reached the
code I cared about.* The richest, most suspicious surface in an SDO server is **block transfer** — the
stateful, multi-frame mode that accumulates a large payload across dozens of sub-block segments, exactly the
shape where buffer-accounting bugs live (and exactly where the C-Open sibling CVEs were). I re-introduced a
deliberate out-of-bounds write into the block sub-block copy, rebuilt, and replayed the entire 2,500-input
corpus against it.

Nothing. The planted bug never fired — because **the block-transfer code was not in my binary at all.**
CANopenNode compiles SDO block transfer *out* by default. The clean twelve-thousand-edge plateau wasn't the
stack being robust; it was a third of the SDO server never existing in the build. A coverage number can look
saturated and still be missing an entire protocol feature.

## Reaching the gated code

Turning block transfer on was its own small saga, and the general lesson is worth more than the specifics.
The obvious knob — editing the documented default in `CO_config.h` — did nothing, because the value that
actually takes effect is a *module-local* `#ifndef` fallback in `CO_SDOserver.h`. My edit was to a default
that was never consulted. Once I found the real one and enabled the feature, the compiler told me block
transfer also requires CRC16 (another module-local default) and a receive buffer of at least 900 bytes.
Three separate configuration surfaces, only one of them the one the documentation points you at.

With the feature compiled in, the frames still bounced — the block handshake needs the node operational
(the NMT fix above) and it needs several `CO_process` ticks between frames to walk INITIATE → response →
sub-block before segments are accepted. Only after all of that did a traced run finally show what I was
after: block initiate accepted, state in `SUBBLOCK_REQ`, the payload buffer filling seven bytes per segment
and flushing to the object dictionary. The prime surface was finally under the fuzzer, and coverage jumped
by roughly five thousand edges — the measure of how much had been invisible before.

The re-run on the block-enabled build was, again, clean. This time the zero meant something.

## Earning the zero a third way

A planted bug is a poor anchor when the buffer is large: block transfer flushes each sub-block to the
object dictionary long before the guard I'd weakened ever mattered, so the plant couldn't overflow in that
configuration anyway. So I finished with a static audit instead — every `memcpy`, `memmove`, and pointer
subtraction in the SDO server's buffer accounting, which is precisely the class a coverage-guided fuzzer is
blind to, because the vulnerable path and the safe path share the same edge and differ only in a data value.

Each one held. The block-END `noData` reduction is guarded against underflow; the upload retransmit's
`cntFailed = cntFailed*7 - block_noData` can't go negative because `count` is clamped to seven before
`block_noData` is derived from it; the segment copies are bounded by the same clamp. I backed that with a
set of boundary seeds — zero-length frames, zero and maximum transfer sizes, sequence numbers at the
sub-block edges, a maximal block-END — and every degenerate case ran clean.

## The result, stated honestly

CANopenNode's receive surface is robust. Across both the default and block-transfer configurations —
hundreds of millions of executions under three sanitizers, plus a static accounting audit and a boundary
sweep — nothing surfaced. That is a real and, I think, useful thing to be able to say about a stack this
widely embedded. It is not a disappointment; it is the point.

## What I'd take away

- **Gate before you build.** Three of four candidate stacks this round were already saturated. The cheapest
  rigor in fuzzing is the hour you spend confirming nobody got there first.
- **A clean coverage plateau is a question, not an answer.** Mine was hiding a compiled-out protocol
  feature. Before you report a zero, re-plant a bug and prove the corpus reaches the code you care about.
- **Configuration is attack surface.** The most interesting code in CANopenNode ships off by default and
  behind a module-local override the documentation doesn't point to. Devices that enable block transfer run
  code most fuzzing never compiles.
- **An in-process harness lies about lifetimes and state.** The LSS stack-use-after-return and the inert SDO
  server were both my harness, not the target. De-confounding them is the work; the crash log is not.

*Built with the fieldbusFuzzer coverage-guided suite (libFuzzer/ASan/UBSan/LeakSanitizer), via a mock CAN
driver and the stack's own rx-dispatch. By Shad Malloy (alosafuzz) — alosafuzz@proton.me.*
