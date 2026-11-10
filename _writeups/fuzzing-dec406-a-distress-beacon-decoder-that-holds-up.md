---
title: "Fuzzing dec406: a distress-beacon decoder that holds up"
date: 2026-11-10
project: fieldbusfuzzer
published: true
summary: "A 406 MHz distress beacon is parsed by whoever receives it, unauthenticated, and the message sits behind a BCH error-correcting code. That checksum is the whole problem for a fuzzer: mutate the bits and the decoder rejects the frame before it reads a field. The fix is to stop fighting the code and compute valid parity for the fuzzer's bits, the way a real beacon does, so every field extractor runs. Done that way across both message generations — 2G and 1G — under ASan, UBSan, and MemorySanitizer, dec406's decoders came back clean. The DSP front-end that turns radio samples into bits is a different story: it is effectively unfuzzable, and this is why. A negative on safety-of-life code, and the technique for reaching code that hides behind a checksum."
---

*Defensive security research on safety-of-life software. This describes a fuzzing
method and a negative result; it contains no exploit, and all work used synthesized
frames, never live beacon RF. The target is unmodified open-source software,
[moricef/dec406](https://github.com/moricef/dec406) (MIT).*

---

When someone sets off a 406 MHz distress beacon — an aircraft ELT, a ship's EPIRB, a
hiker's PLB — the Cospas-Sarsat satellites relay the burst to a ground station that
decodes it and starts a rescue. The receiver parses that message with no authentication
and no handshake; there is only the message and its error-correcting code. More SDR
receivers decode these every year, which makes the decoder worth a careful look. I fuzzed
one — [dec406](https://github.com/moricef/dec406) — and it held up. The interesting part
is what it took to reach the code at all.

## The checksum is the problem

Both beacon generations put the attacker-controlled bits behind a BCH error-correcting
code. The second-generation message is 250 bits — 202 of information and a 48-bit
BCH(250,202) parity. The first-generation long message carries two codes, BCH(82,61) and
BCH(38,26), over its two data blocks. The decoder checks the code first and throws the
whole frame away if it does not validate.

For a coverage-guided fuzzer that is a wall. Flip a bit in a valid frame and the BCH now
fails, so the decoder returns at the top and the field extractors — the country code, the
15-hex identity, the position, the call sign — never run. Point a fuzzer at raw frames
and it spends its entire budget generating codewords the decoder rejects, learning
nothing about the parser you actually care about.

The way through is to stop treating the BCH as an obstacle and treat it as part of the
input, because that is what it is to a real beacon. A beacon does not transmit arbitrary
bits; it computes valid parity for its message and sends the whole codeword. So the
harness does the same: take the fuzzer's information bits, compute the correct BCH parity
by systematic encoding against the published generator polynomial, and hand the decoder a
valid codeword. The code is keyless — there is no secret, any transmitter can do this — so
this is faithful, not a cheat. With it in place the decoder accepts every input and runs
every field extractor, and a self-check confirms the synthesized frames pass the decoder's
own BCH test before the campaign starts.

## Both generations, clean

With the extractors reachable, the campaigns were straightforward. The 2G decoder,
`decode_2g`, ran under ASan and UBSan and then MemorySanitizer across tens of millions of
executions and came back clean — no out-of-bounds, no uninitialized read. The full
coverage of the write-heavy path — the identity, hex-ID, call-sign, and coordinate
formatting — confirmed it was a real negative and not a shallow one.

The 1G decoder, `decode_1g`, has more variety: standard, national, and user location
protocols, serial-user, aircraft address, RLS, orbitography, each with its own
sub-decoder. I reached all of them the same way, synthesizing valid BCH-1 and, for long
frames, BCH-2 parity, and covered both the 112-bit short and 144-bit long formats. ASan
plus UBSan across 138 million executions, then MSan across 92 million: clean on both.

One thing I went looking for turned out to be careful code rather than a bug. The 1G
decoder's second BCH check reads bytes from the back half of the frame, which for a short
112-bit frame would be uninitialized — except the decoder gates that read behind a
"long frame only" check, so a short frame never reaches it. MemorySanitizer, which is the
tool that would catch a stale read there, confirmed there was nothing to catch. That is
the kind of thing that distinguishes a decoder someone thought about from one that merely
passes its own tests.

## The part I could not fuzz, and why that is the finding

The honest account includes the surface I did not get a result on. Between the radio and
the message decoders sits a DSP front-end — a DSSS demodulator for 2G, an IQ demodulator
for 1G — that turns samples into bits. It looks like an untested surface, and it is, but
it is effectively unfuzzable, and the reasons are worth stating because they recur in
other radio software.

The 2G demodulator hard-rejects any input whose chip rate is not within 100 Hz of 38400,
which pins the sample rate near the real 2.4576 MHz and forces each input into the
hundreds of kilobytes. Then the acquisition stage runs an FFT correlation across a grid of
frequency and lag hypotheses, so one execution takes about a second — four runs did not
finish in two minutes. At under one execution per second a coverage-guided fuzzer cannot
explore anything. And random samples never acquire, so even when they run they only reach
the correlator; the despread and bit-slice stages, where per-bit indexing actually
happens, need a genuinely synchronized burst. Producing one means reimplementing the
modulator. A mature demodulator that the author describes as validated bit-perfect,
behind that much setup cost, with loops already bounded by the buffer length — the prior
is a negative, and the cost to confirm it the hard way is not justified. So I concluded it
honestly as not viably fuzzable rather than run a token campaign that would only ever
exercise the acquisition front-end and call it clean.

## What the negative is worth

Put together: dec406's message decoders, for both beacon generations, are memory-safe and
free of uninitialized reads across the full ASan-plus-MSan matrix, reached faithfully by
synthesizing the valid codewords a real beacon would send. The field extractors are
bounded by construction. For safety-of-life software that anyone with a transmitter can
put a message in front of, a clean, well-covered negative — stated plainly, with the one
surface I could not reach named rather than papered over — is a result worth writing down.

The reusable piece is the technique: when a parser hides behind a checksum, do not fight
the checksum, compute it. A keyless error-correcting code or CRC is part of the input, and
a faithful harness produces valid ones so the fuzzer spends its budget on the fields
instead of the gate. The beacon message format and the full fuzz surface are in the
companion [Cospas-Sarsat 406 MHz guide](/guides/cospas-sarsat-406/).
