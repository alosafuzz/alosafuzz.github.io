---
title: "A Researcher's Guide to Cospas-Sarsat 406 MHz Beacons"
protocols: ["Cospas-Sarsat", "406 MHz beacon", "SGB", "FGB"]
vendor: ["cospas-sarsat"]
vendor_group: "Search & Rescue (Cospas-Sarsat)"
sector: ["science", "cross"]
transport: ["rf"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: message format, fuzz surface, and the
known security posture only. This is safety-of-life equipment; everything here uses
synthetic frames, never live beacon RF, and there is no exploit or DoS code.*

---

## 1. What it is & where it runs

When an aircraft, ship, or person in distress activates a **406 MHz beacon** — an ELT
on an aircraft, an EPIRB on a vessel, a PLB carried by a person — the burst is picked up
by the **Cospas-Sarsat** satellite system and relayed to ground stations that decode it
and route a rescue. The decoded message carries the beacon's identity (a 15-hex-character
ID), the protocol and country code, and, for location-protocol beacons, an encoded
position. Ground receivers, and the growing number of SDR-based hobby and monitoring
receivers, parse that message with software like
**[moricef/dec406](https://github.com/moricef/dec406)** (MIT, by Fabrice Morel / F4MLV),
the decoder this guide and its companion writeup fuzzed.

Two message generations coexist:

- **First generation (FGB)** — the legacy 406 MHz format: a 112-bit short message or
  144-bit long message, phase-modulated, protected by BCH error-correction.
- **Second generation (SGB)** — the newer spread-spectrum format: a 250-bit message,
  DSSS-modulated, with a stronger BCH code.

The threat model is specific and unusual: the "client" is a radio transmitter, so an
attacker is anyone who can put a crafted 406 MHz burst (or a crafted recorded IQ file) in
front of a receiver. The receiver parses it unauthenticated — there is no session, no
credential, nothing but the message and its error-correction.

## 2. Frame model — a checksum gate in front of the fields

Both generations put the attacker-controlled information bits behind a **BCH
error-correcting code**, and that code shapes the whole fuzzing problem.

- **SGB (2G):** 250 bits total — 202 information bits plus a 48-bit BCH(250,202) parity,
  generator polynomial `0x1C7EB85DF3C97`. The decoder (`decode_2g`) rejects any codeword
  the BCH cannot validate before it reads a single field.
- **FGB (1G):** the 144-bit long message carries two codes — BCH(82,61) over the first
  data block (21 parity bits) and BCH(38,26) over the second (12 parity bits); the 112-bit
  short message carries only the first. `decode_1g` aborts on an uncorrectable BCH.

After the gate, the fields are bit-positional: country code, protocol, the 15-hex ID, and
the protocol-specific body (standard/national/user location, serial-user, aircraft
address, RLS, orbitography for 1G; the corresponding 2G fields). Those extractors write
into fixed buffers — the identity string, the hex ID, coordinate strings — which is where
a length or index bug would live.

## 3. The fuzz surface, mapped to dec406

- **`decode_2g(const uint8_t *rx_bits)`** (src/dec406_v2g.c) — the 2G message decoder:
  BCH check, then country/position/ID/vessel/call-sign extraction into fixed buffers.
- **`decode_1g(const uint8_t *bits, int length)`** (src/dec406_v1g.c) — the 1G decoder:
  BCH-1 (and BCH-2 for long frames), then the location/identification/protocol
  sub-decoders.
- **The DSP front-ends** (`dsss_demod.c` for 2G, `fgb_iq_demod.c` for 1G) — raw IQ
  samples to bits. These are a different kind of surface (see §6).

**The key to reaching the message decoders:** the BCH is *keyless*. A real beacon
computes valid parity for whatever it transmits, so a faithful harness does the same —
synthesize a valid codeword from fuzzer-controlled information bits, and the decoder
accepts it and runs every field extractor. For the 2G code, a standard systematic encode
against the generator above produces valid parity; for 1G, encode the two blocks with
their respective generators. Without that step a coverage-guided fuzzer bounces off the
BCH check forever and never sees a field.

Fields worth seeding to extremes once you are past the gate: the protocol/country codes
(they drive which sub-decoder runs), the hex-ID and call-sign bit ranges, and the
location bit fields for every protocol variant.

## 4. Known security posture (not a CVE list)

dec406 has **no CVE**. The one piece of adjacent prior art is Costin et al. (2023), which
fuzzed a *different* 406 MHz decoder (`dump406`) and the CCSDS layer, not this codebase —
so dec406's message decoders were genuinely unfuzzed. Because this is safety-of-life
equipment, the sane posture for any work here is synthetic/recorded frames only, no live
beacon transmission, and conservative severity scoring on whatever a receiver actually
does with a crafted message.

## 5. A robustness note — the decoders hold up

Fuzzed through synthesized valid BCH codewords under AddressSanitizer, UBSan, and
MemorySanitizer, **both generations are clean**: `decode_2g` and `decode_1g` showed no
out-of-bounds access and no uninitialized read across hundreds of millions of executions.
The field extractors are bounded by construction — the identity and call-sign buffers are
sized to their fixed field widths, the bit readers stay inside the decoded array, and the
text formatting is length-bounded. One detail worth calling out as careful rather than
buggy: the 1G decoder reads its second BCH block only for long frames, so a short frame
never touches the bytes past bit 112 — MSan confirmed no stale read there.

## 6. The DSP front-ends resist fuzzing (and why)

The IQ demodulators that turn samples into bits are a tempting "untested surface," but
they are not viably fuzzable, and it is worth knowing why before you try. The 2G DSSS
demodulator hard-rejects any input whose chip rate (sample rate over samples-per-symbol)
is not within 100 Hz of 38400, which pins the sample rate near the real 2.4576 MHz and
forces inputs into the hundreds of kilobytes. Worse, the acquisition stage runs an FFT
correlation across frequency and lag hypotheses, so a single execution takes on the order
of a second — far too slow for coverage-guided fuzzing. And random samples never acquire,
so they only reach the correlator; the despread and bit-slice stages, where the per-bit
indexing lives, need a genuinely synced burst, which means reimplementing the modulator to
produce one. A mature, "validated bit-perfect" demodulator behind that much setup cost, on
code whose loops are already bounded by the buffer length, is a poor target. The message
decoders — reached cheaply through synthesized codewords — are where a fuzzer's time is
well spent.

## 7. Further reading

- dec406 source: [github.com/moricef/dec406](https://github.com/moricef/dec406)
- Cospas-Sarsat message specifications: C/S T.001 (first generation) and C/S T.018
  (second generation), published by the Cospas-Sarsat programme.
- The companion writeup — the full ASan + UBSan + MSan campaign on both generations, and
  why the negative is worth keeping — is at
  [/writeups/fuzzing-dec406-a-distress-beacon-decoder-that-holds-up/](/writeups/fuzzing-dec406-a-distress-beacon-decoder-that-holds-up/).
