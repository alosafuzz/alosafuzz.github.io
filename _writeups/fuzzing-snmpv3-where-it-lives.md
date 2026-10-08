---
title: "Fuzzing SNMPv3 where it actually lives"
date: 2026-10-07
project: snmpv3fuzzer
summary: "A coverage-guided campaign against lwIP's SNMPv3 agent (post-CVE-2026-8836): ~200M executions, no memory-safety bug, one benign UB — and making a 'nothing broke' result trustworthy."
---
SNMP is old, unglamorous, and everywhere. It runs the management plane of nearly
every switch, router, printer, UPS, and a great deal of industrial and IoT gear —
and SNMPv3 added a real security model (USM: users, engine IDs, HMAC authentication,
DES/AES privacy) on top of a wire format that is still, underneath, hand-rolled
ASN.1/BER parsing. That combination — ubiquitous, security-relevant, and parsing
attacker-controlled bytes — is exactly what you want to fuzz. The problem is that
the obvious target is already covered.

**net-snmp is saturated.** It is an active OSS-Fuzz project and ships in-tree
harnesses directly on the surface I care about — `snmp_parse_fuzzer`,
`snmp_pdu_parse_fuzzer`, and `snmp_scoped_pdu_parse_fuzzer` for the SNMPv3 scoped
PDU. Re-fuzzing a parser that Google already fuzzes continuously is wasted effort.
So I went looking for an SNMPv3 stack with the same reach but none of the attention,
and found it in **lwIP** — the lightweight TCP/IP stack embedded in a vast number of
microcontrollers and IoT SDKs. Its SNMPv3 agent (`src/apps/snmp/`) is not in
OSS-Fuzz and ships no fuzz harness. And in May 2026, **CVE-2026-8836** — a CVSS 9.8
stack overflow in its USM `msgAuthenticationParameters` handling — proved the surface
was live, memory-unsafe, and unfuzzed.

This is a writeup of a coverage-guided campaign against that surface, pinned at the
commit that *fixed* CVE-2026-8836; so I was sweeping the residual surface, not
rediscovering the known bug. The headline is not a CVE. Across roughly **200
million executions** under AddressSanitizer and UndefinedBehaviorSanitizer — plain
parse, USM authentication, and the crypto-gated scoped PDU, with both a deterministic
crypto shim and the real mbedTLS backend — **I found no memory-safety defect.** One
low-severity undefined-behavior issue, reported and already public (lwIP bug #68758).
The post-patch lwIP SNMPv3 parser held up. As with any honest "nothing broke" result,
the interesting part is *how you make that claim trustworthy.*

## The method, briefly

lwIP is open source, so I fuzzed it **in-process and coverage-guided** (libFuzzer +
ASan/UBSan, clang), compiling the real agent with instrumentation and driving its
real entry point — `snmp_parse_inbound_frame()`, the static function CVE-2026-8836
lived in — directly, with no sockets. The harness builds a `pbuf` from the fuzz
bytes exactly as the UDP transport would and calls the parser. A few decisions did
the work:

- **A minimal port, honest about asserts.** I wrote a NO_SYS lwIP port that compiles
  only the SNMP parse path (no transport, no TCP/IP stack), and made lwIP's own
  `LWIP_ASSERT` non-fatal. That's deliberate: lwIP asserts defensively on malformed
  input, and I did not want those defensive checks masquerading as crashes. Only ASan
  and UBSan get to decide what a real bug is.
- **Phasing by reachability layer, not message type**, so no phase re-fuzzes
  another's code. Phase 1: the outer message + BER decode + USM header parse. Phase
  2: USM authentication verification and key handling, reached by configuring a user.
  Phase 3: the scoped PDU *behind* the privacy gate.
- **Genuine state, not forced state.** Phase 2's auth path only runs for a *known*
  user; with no users configured the parser bails early. So I configured a user and
  let the real code localize the key, run the HMAC over the message, and compare —
  the auth-handling, and any bug in it, is reached the way a real agent reaches it.
- **A valid crypto envelope for the crypto-gated parser.** The scoped PDU in an
  authPriv message is only parsed *after* authentication passes and the body is
  decrypted. Random bytes never get there. So the phase-3 harness assembles a full
  authPriv message around the fuzz input and mints the authentication digest with the
  *same* routine lwIP uses to verify it — so auth passes — and (in the real-crypto
  build) AES-encrypts the fuzz scoped PDU with the same key and IV lwIP will decrypt
  with, so the decrypt round-trips. Only then does the fuzzed scoped PDU reach the
  inner parser. It's the one honest way past the gate.
- **Shim, then real mbedTLS.** Phases ran first against a deterministic crypto shim
  (faithful to the stream/length behavior that matters to lwIP's parser, which is
  where the length bugs live), then again against the *real* lwIP mbedTLS backend
  (genuine HMAC-SHA1/MD5 and AES-CFB). If the shim results were an artifact of the
  stub, the real-crypto runs would have shown it. They didn't.

## Coverage matrix

The point of a "nothing broke" result is the reach behind it.

| Surface | Crypto | What was fuzzed | Executions | Result |
|---|---|---|---|---|
| Outer message + BER decode + USM header | shim | `snmp_parse_inbound_frame`, no user | 87.2M | held up (found **F1**) |
| USM auth-verify + key handling | shim | configured user → HMAC verify path | 42.3M | held up |
| Crypto-gated scoped PDU (authPriv) | shim | valid envelope → decrypt → scoped PDU | 8.6M | held up |
| USM auth-verify + key handling | **real mbedTLS** | real HMAC-SHA1/MD5 over the message | 61.0M | held up |
| Crypto-gated scoped PDU (authPriv) | **real mbedTLS** | real HMAC + real AES-CFB valid envelope | 3.1M | held up |

Target pinned at lwIP `0c957ec0` (the CVE-2026-8836 patch commit); F1 re-confirmed on
current master `d08f4773`. The exec-rate fell by an order of magnitude from phase 1
to phase 3 (≈290k → ≈13k/s) — the signature of each phase reaching deeper, heavier
code: by phase 3 every iteration assembles an envelope, computes a real HMAC,
AES-encrypts, and drives the full authenticate-decrypt-parse path.

## A few things worth reading

Most of this was "held up fine," so here are the parts I found genuinely interesting.

**The one finding — and why I'm calling it low-severity out loud.** Within the first
few hundred executions, UBSan flagged a *left shift of a negative value* in
`snmp_asn1_dec_s32t`, the BER signed-integer decoder (`snmp_asn1.c:472`). When a
multi-byte INTEGER's leading byte has its high bit set, the running value becomes
negative, and the next `*value << 8` is undefined behavior per the C standard. It is
reachable without authentication from any SNMP message carrying such an integer — a
request-id, an SNMPv3 msgID, engine boots or time — across v1, v2c, and v3 alike.
That sounds alarming, and the honest framing matters: **this is a UBSan finding, not
a memory-safety bug.** ASan reported nothing — no out-of-bounds read or write, no
corruption. On every mainstream compiler the shift compiles to an arithmetic shift
and the decoded value is correct. It is undefined behavior (CWE-758) and a one-line
fix — do the shift in unsigned space — but it is a portability/correctness hardening,
not the CVE-2026-8836 class, and I reported it that way. It is below the bar for a CVE,
so I didn't request one; it's filed as lwIP Savannah bug
[#68758](https://savannah.nongnu.org/bugs/index.php?68758).

**Making auth *pass* is the whole trick of phase 3.** It is easy to write a phase-3
harness that looks like it fuzzes the crypto-gated parser but silently fails
authentication on every input — in which case you're just re-running phase 2 and
calling it something fancier. The fix is to verify it. I checked a debug build:
after parsing a valid seed, the request's error status was clean and its security
flags stayed `authPriv` — and lwIP forces the flags down to noAuthNoPriv the instant
authentication or decryption fails. Flags preserved, error zero: the gate was
genuinely passed. Without that check, a phase-3 "result" is worthless.

**Non-fatal asserts are a judgment call, stated plainly.** Turning lwIP's
`LWIP_ASSERT` into a no-op means the fuzzer runs *past* lwIP's own bounds checks on
malformed input, which is what lets ASan see whether a missing check is actually
exploitable rather than merely asserted. The tradeoff is that I am no longer testing
"does lwIP assert here"; I'm testing "if it didn't, would memory be corrupted." For a
memory-safety sweep that's the right call, but it's a choice worth being explicit
about, because it changes what the result means.

## Disclosure status

- **F1 (BER signed-shift UB):** filed on lwIP's Savannah tracker as bug
  [#68758](https://savannah.nongnu.org/bugs/index.php?68758), category *apps*, with a
  one-line patch. **No CVE** — it is undefined behavior, not a security vulnerability,
  and I said so in the report. lwIP's development is on Savannah + the lwip-devel
  mailing list; the GitHub repo is a read-only mirror and not a report channel.
- Everything here is **publishable with no embargo**: the finding is a public,
  non-security correctness bug, and the harness contains no weaponized exploit.

## Lessons

- **Pick the unfuzzed implementation, not the famous protocol.** "SNMPv3" sounds
  picked-over; net-snmp is. The embedded stacks aren't, and a recent CVE is the
  clearest possible signal that a surface is both live and unattended.
- **A robustness result needs its receipts.** "Held up under 200M executions" means
  nothing without naming the reachable surface, phasing by layer, and — for a
  crypto-gated parser — *proving* you got past the gate.
- **Separate UBSan from ASan in how you talk about findings.** A UBSan hit is real
  and worth fixing, but conflating "undefined behavior" with "memory-safety
  vulnerability" is exactly the overclaiming that erodes trust. Scope it honestly;
  file it honestly.
- **A faithful shim and the real library should agree.** Running both is cheap
  insurance against a result that's really an artifact of your own stub.

## Closing

I set out to find a memory-safety bug in an unfuzzed SNMPv3 agent, on a surface a
CVSS-9.8 CVE had just proven to be dangerous. I found one benign undefined-behavior
issue and, otherwise, a parser that held up across every layer I could reach, with
real crypto and without. That is a quieter result than a CVE, and I think it is worth
publishing exactly as it is: the standard this kind of work should be held to is not
how loud the finding is, but how honestly you can defend the claim — including the
claim that nothing broke.

*Found with snmpv3Fuzzer, an open-source coverage-guided SNMPv3 fuzz harness over
lwIP's SNMP parser. By Shad Malloy (alosafuzz) — alosafuzz@proton.me.*

---
