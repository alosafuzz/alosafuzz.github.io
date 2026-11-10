---
title: "Fuzzing ringserver: a seismic server that holds up"
date: 2026-11-10
project: fieldbusfuzzer
published: true
summary: "ringserver is the C daemon in the middle of most seismic data pipes, serving SeedLink and DataLink to anyone who can reach the port. The novelty gate said skip it — the maintainer had just swept the parse paths for malicious input — but a clean negative on a reference server is worth having, and a recent audit can still miss a sub-parser. So I built a harness that drives the daemon's real command loop over a socket and ran the full matrix. ASan and MSan came back clean across tens of millions of executions on both protocols; the only thing UBSan flagged was a time-conversion overflow that wraps harmlessly on any normal build. This is what an honest server negative looks like, and why the MSan half of it took rebuilding three libraries."
---

*Defensive security research. This describes a fuzzing method and a negative result;
it contains no exploit. The target is unmodified open-source software,
[EarthScope/ringserver](https://github.com/EarthScope/ringserver) (Apache-2.0).*

---

Most seismic waveform data in the world passes through one small C program. EarthScope's
**ringserver** holds recent packets in a ring buffer and hands them out over two
protocols — SeedLink for streaming, DataLink for reading and writing — on a single TCP
listener. Clients negotiate before they authenticate: they pick stations, set a read
position, hand over match and reject patterns. So the command parser is reachable by
anyone who can open the port, which is the kind of surface worth a careful look.

## The gate said no, and that was useful information

Before building anything I run a novelty gate, and ringserver came back a no-go. The
reason was specific: in 2026 the maintainer had landed a hardening pass aimed squarely
at "edge case failures on OOM or esoteric/malicious usage," and it touched the
negotiation code, the HTTP path, and the client lifecycle in one sweep. When the person
who owns the code has just audited the exact surface you were going to fuzz, the honest
prior is a negative — you are checking their work, not finding fresh ground.

I built it anyway, and I want to be clear about why, because "the gate said skip it" is
a real argument. Two reasons. A clean memory-safety result on a reference server that
sits in the middle of a critical data pipe is worth having on the record, stated
plainly, rather than assumed. And a recent audit sweeps for the classes the auditor was
looking for; a fuzzer driving the real wire can still turn up a sub-parser or an input
shape the audit didn't reach. If the result came back clean, that confirms the audit on
the terms a fuzzer can speak. If it didn't, that's the gap. Either way the negative is
the product.

## A harness that doesn't lie about the follow-on reads

The temptation with a server like this is to call the command handler directly: build a
`ClientInfo`, drop a command string into it, invoke `HandleNegotiation`. It compiles, it
runs fast, and it is wrong in a way that matters. Several DataLink commands — `MATCH`,
`REJECT`, `WRITE` — read a count on the command line and then pull that many *more* bytes
off the socket. A handler called with one pre-tokenized command never does the second
read. You would fuzz the easy half and report a clean the code never earned.

So the harness drives the daemon's real receive path. Fuzzer bytes go into one end of a
`socketpair`; the other end is half-closed so the daemon reads a full stream and then
sees EOF. The loop is the server's own: `RecvDLCommand` or `RecvLine`, then
`DLHandleCmd` or `SLHandleCmd`, until the session ends — exactly the sequence
`ClientThread` runs in production. The real framing happens, the follow-on reads happen,
and a single input can carry a whole multi-command session that reaches states one
message can't. The only thing taken out is the socket *write*: I wrap `send` to discard,
so the daemon's replies don't fill the pipe and stall a session that should keep going.
A small real ring is stood up once, so the ring-reader calls are real too. The one thing
I check before trusting any of it is the detector itself — a deliberately planted
out-of-bounds read, caught by ASan in that exact binary, then removed.

On that harness, ASan and UBSan ran together across both protocols: tens of millions of
executions on DataLink, more on SeedLink, plus a pass with write permission granted to
reach the post-auth ingestion path. SeedLink was clean through and through. DataLink was
memory-safe — no out-of-bounds, no use-after-free, no leak.

## The one thing UBSan flagged, stated conservatively

UBSan did catch something, in one place, from one class. `POSITION AFTER <time>` parses a
full-range signed 64-bit microsecond timestamp and converts it to nanoseconds by
multiplying by 1000, with no range check first. A large value overflows the 64-bit
result — undefined behavior, on unauthenticated input. The same unchecked multiply sits
on the post-auth WRITE header's start and end times.

It is a real flag and it is a small one, and both of those are true at once. On any
normal two's-complement build — which is every build ringserver ships as — the multiply
wraps deterministically to a nonsensical timestamp that then feeds a ring time-search.
No memory is touched out of bounds, nothing is corrupted, the process does not crash.
Only a build compiled to trap on signed overflow would turn it into an abort. So I score
it as a hardening nit, not a vulnerability: the arithmetic-overflow class that the 2026
audit's bounds work didn't cover, closed by range-checking the timestamp before the
conversion. There is no weaponizable primitive here, and I'm not going to dress one up.

## The MSan half, and why it cost three rebuilds

ASan tells you about memory you touched out of bounds. It says nothing about reading
memory you never initialized — the read-before-length-check class, where a parser
consumes bytes past what the client actually sent. That class is exactly what turned a
different protocol's clean ASan result into a finding for me earlier, so a server
negative isn't finished until MemorySanitizer has run too.

MSan is harder to run honestly here, because ringserver vendors three libraries the
command path actually calls — PCRE2 for the match and reject patterns, libmseed for time
formatting, mxml for the INFO response — and MSan reports every read of memory an
*uninstrumented* library touched as uninitialized. Point MSan at a build where those are
uninstrumented and you get a screen of false positives, not a result. The fix is to
rebuild exactly those three with `-fsanitize=memory`, and leave the libraries that
aren't on this path — mbedtls for TLS, miniz for gzip — uninstrumented, since code that
never runs can't poison anything. One wrinkle earns a footnote: the mbedtls headers
refuse to compile under MSan with assembly enabled, so the daemon is compiled against an
assembly-disabled mbedtls config, which changes nothing at runtime because those objects
are never executed on the SeedLink or DataLink path.

With the three libraries instrumented and the detector again anchor-checked, MSan ran
clean: roughly eleven million executions on DataLink, nine million on SeedLink, zero
uses of uninitialized value. No read-before-check. The class ASan can't see isn't there
either.

## What the negative is worth

Put together: ringserver's unauthenticated command parser is memory-safe and free of
uninitialized reads across the full ASan-plus-MSan matrix, and the only sanitizer flag
is a time-conversion overflow that wraps harmlessly on every build the project ships.
The novelty gate was right that this was recently hardened ground, and running it anyway
turned "probably fine because the maintainer just audited it" into "checked, on the
terms a fuzzer can speak, and here is the one arithmetic nit that bounds-checking
audits don't catch." For a program carrying this much of the world's seismic data, that
is a result worth writing down.

The protocol and harness details — DataLink and SeedLink on the wire, the fields worth
seeding to extremes, and the socketpair-plus-ClientThread technique — are in the
companion [SeedLink & DataLink guide](/guides/seedlink-datalink/).
