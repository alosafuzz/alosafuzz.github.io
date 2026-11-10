---
title: "A Researcher's Guide to SeedLink & DataLink (ringserver)"
protocols: ["SeedLink", "DataLink"]
vendor: ["earthscope"]
vendor_group: "EarthScope (seismology)"
sector: ["science", "cross"]
transport: ["tcp"]
project: fieldbusfuzzer
status: published
---
*Part of the alosafuzz ICS protocol-guide series — written for fuzzing and
vulnerability researchers. Defensive posture: wire format, fuzz surface, and the
known security posture only; no weaponized exploit or DoS code.*

---

## 1. What it is & where it runs

Seismic networks move waveform data in near-real time from thousands of stations to
data centers, and the server in the middle of that pipe is almost always
**[ringserver](https://github.com/EarthScope/ringserver)** — a small C daemon from
EarthScope (formerly IRIS) that holds recent packets in a ring buffer and serves them
to clients. It speaks two application protocols on the same listener:

- **SeedLink** — the long-standing streaming protocol seismic clients use to subscribe
  to stations and channels and receive miniSEED records as they arrive.
- **DataLink** — EarthScope's own protocol for both reading and *writing* packets,
  used by acquisition software feeding the ring and by tools reading from it.

Both run over **TCP** (default 18000, one listener multiplexing SeedLink, DataLink,
and HTTP by sniffing the first bytes). The reach that matters: a SeedLink or DataLink
client negotiates — selects stations, sets a position, supplies match/reject patterns —
**before any authentication**. DataLink *writing* requires a permission, but the whole
negotiation surface does not. Anything that can open the port talks to the command
parser.

## 2. The two protocols on the wire

They share a command tokenizer but frame their commands differently.

**DataLink** is length-framed. Every command is three header bytes — the ASCII `D`,
`L`, and a single byte giving the body length — followed by that many bytes of
command text:

```
44 4C 09  49 44 20 6C 69 62 64 61 6C 69        "DL",len=9,"ID libdali"
```

Commands are space-separated tokens: `ID`, `POSITION SET <pktid>`,
`POSITION AFTER <time>`, `MATCH <size>`, `READ`, `STREAM`, `WRITE <streamid> <start>
<end> <flags> <size>`, `INFO <type>`. A few commands (`MATCH`, `REJECT`, `WRITE`) take
a count in the command line and then read that many *more* bytes off the socket — the
pattern body or the packet payload.

**SeedLink** is line-based: CR/LF-terminated commands, no length prefix.
`HELLO`, `STATION <sta> <net>`, `SELECT <stream>`, `DATA`, `TIME <...>`, `END`,
`INFO <level>`, and the v4 handshake `SLPROTO 4.0`. Here too, `INFO` and station
negotiation are reachable with no credential.

## 3. The fuzz surface, mapped to ringserver

The command path is small and well-signposted in the source:

- **`cmdtoken.c`** — the shared tokenizer. Splits a line into argv, with explicit
  bounds, a NULL sentinel, sign-rejection on the unsigned parsers, and an overflow
  flag. It is written defensively; treat it as the thing most likely to be *clean* and
  spend your mutations downstream.
- **`dlclient.c` / `slclient.c` — `HandleNegotiation()`** — the real dispatch. This is
  where tokens become actions: position changes, selector lists, regex match/reject,
  the WRITE header fields.
- **The attacker-controlled fields worth seeding to extremes:**
  - **time values** — `POSITION AFTER <time>` and the WRITE `start`/`end` are parsed
    as full-range signed 64-bit microsecond timestamps, then converted to nanoseconds
    (a multiply by 1000). Seed `0`, `1`, `INT64_MAX`, and values near `INT64_MAX/1000`.
  - **counts / sizes** — the `MATCH`/`REJECT` size and the WRITE `size` drive a
    follow-on read and a buffer; seed `0`, `1`, and oversize.
  - **regex bodies** — MATCH/REJECT patterns are compiled with PCRE2. The ringserver
    side of that (size handling, termination) is yours to fuzz; the PCRE2 engine is
    not (see §6).
  - **stream IDs** — copied into a fixed `streamid` field; seed long and
    delimiter-heavy.
- **State machine** — SeedLink moves `COMMAND → STATION → STREAM`; some commands are
  only valid in some states. Multi-command sessions reach code single commands never
  do, so a harness has to replay a *sequence*, not one message (see §6).

## 4. Known security posture (not a CVE list)

ringserver has **no published CVE** against its own command parsing, and that is not
an accident. In 2026 the maintainer landed a broad hardening pass explicitly aimed at
"edge case failures on OOM or esoteric/malicious usage," touching the negotiation,
HTTP, and client-lifecycle code together. If you are novelty-gating this target, that
commit is the signal: the memory-safety surface was recently and deliberately swept,
so the honest prior is a negative. The credential model matters too — DataLink
**WRITE** needs `WRITE_PERMISSION`, so the packet-ingestion path is post-auth; the
unauthenticated reach is negotiation, position, selectors, and INFO.

## 5. A robustness note — the command parser holds up

Fuzzed at the wire (see §6) under AddressSanitizer and MemorySanitizer, across tens of
millions of executions on both protocols, the command path is **memory-safe and free
of uninitialized-memory reads**. No out-of-bounds, no use-after-free, no
read-before-length-check. That is the result, and it lines up with §4.

The one thing a sanitizer does flag is a **signed-integer-overflow** (CWE-190, UBSan)
in the time conversion: the microsecond timestamp from `POSITION AFTER` (and from the
post-auth WRITE header) is multiplied by 1000 with no range check, so a large value
overflows the 64-bit result. It is a genuine undefined-behavior flag on
unauthenticated input, but the conservative impact is small: on a normal
two's-complement build the multiply wraps to a nonsensical timestamp that feeds a ring
time-search, with no memory-safety consequence and no crash. Only a build compiled to
trap on overflow would abort. It is a hardening nit — the arithmetic-overflow class
the 2026 audit's bounds work did not cover — fixed by range-checking the timestamp
before the conversion. Nothing here is a weaponizable primitive.

## 6. Harnessing a server daemon faithfully

ringserver is a worthwhile case study in *not* lying to yourself with a harness. The
command handlers are welded to a running server: they read more bytes mid-command,
they write replies, they expect a ring and a client-state object. Two choices keep the
harness honest.

**Drive the real receive path over a socket, not a hand-rolled command feeder.**
Several commands (`MATCH`, `REJECT`, `WRITE`) consume follow-on bytes from the
connection after the command line. A harness that calls the handler with a single
pre-tokenized command silently skips that second read and reports a false clean on it.
Instead, feed fuzzer bytes into one end of a `socketpair`, half-close for EOF, and run
the daemon's own `ClientThread` command loop (`RecvDLCommand`/`RecvLine` →
`DLHandleCmd`/`SLHandleCmd`). The real framing, the real follow-on reads, and the real
multi-command session all happen; the only thing stubbed is the socket *write* side,
wrapped to discard so replies don't back-pressure the pipe and a session runs to
completion. Stand up a small real ring once so the ring-reader calls are real too.

**Under MemorySanitizer, instrument the libraries the parser actually calls.**
ringserver vendors PCRE2 (regex), libmseed (time formatting, miniSEED), and mxml (INFO
XML), and the command path calls into all three. MSan reports *every* read of memory an
uninstrumented library touched as "uninitialized," so an MSan run over a build with
those libraries uninstrumented is pure noise. The fix is to rebuild exactly the
libraries on the fuzzed path with `-fsanitize=memory` and leave the rest (here mbedtls
for TLS, miniz for gzip — neither on the SeedLink/DataLink path) uninstrumented, since
unexecuted code can't poison anything. One build wrinkle: the mbedtls headers refuse
to compile under MSan when assembly is enabled, so compile the daemon against an
assembly-disabled mbedtls config — the real (assembly) mbedtls objects you link are
never executed on this path, so correctness is unaffected. With that done, an MSan
negative means what you want it to: no read-before-check, the exact class ASan can't
see.

## 7. Further reading

- ringserver source and protocol docs: [github.com/EarthScope/ringserver](https://github.com/EarthScope/ringserver)
- SeedLink and DataLink protocol references are in the ringserver `doc/` tree.
- The companion writeup — the full ASan + UBSan + MSan campaign and why the negative
  is worth keeping — is at
  [/writeups/fuzzing-ringserver-a-seismic-server-that-holds-up/](/writeups/fuzzing-ringserver-a-seismic-server-that-holds-up/).
