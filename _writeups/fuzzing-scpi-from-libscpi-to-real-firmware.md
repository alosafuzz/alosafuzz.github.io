---
title: "Fuzzing SCPI, from the open parser to real firmware under QEMU"
date: 2026-10-14
project: fieldbusfuzzer
published: true
summary: "SCPI/LXI test instruments, fuzzed two ways: ~95M in-process executions against libscpi (the one broadly-reused open parser), then the real Keysight VXI-11 stack carved from a DMM firmware image and run under qemu-aarch64. No defensible memory-safety finding — and a lesson about why harness non-determinism has to gate what you call a bug."
---
Every bench holds them: oscilloscopes, DMMs, spectrum analyzers, power supplies,
source-measure units. They speak **SCPI** — the Standard Commands for Programmable
Instruments — and today they speak it over LAN (the LXI standard), not just the old
GPIB bus. That LAN interface is unauthenticated by design, parses attacker-controlled
text, and increasingly sits on plant and lab networks wired into everything else.
Siglent's 2023 cluster (CVE-2023-25367 unfiltered-SCPI RCE at CVSS 9.8, -25369 a DoS
from a malformed command) proved that interface is live and memory-unsafe.

The first thing to get straight is that **"GPIB" is a red herring** for a network
fuzzer: raw IEEE-488 is a parallel hardware bus. The thing on the wire is SCPI over
one of three LAN transports — raw socket (TCP 5025), VXI-11 (ONC-RPC), HiSLIP — and
across all three the bytes converge on one place: the instrument's **SCPI command
parser**. So I went at it from two directions: the open-source parser nearly everyone
embeds, and a real vendor stack I carved out of a firmware image.

The headline is not a CVE. The open parser held up across ~95M executions; the real
vendor VXI-11 stack, fuzzed three different ways, produced only crashes I could not
honestly pin on the vendor's code. This is a writeup about reaching those crashes —
and about the part that mattered most here: knowing when *not* to claim a finding.

## Part 1 — libscpi, in-process and coverage-guided

[`j123b567/scpi-parser`](https://github.com/j123b567/scpi-parser) (`libscpi`) is the
one broadly-reused open SCPI parser; it's embedded in a long tail of real instruments
and has no OSS-Fuzz presence and no sanitizer CI. Open source, so I fuzzed it
**in-process** (libFuzzer + ASan/UBSan, clang), pinned at `886615902b`, driving the
real byte-intake path `SCPI_Input()` → `SCPI_Parse()` → the parameter and expression
readers. Because the parsed command is identical whichever transport delivered it,
**one in-process harness covers the command surface behind raw-5025, VXI-11, and
HiSLIP at once.**

The first pass used the library's demo command table and plateaued the parser at a
mediocre coverage. That was the tell to write a **custom command table** that actually
calls the under-exercised readers — arbitrary-block `#<n><len>` data, numeric/channel
list expressions, the array readers — with correctly-sized buffers. That moved
`llvm-cov` to **lexer 100% / expression 93% / parser 66% region (74% functions)**, and
the residual uncovered code is response *emitters*, not input parsing. Across the runs
(~95M executions total, up to a 60-minute soak at ~84M execs alone), **no crash, no
leak, no UBSan hit.** A clean, source-verified robustness result.

The interesting part was the three bugs I *did* find — because **all three were in
`libscpi`'s own example code, not the library.** An uninitialized `scpi_number_t`
read in the demo measure callbacks (CWE-457); a stack-buffer-overflow in the demo
`TEST:CHANnellist` handler, which passes `length=4` to the channel-list reader for a
2-element array (CWE-787); and a whole-server DoS in the demo TCP server's socket loop
(it ignores `write()` errors and busy-spins or takes SIGPIPE when a client disconnects
mid-reply). Each was de-confounded and set aside — the parser under test bounds its
own writes correctly. They're a courtesy upstream note, not a library vulnerability.
The lesson is the one that keeps recurring: **the scaffolding around a fuzz target
produces bugs that look like target bugs, and your first job is to tell them apart.**

## Part 2 — the real thing: a vendor VXI-11 stack under QEMU

An open parser holding up is useful, but the Siglent CVEs were in *shipped firmware*,
not libscpi. So I carved a real instrument. A Keysight 3446XA Truevolt DMM firmware
image (`DM3446XA...swu`, a SWUpdate container) unpacks to an **aarch64** squashfs
rootfs (a TI K3-class SoC). The instrument application, `Torreys`, carries the whole
SCPI/VXI-11/HiSLIP command set — but it segfaults immediately at `dllEntry` under
qemu-user: it's bound to a hardware-abstraction layer (`libinstrhal`) that doesn't
exist off the device. The full app is not a viable emulation target.

Its dependencies, though, pointed at a much better one: **`libHppVxi11Server.so`**, a
real vendor VXI-11 server whose only dependency is `libtirpc` (ONC-RPC) plus the C/C++
runtime — **no hardware HAL.** It exports `inet_start_VXI11_server()` (and a shutdown
counterpart), which takes no arguments. The catch is that it imports ~25 Win32 symbols (Torreys is a
Windows port): `CreateThread`, `CriticalSection`, `CreateEvent`/`WaitForSingleObject`,
`Tls*`, `_strnicmp`, and friends. So I wrote a small **Win32→POSIX shim** — threads to
pthreads, events to mutex+condvar, TLS to pthread keys — cross-compiled a driver that
calls `inet_start_VXI11_server()`, and ran it under `qemu-aarch64-static` with a host
`rpcbind`. It **stood up**: the server registered VXI-11 Device Core (program 395183)
with the portmapper and decoded a `create_link` RPC into a real VXI-11 reply. A real
closed-firmware VXI-11 server, running and answering, on an x86 box.

## Fuzzing it — three ways, one honest answer

| Method | What ran | Execs | Crashes | Reproduce in isolation |
|---|---|---|---|---|
| Structured black-box (ONC-RPC, 3 campaigns) | mutated create_link/device_write/device_read records over the wire | ~8,700 | 3 | 0 / 13 |
| Fresh-per-case | a disposable server per input (no state, no overlapping threads) | 400 | 0 | — |
| AFL++ coverage-guided (aarch64 qemu-mode) | in-process driver, `afl-qemu-trace` over the whole process | 7,532 | 1 | 0 / 5 |

Every one of the four crashes (three structured, one AFL), across every method, was
**non-reproducible in isolation** and **input-independent** — the structured ones struck
on `device_write`, `device_read`, and `create_link` alike, and one of those inputs had a
perfectly well-formed length. I chased the obvious shim suspects to ground: a `CloseHandle` that leaked
Event objects (fixed — crashes persisted), then a handle model that confused thread
handles with event pointers (fixed with tagged handles — crashes still persisted).

The decisive evidence came from AFL itself. Its **stability metric read 86%** — AFL's
own measurement that the target returns *different coverage for the same input*. The
target is non-deterministic. That is the whole story: a rare (~1 in 2,900 connections)
crash that never reproduces on a single input is the signature of a threading /
per-connection-lifecycle race under **qemu-user's thread emulation plus my shim**, not
a memory-safety bug in the vendor's RPC decode. The fresh-per-case run — no state
accumulation, no overlapping threads — crashed zero times in 400 cases, which is the
same conclusion from the other side. Three independent methods agree.

So: **no defensible vendor finding.** Claiming a Keysight CVE from a non-reproducible
crash on an emulated, shimmed, measurably non-deterministic harness would be exactly
the overclaiming this kind of work has to refuse.

## A few things worth reading

**AFL's stability number is a finding, not a footnote.** Below ~90% it's telling you
the feedback loop is lying to you. On a flaky target, coverage-guided fuzzing degrades
toward noise, and *crashes* are the first thing you should distrust. Here it was the
cleanest single piece of evidence that the crashes were harness artifacts.

**Building afl-qemu-trace for a foreign arch is the easy part.** Fuzzing a *threaded
socket server* with AFL is the hard part: AFL wants one input per exec from stdin, and
a server wants a socket and loops forever. I kept fidelity by making the AFL target a
tiny in-process client that stands up the real server and drives one RPC at it over
loopback, so `afl-qemu-trace` instruments the genuine decode in its real context — no
desock, no calling a reverse-engineered internal function out of context. The price
is the non-determinism above; the alternative (a single-threaded decode harness) buys
determinism at the cost of reconstructing the context, which is where artifacts breed.

**The structured black-box pass was the more defensible tool here.** It talks to the
real server over a real socket; a crash there is wire-reachable by construction. AFL
bought 3× the throughput and edge feedback, but on an 86%-stable target the structured
+ fresh-per-case combination gave the cleaner signal. Match the tool to the target's
determinism, not to its reputation.

## Disclosure status

- **No vendor vulnerability is claimed.** The libscpi robustness result and the real
  VXI-11 result are both negative/qualified; the crashes were attributed to the harness.
- The three `libscpi` *example-code* bugs (CWE-457, CWE-787, and the demo TCP server
  DoS) are in the library's **example/demo code** (`scpi-def.c`, the `test-tcp` server),
  not the parser — so the right channel is an ordinary upstream bug report with triggers
  shown, not a security disclosure: filed as
  [j123b567/scpi-parser#174](https://github.com/j123b567/scpi-parser/issues/174)
  (example hardening, no CVE). Those files are widely copied verbatim into real firmware,
  which is why they're worth fixing; the parser core bounds its own writes correctly.
- Everything here is publishable with no embargo: a robustness result and a methodology,
  on firmware I possess, with no weaponized exploit.

## Lessons

- **Tell the scaffolding from the target.** Every "bug" I found was in example code, a
  demo server, or my own shim. On a shimmed/emulated harness that is the default, not
  the exception.
- **A non-reproducible crash is a lead, not a finding** — and on a non-deterministic
  target it is probably the harness. Isolation replay, fresh-per-case, and AFL's
  stability metric are three cheap ways to say so out loud.
- **Fidelity vs. determinism is a real tradeoff.** Running the whole server keeps the
  decode in context but inherits its threading non-determinism; isolating the decoder
  buys determinism but risks out-of-context artifacts. Pick deliberately and say which.
- **GPIB is a red herring; the parser is the target** — and the one open parser
  everyone embeds is worth more fuzzing attention than the protocol's reputation suggests.

## Closing

I set out to find a memory-safety bug in the SCPI/LXI attack surface, from the open
parser everyone ships to a real vendor's VXI-11 stack pulled out of a firmware image
and run under emulation. I stood up a genuinely novel target — a closed-firmware VXI-11
server, fuzzed coverage-guided on a different architecture — and I did not find a
defensible vendor bug. The parser held up; the crashes were mine. That is a quieter
result than a CVE, and publishing it honestly — including the discipline of refusing
the crashes that wouldn't survive scrutiny — is the point.

*Built with fieldbusFuzzer: an in-process libFuzzer harness over libscpi, a structured
ONC-RPC wire fuzzer, and an AFL++ aarch64 qemu-mode harness around a carved vendor
VXI-11 server. By Shad Malloy (alosafuzz) — alosafuzz@proton.me.*

---
