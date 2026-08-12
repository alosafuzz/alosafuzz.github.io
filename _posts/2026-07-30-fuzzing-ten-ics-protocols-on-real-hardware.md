---
layout: post
title: "Fuzzing ten ICS protocols on real hardware: a coverage map, the findings worth reading, and what happened when I reported them"
date: 2026-07-30 12:00:00 -0600
---
Point a protocol fuzzer at an industrial device and it will happily report hundreds of
crashes. Most of that number tells you more about your test harness than about the device,
and separating the two is most of the work.

Over the past couple of months I built an ICS/OT protocol fuzzer and ran it against real
control-systems gear: an ESP32 running two Modbus stacks, OpenPLC v3 on a Raspberry Pi 4,
and OpenPLC v4 in Docker. This post is less a list of vulnerabilities than an account of
that separation work — how 716 reported crashes resolved to a single bug, how reading source
kept one finding from being overstated, and how five maintainers responded when the
survivors were reported.

A single idea runs underneath all of it. A fuzzer surfaces symptoms; the value is in turning
a symptom into a diagnosis a maintainer can act on, and, where possible, confirming the fix
once it lands. Finding is the easy half. One of the bugs below went from fuzzer hit to merged
upstream fix in a single day, largely because the report did the diagnostic work first.

## The tool

[`icsFuzzer`](https://github.com/alosafuzz/icsFuzzer) is a modular fuzzer covering ten ICS protocols: Modbus, DNP3, OPC-UA,
EtherNet/IP, IEC 61850/MMS, BACnet, IEC 104, PROFINET, S7comm, and FINS. Each protocol
module generates malformed and out-of-spec traffic, classifies the responses, and ships with
a software responder — a spec-faithful mock server that logs every request it handles to a
sidecar file.

That responder is what makes the rest trustworthy. On a live device, a dropped connection is
ambiguous: the device may have crashed, or it may have correctly rejected a bad frame. When
the mock records that it closed a connection deliberately — because the protocol ID was
wrong, say — each crash indicator resolves to either an expected close or a genuine gap. You
calibrate against the mock first, then trust the differences you see on real hardware.

## What I tested: coverage at a glance

Not every protocol had a live target. Five were exercised only against the software responder
for calibration, because I had no real device that spoke them. The honest map:

| Protocol | Live target(s) | Outcome |
|---|---|---|
| **Modbus** | ESP32 (emelianov), ESP32 (ESP-IDF), OpenPLC v3, OpenPLC v4 | **Findings on all four** — see deep dives |
| **S7comm** | OpenPLC v3 & v4 (snap7) | **Crash (CWE-787) + connection-exhaustion DoS** |
| **OPC-UA** | OpenPLC v4 | **Two findings** — one conditional access-control, one low-severity interop |
| **EtherNet/IP** | OpenPLC v3 | Low: CIP silent-drop of unsupported services (spec non-compliance) |
| **DNP3** | OpenPLC v3 (RPi4) | Robust — no findings across the fuzz corpus |
| **IEC 61850 / MMS** | libiec61850 (RPi4) | Robust — no real crashes (173 cases) |
| IEC 104 | software responder only | Robust in calibration (no live target) |
| BACnet | software responder only | Robust in calibration (no live target) |
| GE-SRTP | software responder only | Robust in calibration (no live target) |
| PROFINET | software responder only | Robust in calibration (no live target) |
| FINS | software responder only | Robust in calibration (no live target) |

The sections below cover the four rows that produced something worth reading. The robust rows
matter too — "we fuzzed it and it held up" is a legitimate result — but they do not each need
a section.

## Deep dive 1 — ESP32 Modbus, and the 716 "crashes" that were one bug

The first substantial run targeted Espressif's `esp-modbus` stack on an ESP32. The fuzzer
reported 716 crashes across nearly every category. That figure is close to meaningless on its
own, and it is worth walking through why.

The tell was the distribution. The crashes appeared evenly across unrelated categories, and
genuine bugs tend to cluster rather than spread uniformly. To test that, I added a cold-boot
isolation step: reboot the device, send a single known-good request before any fuzz traffic,
and observe the result.

The cause was the fuzzer itself. Its default unit ID was `0xFF`, which falls inside ESP-IDF's
`0xF8–0xFF` hang range. Roughly 657 of the 716 crashes traced back to that one interaction,
which left each connection in a state that made the following case look like a crash as well.
Adding a `--unit-id` flag and rerunning brought the number down to a deterministic 175 across
repeated runs — five genuine, unauthenticated denial-of-service classes.

The general lesson is worth stating plainly: a fuzzer's raw crash count measures the hygiene
of your harness, not the security of the target. The useful artifact was never 716; it was
the method that reduced 716 to one contaminating bug plus 175 real ones.

The same board also ran a second stack, the widely used `emelianov/modbus-esp8266` library,
which had three distinct MBAP-parsing hang bugs of its own: a bare function code that hangs
and desynchronizes the frame stream, a non-zero protocol ID, and a length-1 frame. Those went
to the maintainer as a public issue with a proof of concept.

## Deep dive 2 — snap7 / S7comm: the one memory-safety bug

The most serious finding was in snap7, the S7comm library OpenPLC bundles. A single Read
Variable request with `count=0xFFFF` crashes the server.

Reading the source replaced a vague "unchecked allocation" guess with a precise cause: a
signed/unsigned comparison defeats the PDU-size guard. `PDURemainder` is a signed `int`
(around 480); `Size` is an unsigned `longword` (2 × 65535 = 131070). In the check
`PDURemainder - Size <= 0`, the `int` is promoted to unsigned, the subtraction wraps to a
large positive value, and the guard never triggers. Execution then copies roughly 131 KB into
a few-hundred-byte response buffer — an out-of-bounds write (CWE-787), CVSS 7.5. The same
code is vendored into OpenPLC v4, not only the archived v3.

It is worth being precise about scope. I demonstrated the crash reproducibly (5 of 5) and
identified the out-of-bounds write by reading the source. I did not attempt to develop it
into anything beyond denial of service, so the memory-safety characterization is root-cause
analysis, not a demonstrated exploit.

OpenPLC v4 introduced a second, separate S7comm problem: its plugin caps snap7's client pool
at 32, where snap7's own default is 1024. As a result, roughly 32 small unauthenticated
connections that stall the parser can lock out every legitimate client. This one is a genuine
v4 regression — the same flood does nothing against v3, which never lowers the cap.

## Deep dive 3 — OpenPLC v4 Modbus: found by the fuzzer, driven to a same-day fix

This finding is the clearest illustration of the idea that a fuzzer's job does not end at
"here is a crash."

The fuzzer surfaced the symptom: OpenPLC v4's Modbus server returned a fixed, incorrect
response to any unassigned function code — a hardcoded function code `0x28` and a transaction
ID of `0`, identical regardless of what the client sent. I traced it out of OpenPLC and into
the `pymodbus` library, narrowed it to a single exception branch, and filed a public issue
with a self-contained, runnable reproduction against the latest release, along with a
concrete suggested fix.

That last part is what matters. Rather than forwarding a stack trace, the report handed the
maintainer a diagnosis they could act on in minutes — and they did. The maintainer agreed
within hours, a community contributor landed two merged pull requests the same day
implementing essentially the fix I had proposed, and the issue closed as completed. I then
reinstalled the development branch and reran the reproduction to confirm the change: the
transaction ID is now echoed, and the fixed response is gone.

Find, diagnose, propose, verify — not simply find. I do not claim the patch; another
contributor wrote it. But a report good enough to be fixed in a day is its own contribution,
and it is the standard I think this work should aim for.

The same Modbus server has a second, lower-severity quirk the fuzzer caught: two well-formed
requests pipelined into one TCP segment receive no response at all. Unlike the S7comm case,
it does not accumulate into a lockout — a fresh client was still served with 250 such
connections held open — so it is an interoperability bug rather than a denial of service.

## Deep dive 4 — OpenPLC v4 OPC-UA: the finding I had to right-size

Fuzzing showed that an anonymous OPC-UA client could write a variable configured read-only.
My first write-up described it as a blanket failure of per-role write enforcement — HIGH
severity, an access-control bypass. Reading the plugin source showed the reality was narrower.

Per-variable enforcement does run for anonymous sessions. The actual mechanism is role
elevation: when a project has no configured users, the server deliberately assigns anonymous
clients the top `engineer`/Admin role, and an in-code comment describes this as a
single-tenant convenience. A variable whose engineer role has write access therefore becomes
writable by any client on the network — but a variable set engineer-read-only stays
protected, and adding a single named user restores the intended behavior.

That is a real issue, but it is medium severity, conditional, and documented as intentional —
not the unqualified bypass I first described. I corrected the finding, including an edit to
the public disclosure thread. Because the behavior is insecure but working as designed, a
report on its own tends to draw a shrug, so I also released a scanner that answers the
question an operator actually has: can an anonymous client write this variable right now,
regardless of the server's internal reasoning?

It is worth being explicit about getting this wrong the first time. Reading source is what
turns a fuzzer's "something looks off here" into a claim you can defend, and occasionally it
tells you the claim was larger than the evidence.

## Disclosure status and open threads

The same broad class of finding drew five quite different maintainer responses. That range,
more than any individual bug, is the useful part.

| Target | Reported | Where | Status |
|---|---|---|---|
| **pymodbus** | Fixed FC / zero-TID exception | `pymodbus#2990` | Fixed same day (merged upstream, verified) |
| **OpenPLC v4** | S7comm DoS, two Modbus bugs, OPC-UA gap | `openplc-runtime#153` | Reported; three CVE IDs pursued via MITRE (CANs filed) for the exhaustion DoS, pipelined-ADU hang, and role-elevation findings; maintainer engagement still pending |
| **emelianov** | Three MBAP parsing hangs | `modbus-esp8266#387` | Public + PoC; three CVE IDs reserved (CANs filed), pending publication |
| **snap7** | `count=0xFFFF` crash (CWE-787) | `SCADACS/snap7#16` | Public issue (dormant repo); pursuing a CVE via MITRE (CNA-of-last-resort) |
| **Espressif** | Five Modbus DoS classes | Private bug-bounty | Vendor tested and respectfully declined as robustness, not vulnerabilities |

Two entries in that table deserve a note. snap7's repository has been dormant since 2022 with
no security channel, so after a public issue drew no response, I am pursuing the CVE through
MITRE as a CNA of last resort. Espressif ran the reproduction, reviewed the source, and
declined all five findings — and the reasoning is defensible: most of the hangs are
connection-scoped and recover as soon as the socket closes, and the "pool exhaustion" is the
stack correctly refusing excess clients. A vendor that engages seriously and disagrees on
classification is a legitimate outcome. Not every genuine bug is a vulnerability.

## Lessons worth keeping

- **Raw crash counts mislead.** 716 reduced to one root cause. Run a cold-boot isolation
  check before trusting a number.
- **Read the source before assigning severity.** It reclassified snap7 (CWE-20 to CWE-787)
  and, in the other direction, reduced the OPC-UA finding from HIGH to conditional medium.
- **Connection-scoped is not the same as sustained.** Whether a denial persists after the
  attacker stops is the line between a real availability finding and a robustness nit —
  exactly the line Espressif drew.
- **Confirm where the code actually lives before disclosing.** My first OpenPLC target URL
  pointed at an organization that never existed; the original repo was archived; the live
  successor was a third organization.
- **A report good enough to be fixed in a day is its own contribution.** The mock responder
  and the diagnostic write-up are what make that possible.

## Closing

The through-line here is not any single crash. It is the discipline of deciding which crashes
are real, describing them accurately, and routing them to the maintainer who can act on them.
A fuzzer that only emits crash counts creates work; one that produces diagnoses a maintainer
can act on — as the pymodbus case shows, from first report to merged fix in a day —
contributes to the systems it tests. That is the standard I think this kind of work should be
held to.

*Tooling: [icsFuzzer on GitHub](https://github.com/alosafuzz/icsFuzzer). Reach me at alosafuzz@proton.me.*
