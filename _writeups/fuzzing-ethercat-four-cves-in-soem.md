---
title: "Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers"
date: 2026-10-15
project: fieldbusfuzzer
published: true
summary: "A coverage-guided fuzzing campaign against SOEM, the open-source EtherCAT master, turned up eight memory-safety findings that RT-Labs consolidated into four CVEs crediting me — all reachable by one malicious device on the bus, all fixed in SOEM 2.0.1. The spine of it is a single integer-underflow pattern repeated across four mailbox sub-protocols, and a disclosure that shows an OSS maintainer running coordination the way it should be run."
---

EtherCAT is the real-time fieldbus under a great deal of modern automation — motion control,
robotics, packaging lines, semiconductor tools. The protocol's performance comes from a
master-centric design: one master clocks the network and every slave answers it. That shape
also defines the attack surface. The interesting target is not the slave firmware but the
**master**, because the master parses data that every slave puts on the wire — and on a bus
with one compromised or counterfeit device, that data is attacker-controlled.

[SOEM](https://github.com/OpenEtherCATsociety/SOEM) (Simple Open EtherCAT Master), maintained by
RT-Labs, is the open-source master that a long tail of products embed. It has no OSS-Fuzz
presence and no sanitizer CI, and it parses slave-supplied mailbox messages — SoE, CoE, EoE,
FoE — plus raw frame data. That is exactly the kind of surface this suite exists to reach.

## The surface, and why "adjacent" is the right threat model

Every CVE here is scored `AV:A` — adjacent network. That is not a hedge; it is the honest
model for a fieldbus. An EtherCAT segment is not the internet, but it is also not a trust
boundary: devices are swapped, sourced from distributors, and occasionally counterfeit, and a
single malicious slave sees and answers every mailbox exchange the master initiates. The
question a fuzzer asks is simple: if one device on the bus lies about a length field, what
happens inside the master?

## Method: in-process coverage, confirmed over a wire

I fuzzed SOEM in-process with **libFuzzer + ASan/UBSan**, against a pinned checkout, with seven
harnesses split by parser: `inframe` and `stateful` for frame processing, and `coe`, `soeread`,
`foe`, `eoe`, `eoegetip` for the mailbox sub-protocols. Each harness feeds fuzz bytes where a
slave's bytes actually enter the master, so a crash corresponds to something a slave could send.

In-process fuzzing earns speed and coverage but it can also manufacture crashes that don't exist
in the real control flow. So every finding was re-confirmed with a **two-process live
reproduction** over a `veth` pair — a real SOEM master process talking to a minimal malicious-slave
process — before I was willing to call it a finding. That `livetest`/`prodtest` layer is in the
repo; it is the difference between "the fuzzer crashed" and "a device on the bus crashes the master."

## The spine: one integer-underflow pattern, four protocols

The headline finding, **CVE-2026-70388**, is not one bug so much as one *mistake made four
times*. The SoE, CoE, EoE and FoE handlers each compute a payload size by subtracting a fixed
header size from a slave-supplied length field, in signed arithmetic. When a slave reports a
length smaller than the header, the subtraction goes negative; the negative value is then used
as a copy size, where it is reinterpreted as an enormous positive number (on the order of 2^63).
The copy writes far past its destination buffer — a classic signed-to-unsigned underflow
(`CWE-191`/`195`) turned out-of-bounds write (`CWE-787`). I found it independently in four
handlers (`sdoread`, `soeread`, `eoerecv`, `eoegetip`); the same shape each time.

The fix is as centralized as the bug was distributed: RT-Labs added one validation step inside
the central mailbox receive function that checks every incoming message's length against the
per-protocol minimum and the physical mailbox size before any parser sees it. One guard, in the
one place every mailbox message passes through, closes all four.

## The other three

- **CVE-2026-82947** (HIGH, `AV:A`) — multiple out-of-bounds *reads* in frame processing. My
  contribution here is the `inframe` path: the offset of the working counter is taken from the
  frame without validating that it lands inside the buffer. In fairness to the record, this CVE
  is broader than my two findings — it also folds in cyclic-mailbox and EoE-timestamp read paths
  reported by others — so I claim the frame-receive reads, not the whole 7.1.
- **CVE-2026-82943** (MEDIUM, `AV:A`) — an out-of-bounds *read* driven by an unchecked length,
  where a slave claiming a large length while sending a short message walks the copy into
  adjacent memory and returns up to 64 KB of it to the caller (`CWE-125`/`200`, an information
  disclosure). My FoE finding is one half of this; a separate SoE stale-pointer read, patched by
  Sankalp Thakur, is the other.
- **CVE-2026-82946** (MEDIUM, `AV:A`) — a NULL-pointer dereference in mailbox error handling, and
  the one I'm **sole-credited** on. When the receive function gets an error-typed response it
  frees its buffer and clears the pointer, but the retry loop continues without acquiring a new
  one and hands the NULL pointer to the next receive. Two messages — an error followed by
  anything — crash the master. The fix acquires a fresh buffer before each retry.

## CVE summary

| CVE | Class | CVSS 3.1 | My findings | Credit |
|---|---|---|---|---|
| CVE-2026-70388 | Integer-underflow OOB write (SoE/CoE/EoE/FoE) | 8.3 HIGH `AV:A` | #3, #5, #7, #8 | co-credit |
| CVE-2026-82947 | OOB reads in frame processing | 7.1 HIGH `AV:A` | #1, #2 (CVE is broader) | co-credit |
| CVE-2026-82943 | OOB read, unchecked length (≤64 KB disclosure) | 6.5 MED `AV:A` | #6 (+ others' SoE read) | co-credit |
| CVE-2026-82946 | NULL-deref, mailbox error handling | 6.5 MED `AV:A` | #4 | **sole** |

All four are fixed in **SOEM 2.0.1**; upgrade, and keep EtherCAT segments off shared networks.

## Disclosure: how it should look

I reported the eight findings to RT-Labs on 2026-08-13 over their security channel. What
happened next is the part worth holding up as a model. RT-Labs handles CVE assignment itself,
and rather than cutting eight thin CVEs they **consolidated** my findings into four that describe
the actual bug classes. (The advisory assigns six CVEs in all; the other two — a CoE SDO
multi-segment overflow and an FMMU configuration-table overflow — were reported by other
researchers and are not mine, so I don't claim them here.) They ran the CVSS scoring openly — and when reporters pushed back, two of my scores came *down*
(one HIGH to MEDIUM). I want to be clear that this is the healthy outcome, not a disappointment:
a vendor that revises a score downward after technical feedback is a vendor doing the arithmetic
honestly rather than inflating a headline. They shipped the fix in 2.0.1 and coordinated a single
publication date across all the reporters.

That is the counterweight to the usual disclosure horror stories. The spectrum I've written about
before ran from "fixed in a day" to "vendor declined"; RT-Labs adds a point I hadn't documented —
a maintained open-source project running a real, multi-reporter coordinated process to completion.

## What I'd take away

- **Fuzz the master.** On a master-centric bus the parser that matters is the one reading
  everyone else's bytes. The slave is not where the interesting memory-safety surface lives.
- **One pattern, audited everywhere, beats one bug fixed once.** The underflow was worth finding
  four times because that's what told the maintainer to put the guard in the shared receive path
  rather than in four parsers.
- **Confirm in-process crashes on a wire.** The `veth` two-process replay is what earns the word
  "finding." Coverage-guided speed is worthless if it produces crashes the real control flow
  can't reach.
- **Say exactly what you found.** CVE-2026-82947 is a 7.1 that bundles more than I contributed;
  the honest claim is the two frame-receive reads, not the score.

*Built with fieldbusFuzzer — seven libFuzzer/ASan harnesses over SOEM plus a `veth` live-reproduction
layer, open-sourced at [github.com/alosafuzz/fieldbusFuzzer](https://github.com/alosafuzz/fieldbusFuzzer). By Shad Malloy (alosafuzz) — alosafuzz@proton.me.*
