---
title: "After the fuzzer: the disclosure spectrum, with SOEM as the model"
date: 2026-10-16
project: fieldbusfuzzer
published: true
summary: "Finding the crash is the easy part. What happens after — de-confounding it, proving it on the wire, right-sizing the severity, and then getting a human at the vendor to agree and ship a fix — is most of the work and all of the variance. A tour of that spectrum, anchored on the SOEM/EtherCAT disclosure that went the way coordination should."
---

Point a coverage-guided fuzzer at a protocol parser and it will hand you a pile of crashes by
lunchtime. Almost none of that pile is a finding yet. Turning it into one — and then into a fix a
real vendor ships — is where the work actually lives, and it looks completely different depending on
who's on the other end. This is a map of that terrain, with the [SOEM/EtherCAT
disclosure]({{ '/writeups/fuzzing-ethercat-four-cves-in-soem/' | relative_url }}) as the anchor,
because it went about as well as coordinated disclosure gets.

## First: the crash is not the finding

Before a crash earns an email to a vendor it has to survive three filters, and most don't.

**Is it the harness or the target?** An in-process fuzzer runs with sanitizers, custom allocators,
and whatever scaffolding you wrote, and all of that can manufacture crashes that don't exist in the
real control flow. A single logic bug can also *look* like hundreds of crashes until you minimize and
dedupe. The discipline is to assume every crash is an artifact until proven otherwise: rebuild on a
plain, production-shaped binary; replay the input; watch what the real code actually does. Most of my
"findings" die here, and that is the system working.

**Does it reach the real wire?** For a response parser especially, "the fuzzer fed these bytes to the
decode function" is not the same as "a device on the network can send these bytes." For the
client-side findings I keep, I stand up a rogue peer on a real socket and point a *stock* client at
it — no wrapping, no in-process shortcut — and confirm the crash fires end to end. If it doesn't
survive the socket, it isn't a finding.

**Is the severity honest?** The write primitive the sanitizer shows you is the ceiling, not the
claim. If what you can actually demonstrate is a one-byte over-read that returns an exception and
keeps running, that's what you report, not the theoretical out-of-bounds write it shares a code path
with. Right-sizing downward costs nothing and buys every future report credibility.

None of this is specific to one protocol; it's the same loop on the EtherCAT master, the metering
stacks, and everything else. The deeper method lives in the companion posts on
[ten ICS protocols]({{ '/writeups/fuzzing-ten-ics-protocols-on-real-hardware/' | relative_url }}) and
[SOEM]({{ '/writeups/fuzzing-ethercat-four-cves-in-soem/' | relative_url }}).

## Then: the spectrum

Say you've done all that and you have a real, minimized, right-sized bug. What happens next is not
one process — it's a spectrum, and where a given report lands says more about the maintainer than
about the bug.

**Fixed in a day.** The best outcome is also the quietest. A clear report with a runnable reproducer
against a responsive open-source maintainer can close in a single commit — a pymodbus issue I
reported was fixed and merged the same day. No CVE, no advisory, no ceremony. A report good enough to
be fixed in a day is its own contribution, and it is worth optimizing reports *for that outcome*
rather than for a CVE count.

**Coordinated, multi-reporter, done right — the SOEM case.** My EtherCAT work turned up eight
memory-safety findings in SOEM, the open-source master maintained by RT-Labs. What RT-Labs did with
them is the model. They handle CVE assignment themselves, and rather than cutting eight thin CVEs
they consolidated my findings *with independent reports from several other researchers* into a small
set that described the actual bug classes. They ran the CVSS scoring in the open — and when reporters
pushed back, two of my scores came **down**, one from HIGH to MEDIUM. They shipped the fix in a
single release and coordinated one publication date across every reporter. A vendor that revises a
score downward after technical feedback is doing the arithmetic honestly instead of inflating a
headline; that is the tell of a process you can trust.

**Who gets to assign the number.** The CVE itself can come from very different places, and knowing
which saves weeks. A vendor that is its own CNA (RT-Labs) assigns and credits directly. For a project
hosted on GitHub, the maintainer can open a GitHub Security Advisory and GitHub — a CNA — mints the
ID and credits the reporter; that's the path I'm waiting on for a nanoMODBUS report, where an
independent fuzzer has already reproduced the same finding on the same commit. And when no CNA covers
the project at all, MITRE's CNA-of-last-resort is the backstop. The ID is the least interesting part;
the fix is the point. But picking the right assignment path up front keeps a good report from
stalling.

**Vendor disagrees — and may be right.** Not every report ends in a fix, and "declined" is not the
same as "wrong." I reported a set of findings to Espressif in an esp-modbus stack; they triaged them,
ran the reproducers, and classified all of them as robustness issues rather than vulnerabilities —
connection-scoped behavior that self-heals, expected transport resets. I think that's a defensible
call. The honest way to write that up is as a classification disagreement presented fairly, not as a
grievance. Disclosure is a conversation with a person who knows their own threat model better than
you do, and sometimes the conversation ends with them teaching you something.

**Already public, or overtaken.** Sometimes the vendor doesn't move, or a parallel finding lands
first, and the responsible thing is simply to publish the methodology and the defensive takeaways
without a live PoC — a blog post instead of an advisory. That's still a contribution; it just isn't a
CVE.

## What actually moves a vendor

Across all of those outcomes, the reports that land share the same properties, and none of them is
"severity." They are **reproducible** (a single frame or a short script, not "run the fuzzer for an
hour"), **minimized** (the smallest input that still triggers it), **right-sized** (the claim matches
the demonstration), and **scoped** (exact affected versions, exact unaffected ones — a C library bug
that doesn't touch the C++ or managed ports should say so). A report with those four properties is
easy for a maintainer to act on, and ease of action is the single biggest predictor of a fix. SOEM
got fixed fast partly because the bug class was one honest pattern described precisely, not eight
dramatic headlines.

## The takeaway

The fuzzer is a cheap way to generate suspicion. Everything after it — the de-confounding, the wire
proof, the conservative scoring, and then the human on the other end — is where suspicion becomes a
fixed bug, and it's the part worth getting good at. The SOEM disclosure is the version of that story
where everyone did their job: the tooling was honest, the report was precise, and the maintainer ran
real coordination to completion. Most won't go that smoothly. Knowing where on the spectrum you've
landed — and writing the report that gives it the best chance of landing well — is most of the craft.

*By Shad Malloy (alosafuzz) — alosafuzz@proton.me. Tooling for the fieldbus work is open-sourced at
[github.com/alosafuzz/fieldbusFuzzer](https://github.com/alosafuzz/fieldbusFuzzer).*
