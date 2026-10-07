---
title: icsScanner
slug: icsscanner
status: active
order: 2
repo: https://github.com/alosafuzz/ics-scanner
summary: >-
  A safety-first active discovery + assessment scanner for ICS/OT networks, with a bounded default-credential/identity-probe check library and a safety-critical execution tier.
---
icsScanner performs active discovery and bounded, read-mostly assessment of ICS/OT devices. Its design centers on *safety*: destructive or physically-actuating checks live behind a two-step plan/confirm tier with no single-command execution path.

Its protocol reverse-engineering feeds icsFuzzer — several of the [Protocol Guides](/guides/) began as wire formats recovered while building icsScanner checks.
