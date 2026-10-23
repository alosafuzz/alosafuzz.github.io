---
title: fieldbusFuzzer
slug: fieldbusfuzzer
status: active
order: 2
repo: https://github.com/alosafuzz/fieldbusFuzzer
summary: >-
  A coverage-guided (libFuzzer/ASan/UBSan) fuzzing suite for fieldbus and industrial protocols. Its EtherCAT/SOEM campaign produced four CVEs, coordinated with RT-Labs and fixed in SOEM 2.0.1.
---
fieldbusFuzzer is the coverage-guided counterpart to [icsFuzzer](/projects/icsfuzzer/): instead of generated payloads, each target is driven in-process with libFuzzer under ASan/UBSan, and in-process crashes are re-confirmed over a real wire before anything is called a finding.

The flagship result is **EtherCAT/SOEM**. A seven-harness campaign against [SOEM](https://github.com/OpenEtherCATsociety/SOEM) (the open-source EtherCAT master) turned up eight memory-safety findings that **RT-Labs** consolidated into **four CVEs** — CVE-2026-70388, -82943, -82946, -82947 — all reachable by a single malicious device on the bus and all fixed in **SOEM 2.0.1**. The coordination is written up as a model of how an OSS maintainer should run disclosure. See the [advisory](/advisories/soem-rrtl-260921-1/) and the writeup, [*Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers*](/writeups/fuzzing-ethercat-four-cves-in-soem/).

A second target, **SCPI/LXI** (libscpi), produced a robustness result rather than a CVE — the core parser held up under sustained fuzzing. See [*Fuzzing SCPI: from libscpi to real firmware*](/writeups/fuzzing-scpi-from-libscpi-to-real-firmware/) and the [SCPI/LXI guide](/guides/scpi-lxi/).

The published modules, harnesses, seeds, and the two-process live-reproduction layer are open-sourced in the [repository](https://github.com/alosafuzz/fieldbusFuzzer).
