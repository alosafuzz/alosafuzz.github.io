---
title: snmpv3Fuzzer
slug: snmpv3fuzzer
status: active
order: 4
summary: >-
  Coverage-guided fuzzing of SNMPv3/USM in embedded stacks (lwIP), targeting the memory-unsafe surface net-snmp's OSS-Fuzz coverage leaves open.
---
net-snmp is saturated by OSS-Fuzz; the real gap is embedded SNMPv3 stacks. snmpv3Fuzzer targets lwIP's SNMPv3 agent — CVE-2026-8836 (a CVSS 9.8 USM stack overflow) proves the surface is live and unfuzzed — with a phased, reachability-layered libFuzzer harness.
