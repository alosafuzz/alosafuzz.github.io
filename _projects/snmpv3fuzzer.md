---
title: snmpv3Fuzzer
slug: snmpv3fuzzer
status: active
order: 4
repo: https://github.com/alosafuzz/snmpv3Fuzzer
summary: >-
  Coverage-guided fuzzing of SNMPv3/USM in embedded stacks (lwIP), targeting the memory-unsafe surface net-snmp's OSS-Fuzz coverage leaves open.
---
net-snmp is saturated by OSS-Fuzz; the real gap is embedded SNMPv3 stacks. snmpv3Fuzzer targets lwIP's SNMPv3 agent — CVE-2026-8836 (a CVSS 9.8 USM stack overflow) proves the surface is live and unfuzzed — with a phased, reachability-layered libFuzzer harness (plain parse, USM auth, and the crypto-gated scoped PDU via a valid-envelope technique).

Result: across ~200M executions under ASan/UBSan, with both a crypto shim and the real mbedTLS backend, the post-patch lwIP SNMPv3 parser **held up** — no memory-safety defect, one low-severity undefined-behavior issue reported upstream ([lwIP #68758](https://savannah.nongnu.org/bugs/index.php?68758), no CVE). See the writeup, [Fuzzing SNMPv3 where it actually lives](/writeups/fuzzing-snmpv3-where-it-lives/).
