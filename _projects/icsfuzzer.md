---
title: icsFuzzer
slug: icsfuzzer
status: active
order: 1
repo: https://github.com/alosafuzz/icsFuzzer
summary: >-
  A structured-generator fuzzer for ICS/OT protocols. 14 protocol modules — Modbus, DNP3, S7comm, BACnet, EtherNet/IP, OPC-UA, PROFINET, IEC 104, IEC 61850, FINS, GE SRTP, FactoryTalk RNA, LwM2M, and Schneider UMAS.
---
icsFuzzer sends malformed and boundary-case packets to industrial devices to find crashes and spec-violations. It is a *generator*-based fuzzer: every case is a deterministic, auditable payload built in pure Python, exportable without a live target, and calibrated against a software responder before any hardware run.

Each protocol module ships with a software responder (for calibration) and a test suite. The per-protocol **field guides** under [Protocol Guides](/guides/) document the wire format and fuzz surface of each.

Findings have been coordinated with maintainers across the full spectrum of responses — from same-day fixes to vendor-declined — always honestly scoped.
