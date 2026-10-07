---
title: hartFuzz
slug: hartfuzz
status: active
order: 5
summary: >-
  Coverage-guided fuzzing of HART-IP (FieldComm Group hipserver) — the native Ethernet transport for field instrumentation.
---
hartFuzz targets HART-IP, the Ethernet transport for pressure/temp/flow transmitters across oil & gas, chemical, and water. CVE-2020-16209 (CVSS 9.8) hit the official reference implementation; no coverage-guided campaign has followed since the patch. No special hardware is needed for phase 1 — HART-IP is TCP/UDP-native.
