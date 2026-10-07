---
title: timeFuzzer
slug: timefuzzer
status: complete
order: 3
repo: https://github.com/alosafuzz/timeFuzzer
summary: >-
  Coverage-guided fuzzing of time-synchronization protocols (linuxptp/PTP, gPTP, NTS-KE) — a cross-vertical robustness study.
---
timeFuzzer applies coverage-guided (libFuzzer/AFL++ + ASan/UBSan) fuzzing to the highest-gap time-sync protocols. A campaign across four implementations (linuxptp, ptpd, chrony, ntpsec) with two cross-implementation differentials produced a robustness result: the parsers held up. Publishable as a methodology/robustness piece across OT, finance, and telecom timing.
