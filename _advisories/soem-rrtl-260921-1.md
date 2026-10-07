---
title: "Cybersecurity Advisory for SOEM (RRTL-260921-1)"
date: 2026-09-21
vendor: [OpenEtherCATsociety]
tlp: clear
---
> **Note:** the full styled advisory document is preserved at
> [/advisories/soem-rrtl-260921-1.html](/advisories/soem-rrtl-260921-1.html). This
> entry is the index record. Replace with the distilled advisory body at publish.

A reported-but-unfixed receive-buffer overflow in SOEM's
`ecx_receive_processdata_group()` (issue #352): a corrupted PDO packet overflows the
receive buffer. No CVE assigned. Documented here as a coordinated-disclosure record.
