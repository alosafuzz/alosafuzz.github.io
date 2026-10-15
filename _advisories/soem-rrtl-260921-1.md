---
title: "Advisory for SOEM (RRTL-260921-1)"
date: 2026-10-15
project: fieldbusfuzzer
vendor: [rt-labs]
cve: [CVE-2026-70388, CVE-2026-82943, CVE-2026-82946, CVE-2026-82947]
tlp: clear
published: true
summary: "Four CVEs in SOEM, the open-source EtherCAT master, all reachable by a single malicious device on the bus and all fixed in SOEM 2.0.1. Found by coverage-guided fuzzing; coordinated through RT-Labs."
---

**TLP:CLEAR.** This page records the four vulnerabilities in **SOEM** (Simple Open EtherCAT
Master) that I reported and am credited on in the vendor advisory
**[RRTL-260921-1](https://rt-labs.com/wp-content/uploads/2026/10/RRTL-260921-01.pdf)** published by
[RT-Labs](https://rt-labs.com/cyber-security/). That advisory assigns six CVEs in total; the other
two — CVE-2026-82944 (a CoE SDO multi-segment buffer overflow) and CVE-2026-82945 (an FMMU
configuration-table overflow) — were reported by other researchers and do not involve my findings,
so they are not detailed here. The narrative behind the four below — the fuzzing campaign, the
shared integer-underflow pattern, and why the coordination went well — is in the companion writeup,
[*Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers*]({{ '/writeups/fuzzing-ethercat-four-cves-in-soem/' | relative_url }}).

## Overview

SOEM is the open-source EtherCAT master maintained by RT-Labs and embedded in a long tail of
automation products. The master parses data that **every** slave puts on the wire, so on a bus
with one compromised or counterfeit device, that data is attacker-controlled. All four
vulnerabilities below affect **SOEM versions up to and including 2.0.0** and can be triggered by a
malicious or compromised device on the same EtherCAT network. All are fixed in **SOEM 2.0.1**.

## Affected products

| Product | Status |
|---|---|
| SOEM versions prior to 2.0.1 | Affected |
| SOEM 2.0.1 and later | Fixed |

## Mitigation

Upgrade to **SOEM 2.0.1 or later**; all four vulnerabilities are fixed in that release. As defense
in depth, keep EtherCAT devices off public networks — a bus that an attacker cannot place a device
on is not reachable by any of these. Devices on isolated or firewalled networks are at
significantly reduced risk.

## Vulnerabilities

### CVE-2026-70388 — Memory corruption via integer underflow in message-length validation

A malicious device can send a crafted mailbox message that causes the master to write data outside
allocated memory, potentially leading to code execution.

| | |
|---|---|
| **CVE** | CVE-2026-70388 |
| **CWE** | CWE-191 (Integer Underflow), CWE-195 (Signed-to-Unsigned Conversion Error), CWE-787 (Out-of-bounds Write) |
| **CVSS 3.1** | 8.3 (HIGH) — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H` |
| **Fix** | Upgrade to SOEM 2.0.1 |

**Technical detail.** The SoE, CoE, EoE and FoE message handlers compute a payload size by
subtracting a fixed header size from the slave-supplied length field using signed arithmetic. When
the slave reports a length smaller than the header, the result is a large negative number; used as
a memory-copy size it is treated as a huge positive value (~2^63 bytes), writing far past the
destination buffer.

**Fix.** A validation step was added to the central mailbox receive function. It now checks every
incoming message's length against the per-protocol minimum and against the physical mailbox size
before handing the message to any parser; a message that fails either check is discarded.

**Acknowledgments:** f0rw4rd (quellsec.dev), alosafuzz, 3ntr0py1337 (LeetProtect Research),
Brian Willows (graith.co.uk), Eun0us (EspilonOrg).

---

### CVE-2026-82943 — Out-of-bounds read via unchecked length values

A malicious device can cause the master to read beyond the intended buffer, disclosing up to ~64KB
of adjacent memory back to the attacker.

| | |
|---|---|
| **CVE** | CVE-2026-82943 |
| **CWE** | CWE-125 (Out-of-bounds Read), CWE-195 (Signed-to-Unsigned Conversion Error), CWE-200 (Exposure of Sensitive Information) |
| **CVSS 3.1** | 6.5 (MEDIUM) — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Fix** | Upgrade to SOEM 2.0.1 |

**Technical detail.** The FoE, SoE and CoE handlers used the slave-supplied length field as the
source size for a memory copy without checking it against the actual received buffer (at most 1487
bytes). A slave that claims a large length while sending a short message causes the copy to read
past the buffer into adjacent memory, which is then returned to the caller as data. A separate bug
in the SoE handler used an unassigned internal pointer as the copy source after the receive
completed, reading from near address zero.

**Fix.** The central mailbox receive validation (added for CVE-2026-70388) also limits the
slave-supplied length to the physical mailbox capacity, bounding derived copy sizes by the actual
buffer. The stale-pointer issue was fixed by computing the source pointer after the receive returns
(patch provided by Sankalp Thakur).

**Acknowledgments:** f0rw4rd (quellsec.dev), alosafuzz, 3ntr0py1337 (LeetProtect Research),
Brian Willows (graith.co.uk).

---

### CVE-2026-82946 — NULL pointer dereference in mailbox error handling

A malicious device can crash the master with a simple two-message sequence.

| | |
|---|---|
| **CVE** | CVE-2026-82946 |
| **CWE** | CWE-476 (NULL Pointer Dereference), CWE-690 (Unchecked Return Value to NULL Pointer Dereference) |
| **CVSS 3.1** | 6.5 (MEDIUM) — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Fix** | Upgrade to SOEM 2.0.1 |

**Technical detail.** When the mailbox receive function gets an error-typed response it frees the
internal buffer and clears the pointer to NULL, but the retry loop continues without acquiring a new
buffer. On the next iteration it passes the NULL pointer to a receive call, causing an immediate
crash.

**Fix.** The retry loop now acquires a fresh buffer before each attempt.

**Acknowledgments:** alosafuzz.

---

### CVE-2026-82947 — Multiple out-of-bounds reads in frame processing

Multiple frame-processing paths use length and offset values from device messages without bounds
checks, allowing a malicious device to read outside allocated buffers — disclosing memory or
crashing the master.

| | |
|---|---|
| **CVE** | CVE-2026-82947 |
| **CWE** | CWE-125 (Out-of-bounds Read), CWE-787 (Out-of-bounds Write), CWE-191 (Integer Underflow), CWE-129 (Improper Validation of Array Index) |
| **CVSS 3.1** | 7.1 (HIGH) — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` |
| **Fix** | Upgrade to SOEM 2.0.1 |

**Technical detail.** In each affected path, a length or offset taken from an incoming frame or
slave configuration is used directly to size a read without first checking it against the actual
buffer. In the frame-receive path the working-counter offset is not validated against the buffer
bounds. In the cyclic-mailbox handlers the read/write size comes from a slave-supplied
configuration value without being capped to the available buffer, so a slave reporting an oversized
mailbox reads or writes into adjacent memory (cyclic-mailbox mode only). In the EoE receive path,
timestamp handling assumes the buffer is large enough to contain a timestamp.

**Fix.** Each path now validates the relevant value against the actual buffer size before use;
frames or fragments that fail validation are discarded.

**Acknowledgments:** f0rw4rd (quellsec.dev), alosafuzz, Brian Willows (graith.co.uk).

## Credit

I ([alosafuzz](https://github.com/alosafuzz)) am sole-credited on **CVE-2026-82946** and
co-credited on the other three above. The eight findings from my coverage-guided campaign were
consolidated by RT-Labs into these four CVEs alongside independent reports from the other
researchers listed above. The advisory assigns two further CVEs I am not credited on —
CVE-2026-82944 and CVE-2026-82945 — reported by others; see the vendor advisory for those.

## References

- RT-Labs advisory **RRTL-260921-1** — [PDF](https://rt-labs.com/wp-content/uploads/2026/10/RRTL-260921-01.pdf), index at <https://rt-labs.com/cyber-security/>
- [SOEM on GitHub](https://github.com/OpenEtherCATsociety/SOEM) (fixed in 2.0.1)
- Companion writeup: [*Fuzzing EtherCAT: four CVEs in SOEM's mailbox handlers*]({{ '/writeups/fuzzing-ethercat-four-cves-in-soem/' | relative_url }})

## Revision history

| Version | Date | Summary |
|---|---|---|
| 1 | 2026-10-15 | Initial public release of the four CVEs crediting alosafuzz in RT-Labs RRTL-260921-1. |
