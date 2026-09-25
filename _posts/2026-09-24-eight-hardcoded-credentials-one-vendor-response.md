---
layout: post
title: "Eight hardcoded credentials, one vendor response: a Moxa disclosure story"
date: 2026-09-24 08:00:00 -0600
---
Over several ingest passes this month, where firmware images would be manually downloaded and
then analyzed in depth, Zoe and I found eight distinct hardcoded or missing-authentication issues
across seven Moxa product families — industrial computers, an energy meter, a managed switch
line, a secure router, and a mobile automation router. We reported all eight to Moxa's PSIRT on
September 19th. They acknowledged the same day. Five days later, they declined every one of them,
classifying all eight as "documented, user-changeable default credentials" rather than product
vulnerabilities.

For two of the eight, that's a fair characterization. For at least five, we disagree — we pulled
the actual credentials out of cracked password hashes and compiled firmware tables, not out of
any manual. This post walks through what we found, what we sent, what Moxa said back, and why we
think the record should stay as we found it, even though we're not pushing the disagreement
further right now.

## How we found these

This came out of a firmware review for **icsScanner**, a safety-tiered ICS/OT vulnerability
scanner I've been building, with Zoe contributing to several of the disclosure threads it's
produced. icsScanner isn't public yet — this disclosure is part of the research and validation
work behind it, not a side project: three of the eight findings below are now shipped as real,
working detection checks inside the tool, and the whole batch is a case study in the kind of
vendor sweep the scanner's own check library gets built from. More on icsScanner itself in a
future post, once it's ready to release.

The methodology across all eight findings was the same: get real, vendor-shipped firmware (from
Moxa's own no-login CDN, in every case — nothing here came from a leak or a paywalled source),
extract it with the right tool for whatever container format it turned out to be, and look for
exactly two things: hardcoded credentials, and services that don't require any credential at all.

Five of the eight didn't need any interpretation. They needed extraction:

- **DA-660/DA-661/DA-660A family** (Intel IXP425-based industrial computers): a root SSH account
  whose password hash — the literal string `gs5hdcM0NRKeI`, straight out of `/etc/shadow` —
  cracks to `root` on the first attempt with Python's own `crypt` module. Confirmed identically
  across two independent leaked BSP source trees and two real shipped firmware images seven years
  apart (2011 and 2018).
- **DA-681-LX/DA-682/DA-710 family** (the x86 side of Moxa's embedded-computer line): a `moxa`
  user with a cracked password of `moxa`, sitting in the full `sudo` group with unrestricted
  access — confirmed across five firmware images spanning 2009 to 2021.
- **EM-1220-LX/EM-1240-LX** (energy meters — a different product category and platform entirely
  from the two above): root Telnet access, password cracked from a DES-crypt hash in
  `/etc/passwd`, with Telnet running unconditionally via an `inittab respawn` entry.
- **ICS-G7526A/G7528A and sibling IKS switches** (Moxa's current "A"-generation managed
  industrial Ethernet switches): `admin`/`moxa`, read directly out of the firmware's own compiled
  NVRAM factory-default configuration table — not cracked, just sitting there in the binary.
  Confirmed byte-identical across the 2023 and 2025 firmware builds, and independently confirmed
  in a second, genuinely different firmware codebase for a sibling switch line.
- **MAR-2000 Mobile Automation Router**: an `admin`/`admin` "System Administrator" account, whose
  password we read straight out of the web application's own Node.js source —
  `bcrypt.hashSync('admin', ...)` in the `defaultData()` function that seeds the account at first
  boot. The web app listens on all interfaces by default, on port 80, and starts unconditionally.

None of those five values appear in any Moxa manual we could find. They're not something we think
a technician would ever see without pulling apart the firmware the way we did.

The other three are a genuinely different shape, and we filed them that way from the start:

- **EDR-series secure routers**: the closest of the eight to something you could call
  "documented" — the default (`moxa`, or a blank password depending on firmware generation) is
  set by a plaintext shell script (`chg_passwd.sh`) that Moxa itself wrote to run at first boot.
  It's still not in a customer-facing manual, but it's vendor-authored, intentional bootstrap
  logic rather than a credential we cracked.
- **ioLogik 2500 I/O modules**: `admin`/`moxa` over a proprietary TCP protocol, corroborated by
  Moxa's own MXIO SDK sample code using that exact credential in a connection example. Loosely
  "documented," in the sense that it's sitting in example code Moxa published for developers —
  just not in a product manual a customer would read.
- **MAR-2000's Mosquitto broker**: not a credential at all. The device ships an MQTT broker with
  no `password_file`, no `acl_file`, and no `allow_anonymous` directive configured anywhere —
  Mosquitto's own documented behavior in that state is to accept anonymous connections. This is a
  missing-authentication finding (CWE-306), and Moxa's response, framed entirely around
  "credentials," doesn't really engage with it as what it actually is.

Every finding was cross-checked against Moxa's own public advisory history before we called
anything novel — two of the eight product lines already had unrelated, previously-disclosed CVEs
we had to rule out as duplicates (a post-authentication privilege-escalation bug on the EDR line,
and unrelated XSS/CSRF issues on the switch family). None of the eight overlapped with prior
public disclosures.

## What we sent

A single combined report, PGP-encrypted to Moxa's current key (after a brief detour: their
published key had quietly expired, and PSIRT needed to point us at the renewed one before we
could send anything). Eight findings, four working proof-of-concept scripts covering the
protocols where we could build one cleanly (SSH, Telnet, a JSON login flow, and anonymous MQTT),
and — for the findings whose exact protocol we hadn't fully reverse-engineered — a plain
description of how to reproduce it by hand instead of a script we couldn't fully verify.

Sent September 19th. Acknowledged the same day: *"We are currently reviewing the reported
vulnerability and will provide updates on the progress."*

## What Moxa said

Five days later, a single reply covering all eight findings at once:

> "We have carefully reviewed all eight findings. All of the reported credentials are
> factory-default accounts that can be changed by the user. They are documented in the publicly
> available user manuals for these products, and users are instructed to change them during
> initial setup. Because these credentials are user-configurable rather than hardcoded, we do not
> treat them as product vulnerabilities. We will therefore not be opening vulnerability cases or
> publishing security advisories for these findings. In addition, several of the reported products
> have already reached End of Support."

They closed by asking that if we publish, we describe the findings as "documented, user-changeable
default credentials."

## Where we agree, and where we don't

We're not going to pretend Moxa's position is baseless — for the EDR-series and ioLogik findings,
"vendor-authored default, not a customer secret" is a defensible read of what we actually found,
even if "documented" is generous. Both are user-changeable, and neither required cracking
anything to recover.

But that framing doesn't hold for the other five, and specifically not for the credential we're
most confident about across the board: none of the DA-660, DA-681, EM-1220/1240, ICS-G7526A, or
MAR-2000 values are printed in any manual. They're recoverable by cracking a password hash pulled
out of a firmware image, or by reading a compiled configuration table, or by reading application
source code shipped inside the firmware — three different mechanisms, all of which are the actual
definition of a hardcoded credential (CWE-798), not a documented default a technician is
instructed to change. A value that only exists once you've disassembled the firmware isn't
"user-configurable rather than hardcoded" in any meaningful sense; it's hardcoded *and* happens to
be technically changeable after the fact, which describes almost every hardcoded credential ever
found.

We also don't think "several products have reached End of Support" changes the calculus much —
these are industrial devices with service lifespans measured in decades, and EOS status doesn't
un-deploy the units already running in the field.

We're documenting this disagreement plainly rather than either accepting Moxa's framing wholesale
or escalating past PSIRT. Practically: three of the eight findings (the two SSH ones and the
Telnet one) were trivial enough for our own scanner's existing check modules that we've shipped
them as detection checks anyway — an operator running icsScanner against their own fleet will
still get flagged if one of these devices is sitting on their network with the factory default
still active, regardless of what either side calls it.

## Takeaways

A few things worth generalizing from this one:

1. **"Can the user change it" is not the same question as "is it hardcoded."** Almost any
   password can be changed after the fact. What matters for CWE-798 is whether the *shipped
   default* required reverse engineering to discover, not whether a config screen exists to
   change it later.
2. **A CNA vendor declining to open a case isn't the same as the finding being wrong.** Moxa is a
   CVE Numbering Authority; that status covers case management, not an independent arbiter of
   whether a specific finding meets the CWE-798 bar. We'd take the same evidence back to CISA's
   coordination process if this were a case where the vendor were flatly unreachable — here, PSIRT
   was responsive and professional throughout, we just land in a different place on the
   classification question.
3. **Ship the detection anyway where you can.** A disputed classification doesn't make the
   underlying exposure go away for whoever's actually running the device. If you can build the
   check with material you already have, build it.

---

*Findings from this disclosure: DA-660/DA-661/DA-660A family (SSH), DA-681-LX/DA-682/DA-710
family (SSH), EM-1220-LX/EM-1240-LX (Telnet), ICS-G7526A/G7528A and sibling switches (web),
MAR-2000 web console (web) and MQTT broker, EDR-series secure routers (web), ioLogik 2500 I/O
modules (proprietary TCP). All CVSS 3.1 9.8 Critical where scored
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), computed with the standard `cvss` scoring library, not
hand-estimated. No CVE has been assigned to any of the eight. The SSH/Telnet findings for the
DA-660, DA-681, and EM-1220/1240 families are now shipped as detection checks in icsScanner's own
registry — more on that tool once it's public. Reach me at alosafuzz@proton.me.*
