# Publishing to alosafuzz.github.io

The reusable publish workflow for **every alosafuzz project** — icsFuzzer, icsScanner,
timeFuzzer, snmpv3Fuzzer, hartFuzz, detection-gen, and whatever ships next. Full
rationale in `docs/site-architecture.md`.

## The one rule: source stays private, products get published

Each project keeps its raw working notes **private** in its own repo
(`<project>/lab-notes/*-research.md`). Those notes carry verification caveats, build
logs, open questions, and sometimes embargoed disclosure detail — they are **never**
committed to this site repo. What gets published is the **distilled product** of a
note, in one of five forms:

| You have… | Publish it as… | Goes in |
|---|---|---|
| a reverse-engineered protocol wire format + fuzz surface | a **guide** | `_guides/` |
| a narrative "here's what I did / found" story | a **writeup** | `_writeups/` |
| a coordinated-disclosure / CVE record | an **advisory** | `_advisories/` |
| a new tool | a **project** page | `_projects/` |
| co-authored / external work (e.g. Bishop Fox) | a **publication** stub (link-only) | `_publications/` |

Nothing is published while a disclosure embargo is open.

## How the site builds & deploys

Jekyll; **GitHub Pages compiles it on push** — no local toolchain needed. To publish:
commit to this repo and push to `main`. Pages rebuilds automatically. (Optional local
preview: `bundle install && bundle exec jekyll serve`.)

If a page moves (changed slug/section), add `redirect_from:` entries for the old URLs
so existing links keep resolving — see the migrated writeups for examples.

## Front-matter templates

**Guide** (`_guides/<proto>.md`) — indexed by vendor:
```yaml
---
title: "A Researcher's Guide to <Protocol>"
protocols: ["<Protocol>"]
vendor: ["siemens"]            # siemens|rockwell|schneider|ge|omron|cross|...
vendor_group: "Siemens"        # the heading it groups under on /guides/
sector: ["manufacturing"]      # electric|building|manufacturing|iiot|cross
transport: ["iso-on-tcp"]
project: icsfuzzer
status: draft                  # draft|published
---
```
Rule for guides: **research-focused, defensive framing, no weaponized exploit code**
(name the vulnerable field, CVE, CWE, trigger *shape*, seed hex — not a drop-in
exploit). **Shipped modules only** — write a guide once the module exists.

**Writeup** (`_writeups/<slug>.md`) — narrative, dated:
```yaml
---
title: "..."
date: 2026-07-30
project: icsfuzzer
summary: "one line for the index"
redirect_from: [ /old/url/ ]   # only if the page moved
---
```

**Advisory** (`_advisories/<id>.md`) — TLP-marked disclosure record:
```yaml
---
title: "Advisory for <product> (<ref>)"
date: 2026-09-21
vendor: [<vendor>]
cve: [CVE-2026-xxxxx]          # if assigned
tlp: clear
---
```

**Project** (`_projects/<name>.md`):
```yaml
---
title: <Tool>
slug: <name>
status: active                 # active|maintained|complete
order: 7
repo: https://github.com/alosafuzz/<repo>
summary: >-
  one-paragraph what-it-is
---
```
A project page auto-lists its guides/publications (anything tagged `project: <slug>`).

**Publication** (`_publications/<slug>.md`) — external, link-only:
```yaml
---
title: "..."
host: "Bishop Fox"
external: true
url: "https://bishopfox.com/blog/..."
date: 2026-05-26
project: icsfuzzer             # optional; surfaces it on that project page too
---
short description (rendered above the outbound link)
```

## Workflow for another project (e.g. icsScanner, timeFuzzer)

1. Do the work; keep the raw note private in your project's `lab-notes/`.
2. Distill the publishable part into the right collection file here (templates above).
3. Tag it `project: <your-project-slug>` so it surfaces on your `/projects/` page.
4. Commit + push to `main`; Pages rebuilds.
5. Update your project's guide/publish tracker (e.g. icsFuzzer's
   `protocol-guides-backlog.md`, icsScanner's `protocol-guides-sidequest.md`).

Vendor/sector/transport vocabularies are shared across all projects — reuse existing
slugs; add a new one only when nothing fits.
