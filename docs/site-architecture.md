# alosafuzz.github.io — Site Architecture & Growth Plan

*Planning doc (2026-10-06). Authoritative structure for the public alosafuzz
research-program site. Decisions below were confirmed with the user; this file's
intended permanent home is the site repo's root once it exists — it lives in
`ics-fuzzer/lab-notes/` for now because that's where the first big content batch
(the 14 protocol guides) was produced.*

## Confirmed decisions (2026-10-06)

- **Target:** a new **GitHub Pages site**, `alosafuzz.github.io`.
- **Research notes stay PRIVATE (source only).** The site publishes only the
  *distilled products* of the `lab-notes/*-research.md` notes — never the raw notes.
- **Protocol guides are indexed by vendor/ecosystem** (sector + transport as
  secondary tags).
- **Design for growth across projects** — icsScanner, icsFuzzer, the protocol
  research-note stream, the sibling fuzzers (timeFuzzer, snmpv3Fuzzer, hartFuzz),
  detection-gen, and whatever comes next. The site is a *program portfolio*, not a
  single-tool blog.

## Core principle: source vs. product

The real separation is not "notes vs. blogs" as two public sections — it is
**source (private) vs. product (public)**:

```
PRIVATE (per-project repos)            PUBLIC (site repo)
lab-notes/*-research.md   ──distill──▶  /guides/      (reference, evergreen)
   + build logs, open Qs,              /writeups/    (narrative, dated)
   caveats, embargoed detail           /advisories/  (disclosure, TLP, dated)
```

Each research note distills into exactly one public form. Raw notes never enter
the public site repo — the boundary is physical (different repo), not just
editorial. This is what keeps verification-status caveats and embargoed disclosure
detail off the public site by construction.

## Top-level information architecture

```
alosafuzz.github.io/
├── /                 Home — one-paragraph who/what, featured work, latest 3 posts
├── /projects/        Projects index (THE program; the primary scaling unit)
│   ├── icsfuzzer/
│   ├── icsscanner/
│   ├── timefuzzer/
│   ├── snmpv3fuzzer/
│   ├── hartfuzz/
│   ├── detection-gen/      (cross-linked; Bishop Fox hosts the deep-dive posts)
│   └── <future-project>/   (add a folder from the template — index auto-lists)
├── /guides/          Protocol Guides library (reference, evergreen, by vendor)
├── /writeups/        Blog — narrative posts, dated, chronological + tags
├── /advisories/      Formal CVE/disclosure pages (TLP template from alosafuzz.html)
├── /publications/    External / co-authored work (Bishop Fox etc.) — CROSS-LINKS, not hosted
├── /now/             (optional) current research direction, curated from TOPICS.md
└── /about/           bio, byline, contact, PGP key, disclosure policy
```

**Projects are first-class and folder-per-project** — this is the unit of growth.
Adding a new tool = drop a `/projects/<name>/` landing page from the template;
the projects index lists it automatically. Each project landing page states:
what it is, status (active / maintained / complete), the GitHub repo link, and an
auto-generated list of related guides / writeups / advisories (via the `project`
tag — see taxonomy).

## Taxonomy — one controlled vocabulary, reused everywhere

Every content file carries front-matter from a small, fixed vocabulary. This is
what lets content appear in its own section *and* on the relevant project page
without duplication, and what lets the library grow to 30+ guides without a
re-architecture.

```yaml
---
title:      "A Researcher's Guide to Schneider UMAS"
type:       guide            # guide | writeup | advisory | project | publication (external)
project:    icsfuzzer        # which program project this belongs to
protocols:  [umas, modbus]   # controlled protocol slugs
vendor:     [schneider]      # controlled: siemens|rockwell|schneider|ge|omron|cross|...
sector:     [cross]          # electric | building | manufacturing | iiot | cross
transport:  [modbus-tcp]     # modbus-tcp | iso-on-tcp | coap | dce-rpc | raw-ethernet | ...
status:     draft            # draft | published | updated
date:       2026-10-06        # writeups/advisories (dated); guides use updated:
cve:        []               # advisories only
tags:       []               # free-form overflow
---
```

- **Guides** are indexed primarily by `vendor`, filterable by `sector`/`transport`.
- **Project pages** query `project:<name>` to list everything related.
- **Advisories** key off `cve` + `vendor`.
- Adding a new protocol/vendor/project = add a slug to the vocabulary; no structural
  change.

## Repo & publishing model

- **One dedicated site repo** (`alosafuzz/alosafuzz.github.io`) holds the **public
  products**: `/guides`, `/writeups`, `/advisories`, `/projects`, the theme, and
  this architecture doc. It is the canonical public copy.
- **Project repos** (`ics-fuzzer`, `ics-scanner`, `time-fuzzer`, …) keep their
  **raw `lab-notes/` (private source) + code**. Nothing in `lab-notes/` is synced.
- **Publishing = distill + commit to the site repo.** A guide becomes public when
  its distilled form is committed under `/guides/<vendor>/`. No submodules, no
  sync script — the source/product wall is the repo boundary.
- **External / co-authored work is cross-linked, never hosted.** Bishop Fox company
  publications (byline "we") stay on bishopfox.com; the alosafuzz site links to them
  from `/publications/` and from any topically-related project page. Schneider P3
  stays unreferenced until its embargo clears. See the "External crosslinking" section.

## External crosslinking (Bishop Fox & other co-authored work)

Co-authored / company work isn't hosted on the alosafuzz site, but it *is* part of
the portfolio, so it's represented as **link-only stub entries** in the same
taxonomy. A stub is a front-matter-only file (no body) with:

```yaml
---
title:    "Sparkplug B Protocol Fuzzing with AI Assistance"
type:     publication
external: true
host:     "Bishop Fox"
url:      "https://bishopfox.com/blog/sparkplug-b-protocol-fuzzing-with-ai-assistance"
date:     2026-05-26
project:  icsfuzzer        # so it also surfaces on the relevant project page
tags:     [sparkplug, mqtt, ai-assisted-fuzzing]
---
```

Because stubs carry `project`/`tags`, they appear in `/publications/` **and** on any
project page that queries the same tag — the icsFuzzer page can list the Sparkplug B
post as lineage without hosting it. The renderer shows `external: true` items as an
outbound link (with the `host` badge), never as a local page.

### Canonical list — Shad Malloy on bishopfox.com (pulled 2026-10-06)

Source of truth = the author page `https://bishopfox.com/authors/shad-malloy`
(**re-pull at publish time** — Bishop Fox adds posts; the CVE/HTTP-3 track in
[[project_cve_pipeline]] may land more advisories under this byline).

| Title | URL | Date | Maps to |
|---|---|---|---|
| Traefik \| Version Through 3.7.11 | `bishopfox.com/blog/traefik-version-through-3-7-11` | 2026-08-31 | advisory / CVE-pipeline track (HTTP/3) |
| Sparkplug B Protocol Fuzzing with AI Assistance | `bishopfox.com/blog/sparkplug-b-protocol-fuzzing-with-ai-assistance` | 2026-05-26 | `project: icsfuzzer` (AI-assisted ICS fuzzing lineage; co-author David Colón per [[project_blog_post]]) |
| Taking Maestro in Stride: AI Threat Modeling Frameworks | `bishopfox.com/blog/taking-maestro-in-stride-ai-threat-modeling-frameworks` | 2026-04-16 | AI-security research thread (future MCP/agent-security project if it ships) |

Note: the author-page fetch did not surface co-authors; David Colón (Sparkplug B)
and the Zoe Duncan 3-post icsScanner/detection-gen series are recorded in
[[project_blog_post]] — reconcile co-author bylines from the live post pages at
publish time.

## Generator choice

- **Recommended: Hugo.** Native taxonomies/front-matter, fast builds, good for a
  growing cross-tagged reference library (the `project`/`vendor`/`sector` queries
  above are first-class). Scales cleanly past 30+ guides.
- **Fallback: Jekyll.** Zero-CI on GitHub Pages (GH builds it natively), markdown +
  front-matter, collections for guides/writeups/advisories. Lower setup, slightly
  weaker taxonomy ergonomics.
- Either way: **content is markdown + front-matter**, rendered by the generator —
  *not* hand-maintained HTML per guide (14 → 30+ guides makes per-file HTML
  unmaintainable). Reuse `alosafuzz.html`'s CSS (dark-mode tokens, TLP markings,
  tables) as the base theme, especially for the advisory layout.

## Growth playbook ("how to add X")

- **A protocol guide:** write the private research note → *if a module ships*
  (shipped-modules-only rule), distill to `/guides/<vendor>/<proto>.md` with
  front-matter → appears in the guides index and its project page automatically.
  Pipeline + status tracked in `protocol-guides-backlog.md` (icsFuzzer modules) and
  `ics-scanner/lab-notes/protocol-guides-sidequest.md` (icsScanner RE'd protocols).
- **A new project** (next fuzzer/scanner): `/projects/<name>/index.md` from the
  project template → projects index lists it; tag its guides/posts/advisories
  `project:<name>`.
- **An advisory:** `/advisories/<id>.md` from the TLP template → advisories index +
  the affected project's page via `vendor`/`cve`.
- **A writeup:** `/writeups/<slug>.md`, dated, with `project`/`tags`.

## Current content → section map (what's ready to flow in)

| Source (private) | Public section | Status |
|---|---|---|
| 14 `*-protocol-guide.md` | `/guides/` (by vendor) | drafted, ready to distill-in |
| `blog-post-ics-fuzzing.md` + OPC-UA addendum | `/writeups/` | published prose; port over |
| `alosafuzz.html` (SOEM advisory) | `/advisories/` | becomes the advisory template |
| icsFuzzer / icsScanner / timeFuzzer / snmpv3Fuzzer / hartFuzz / detection-gen | `/projects/` | need short landing pages |
| `TOPICS.md` backlog | `/now/` (optional, curated) | transparency view only |
| 3 Bishop Fox posts (Traefik / Sparkplug B / Maestro) | `/publications/` + project tags | external stubs (link-only) |
| all `*-research.md` | — | PRIVATE, never published |

## Open items (next session)

1. Pick the generator (Hugo vs. Jekyll) and scaffold the site repo + theme from
   `alosafuzz.html`'s CSS.
2. Confirm the controlled vocabularies (vendor list, transport list) against the
   full current + near-term protocol set.
3. Decide whether `/now/` ships in v1 or waits.
4. Write the per-project landing pages (6 projects today).
5. Distill the 14 guides into `/guides/<vendor>/` with front-matter (mechanical).
6. Create `/publications/` with the 3 Bishop Fox stubs; re-pull the author page
   (`bishopfox.com/authors/shad-malloy`) at publish for new items + co-author bylines.
