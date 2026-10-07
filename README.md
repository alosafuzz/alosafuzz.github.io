# alosafuzz.github.io

Source for the alosafuzz research-program site. Built with Jekyll; **GitHub Pages
compiles it on push** (no local toolchain required).

## Structure
- `_projects/`     one page per program project (icsFuzzer, icsScanner, …)
- `_guides/`       protocol reference guides (research-focused), indexed by vendor
- `_writeups/`     narrative blog posts (dated)
- `_advisories/`   coordinated-disclosure / CVE pages (TLP-marked)
- `_publications/` external / co-authored work (Bishop Fox, etc.) — link-only stubs
- `_layouts/`, `assets/css/style.css`  theme

## Adding content
See **PUBLISHING.md** — the reusable publish workflow every alosafuzz project follows
(source `lab-notes/*-research.md` stays private; only distilled products land here).

Architecture rationale: `docs/site-architecture.md`.
