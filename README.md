# OT Risk: shop-floor vulnerability risk platform (v0.2 test build)

OT Risk is a static single-page app that puts the **Securing the Shop Floor v2** framework into practice:

> Risk Score (0–100) = AIS × VSS × LF × RCIS ÷ 3.375

No backend, no accounts, no build step. Your data stays in the browser's localStorage, and the app **never scans networks**. Every night a GitHub Action refreshes public threat data (CISA KEV, FIRST EPSS, CISA ICS advisories) into `data/`, and the app matches it against your saved equipment.

Live test site: https://smokymountains67.github.io/ot-risk/ · New users: open **Help** (`#/help`).

> Scores, deadlines, loss estimates and fix guidance are **decision support, not engineering advice**. Validate with the OEM and process safety. Patches, firmware updates and reboots on controllers belong in a planned maintenance window.

## Run locally
```bash
cd ot-risk-site
python3 -m http.server 8080      # then open http://localhost:8080
```
Use a web server (not `file://`) so the browser can load `data/*.json`. Without it the app falls back to the bundled KEV snapshot and equipment matching is off. Any static host works: GitHub Pages, Cloudflare Pages, Netlify, or an internal IIS/nginx server.

## Features
| Area | What it does |
|---|---|
| **Help** (`#/help`) | 10-step Getting Started guide (company/site setup, maturity wizard, adding and importing assets, vulnerabilities, feed alerts, reading the score, risk register, fixing, backup/restore) and a glossary (KEV, EPSS, CVSS, AIS, VSS, LF, RCIS, Purdue levels, FAIR, CSAF…). "?" tips on every screen. A self-checking **Start here** checklist on the dashboard. |
| **Nightly feeds** | Header badge shows the feed date (green = fresh, amber = older than 3 days, orange = bundled snapshot). `data/` holds CISA KEV, FIRST EPSS (trimmed), and every CISA ICS advisory (CSAF) with vendor, products, versions, CVEs, CVSS and remediation text. |
| **Alerts** (`#/alerts`) + **New since your last visit** | Assets are matched by vendor / model / firmware against the ICS advisories and KEV. Each result is a **possible match** with High/Medium/Low confidence and the reason ("model number 1756-EN2T appears in the advisory; firmware 10.010 is inside the affected range ≤ 11.002"). **Confirm** creates vulnerability records prefilled with CVE, CVSS, EPSS, KEV and the advisory link; **Dismiss** is remembered (with optional reason, undoable). Existing findings are **re-scored and flagged** when a CVE joins KEV or its EPSS crosses the threat threshold. |
| **Fix guide** (`#/vuln/<id>`) | Why the score is what it is, contain-by / fix-by dates, vendor fixes and mitigations from the CISA advisory, the KEV required action, and **OT-safe compensating controls** (restrict reachability, disable the service, remote-access lockdown, controller protection features, allowlisting, monitoring, backups, isolation, exception). Tick controls to add them to the record and mark it Contained. Controllers get a maintenance-window caveat. |
| **Calculator** (`#/calc`) | OWASP-calculator style; the whole scenario lives in the URL. Live score, breakdown, KEV floor, SLA, optional FAIR ALE (P10/P50/P90). |
| **Company & Sites, Maturity wizard, Asset inventory, Risk register, Dashboard, Import** | As in v0.1 (see below). Import now recommends passive/vendor-tool exports first and puts a clear warning on Nmap/NSE. |
| **Data** | JSON backup/restore (with "last exported" reminder), sample/empty reset, privacy toggle, alert settings. |

### Privacy: CVE look-ups
Default is **Use only nightly feeds**: the Look up button reads KEV, EPSS and CVSS from `data/`, so nothing about your equipment leaves the browser. Turning it off (Data screen) also queries `api.first.org` and `services.nvd.nist.gov` live, which reveals the CVE IDs you track to those services. The UI says which mode is on next to every Look up button.

### Imports
Recommended path: inventory/asset CSV exports from passive or vendor tools you already run (Claroty, Nozomi Networks, Dragos, Microsoft Defender for IoT, Tenable OT), switch ARP/MAC and CDP/LLDP tables, DHCP leases, PLC project I/O lists. Nmap XML is supported, but only from a scan with written OT/process-owner sign-off, inside a maintenance window, one host at a time, never during production.

## Nightly feed job
`.github/workflows/feeds.yml` runs daily at 09:17 UTC and on demand (**Actions → Nightly threat feeds → Run workflow**). It:
1. sparse-clones `github.com/cisagov/CSAF` (`csaf_files/OT/white`, ~4,000 advisories),
2. runs `node scripts/build-feeds.mjs --csaf /tmp/csaf --out data`, which downloads the CISA KEV JSON and the FIRST EPSS CSV,
3. runs `node tests/run-tests.js`,
4. commits `data/` if anything changed and asks Pages to rebuild.

| File | Contents | Size (gzip) |
|---|---|---|
| `data/meta.json` | build timestamp, versions, counts, sources | <1 KB |
| `data/kev.json` | `{cve: [dateAdded, vendor, product, ransomware, dueDate, name, requiredAction]}` | ~50 KB |
| `data/epss.json` | `{cve: [epss, percentile]}` for CVEs in KEV, ICS advisories, `scripts/epss-extra.txt`, plus every CVE with EPSS ≥ 0.10 | ~240 KB |
| `data/ics.json` | advisories: id, title, dates, URL, vendors, `[vendor, product, versionRange]`, CVEs, CVSS | ~500 KB |
| `data/ics-fixes.json` | per-advisory vendor fixes / mitigations / workarounds (loaded only when a Fix guide opens) | ~770 KB |

## Tests
```bash
node tests/run-tests.js     # scoring worked examples, version-range parser, matcher, re-scoring, guidance
```

## Files
```
index.html, css/styles.css
js/scoring.js     v2 scoring engine (Node + browser)
js/matcher.js     equipment ↔ advisory/KEV matcher, version-range parser, re-score diff (Node + browser)
js/guidance.js    fix grouping + OT-safe compensating controls (Node + browser)
js/feeds.js       loads data/*.json, falls back to js/kev-data.js
js/help.js        Getting Started, glossary, "?" tips
js/importers.js   Nmap XML / CSV / collector JSON parsers
js/app.js         views, routing, storage
js/sample.js      fictional plant (Northfield Air Systems)
js/kev-data.js    bundled CISA KEV snapshot (fallback)
scripts/build-feeds.mjs   nightly feed builder (Node 20, no dependencies)
tests/run-tests.js
data/             nightly feed output (committed by the Action)
samples/          test import files
docs/RESEARCH.md, docs/COLLECTOR-SPEC.md
```

## Sample data
**Northfield Air Systems (fictional)** is an HVAC-equipment maker with two plants and 21 assets. Company, sites, IPs, owners and dollar figures are invented; vendor/model names are real product lines so the feed matching has something to find.

## Known limits (v0.2)
- **Matching is text-based and fuzzy.** It compares vendor, model and firmware strings to CISA's product lists. Expect some wrong "possible matches" and some misses, especially when the asset's model is a nickname or the advisory lists product families. Catalog numbers and exact firmware strings on assets make a big difference. Low-confidence matches are hidden by default.
- **KEV has no version data,** so KEV-only matches (e.g. Microsoft Windows) are grouped and marked Low; tick only the CVEs that apply.
- **EPSS is trimmed** to KEV/ICS CVEs and anything ≥ 0.10 to keep the download small. A CVE missing from the set is very likely < 0.10 (or enable live look-ups).
- CVSS in feeds-only mode comes from CISA advisories only; other CVEs need CVSS typed in (or live look-ups on).
- Data is per browser (localStorage). No multi-user access, no audit trail yet. Back up regularly.
- No email digest: the server never sees your asset list. That comes with the pilot backend.
- The nightly commit adds a few MB of changed JSON to git history per day when advisories change.

## Roadmap (short)
1. **v0.3:** asset completeness to-dos, Rockwell L5X / Siemens project-file import, audit log of decisions and re-scores, matcher tuning on real (anonymized) inventories, one-page PDF report.
2. **Pilot backend:** small API + Postgres (tenants → sites → zones → assets → findings → decisions), SSO, roles, server-side nightly matching and a **daily email digest** of new matches, internal hosting.
3. **Commercial:** multi-tenant, connectors (Claroty/Nozomi/Dragos/Defender for IoT/Tenable OT exports and APIs), passive collector (`otrisk.collector.v1`), ticketing, compliance mapping.
