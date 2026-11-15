# OT Risk: shop-floor vulnerability risk platform (v0.1 test build)

OT Risk is a static single-page app that puts the **Securing the Shop Floor v2** framework into practice:

> Risk Score (0–100) = AIS × VSS × LF × RCIS ÷ 3.375

The app has no backend, no accounts, and no build step. Data stays in the browser's localStorage, and the app **never scans networks**.

## Run locally
```bash
cd ot-risk-site
python3 -m http.server 8080      # then open http://localhost:8080
```
Any static host will work: GitHub Pages, Cloudflare Pages, Netlify, or an internal IIS/nginx server.

## MVP features
| Area | What it does |
|---|---|
| **Calculator** (`#/calc`) | Works like the OWASP Risk Rating calculator, and the whole scenario lives in the URL (`#/calc/(OP:3/SA:2/.../MAT:Reasonably)`), so any link can be shared. It gives a live score, a breakdown, the KEV floor, the response SLA for the selected maturity, and an optional FAIR ALE (Monte Carlo P10/P50/P90). **Look up** pulls CVSS from NVD and EPSS from FIRST, and KEV from the bundled CISA snapshot. |
| **Company & Sites** | A company profile plus multiple sites, with a site switcher in the header. |
| **Maturity wizard** | Walks through the 9 factors, then shows the level (Poorly / Reasonably / Highly), the VMP focus, the SLA table, compensating-control expectations, and the weakest factors. |
| **Asset inventory** | Name, type, vendor/model, firmware, IP/MAC, Purdue level, zone, owner, and the 4 AIS criteria. AIS is auto-computed, and each asset shows its worst open risk. |
| **Vulnerabilities per asset** | CVE, CVSS, KEV, EPSS, public exploit, reachability, RCIS, status, found date, owner, compensating control, decision, and optional FAIR inputs. |
| **Risk register** | Ranks every vulnerability, with due dates for containment and remediation (risk level × site maturity), overdue flags, filters, and CSV export. |
| **Dashboard** | Counts by band, open KEV, past-SLA items, maturity, a sum of ALE medians, a Purdue × risk heat map, assets by zone, and the top risks. |
| **Import** | Nmap XML (including the `enip-info`, `s7-info`, `modbus-discover`, and `bacnet-info` NSE scripts), CSV (flexible headers, CVE column), and collector JSON (`otrisk.collector.v1`). It shows a preview first and matches on IP/MAC. Your criticality ratings and Purdue choices are never overwritten. |
| **Data** | JSON backup/restore, reload the sample plant, start empty, and re-check KEV flags. |

## Sample data
**Northfield Air Systems (fictional)** is an HVAC-equipment maker with two plants and 21 assets. The CVE/CVSS/KEV/EPSS values are real as of 15 Nov 2026. Test import files are in `samples/`.

## Files
```
index.html, css/styles.css
js/scoring.js     v2 scoring engine (also runs in Node: require('./js/scoring.js'))
js/importers.js   Nmap XML / CSV / collector JSON parsers
js/app.js         views, routing, storage
js/sample.js      fictional plant
js/kev-data.js    CISA KEV snapshot (catalog 2026.11.13, 1,781 CVEs)
samples/          test import files
docs/RESEARCH.md  what similar products do and what we borrow
docs/COLLECTOR-SPEC.md   feed format for a future on-site collector
```

## Known limits (v0.1)
- Data is per browser. To move it, use the JSON export/import. There is no multi-user access and no audit trail yet.
- The KEV list is a bundled snapshot. EPSS and NVD are looked up live when you click; NVD rate-limits anonymous lookups (about 5 every 30 s).
- New imported assets get default criticality (2/1/2/1), so a person has to rate them.
- The Purdue level for imported assets is a guess from ports, and it is flagged as one.

## Path to a backend / multi-tenant version
1. **v0.2:** keep it static but move storage to IndexedDB, add a nightly KEV/EPSS refresh through a small scheduled job (a GitHub Action or Cloudflare Worker) that writes JSON next to the site, and add an audit log of decisions.
2. **v1 (pilot):** add a small API (FastAPI or Node) with Postgres. Tables: tenants → sites → zones → assets → findings → decisions. Add SSO (Entra ID/Google), roles (viewer / engineer / approver), and a server-side KEV/EPSS sync. The scoring engine stays the same shared JS/TS module.
3. **v2 (commercial):** multi-tenant with row-level security, a collector agent per site pushing `otrisk.collector.v1` over mTLS, connectors (Claroty/Nozomi/Tenable OT/Dragos exports, ServiceNow/Jira tickets), and SOC 2 controls.
