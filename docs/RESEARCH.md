# What similar products do, and what OT Risk borrows

This is a short scan, not a full market study. It draws on vendor pages and 2026 buyer guides (CIOPages, Reliamag, StartupStash), checked 15 Nov 2026. Please verify before quoting any of it externally.

| Product | Discovery approach | Notable ideas | Borrow for OT Risk |
|---|---|---|---|
| **OWASP Risk Rating calculator** (owaspriskrating.com) | n/a | A single page where the whole score lives in the URL hash, so links are shareable. | ✅ Done: the `#/calc/(...)` state string. |
| **Claroty** (xDome SaaS / CTD on-prem) | Passive DPI, "Safe Queries" active discovery, **project-file analysis**, Claroty Edge (a hardware-free collector that runs on Windows, Linux, or Docker) | Exposure management, secure remote access, and in 2026 a "Visibility Score" with tasks that fill gaps in asset attributes. | Add a **completeness score per asset** (missing firmware/owner/zone becomes a to-do). Import PLC project files. A lightweight collector packaged as a Docker or Windows service. |
| **Nozomi Networks** (Guardian sensors, Vantage cloud; acquired by Mitsubishi Electric, Jan 2026) | Passive SPAN/TAP; "Smart Polling" for opt-in active queries; Arc endpoint sensor | Multi-site trunk (sensors feeding a central console); asset- and threat-intel subscriptions | A **site → central** model: each site's collector pushes to one tenant. |
| **Dragos Platform** (acquired runZero and NetRise in Sept 2026) | Passive first; active collection adds firmware, OS, and patch detail | Threat-intel content, the "Now / Next / Never" style of vulnerability triage, IR retainers | Triage language that plant engineers understand. **runZero-style safe active discovery** as an *optional*, operator-approved collector mode for Level 3+. |
| **Tenable OT Security** | Passive plus patented "Safe Active Queries"; **imports SCD, ACD, CSV, and PLC project files** | Feeds Tenable One, so IT and OT share one exposure view; attack-path analysis | CSV import (✅ done); Rockwell **.L5X/.ACD** and Siemens project import on the roadmap; attack paths shown as "reachability" (R in v2). |
| **Armis Centrix** | Agentless: passive traffic plus integrations (switches, firewalls, CMDB, EDR) and a large device-knowledge base | Builds the inventory by **pulling from existing tools** rather than scanning | Integrations as a discovery source: switch CAM/ARP tables, firewall logs, DHCP, AD. These are low-risk ways to learn about assets. |
| **GRASSMARLIN** (NSA, open source, archived) | Passive only, from PCAP | A logical network map from captured traffic, classified by ICS protocol | A **PCAP-to-asset** import path, so offline analysis can run on a laptop and never touch the network. |
| **Nmap + OT NSE scripts** (`enip-info`, `s7-info`, `modbus-discover`, `bacnet-info`) | Active, so it has to be handled carefully | Free, and it gives vendor, model, and firmware | ✅ Import parser done. Guidance: only in maintenance windows, and only with ops sign-off. Use `-sT --scan-delay`, a narrow port list, and no `-sV`/`-O` against Level 0–1. |

## Discovery approaches, ranked by safety
1. **Documentation and project files.** Engineering drawings, PLC project exports (.L5X), and spare-parts lists. Zero network risk.
2. **Infrastructure data.** Switch MAC/ARP tables, DHCP leases, firewall logs, SNMP from network gear only.
3. **Passive capture.** A SPAN or TAP feeding a sensor, or a PCAP processed offline. Zero packets go to the devices.
4. **Vendor-approved safe active queries.** Native protocol reads at a low rate (as in Tenable, Claroty, and Nozomi).
5. **Generic active scanning** (Nmap, IT vulnerability scanners). Fine on Levels 3–5. On Levels 0–2 it needs a maintenance window, a narrow scope, and sign-off. It has been known to crash older PLCs and HMIs.

OT Risk v0.1 only **imports** results. The future collector (see `COLLECTOR-SPEC.md`) will default to modes 2–3 and treat mode 4 as an opt-in, per subnet.
