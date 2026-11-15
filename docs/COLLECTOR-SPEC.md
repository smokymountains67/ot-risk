# OT Risk collector feed: `otrisk.collector.v1` (draft)

This is the format a future **on-site collector agent** will use to send asset observations to OT Risk. The v0.1 web app already accepts it through **Import** (drop the JSON file), so the format can be tested before the agent exists.

## Design rules
- **Passive by default.** Data comes from a SPAN/TAP, offline PCAP, switch ARP/CAM tables, DHCP, or firewall logs. Active querying is a separate per-subnet opt-in that needs a named approver and a maintenance window, and it is never enabled on Levels 0–1 by default.
- **Outbound only.** The collector pushes to the OT Risk API over HTTPS with mTLS (v1+). It never accepts inbound connections from the internet.
- **Observations, not decisions.** The collector can propose vendor, model, firmware, protocols, and a Purdue guess. Criticality ratings and confirmed Purdue levels stay human-owned and are never overwritten.
- **Idempotent.** Assets match on MAC first, then IP within the site. `firstSeen` and `lastSeen` drive stale-asset reports.

## Payload
```json
{
  "schema": "otrisk.collector.v1",
  "collector": { "id": "plant2-sensor-01", "method": "passive|infra|safe-active|import", "version": "0.1.0" },
  "site": "s2",
  "collectedAt": "2026-11-14T22:00:00Z",
  "assets": [
    {
      "ip": "10.20.20.10", "mac": "00:1B:1B:10:20:30",
      "name": "optional hostname", "vendor": "Siemens", "model": "CPU 1515-2 PN", "firmware": "2.9.4",
      "type": "PLC", "purdue": "L1", "zone": "Weld Cell",
      "protocols": ["S7comm-plus"], "peers": ["10.20.50.15"],
      "firstSeen": "2026-10-01T12:00:00Z", "lastSeen": "2026-11-14T21:59:00Z",
      "cves": ["CVE-2020-15782"]
    }
  ]
}
```
`peers` (planned) records which hosts talk to an asset. That will let the app **compute reachability (R)** from real flows instead of asking a person.

## Planned endpoint (v1 backend)
`POST /api/v1/sites/{siteId}/observations`. The body is the payload above, and the response is `{ "accepted": n, "new": n, "updated": n }`.
