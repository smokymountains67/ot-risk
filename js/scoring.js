// OT Risk – scoring engine implementing "Securing the Shop Floor" Framework v2.
// Risk Score (0-100) = AIS x VSS x LF x RCIS / 3.375
(function (g) {
  const PURDUE = {
    'L0': { label: 'Level 0 – Physical process', mod: 3 },
    'L1': { label: 'Level 1 – Basic control (PLC/RTU)', mod: 3 },
    'L2': { label: 'Level 2 – Supervisory (HMI/SCADA/EWS)', mod: 2 },
    'L3': { label: 'Level 3 – Operations (MES/historian)', mod: 2 },
    'L3.5': { label: 'Level 3.5 – IT/OT DMZ', mod: 3 },
    'L4': { label: 'Level 4 – Business systems', mod: 1 },
    'L5': { label: 'Level 5 – Enterprise IT', mod: 1 },
  };
  const AIS_CRITERIA = [
    { key: 'op', name: 'Operational impact', opts: ['Minimal disruption', 'Delays production', 'Halts production'] },
    { key: 'sa', name: 'Safety risk', opts: ['No direct safety impact', 'Can create hazardous conditions', 'Immediate physical harm potential'] },
    { key: 'rd', name: 'Redundancy & failover', opts: ['Fully redundant, instant failover', 'Some redundancy, manual switch-over', 'No redundancy, single point of failure'] },
    { key: 'rc', name: 'Regulatory compliance risk', opts: ['No compliance impact', 'Potential fines', 'High financial/legal consequences'] },
  ];
  const MATURITY_FACTORS = [
    ['OT security leadership', 'No dedicated security team', 'Shared IT/OT security responsibility', 'Dedicated OT security personnel and leadership'],
    ['Network segmentation', 'Flat network, IT and OT mixed', 'Basic segmentation, some firewalls', 'Fully segmented, strict access control'],
    ['Asset inventory & visibility', 'No formal inventory, shadow assets unknown', 'Partial inventory, manually updated', 'Real-time tracking with automated discovery'],
    ['Vulnerability management', 'No structured process, ad-hoc patching', 'Some scanning, limited remediation timelines', 'Risk-based VM with defined SLAs'],
    ['Regulatory compliance', 'No awareness of requirements', 'Partial compliance, some audit tracking', 'Fully integrated, proactive compliance program'],
    ['Company size & org complexity', 'High complexity, limited security focus', 'Moderate complexity, some structured processes', 'Streamlined complexity, strong governance'],
    ['Shop floor & OT asset complexity', 'Unstructured OT, poor asset tracking', 'Semi-organized OT, moderate tracking', 'Well-structured OT, high visibility'],
    ['Cybersecurity budget & resources', 'Minimal funding, few resources', 'Some budget, limited dedicated team', 'Strong funding, dedicated team'],
    ['Third-party vendor dependencies', 'Heavy reliance on vendors for security', 'Moderate vendor involvement', 'Minimal reliance on vendors'],
  ];
  const LF_TABLE = { 2: 0.5, 3: 0.75, 4: 1.0, 5: 1.25, 6: 1.5 };
  const BANDS = [
    { min: 50, level: 'Critical', cls: 'crit' },
    { min: 30, level: 'High', cls: 'high' },
    { min: 15, level: 'Moderate', cls: 'mod' },
    { min: 0, level: 'Low', cls: 'low' },
  ];
  // Containment by risk level (same for all); remediation days by maturity
  const SLA = {
    Critical: { contain: 3, remediate: { Poorly: 90, Reasonably: 30, Highly: 14 } },
    High: { contain: 14, remediate: { Poorly: 180, Reasonably: 90, Highly: 30 } },
    Moderate: { contain: null, remediate: { Poorly: 365, Reasonably: 180, Highly: 90 } },
    Low: { contain: null, remediate: { Poorly: null, Reasonably: null, Highly: 180 } },
  };
  const COMP_CONTROLS = {
    Poorly: 'Default to isolation: disable/disconnect remote access, restrict to named users, vendor hardening, manual weekly check, owner signs exception.',
    Reasonably: 'Firewall/ACL to known hosts only, IDS signature/alert where available, exception in risk register reviewed quarterly.',
    Highly: 'Zone/conduit enforcement (IEC 62443-3-2), tuned passive OT detection, automated exception expiry and re-scoring on KEV/EPSS change.',
  };

  function maturityLevel(total) {
    if (!total) return null;
    return total <= 14 ? 'Poorly' : total <= 21 ? 'Reasonably' : 'Highly';
  }
  function ais(crit, purdue) {
    const p = (PURDUE[purdue] || PURDUE.L2).mod;
    const s = (+crit.op || 1) + (+crit.sa || 1) + (+crit.rd || 1) + (+crit.rc || 1) + p;
    return { score: s, level: s >= 12 ? 'High' : s >= 8 ? 'Moderate' : 'Low', purdueMod: p };
  }
  function vss(cvss) {
    const c = +cvss;
    if (!(c > 0)) return { score: 5, cat: 'Moderate (no CVSS – manual)' };
    if (c >= 9) return { score: 10, cat: 'Critical' };
    if (c >= 7) return { score: 7, cat: 'High' };
    if (c >= 4) return { score: 5, cat: 'Moderate' };
    return { score: 3, cat: 'Low' };
  }
  function threat(kev, epss, publicExploit) {
    if (kev) return { t: 3, why: 'CISA KEV' };
    if ((+epss || 0) >= 0.1 || publicExploit) return { t: 2, why: (+epss >= 0.1 ? 'EPSS ≥ 0.10' : 'Public exploit') };
    return { t: 1, why: 'EPSS < 0.10, no known exploit' };
  }
  function band(score) { return BANDS.find(b => score >= b.min); }
  // v: {cvss, kev, epss, publicExploit, reach(1-3), rcis}
  function score(asset, v) {
    const a = ais(asset.crit || {}, asset.purdue);
    const s = vss(v.cvss);
    const th = threat(v.kev, v.epss, v.publicExploit);
    const r = Math.min(3, Math.max(1, +v.reach || 2));
    const lf = LF_TABLE[th.t + r];
    const rcis = +v.rcis || 1.0;
    let raw = a.score * s.score * lf * rcis / 3.375;
    raw = Math.round(raw * 10) / 10;
    let b = band(raw), floored = false;
    if (v.kev && r >= 2 && raw < 30) { b = BANDS[1]; floored = true; }
    return { ais: a, vss: s, threat: th, reach: r, lf, rcis, score: raw, level: b.level, cls: b.cls, floored };
  }
  function slaFor(level, maturity, foundISO) {
    const m = maturity || 'Reasonably';
    const s = SLA[level]; const out = { containDays: s.contain, remediateDays: s.remediate[m] };
    if (foundISO) {
      const f = new Date(foundISO);
      if (out.containDays) out.containBy = new Date(f.getTime() + out.containDays * 864e5).toISOString().slice(0, 10);
      if (out.remediateDays) out.remediateBy = new Date(f.getTime() + out.remediateDays * 864e5).toISOString().slice(0, 10);
    }
    return out;
  }
  // FAIR-style ALE via Monte Carlo with triangular distributions.
  function tri(a, m, b, r) { if (b <= a) return a; const c = (m - a) / (b - a); return r < c ? a + Math.sqrt(r * (b - a) * (m - a)) : b - Math.sqrt((1 - r) * (b - a) * (b - m)); }
  function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  function ale(lef, lm, n = 10000) {
    if (!lef || !lm || lef.some(x => isNaN(+x)) || lm.some(x => isNaN(+x))) return null;
    const R = rng(42), out = new Float64Array(n);
    for (let i = 0; i < n; i++) out[i] = tri(+lef[0], +lef[1], +lef[2], R()) * tri(+lm[0], +lm[1], +lm[2], R());
    out.sort(); const q = p => out[Math.floor(p * (n - 1))];
    let sum = 0; for (const x of out) sum += x;
    return { p10: q(.1), p50: q(.5), p90: q(.9), mean: sum / n };
  }
  g.OTScore = { PURDUE, AIS_CRITERIA, MATURITY_FACTORS, LF_TABLE, BANDS, SLA, COMP_CONTROLS, maturityLevel, ais, vss, threat, band, score, slaFor, ale };
  if (typeof module !== 'undefined') module.exports = g.OTScore;
})(typeof window !== 'undefined' ? window : globalThis);
