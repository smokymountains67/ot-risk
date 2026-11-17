// Nightly threat-feed builder for OT Risk. Node 20+, no dependencies.
// Usage: node scripts/build-feeds.mjs --csaf /path/to/cisagov-CSAF-clone [--out data] [--epss-file file.csv.gz] [--kev-file kev.json]
// Writes compact JSON into data/: kev.json, epss.json, ics.json, meta.json
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, arr) => (x.startsWith('--') ? a.concat([[x.slice(2), arr[i + 1]]]) : a), []));
const OUT = args.out || 'data';
const CSAF = args.csaf;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const now = new Date().toISOString();
const clip = (s, n) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
fs.mkdirSync(OUT, { recursive: true });

async function get(url, binary) {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(url, { headers: { 'user-agent': 'ot-risk-feed-builder (github.com/smokymountains67/ot-risk)' } });
      if (!r.ok) throw new Error(url + ' -> HTTP ' + r.status);
      return binary ? Buffer.from(await r.arrayBuffer()) : await r.text();
    } catch (e) { if (i === 2) throw e; await new Promise(res => setTimeout(res, 5000 * (i + 1))); }
  }
}

// ---------- 1. CISA KEV ----------
const kevRaw = JSON.parse(args['kev-file'] ? fs.readFileSync(args['kev-file'], 'utf8') : await get(KEV_URL));
const kev = {};
for (const v of kevRaw.vulnerabilities) {
  // [dateAdded, vendor, product, knownRansomware, dueDate, name, requiredAction]
  kev[v.cveID] = [v.dateAdded, v.vendorProject, v.product, v.knownRansomwareCampaignUse === 'Known', v.dueDate, clip(v.vulnerabilityName, 120), clip(v.requiredAction, 220)];
}
const kevMeta = { version: kevRaw.catalogVersion, released: kevRaw.dateReleased, count: kevRaw.count || Object.keys(kev).length };
console.log('KEV', kevMeta);

// ---------- 2. CISA ICS advisories (CSAF, OT/white) ----------
const advisories = [];
const BOILER = /^(CISA (recommends|reminds|also|encourages)|Minimize network exposure|Locate control system networks|When remote access is required|Organizations observing suspected|No known public exploitation|This vulnerability (is|has) not)/i;
function walkCSAF(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walkCSAF(p)); else if (/^icsm?a-.*\.json$/i.test(e.name)) out.push(p);
  }
  return out;
}
if (CSAF) {
  const root = path.join(CSAF, 'csaf_files', 'OT', 'white');
  const files = walkCSAF(root);
  for (const f of files) {
    let d; try { d = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { console.warn('skip', f, e.message); continue; }
    const doc = d.document || {}, tr = doc.tracking || {};
    const id = (tr.id || path.basename(f, '.json')).toUpperCase();
    const products = [], pidName = {}, vendors = new Set();
    (function walk(br, ctx) {
      for (const b of br || []) {
        const c = Object.assign({}, ctx);
        if (b.category === 'vendor') c.vendor = b.name;
        if (b.category === 'product_name' || b.category === 'product_family') c.product = c.product ? c.product + ' ' + b.name : b.name;
        if (b.branches) walk(b.branches, c);
        else {
          const vendor = c.vendor || '';
          if (vendor) vendors.add(vendor);
          const pname = c.product || (b.product && b.product.name) || b.name;
          const ver = (b.category === 'product_name' || b.category === 'product_family') ? '' : b.name;
          products.push([vendor, clip(pname, 140), clip(ver, 80)]);
          if (b.product) pidName[b.product.product_id] = products.length - 1;
        }
      }
    })((d.product_tree || {}).branches, {});
    const cves = [], cvss = {}, fixes = new Map();
    for (const v of d.vulnerabilities || []) {
      if (v.cve) { cves.push(v.cve); const sc = (v.scores || []).map(s => (s.cvss_v3 || s.cvss_v4 || s.cvss_v2 || {}).baseScore).filter(x => x != null); if (sc.length) cvss[v.cve] = Math.max(...sc); }
      for (const r of v.remediations || []) {
        const key = r.category + '|' + clip(r.details, 600);
        if (!fixes.has(key)) fixes.set(key, { k: r.category, x: clip(r.details, 600), u: r.url || undefined, c: [] });
        if (v.cve && !fixes.get(key).c.includes(v.cve)) fixes.get(key).c.push(v.cve);
      }
    }
    // Vendor general recommendations (not the CISA boilerplate) become mitigations too.
    for (const n of doc.notes || []) {
      if (n.category === 'general' && /recommend/i.test(n.title || '') && !/^Recommended Practices$/i.test(n.title || '') && !BOILER.test(n.text || '')) {
        const key = 'general|' + clip(n.text, 600); if (!fixes.has(key)) fixes.set(key, { k: 'general', x: clip(n.text, 600), c: [] });
      }
    }
    // Dedupe products
    const seen = new Set(), prods = [];
    for (const p of products) { const k = p.join('|'); if (!seen.has(k)) { seen.add(k); prods.push(p); } }
    const fx = [...fixes.values()].slice(0, 25).map(x => { if (x.c.length === cves.length) delete x.c; return x; });
    const isMed = /^ICSMA/i.test(id);
    advisories.push({
      id, t: clip(doc.title, 160), d: (tr.current_release_date || tr.initial_release_date || '').slice(0, 10), r: (tr.initial_release_date || '').slice(0, 10),
      u: 'https://www.cisa.gov/news-events/ics-' + (isMed ? 'medical-advisories' : 'advisories') + '/' + id.toLowerCase(),
      v: [...vendors], p: prods.slice(0, 1000), c: cves, s: cvss, f: fx,
    });
  }
  advisories.sort((a, b) => (b.r || b.d).localeCompare(a.r || a.d));
  console.log('ICS advisories', advisories.length);
} else console.warn('No --csaf dir given; keeping previous ics.json if present');

// ---------- 3. EPSS (trimmed to KEV + ICS CVEs + extras + EPSS >= 0.1) ----------
const want = new Set(Object.keys(kev));
advisories.forEach(a => a.c.forEach(c => want.add(c)));
const extraFile = path.join(path.dirname(new URL(import.meta.url).pathname), 'epss-extra.txt');
if (fs.existsSync(extraFile)) fs.readFileSync(extraFile, 'utf8').split(/\s+/).filter(x => /^CVE-/.test(x)).forEach(c => want.add(c));
const gz = args['epss-file'] ? fs.readFileSync(args['epss-file']) : await get(EPSS_URL, true);
const csv = zlib.gunzipSync(gz).toString('utf8').split('\n');
let epssMeta = {};
const epss = {};
for (const line of csv) {
  if (line.startsWith('#')) { const m = /model_version:([^,]+),score_date:(\S+)/.exec(line); if (m) epssMeta = { model: m[1], date: m[2] }; continue; }
  const [cve, e, p] = line.split(',');
  if (!cve || !cve.startsWith('CVE-')) continue;
  const ev = +e;
  if (want.has(cve) || ev >= 0.1) epss[cve] = [+ev.toFixed(5), +(+p).toFixed(4)];
}
epssMeta.count = Object.keys(epss).length;
epssMeta.scope = 'CVEs in CISA KEV, CISA ICS advisories, scripts/epss-extra.txt, plus every CVE with EPSS >= 0.10';
console.log('EPSS', epssMeta);

// ---------- write ----------
const write = (name, obj) => { const s = JSON.stringify(obj); fs.writeFileSync(path.join(OUT, name), s); console.log('wrote', name, (s.length / 1024).toFixed(0) + ' KB'); };
write('kev.json', { meta: kevMeta, kev });
write('epss.json', { meta: epssMeta, epss });
let icsMeta;
if (CSAF) { icsMeta = { count: advisories.length, newest: advisories[0] && advisories[0].r, source: 'github.com/cisagov/CSAF csaf_files/OT/white' }; const fixes = {}; for (const a of advisories) { if (a.f.length) fixes[a.id] = a.f; delete a.f; }
  write('ics.json', { meta: icsMeta, adv: advisories });
  write('ics-fixes.json', { meta: { count: Object.keys(fixes).length }, fixes }); }
else { try { icsMeta = JSON.parse(fs.readFileSync(path.join(OUT, 'ics.json'), 'utf8')).meta; } catch (e) { icsMeta = null; } }
write('meta.json', {
  updated: now, kev: kevMeta, epss: epssMeta, ics: icsMeta,
  sources: { kev: KEV_URL, epss: EPSS_URL, ics: 'https://github.com/cisagov/CSAF' },
});
