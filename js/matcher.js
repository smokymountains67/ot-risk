// OT Risk – equipment matcher. Matches saved assets (vendor / model / firmware) against
// CISA ICS advisories (CSAF) and the CISA KEV catalog. Everything it returns is a
// "possible match" with a confidence and a plain-English reason; a person confirms or dismisses it.
// Runs in the browser (window.OTMatch) and in Node (require('./js/matcher.js')).
(function (g) {
  const SUFFIX = /\b(inc|incorporated|corp|corporation|co|company|ltd|limited|gmbh|ag|sa|s a|llc|plc|group|industries|international|holdings|kg|se|bv|oy|ab|spa|srl|the)\b/g;
  const ALIAS = {
    'allen bradley': 'rockwell automation', 'rockwell': 'rockwell automation', 'rockwell automation allen bradley': 'rockwell automation',
    'schneider': 'schneider electric', 'se schneider electric': 'schneider electric', 'general electric': 'ge', 'ge vernova': 'ge', 'ge digital': 'ge', 'ge grid solutions': 'ge',
    'mitsubishi': 'mitsubishi electric', 'emerson process management': 'emerson', 'emerson electric': 'emerson', 'honeywell process solutions': 'honeywell',
    'siemens energy': 'siemens', 'siemens healthineers': 'siemens healthineers', 'hitachi energy': 'hitachi energy', 'abb': 'abb', 'johnson controls': 'johnson controls',
    'delta': 'delta electronics', 'phoenix': 'phoenix contact', 'microsoft windows': 'microsoft', 'fanuc america': 'fanuc', 'cisco systems': 'cisco',
  };
  const GENERIC_VENDOR = new Set(['', 'generic', 'unknown', 'other', 'n a', 'na', 'various', 'custom', 'dell', 'hp', 'lenovo']);
  const STOP = new Set(['series', 'cpu', 'module', 'modules', 'with', 'on', 'the', 'and', 'for', 'plus', 'pn', 'dp', 'sp1', 'sp2', 'win', 'family', 'version', 'versions',
    'all', 'prior', 'firmware', 'controller', 'controllers', 'incl', 'including', 'variants', 'variant', 'products', 'product', 'ethernet', 'network', 'edition', 'software',
    'of', 'to', 'and', 'or', 'based', 'java', 'generic', 'device', 'devices', 'system', 'systems', 'server', 'servers', 'station', 'industrial', 'automation', 'electric',
    'unit', 'units', 'card', 'cards', 'type', 'model', 'models', 'web', 'from', 'before', 'earlier', 'later', 'than', 'using', 'v1', 'v2', 'v3', 'v4', 'v5', 'reporting', 'plc', 'hmi', 'rtu',
    'interface', 'basic', 'standard', 'advanced', 'professional', 'pro', 'lite', 'compact', 'panel', 'touch', 'communication', 'processor', 'adapter', 'gateway', 'switch', 'switches', 'drive', 'drives',
    'terminal', 'terminals', 'operator', 'control', 'controls', 'remote', 'safety', 'power', 'data', 'manager', 'management', 'client', 'service', 'services', 'tool', 'tools', 'suite', 'platform', 'runtime', 'studio', 'view']);

  function normVendor(s) {
    let n = String(s || '').toLowerCase().replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, ' ').replace(SUFFIX, ' ').replace(/\s+/g, ' ').trim();
    if (ALIAS[n]) return ALIAS[n];
    const two = n.split(' ').slice(0, 2).join(' ');
    if (ALIAS[two]) return ALIAS[two];
    return n;
  }
  function vendorKeys(s) {
    return String(s || '').split(/\s*(?:\/|,|;|\+|\band\b|&)\s*/i).map(normVendor).filter(v => v && !GENERIC_VENDOR.has(v));
  }
  function vendorMatch(assetKeys, advVendor) {
    const vk = vendorKeys(advVendor);
    for (const a of assetKeys) for (const b of vk) {
      if (a === b) return b;
      if ((a.startsWith(b + ' ') || b.startsWith(a + ' ')) && Math.min(a.length, b.length) >= 3) return b;
      if (a.split(' ')[0] === b.split(' ')[0] && a.split(' ')[0].length >= 5) return b;
    }
    return null;
  }
  // Tokens from a model string: "strong" tokens carry digits (catalog/model numbers),
  // "family" tokens are distinctive words such as ControlLogix, PanelView, SCALANCE.
  function tokens(s, vendorWords) {
    const out = { strong: new Set(), family: new Set() };
    const raw = String(s || '').toLowerCase().replace(/[(),;:/\[\]"']/g, ' ').split(/\s+/).filter(Boolean);
    for (let t of raw) {
      t = t.replace(/^[-.]+|[-.!*]+$/g, '');
      if (!t || STOP.has(t) || (vendorWords && vendorWords.has(t))) continue;
      if (/\d/.test(t) && /[a-z]/.test(t) && t.length >= 3 && !/^v?\d+(\.\d+)+[a-z]?$/.test(t) && !/^(sp|r|v)\d+$/.test(t)) out.strong.add(t);
      else if (/^\d{3,}(-\d+)?$/.test(t) && !/^(19|20)\d\d$/.test(t)) out.strong.add(t);
      else if (/^[a-z][a-z-]{3,}$/.test(t)) out.family.add(t);
    }
    return out;
  }
  const WEAK_FAMILY = new Set(['windows', 'linux', 'vision', 'embedded', 'desktop', 'office', 'simatic', 'sipLus', 'modicon'.toLowerCase(), 'siplus']);
  // Known catalog-number → family hints (vendor-neutral where possible)
  const HINTS = [[/\b1756-l7\d/i, '5570'], [/\b1756-l8\d/i, '5580'], [/\b1769-l3\d/i, '5370'], [/\b5069-l3\d/i, '5380'], [/\b5069-l4\d/i, '5480'], [/\b1766-l32/i, '1400'], [/\b1763-l16/i, '1100']];
  function modelTokens(model, vendorWords) {
    const t = tokens(model, vendorWords);
    t.baseCount = t.strong.size;
    for (const [re, add] of HINTS) if (re.test(model || '')) t.strong.add(add);
    for (const x of [...t.strong]) { const m = /^[a-z](\d{3,})$/.exec(x); if (m) t.strong.add(m[1]); }
    return t;
  }
  const hasWord = (text, tok) => {
    const i = text.indexOf(tok); if (i < 0) return false;
    const before = i === 0 ? ' ' : text[i - 1], after = text[i + tok.length] || ' ';
    if (/[a-z0-9]/.test(before)) return false;
    // allow catalog variants: "1756-en2t" matches "1756-en2tr" when the token is long and specific
    if (/[a-z0-9]/.test(after)) return tok.length >= 6 && /\d/.test(tok) && /-/.test(tok);
    return true;
  };

  // ---- version handling ----
  function parseVer(s) {
    const m = /(\d+(?:[._]\d+)*)/.exec(String(s || '').replace(/^[^\d]*?(?=\d)/, ''));
    return m ? m[1].split(/[._]/).map(Number) : null;
  }
  function cmp(a, b) { for (let i = 0; i < Math.max(a.length, b.length); i++) { const x = a[i] || 0, y = b[i] || 0; if (x !== y) return x < y ? -1 : 1; } return 0; }
  const VERSIONISH = /^[a-z]{0,2}\s?\d+(?:[._]\d+)*[a-z]?$/i;
  // Returns { kind: 'all'|'range'|'exact'|'unknown', text, test(fwString) -> true|false|null }
  function parseRange(expr, productName) {
    let e = String(expr || '').trim();
    const text = e || '';
    const any = { kind: 'all', text: text || 'all versions', test: () => true };
    if (!e) {
      const m = /(?:versions?\s+)?(?:v)?(\d+(?:\.\d+)*)\s+and\s+(?:prior|earlier|below|before)|prior to\s+v?(\d+(?:\.\d+)*)|(?:before|<)\s*v?(\d+(?:\.\d+)*)|all versions/i.exec(productName || '');
      if (!m) return { kind: 'unknown', text: 'no version info', test: () => null };
      if (/all versions/i.test(m[0])) return any;
      if (m[1]) e = '<=' + m[1]; else e = '<' + (m[2] || m[3]);
    }
    e = e.replace(/^vers:[a-z]+\//i, '');
    if (e === '*' || /^all[ _]versions?$/i.test(e)) return any;
    let m = /^v?(\d+(?:\.\d+)*)\s+and\s+(?:prior|earlier|below)$/i.exec(e); if (m) e = '<=' + m[1];
    m = /^(?:prior to|before)\s+v?(\d+(?:\.\d+)*)$/i.exec(e); if (m) e = '<' + m[1];
    const parts = e.split('|').map(p => p.trim()).filter(Boolean);
    const cons = [];
    for (const p of parts) {
      const c = /^(<=|>=|<|>|=)?\s*(.+)$/.exec(p);
      if (!c) return { kind: 'unknown', text, test: () => null };
      const ver = c[2].trim().replace(/_/g, '.');
      if (!c[1] && !VERSIONISH.test(ver)) return { kind: 'unknown', text, test: () => null };
      const v = parseVer(ver); if (!v) return { kind: 'unknown', text, test: () => null };
      cons.push([c[1] || '=', v]);
    }
    if (!cons.length) return { kind: 'unknown', text, test: () => null };
    return {
      kind: cons.length === 1 && cons[0][0] === '=' ? 'exact' : 'range', text,
      test(fw) {
        const f = parseVer(fw); if (!f) return null;
        return cons.every(([op, v]) => { const r = cmp(f, v); return op === '<' ? r < 0 : op === '<=' ? (r <= 0 || (v.length < f.length && cmp(f.slice(0, v.length), v) === 0)) : op === '>' ? r > 0 : op === '>=' ? r >= 0 : (r === 0 || (v.length < f.length && cmp(f.slice(0, v.length), v) === 0)); });
      },
    };
  }

  // ---- feed indexing ----
  function buildIndex(feed) {
    const byVendor = new Map(), byCve = new Map();
    (feed.ics && feed.ics.adv || []).forEach((a, i) => {
      for (const v of a.v || []) for (const k of vendorKeys(v)) { if (!byVendor.has(k)) byVendor.set(k, new Set()); byVendor.get(k).add(i); }
      for (const c of a.c || []) { if (!byCve.has(c)) byCve.set(c, []); byCve.get(c).push(i); }
    });
    const kevByVendor = new Map();
    for (const [cve, k] of Object.entries(feed.kev || {})) {
      for (const vk of vendorKeys(k[1])) { if (!kevByVendor.has(vk)) kevByVendor.set(vk, []); kevByVendor.get(vk).push(cve); }
    }
    return { byVendor, byCve, kevByVendor };
  }
  function candidates(map, assetKeys) {
    const out = new Set();
    for (const [k, set] of map) for (const a of assetKeys) {
      if (k === a || k.startsWith(a + ' ') || a.startsWith(k + ' ') || (k.split(' ')[0] === a.split(' ')[0] && a.split(' ')[0].length >= 5)) { for (const i of set) out.add(i); break; }
    }
    return out;
  }
  const CONF = { High: 3, Medium: 2, Low: 1 };

  // Match one asset. Returns [{key, type:'ics'|'kev', confidence, conf, reason, ...}]
  function matchAsset(asset, feed, idx) {
    idx = idx || buildIndex(feed);
    const aKeys = vendorKeys(asset.vendor);
    if (!aKeys.length) return [];
    const vendorWords = new Set(aKeys.join(' ').split(' '));
    const mt = modelTokens(asset.model, vendorWords);
    if (!mt.strong.size && !mt.family.size) return [];
    const out = [];
    const advs = feed.ics && feed.ics.adv || [];
    for (const i of candidates(idx.byVendor, aKeys)) {
      const a = advs[i];
      let best = null;
      for (const [pv, pname, pver] of a.p || []) {
        if (!vendorMatch(aKeys, pv)) continue;
        const text = ' ' + String(pname).toLowerCase().replace(/[(),;:/\[\]"']/g, ' ') + ' ';
        const sHits = [...mt.strong].filter(t => hasWord(text.trim(), t) || text.includes(' ' + t + ' '));
        const fHits = [...mt.family].filter(t => text.includes(' ' + t + ' ') || text.includes(' ' + t + '-'));
        if (!sHits.length && !fHits.length) continue;
        const pt = tokens(pname, vendorWords);
        // Family word matched but the product names a different model number: almost surely a different product.
        if (!sHits.length && mt.strong.size && pt.strong.size) continue;
        const rng = parseRange(pver, pname);
        const fw = asset.firmware ? rng.test(asset.firmware) : null;
        const model = sHits.length ? 'strong' : 'family';
        let confidence;
        if (fw === false) confidence = 'Low';
        else if (model === 'strong') confidence = fw === true ? 'High' : 'Medium';
        else confidence = fw === true ? 'Medium' : 'Low';
        // family-only: Medium only if every distinctive word in the product name is on the asset too
        if (model === 'family' && confidence === 'Medium') {
          const uncovered = [...pt.family].filter(w => !mt.family.has(w));
          if (uncovered.length || mt.strong.size || fHits.every(w => WEAK_FAMILY.has(w))) confidence = 'Low';
        }
        // strong: High only when the product names no other model number, or all of the asset's numbers match
        if (model === 'strong' && confidence === 'High') {
          const otherNums = [...pt.strong].filter(x => !sHits.some(h => x.includes(h) || h.includes(x)));
          if ((otherNums.length && sHits.length < mt.strong.size) || sHits.length < Math.min(2, mt.baseCount)) confidence = 'Medium';
        }
        const cand = { pname, pver: rng.text, kind: rng.kind, fw, model, hits: sHits.length ? sHits : fHits, confidence };
        const rank = c => CONF[c.confidence] * 10 + (c.model === 'strong' ? 2 : 0) + (c.fw === true ? 1 : 0);
        if (!best || rank(cand) > rank(best)) best = cand;
      }
      if (!best) continue;
      const kevCves = (a.c || []).filter(c => feed.kev && feed.kev[c]);
      const fwWhy = best.fw === true ? `firmware ${asset.firmware} is inside the affected range (${best.pver})`
        : best.fw === false ? `firmware ${asset.firmware} looks outside the affected range (${best.pver}), so it may already be fixed`
          : asset.firmware ? `couldn't compare firmware ${asset.firmware} with "${best.pver}"; check by hand` : `no firmware recorded on the asset; affected: ${best.pver}`;
      out.push({
        key: asset.id + '|' + a.id, type: 'ics', assetId: asset.id, advId: a.id, title: a.t, url: a.u, date: a.r || a.d,
        cves: a.c || [], cvss: a.s || {}, kevCves, product: best.pname, confidence: best.confidence, conf: CONF[best.confidence],
        reason: `Vendor matches; model term${best.hits.length > 1 ? 's' : ''} "${best.hits.join('", "')}" ${best.model === 'strong' ? '(model/catalog number)' : '(product family)'} appear${best.hits.length > 1 ? '' : 's'} in "${best.pname}"; ${fwWhy}.`,
      });
    }
    // KEV (no version data in KEV): grouped per KEV vendor/product
    const kevGroups = new Map();
    const covered = new Set(out.flatMap(m => m.cves));
    for (const k of aKeys) for (const [vk, cves] of idx.kevByVendor) {
      if (!(vk === k || vk.startsWith(k + ' ') || k.startsWith(vk + ' '))) continue;
      for (const cve of cves) {
        if (covered.has(cve)) continue;
        const e = feed.kev[cve], prod = String(e[2] || '');
        const pt = ' ' + prod.toLowerCase().replace(/[(),;:/\[\]"']/g, ' ') + ' ';
        const sHits = [...mt.strong].filter(t => pt.includes(' ' + t + ' '));
        const fHits = [...mt.family].filter(t => pt.includes(' ' + t + ' '));
        if (!sHits.length && !fHits.length) continue;
        const gk = e[1] + '|' + prod;
        if (!kevGroups.has(gk)) kevGroups.set(gk, { vendor: e[1], product: prod, cves: [], hits: new Set(sHits.length ? sHits : fHits), strong: !!sHits.length });
        kevGroups.get(gk).cves.push(cve);
      }
    }
    for (const [gk, gr] of kevGroups) {
      gr.cves.sort((x, y) => (feed.kev[y][0] || '').localeCompare(feed.kev[x][0] || ''));
      const confidence = gr.strong && gr.cves.length <= 5 ? 'Medium' : 'Low';
      out.push({
        key: asset.id + '|KEV:' + gk, type: 'kev', assetId: asset.id, title: `${gr.vendor} ${gr.product}: ${gr.cves.length} known-exploited CVE${gr.cves.length > 1 ? 's' : ''}`,
        url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', date: feed.kev[gr.cves[0]][0], cves: gr.cves, cvss: {}, kevCves: gr.cves.slice(),
        product: gr.vendor + ' ' + gr.product, confidence, conf: CONF[confidence],
        reason: `Vendor matches and "${[...gr.hits].join('", "')}" appears in KEV product "${gr.product}". KEV doesn't list affected versions, so check each CVE against your version.`,
      });
    }
    return out.sort((x, y) => y.conf - x.conf || (y.kevCves.length - x.kevCves.length) || String(y.date).localeCompare(String(x.date)));
  }

  // Match all assets; drops matches whose CVEs are all already recorded on that asset.
  function matchAll(assets, vulns, feed) {
    const idx = buildIndex(feed), res = [];
    for (const a of assets) {
      const have = new Set(vulns.filter(v => v.assetId === a.id).map(v => v.cve));
      for (const m of matchAsset(a, feed, idx)) {
        m.recorded = m.cves.filter(c => have.has(c));
        m.missing = m.cves.filter(c => !have.has(c));
        if (m.cves.length && !m.missing.length) continue;
        res.push(m);
      }
    }
    return res;
  }

  // Compare stored vulnerability fields with the latest feeds. Returns change records; mutates nothing.
  function feedChanges(vulns, feed) {
    const out = [];
    for (const v of vulns) {
      if (!v.cve || !/^CVE-/.test(v.cve)) continue;
      const kevNow = !!(feed.kev && feed.kev[v.cve]);
      const e = feed.epss && feed.epss[v.cve];
      const epssNow = e ? e[0] : null;
      const ch = { vulnId: v.id, cve: v.cve };
      if (kevNow !== !!v.kev && (kevNow || feed.kevAuthoritative)) { ch.kevFrom = !!v.kev; ch.kevTo = kevNow; }
      if (epssNow != null && epssNow !== (v.epss === '' || v.epss == null ? null : +v.epss)) { ch.epssFrom = v.epss === '' ? null : v.epss; ch.epssTo = epssNow; }
      if ('kevTo' in ch || 'epssTo' in ch) out.push(ch);
    }
    return out;
  }

  g.OTMatch = { normVendor, vendorKeys, vendorMatch, tokens, parseVer, parseRange, buildIndex, matchAsset, matchAll, feedChanges };
  if (typeof module !== 'undefined') module.exports = g.OTMatch;
})(typeof window !== 'undefined' ? window : globalThis);
