// OT Risk – loads the nightly threat feeds from data/*.json (built by .github/workflows/feeds.yml).
// Falls back to the bundled KEV snapshot (js/kev-data.js) when data/ can't be loaded (e.g. opened from file://).
(function (g) {
  const F = {
    status: 'snapshot', meta: null, kev: g.KEV || {}, epss: {}, ics: { meta: null, adv: [] }, fixes: null, error: '',
    byCve: new Map(),
    async load() {
      F.status = 'loading';
      try {
        const get = n => fetch('data/' + n, { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error(n + ' HTTP ' + r.status); return r.json(); });
        const [meta, kev, epss, ics] = await Promise.all([get('meta.json'), get('kev.json'), get('epss.json'), get('ics.json')]);
        F.meta = meta; F.kev = kev.kev; F.epss = epss.epss; F.ics = ics;
        g.KEV = kev.kev; g.KEV_META = kev.meta;
        F.byCve = new Map(); (ics.adv || []).forEach((a, i) => (a.c || []).forEach(c => { if (!F.byCve.has(c)) F.byCve.set(c, []); F.byCve.get(c).push(i); }));
        F.status = 'live';
      } catch (e) {
        F.status = 'snapshot'; F.error = String(e.message || e); F.kev = g.KEV || {};
      }
      return F.status;
    },
    async loadFixes() {
      if (F.fixes) return F.fixes;
      try { const r = await fetch('data/ics-fixes.json', { cache: 'no-cache' }); F.fixes = (await r.json()).fixes || {}; } catch (e) { F.fixes = {}; }
      return F.fixes;
    },
    ok: () => F.status === 'live',
    advisoriesFor: cve => (F.byCve.get(cve) || []).map(i => F.ics.adv[i]),
    cvssFor(cve) { let best = null; for (const a of F.advisoriesFor(cve)) { const s = a.s && a.s[cve]; if (s != null && (best == null || s > best)) best = s; } return best; },
    epssFor: cve => (F.epss[cve] || [null])[0],
    ageDays() { if (!F.meta) return null; return Math.floor((Date.now() - new Date(F.meta.updated).getTime()) / 864e5); },
    asFeed: () => ({ kev: F.kev, epss: F.epss, ics: F.ics, kevAuthoritative: F.status === 'live' }),
  };
  g.OTFeeds = F;
})(window);
