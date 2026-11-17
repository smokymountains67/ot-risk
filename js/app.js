// OT Risk – single-page app (vanilla JS, hash routing, localStorage persistence)
(function () {
  const S = window.OTScore, KEY = 'otrisk.v0';
  const $ = (s, el = document) => el.querySelector(s);
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = p => p + Math.random().toString(36).slice(2, 9);
  const today = () => new Date().toISOString().slice(0, 10);
  const money = n => n == null ? '—' : '$' + Math.round(n).toLocaleString();
  const pill = r => `<span class="pill ${r.cls}">${esc(r.level)} ${r.score}</span>`;
  const H = window.OTHelp, G = window.OTGuide, F = window.OTFeeds, M = window.OTMatch;
  const tip = k => { const t = H.TIPS[k] || k; return `<span class="tip" tabindex="0" role="note" aria-label="${esc(t)}" data-tip="${esc(t)}">?</span>`; };
  const disc = (extra = '') => `<div class="disc">${esc(G.DISCLAIMER)}${extra ? ' ' + esc(extra) : ''}</div>`;

  // ---------- state ----------
  let D = load();
  function load() { try { const j = JSON.parse(localStorage.getItem(KEY)); if (j && j.sites) return migrate(j); } catch (e) { } const s = migrate(SAMPLE_DATA()); localStorage.setItem(KEY, JSON.stringify(s)); return s; }
  // v0.2 additions: settings, feed/match state, UI flags. Older backups are upgraded in place.
  function migrate(d) {
    d.settings = Object.assign({ feedsOnly: true, showLow: false }, d.settings || {});
    d.feed = Object.assign({ known: {}, newKeys: {}, dismissed: {}, confirmed: {}, changes: [], lastFeed: null, lastVisit: null }, d.feed || {});
    d.ui = Object.assign({ hideChecklist: false, lastBackup: null }, d.ui || {});
    return d;
  }
  function save() { localStorage.setItem(KEY, JSON.stringify(D)); }
  const site = () => D.sites.find(s => s.id === D.activeSiteId) || D.sites[0];
  const matTotal = s => (s && s.maturity && s.maturity.every(x => x)) ? s.maturity.reduce((a, b) => a + b, 0) : null;
  const matLevel = s => S.maturityLevel(matTotal(s));
  const siteAssets = () => D.assets.filter(a => a.siteId === (site() || {}).id);
  const assetById = id => D.assets.find(a => a.id === id);
  function scored(filterSite = true) {
    const ids = new Set((filterSite ? siteAssets() : D.assets).map(a => a.id));
    const mat = matLevel(site());
    return D.vulns.filter(v => ids.has(v.assetId)).map(v => {
      const a = assetById(v.assetId); const r = S.score(a, v); const sla = S.slaFor(r.level, mat, v.found);
      const open = v.status === 'Open', contained = v.status === 'Contained';
      const t = today();
      const overdue = (open && sla.containBy && sla.containBy < t) || ((open || contained) && sla.remediateBy && sla.remediateBy < t);
      return { v, a, r, sla, overdue };
    }).sort((x, y) => y.r.score - x.r.score);
  }

  // ---------- router ----------
  const routes = { '': dashboard, calc, assets, asset: assetDetail, register, import: importView, maturity, company, settings, help, alerts, vuln: vulnDetail };
  function route() {
    if (/^#help-/.test(location.hash)) { const el = document.getElementById(location.hash.slice(1)); if (el) { el.scrollIntoView(); return; } location.hash = '#/help'; return; }
    const h = location.hash.replace(/^#\/?/, ''); const [name, ...rest] = h.split('/');
    document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.r === name));
    renderSiteSel();
    (routes[name] || dashboard)(rest.join('/'));
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);
  function renderSiteSel() {
    const sel = $('#siteSel'); sel.innerHTML = D.sites.map(s => `<option value="${esc(s.id)}" ${s.id === D.activeSiteId ? 'selected' : ''}>${esc(s.name)}</option>`).join('');
    sel.onchange = () => { D.activeSiteId = sel.value; save(); route(); };
  }
  const view = html => { $('#view').innerHTML = html; };
  function modal(html, onMount) { $('#modalBody').innerHTML = html; $('#modal').classList.remove('hidden'); onMount && onMount($('#modalBody')); }
  function closeModal() { $('#modal').classList.add('hidden'); }
  $('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });

  // ---------- nightly feeds: matching, re-scoring, header status ----------
  let MATCHES = [];
  const isReach = v => Math.min(3, Math.max(1, +v.reach || 2));
  function processFeeds() {
    if (!F.ok()) { MATCHES = []; renderFeedStat(); return; }
    const feed = F.asFeed(), t = today();
    // 1) equipment matching
    MATCHES = M.matchAll(D.assets, D.vulns, feed);
    const live = new Set(MATCHES.map(m => m.key));
    for (const m of MATCHES) {
      if (!D.feed.known[m.key]) { D.feed.known[m.key] = t; if (!D.feed.dismissed[m.key] && !D.feed.confirmed[m.key]) D.feed.newKeys[m.key] = t; }
    }
    for (const k of Object.keys(D.feed.newKeys)) if (!live.has(k) || D.feed.dismissed[k] || D.feed.confirmed[k]) delete D.feed.newKeys[k];
    // 2) re-score existing findings when KEV / EPSS changes
    for (const ch of M.feedChanges(D.vulns, feed)) {
      const v = D.vulns.find(x => x.id === ch.vulnId), a = v && assetById(v.assetId); if (!a) continue;
      const before = S.score(a, v);
      if ('kevTo' in ch) v.kev = ch.kevTo;
      if ('epssTo' in ch) v.epss = ch.epssTo;
      v.feedChecked = t;
      const after = S.score(a, v);
      const meaningful = 'kevTo' in ch || before.level !== after.level || before.threat.t !== after.threat.t;
      if (meaningful) {
        v.rescored = { at: t, from: before.score, fromLevel: before.level, to: after.score, toLevel: after.level, why: [('kevTo' in ch) ? (ch.kevTo ? 'added to CISA KEV' : 'removed from CISA KEV') : '', ('epssTo' in ch && before.threat.t !== after.threat.t) ? `EPSS ${ch.epssFrom ?? '—'} → ${ch.epssTo}` : ''].filter(Boolean).join('; ') || 'feed data changed' };
        D.feed.changes.unshift(Object.assign({ vulnId: v.id, cve: v.cve, assetId: a.id, ack: false }, v.rescored));
      }
    }
    D.feed.changes = D.feed.changes.slice(0, 200);
    D.feed.lastFeed = F.meta && F.meta.updated;
    save(); renderFeedStat();
  }
  const visibleMatches = (all = false) => MATCHES.filter(m => (all || D.settings.showLow || m.confidence !== 'Low'));
  const siteMatchFilter = m => { const a = assetById(m.assetId); return a && a.siteId === (site() || {}).id; };
  const openMatches = () => visibleMatches().filter(m => !D.feed.dismissed[m.key] && !D.feed.confirmed[m.key]);
  const newMatches = () => openMatches().filter(m => D.feed.newKeys[m.key]);
  const openChanges = () => D.feed.changes.filter(c => !c.ack && D.vulns.some(v => v.id === c.vulnId));
  function renderFeedStat() {
    const el = $('#feedStat'), b = $('#alertBadge'); if (!el) return;
    if (F.status === 'loading') { el.className = 'feedstat'; el.textContent = 'Feeds: loading…'; return; }
    if (F.ok()) {
      const age = F.ageDays(), d = (F.meta.updated || '').slice(0, 10);
      el.className = 'feedstat ' + (age > 3 ? 'stale' : 'live');
      el.textContent = 'Feeds: ' + d + (age > 3 ? ' (stale)' : '');
      el.title = `Nightly feeds updated ${F.meta.updated} · KEV catalog ${F.meta.kev.version} (${F.meta.kev.count}) · EPSS ${String(F.meta.epss.date).slice(0, 10)} · ${F.meta.ics ? F.meta.ics.count + ' CISA ICS advisories' : ''}`;
    } else {
      el.className = 'feedstat snap'; el.textContent = 'Feeds: snapshot ' + (window.KEV_META ? KEV_META.version : '');
      el.title = 'Nightly feeds could not be loaded (' + (F.error || 'offline') + '). Using the KEV snapshot bundled with the site; equipment matching is off.';
    }
    const n = newMatches().length + openChanges().length;
    b.textContent = n; b.classList.toggle('hidden', !n);
  }
  function matchRow(m, compact) {
    const a = assetById(m.assetId); if (!a) return '';
    const isNew = D.feed.newKeys[m.key], dis = D.feed.dismissed[m.key];
    const kevN = m.kevCves.length;
    return `<tr><td><a href="#/asset/${esc(a.id)}">${esc(a.name)}</a><div class="small mute">${esc(a.vendor)} ${esc(a.model)} · fw ${esc(a.firmware || '—')}</div></td>
      <td>${isNew ? '<span class="tag new">NEW</span> ' : ''}<a href="${esc(m.url)}" target="_blank" rel="noopener">${esc(m.advId || 'CISA KEV')}</a> ${esc(m.title)}
        <div class="small">${m.missing.length} CVE${m.missing.length === 1 ? '' : 's'} not yet recorded${kevN ? ` · <span class="tag kev">${kevN} KEV</span>` : ''} · ${esc(m.date || '')}</div>
        ${compact ? '' : `<div class="reason">Possible match: ${esc(m.reason)}</div>`}</td>
      <td><span class="conf ${m.confidence}">${m.confidence}</span>${compact ? `<div class="reason" style="max-width:260px">${esc(m.reason.slice(0, 140))}${m.reason.length > 140 ? '…' : ''}</div>` : ''}</td>
      <td class="row" style="flex-wrap:nowrap">${dis ? `<span class="small mute">Dismissed ${esc(dis.at)}${dis.why ? ': ' + esc(dis.why) : ''}</span> <button data-undis="${esc(m.key)}">Undo</button>` : `<button class="pri" data-confirm="${esc(m.key)}">Confirm</button><button data-dismiss="${esc(m.key)}">Dismiss</button>`}</td></tr>`;
  }
  function bindMatchButtons(root, after) {
    root.querySelectorAll('[data-confirm]').forEach(b => b.onclick = () => confirmMatch(MATCHES.find(m => m.key === b.dataset.confirm), after));
    root.querySelectorAll('[data-dismiss]').forEach(b => b.onclick = () => {
      const why = prompt('Dismiss this possible match. Optional reason (e.g. "different hardware series", "firmware already updated"):', '');
      if (why === null) return; D.feed.dismissed[b.dataset.dismiss] = { at: today(), why: why.trim() }; delete D.feed.newKeys[b.dataset.dismiss]; save(); renderFeedStat(); after();
    });
    root.querySelectorAll('[data-undis]').forEach(b => b.onclick = () => { delete D.feed.dismissed[b.dataset.undis]; save(); renderFeedStat(); after(); });
  }
  function confirmMatch(m, after) {
    if (!m) return; const a = assetById(m.assetId);
    const isKev = m.type === 'kev', many = m.missing.length > 5;
    const defReach = ['L3.5', 'L4', 'L5'].includes(a.purdue) ? 3 : 2;
    modal(`<h2 style="margin-top:0">Confirm possible match – ${esc(a.name)}</h2>
      <p class="small"><b>${esc(m.advId || 'CISA KEV')}</b> ${esc(m.title)} · <a href="${esc(m.url)}" target="_blank" rel="noopener">open source</a></p>
      <p class="reason">${esc(m.reason)}</p>
      ${isKev ? '<div class="note">KEV does not list affected versions. Tick only the CVEs that apply to this asset’s version/edition.</div>' : ''}
      <p>Create a vulnerability record for each CVE you tick. CVSS comes from the advisory, EPSS and KEV from the nightly feeds; the vendor's fixes and mitigations will show in the Fix guide.</p>
      <div style="max-height:320px;overflow:auto"><table class="small"><tr><th><input type="checkbox" id="cmAll" style="width:auto" ${isKev && many ? '' : 'checked'}></th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th></tr>
      ${m.missing.map(c => `<tr><td><input type="checkbox" class="cmck" value="${esc(c)}" style="width:auto" ${isKev && many ? '' : 'checked'}></td><td>${esc(c)}${isKev && KEV[c] ? `<div class="mute">${esc(KEV[c][5] || '')}</div>` : ''}</td><td>${m.cvss[c] ?? F.cvssFor(c) ?? '—'}</td><td>${F.epssFor(c) ?? '—'}</td><td>${KEV[c] ? '<span class="tag kev">KEV</span>' : '—'}</td></tr>`).join('')}</table></div>
      ${m.recorded.length ? `<p class="small mute">Already recorded on this asset: ${esc(m.recorded.join(', '))}</p>` : ''}
      <div class="form"><div><label>Reachability for these ${tip('reach')}</label><select id="cmR">${[[3, '3 – Internet/IT/remote path'], [2, '2 – OT only'], [1, '1 – Local/isolated']].map(([k, t]) => `<option value="${k}" ${k === defReach ? 'selected' : ''}>${t}</option>`).join('')}</select></div><div><label>Owner</label><input id="cmO" value="${esc(a.owner || '')}"></div></div>
      <div class="row" style="margin-top:12px"><button class="pri" id="cmGo">Create vulnerability records</button><button id="cmX">Cancel</button></div>`, el => {
      $('#cmX', el).onclick = closeModal;
      $('#cmAll', el).onchange = e => el.querySelectorAll('.cmck').forEach(c => c.checked = e.target.checked);
      $('#cmGo', el).onclick = () => {
        const picked = [...el.querySelectorAll('.cmck')].filter(c => c.checked).map(c => c.value);
        if (!picked.length) { alert('Tick at least one CVE, or Cancel.'); return; }
        const reach = +$('#cmR', el).value, owner = $('#cmO', el).value;
        for (const cve of picked) {
          if (D.vulns.some(v => v.assetId === a.id && v.cve === cve)) continue;
          const k = KEV[cve], cv = m.cvss[cve] ?? F.cvssFor(cve), ep = F.epssFor(cve);
          D.vulns.push({ id: uid('v'), assetId: a.id, cve, title: (k && k[5]) || m.title, cvss: cv ?? '', kev: !!k, epss: ep ?? '', publicExploit: false, reach, rcis: 1.0, status: 'Open', found: today(), owner, decision: '', compensating: '', fair: null,
            source: 'feed', advisories: F.advisoriesFor(cve).map(x => ({ id: x.id, t: x.t, u: x.u })).slice(0, 6) });
        }
        D.feed.confirmed[m.key] = { at: today(), cves: picked }; delete D.feed.newKeys[m.key];
        save(); closeModal(); processFeeds(); after ? after() : route();
      };
    });
  }

  // ---------- dashboard ----------
  function dashboard() {
    const s = site(), rows = scored(), act = rows.filter(x => x.v.status !== 'Remediated' && x.v.status !== 'Accepted');
    const cnt = l => act.filter(x => x.r.level === l).length;
    const kevOpen = act.filter(x => x.v.kev).length, overdue = act.filter(x => x.overdue).length;
    const mt = matTotal(s), ml = matLevel(s);
    const levels = ['L0', 'L1', 'L2', 'L3', 'L3.5', 'L4', 'L5'], bands = ['Critical', 'High', 'Moderate', 'Low'];
    const heat = levels.map(L => `<tr><td style="text-align:left">${L}</td>${bands.map(b => { const n = act.filter(x => x.a.purdue === L && x.r.level === b).length; return `<td class="${n ? S.BANDS.find(z => z.level === b).cls : 'h0'}">${n || '·'}</td>`; }).join('')}</tr>`).join('');
    const zones = {}; siteAssets().forEach(a => zones[a.zone || '(none)'] = (zones[a.zone || '(none)'] || 0) + 1);
    const maxZ = Math.max(1, ...Object.values(zones));
    const aleRows = act.filter(x => x.v.fair).map(x => ({ x, ale: S.ale(x.v.fair.lef, x.v.fair.lm) }));
    const aleSum = aleRows.reduce((t, y) => t + (y.ale ? y.ale.p50 : 0), 0);
    view(`<div class="row"><h1>${esc(s.name)}</h1>${tip('dashboard')}<span class="right mute">${esc(D.company.name)}</span></div>
    ${checklist()}${feedPanel()}
    <div class="grid g4">
      <div class="card kpi"><div class="l">Critical</div><div class="n" style="color:var(--crit)">${cnt('Critical')}</div></div>
      <div class="card kpi"><div class="l">High</div><div class="n" style="color:var(--high)">${cnt('High')}</div></div>
      <div class="card kpi"><div class="l">Moderate / Low</div><div class="n">${cnt('Moderate')} / ${cnt('Low')}</div></div>
      <div class="card kpi"><div class="l">Open KEV-listed</div><div class="n" style="color:#ffb3b5">${kevOpen}</div></div>
      <div class="card kpi"><div class="l">Past SLA</div><div class="n" style="color:${overdue ? 'var(--crit)' : 'var(--low)'}">${overdue}</div></div>
      <div class="card kpi"><div class="l">OT assets</div><div class="n">${siteAssets().length}</div></div>
      <div class="card kpi"><div class="l">Maturity</div><div class="n" style="font-size:20px">${ml ? esc(ml) + ' Secured' : '<a href="#/maturity">Assess →</a>'}</div><div class="mute small">${mt ? mt + ' / 27' : 'not assessed'}</div></div>
      <div class="card kpi"><div class="l">Est. annual loss (P50, ${aleRows.length} risks)</div><div class="n" style="font-size:22px">${aleRows.length ? money(aleSum) : '—'}</div><div class="mute small">FAIR-style estimate, sum of medians</div></div>
    </div>
    <div class="grid g2" style="margin-top:14px">
      <div class="card"><h2 style="margin-top:0">Top risks</h2><table><tr><th>Risk</th><th>Asset</th><th>CVE</th><th>Status</th><th>Due</th></tr>
        ${act.slice(0, 8).map(x => `<tr><td>${pill(x.r)}</td><td><a href="#/asset/${esc(x.a.id)}">${esc(x.a.name)}</a><div class="mute small">${esc(x.a.purdue)} · ${esc(x.a.zone)}</div></td><td>${esc(x.v.cve)} ${x.v.kev ? '<span class="tag kev">KEV</span>' : ''}</td><td>${esc(x.v.status)}</td><td>${dueCell(x)}</td></tr>`).join('') || '<tr><td colspan=5 class="mute">No open vulnerabilities.</td></tr>'}
      </table><p><a href="#/register">Full risk register →</a></p></div>
      <div class="card"><h2 style="margin-top:0">Open risk by Purdue level</h2><table class="heat"><tr><th>Level</th>${bands.map(b => `<th style="text-align:center">${b}</th>`).join('')}</tr>${heat}</table>
      <h2>Assets by zone</h2>${Object.entries(zones).map(([z, n]) => `<div class="row small"><span style="width:110px">${esc(z)}</span><div class="bar" style="flex:1"><span style="width:${n / maxZ * 100}%;background:var(--blue)"></span></div><span style="width:24px;text-align:right">${n}</span></div>`).join('')}
      ${ml ? `<h2>What ${esc(ml)} Secured means here</h2><p class="small">${esc(S.COMP_CONTROLS[ml])}</p>${disc()}` : ''}</div>
    </div>`);
    bindDash();
  }
  function bindDash() {
    const v = $('#view');
    bindMatchButtons(v, route);
    if ($('#hideCk')) $('#hideCk').onclick = () => { D.ui.hideChecklist = true; save(); route(); };
    if ($('#ackAll')) $('#ackAll').onclick = () => { D.feed.changes.forEach(c => c.ack = true); D.vulns.forEach(x => delete x.rescored); save(); renderFeedStat(); route(); };
    if ($('#seenAll')) $('#seenAll').onclick = () => { D.feed.newKeys = {}; save(); renderFeedStat(); route(); };
  }
  // "Start here" checklist: each step checks itself off from the data.
  function checklist() {
    if (D.ui.hideChecklist) return '';
    const s = site(), sa = siteAssets(), ids = new Set(sa.map(a => a.id));
    const steps = [
      ['Name your company and sites', '#/company', D.company.name && D.company.name !== 'My Company'],
      ['Run the 9-question maturity wizard for this site', '#/maturity/0', !!matTotal(s)],
      ['Add or import your equipment (vendor, model, firmware)', '#/assets', sa.length > 0],
      ['Rate each asset\'s criticality and confirm Purdue level', '#/assets', sa.length > 0 && sa.every(a => (a.source === 'sample' || a.source === 'manual' || a.critReviewed) && !a.purdueGuessed)],
      ['Review feed alerts: confirm or dismiss possible matches', '#/alerts', Object.keys(D.feed.confirmed).length + Object.keys(D.feed.dismissed).length > 0],
      ['Open a Fix guide and record compensating controls', '#/register', D.vulns.some(v => ids.has(v.assetId) && v.compensating)],
      ['Export a JSON backup', '#/settings', !!D.ui.lastBackup],
    ];
    const done = steps.filter(x => x[2]).length;
    return `<div class="card" style="margin-bottom:14px"><div class="row"><h2 style="margin:0">Start here</h2><span class="mute small">${done} of ${steps.length} done</span><a class="right small" href="#/help">Full guide →</a><button id="hideCk" class="small">Hide</button></div>
      <div class="progress"><span style="width:${done / steps.length * 100}%"></span></div>
      <ol class="check">${steps.map(([t, l, ok]) => `<li class="${ok ? 'done' : ''}"><span class="${ok ? 'ok' : 'todo'}">${ok ? '✓' : '○'}</span><a href="${l}">${t}</a></li>`).join('')}</ol></div>`;
  }
  function feedPanel() {
    if (!F.ok()) return F.status === 'loading' ? '' : `<div class="note" style="margin-bottom:14px">Nightly threat feeds aren't available right now (${esc(F.error || 'offline')}). Scores use the bundled KEV snapshot ${esc(window.KEV_META ? KEV_META.version : '')}; equipment matching is paused.</div>`;
    const nm = newMatches().filter(siteMatchFilter), ch = openChanges().filter(c => { const a = assetById(c.assetId); return a && a.siteId === site().id; });
    const om = openMatches().filter(siteMatchFilter);
    const hi = nm.filter(m => m.confidence === 'High').length, me = nm.filter(m => m.confidence === 'Medium').length;
    return `<div class="card" style="margin-bottom:14px;border-color:${nm.length || ch.length ? '#1e5a85' : 'var(--line)'}"><div class="row"><h2 style="margin:0">New since your last visit</h2>${tip('alerts')}
      <span class="mute small">feeds ${esc((F.meta.updated || '').slice(0, 10))} · ${esc(String(F.meta.ics ? F.meta.ics.count : 0))} ICS advisories · KEV ${esc(F.meta.kev.version)}</span><a class="right" href="#/alerts">All alerts (${om.length}) →</a></div>
      ${nm.length ? `<p class="small">${nm.length} new possible match${nm.length === 1 ? '' : 'es'} for this site: <span class="conf High">${hi} High</span> <span class="conf Medium">${me} Medium</span>${D.settings.showLow ? ` <span class="conf Low">${nm.length - hi - me} Low</span>` : ''}. Confirm the real ones; dismiss the rest. ${tip('confidence')}</p>
        <div style="overflow:auto"><table><tr><th>Asset</th><th>Advisory</th><th>Confidence</th><th></th></tr>${nm.slice(0, 6).map(m => matchRow(m, true)).join('')}</table></div>
        <div class="row small" style="margin-top:6px">${nm.length > 6 ? `<a href="#/alerts">+ ${nm.length - 6} more →</a>` : ''}<button class="right small" id="seenAll">Mark all as seen</button></div>` : '<p class="small mute">No new advisory matches for this site.</p>'}
      ${ch.length ? `<h3>Re-scored from feed changes (${ch.length})</h3><table class="small"><tr><th>Asset</th><th>CVE</th><th>Change</th><th>Score</th></tr>${ch.slice(0, 8).map(c => { const a = assetById(c.assetId); return `<tr><td><a href="#/asset/${esc(a.id)}">${esc(a.name)}</a></td><td><a href="#/vuln/${esc(c.vulnId)}">${esc(c.cve)}</a></td><td>${esc(c.why)}</td><td>${esc(c.fromLevel)} ${c.from} → <b>${esc(c.toLevel)} ${c.to}</b></td></tr>`; }).join('')}</table><button class="small" id="ackAll" style="margin-top:6px">Acknowledge</button>` : ''}
    </div>`;
  }
  function dueCell(x) {
    const s = x.sla, st = x.v.status; if (st === 'Remediated' || st === 'Accepted') return '<span class="mute">—</span>';
    const c = st === 'Open' && s.containBy ? `Contain ${s.containBy}` : '';
    const r = s.remediateBy ? `Fix ${s.remediateBy}` : 'Lifecycle';
    return `<span class="small ${x.overdue ? '' : 'mute'}" style="${x.overdue ? 'color:#ff8b8e;font-weight:700' : ''}">${[c, r].filter(Boolean).join('<br>')}${x.overdue ? '<br>OVERDUE' : ''}</span>`;
  }

  // ---------- calculator (state in URL, OWASP-calculator style) ----------
  const CALC_DEF = { OP: 1, SA: 1, RD: 1, RG: 1, PL: 'L1', CV: '', KEV: 0, EP: '', PX: 0, RE: 2, RC: '1.0', MAT: 'Reasonably', LEF: '', LM: '' };
  function parseCalc(str) {
    const o = Object.assign({}, CALC_DEF);
    (str || '').replace(/^\(|\)$/g, '').split('/').forEach(kv => { const i = kv.indexOf(':'); if (i > 0) { const k = kv.slice(0, i), v = decodeURIComponent(kv.slice(i + 1)); if (k in o) o[k] = v; } });
    return o;
  }
  const calcHash = o => '#/calc/(' + Object.keys(CALC_DEF).filter(k => o[k] !== '' && o[k] != null).map(k => k + ':' + encodeURIComponent(o[k])).join('/') + ')';
  function calcFromVuln(a, v) {
    return calcHash({ OP: a.crit.op, SA: a.crit.sa, RD: a.crit.rd, RG: a.crit.rc, PL: a.purdue, CV: v.cvss, KEV: v.kev ? 1 : 0, EP: v.epss ?? '', PX: v.publicExploit ? 1 : 0, RE: v.reach, RC: v.rcis, MAT: matLevel(site()) || 'Reasonably', LEF: v.fair ? v.fair.lef.join('-') : '', LM: v.fair ? v.fair.lm.join('-') : '' });
  }
  function calc(arg) {
    const o = parseCalc(arg);
    const sel = (k, opts) => `<select data-k="${k}">${opts.map(([v, t]) => `<option value="${esc(v)}" ${String(o[k]) === String(v) ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>`;
    const crit = S.AIS_CRITERIA.map((c, i) => `<div class="factor"><label>${c.name}</label>${sel(['OP', 'SA', 'RD', 'RG'][i], c.opts.map((t, j) => [j + 1, `${j + 1} – ${t}`]))}</div>`).join('');
    view(`<div class="row"><h1>Risk Calculator</h1>${tip('calc')}<span class="mute small">Framework v2 · the link updates as you change inputs, so you can share any scenario.</span></div>
    <div class="calc"><div>
      <div class="card"><h2 style="margin-top:0">1 · Asset Importance (AIS) ${tip('ais')}</h2><div class="form">${crit}
        <div class="factor"><label>Purdue level</label>${sel('PL', Object.entries(S.PURDUE).map(([k, p]) => [k, `${p.label} (+${p.mod})`]))}</div></div></div>
      <div class="card" style="margin-top:12px"><h2 style="margin-top:0">2 · Vulnerability Severity (VSS) ${tip('vss')} & 3 · Likelihood (LF) ${tip('lf')}</h2><div class="form">
        <div><label>CVE (optional – looks up CVSS, KEV, EPSS)</label><div class="row"><input id="cveIn" placeholder="CVE-2021-22681" style="flex:1"><button id="cveGo">Look up</button></div><div id="cveMsg" class="small mute"></div>${lookupNote()}</div>
        <div><label>CVSS base score (0–10)</label><input data-k="CV" type="number" step="0.1" min="0" max="10" value="${esc(o.CV)}" placeholder="blank = manual Moderate"></div>
        <div><label>CISA KEV listed? ${tip('kev')}</label>${sel('KEV', [[0, 'No'], [1, 'Yes – known exploited']])}</div>
        <div><label>EPSS probability (0–1) ${tip('epss')}</label><input data-k="EP" type="number" step="0.0001" min="0" max="1" value="${esc(o.EP)}"></div>
        <div><label>Public exploit / Metasploit module?</label>${sel('PX', [[0, 'No / unknown'], [1, 'Yes']])}</div>
        <div><label>Exposure & reachability (R) ${tip('reach')}</label>${sel('RE', [[3, '3 – Internet, enterprise IT, or remote-access path'], [2, '2 – Only from inside OT / same zone'], [1, '1 – Local/physical only, or isolated']])}</div>
      </div></div>
      <div class="card" style="margin-top:12px"><h2 style="margin-top:0">4 · Regulatory (RCIS) ${tip('rcis')} & site maturity ${tip('maturity')}</h2><div class="form">
        <div><label>Regulatory compliance impact</label>${sel('RC', [['1.0', '1.0 – Minimal'], ['1.2', '1.2 – Potential fines'], ['1.5', '1.5 – Severe legal/regulatory']])}</div>
        <div><label>Site security maturity (sets SLAs, not the score)</label>${sel('MAT', [['Poorly', 'Poorly Secured (9–14)'], ['Reasonably', 'Reasonably Secured (15–21)'], ['Highly', 'Highly Secured (22–27)']])}</div>
      </div></div>
      <div class="card" style="margin-top:12px"><h2 style="margin-top:0">5 · Optional: FAIR-style annual loss estimate ${tip('fair')}</h2>
        <div class="form"><div><label>Loss events per year: min-most likely-max</label><input data-k="LEF" value="${esc(o.LEF)}" placeholder="0.02-0.05-0.15"></div>
        <div><label>Loss per event $: min-most likely-max</label><input data-k="LM" value="${esc(o.LM)}" placeholder="150000-350000-1200000"></div></div>
        <div id="aleOut" class="small" style="margin-top:8px"></div></div>
    </div>
    <div><div class="sticky"><div class="card"><div id="gauge"></div><table class="break small" id="brk"></table><div id="slaOut" class="small"></div>
      <div class="row" style="margin-top:10px"><button class="pri" id="copyLink">Copy share link</button><a class="btn" href="#/calc">Reset</a></div>
      <div class="hashbox mute" id="hashOut" style="margin-top:8px"></div></div></div></div></div>`);
    const upd = () => {
      document.querySelectorAll('[data-k]').forEach(e => o[e.dataset.k] = e.value);
      const asset = { crit: { op: +o.OP, sa: +o.SA, rd: +o.RD, rc: +o.RG }, purdue: o.PL };
      const r = S.score(asset, { cvss: o.CV, kev: o.KEV === '1', epss: o.EP, publicExploit: o.PX === '1', reach: +o.RE, rcis: +o.RC });
      $('#gauge').innerHTML = `<div class="gauge ${r.cls}"><div class="big">${r.score}</div><div class="lvl">${r.level}${r.floored ? ' (KEV floor)' : ''}</div><div class="small">out of 100</div></div>`;
      $('#brk').innerHTML = `<tr><td>AIS (${r.ais.level})</td><td>${r.ais.score}</td></tr><tr><td>VSS (${esc(r.vss.cat)})</td><td>${r.vss.score}</td></tr>
        <tr><td>Threat T (${esc(r.threat.why)})</td><td>${r.threat.t}</td></tr><tr><td>Reachability R</td><td>${r.reach}</td></tr><tr><td>LF (T+R=${r.threat.t + r.reach})</td><td>× ${r.lf}</td></tr>
        <tr><td>RCIS</td><td>× ${r.rcis}</td></tr><tr><td class="mute">${r.ais.score} × ${r.vss.score} × ${r.lf} × ${r.rcis} ÷ 3.375</td><td>${r.score}</td></tr>`;
      const sla = S.slaFor(r.level, o.MAT);
      $('#slaOut').innerHTML = `<h3>Response (${esc(o.MAT)} Secured)</h3><div>Contain: <b>${sla.containDays ? sla.containDays + ' days' : (r.level === 'Moderate' ? 'next maintenance window' : 'monitor')}</b> · Remediate: <b>${sla.remediateDays ? sla.remediateDays + ' days' : 'lifecycle'}</b></div><p class="mute">${esc(S.COMP_CONTROLS[o.MAT])}</p>${disc()}`;
      const p = s => (s || '').split('-').map(Number);
      const al = (o.LEF && o.LM) ? S.ale(p(o.LEF), p(o.LM)) : null;
      $('#aleOut').innerHTML = al ? `<b>Estimated annualized loss:</b> P10 ${money(al.p10)} · <b>P50 ${money(al.p50)}</b> · P90 ${money(al.p90)} <span class="mute">(10,000-draw Monte Carlo, triangular inputs, an estimate, not a forecast)</span>${disc()}` : '<span class="mute">Enter both ranges to estimate. Use this for risks that need funding or an executive exception.</span>';
      const h = calcHash(o); history.replaceState(null, '', h); $('#hashOut').textContent = location.href;
    };
    document.querySelectorAll('[data-k]').forEach(e => e.addEventListener(e.tagName === 'SELECT' ? 'change' : 'input', upd));
    $('#copyLink').onclick = () => { navigator.clipboard.writeText(location.href).then(() => $('#copyLink').textContent = 'Copied ✓'); };
    $('#cveGo').onclick = async () => {
      const id = $('#cveIn').value.trim().toUpperCase(); if (!/^CVE-\d{4}-\d{4,}$/.test(id)) { $('#cveMsg').textContent = 'Enter a CVE ID like CVE-2021-22681'; return; }
      $('#cveMsg').textContent = 'Looking up…'; const info = await lookupCVE(id);
      if (info.cvss != null) $('[data-k=CV]').value = info.cvss; $('[data-k=KEV]').value = info.kev ? 1 : 0; if (info.epss != null) $('[data-k=EP]').value = info.epss;
      $('#cveMsg').innerHTML = esc(info.msg); upd();
    };
    upd();
  }
  function lookupNote() {
    return D.settings.feedsOnly
      ? `<div class="small mute" style="margin-top:3px">🔒 Feeds-only mode: Look up uses the nightly data hosted with this site; nothing is sent to outside services. ${tip('feedsOnly')} <a href="#/settings">change</a></div>`
      : `<div class="small" style="margin-top:3px;color:#f5d48a">⚠ Live look-ups are on: the CVE ID is sent to FIRST.org and NIST NVD, which reveals the CVEs you track. ${tip('feedsOnly')} <a href="#/settings">change</a></div>`;
  }
  async function lookupCVE(id) {
    const out = { kev: !!(window.KEV && KEV[id]), epss: null, cvss: null, msgs: [] };
    out.msgs.push(out.kev ? `KEV: yes (added ${KEV[id][0]})` : `KEV: no (catalog ${KEV_META.version})`);
    if (out.kev && KEV[id][5]) out.title = KEV[id][5];
    const fe = F.epssFor(id), fc = F.cvssFor(id), adv = F.advisoriesFor(id);
    if (fe != null) { out.epss = fe; out.msgs.push('EPSS ' + fe + ' (nightly feed)'); }
    if (fc != null) { out.cvss = fc; out.msgs.push('CVSS ' + fc + ' (CISA ' + adv[0].id + ')'); if (!out.title) out.title = adv[0].t; }
    if (D.settings.feedsOnly) {
      if (fe == null) out.msgs.push(F.ok() ? 'EPSS: not in the nightly set (it holds KEV/ICS CVEs and anything ≥ 0.10), so it is likely low' : 'EPSS: feeds not loaded');
      if (fc == null) out.msgs.push('CVSS: not in a CISA ICS advisory; enter it from the vendor or NVD page');
      out.msg = out.msgs.join(' · '); return out;
    }
    if (fe == null) try { const r = await fetch('https://api.first.org/data/v1/epss?cve=' + id); const j = await r.json(); if (j.data && j.data[0]) { out.epss = +(+j.data[0].epss).toFixed(4); out.msgs.push('EPSS ' + out.epss + ' (FIRST live)'); } else out.msgs.push('EPSS: none'); } catch (e) { out.msgs.push('EPSS lookup failed'); }
    if (fc == null) try {
      const r = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + id); const j = await r.json(); const c = j.vulnerabilities && j.vulnerabilities[0] && j.vulnerabilities[0].cve;
      if (c) { const m = c.metrics || {}; const k = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'].find(x => m[x]); if (k) { out.cvss = m[k][0].cvssData.baseScore; out.msgs.push('CVSS ' + out.cvss + ' (NVD live)'); } if (!out.title) out.title = (c.descriptions || [])[0]?.value?.slice(0, 140) || ''; }
    } catch (e) { out.msgs.push('NVD lookup failed (rate limit?) – enter CVSS manually'); }
    out.msg = out.msgs.join(' · '); return out;
  }

  // ---------- assets ----------
  function assets() {
    const list = siteAssets(), sc = scored();
    const worst = id => sc.filter(x => x.a.id === id && x.v.status !== 'Remediated' && x.v.status !== 'Accepted')[0];
    view(`<div class="row"><h1>OT Asset Inventory</h1>${tip('assets')}<span class="mute">${list.length} assets · ${esc(site().name)}</span>
      <span class="right"><input id="flt" placeholder="Filter…" style="width:200px"></span><button class="pri" id="addA">+ Add asset</button><a class="btn" href="#/import">Import scan…</a></div>
    <div class="card" style="margin-top:10px;overflow:auto"><table id="atab"><tr><th>Name</th><th>Type</th><th>Vendor / model</th><th>Firmware</th><th>IP</th><th>Purdue</th><th>Zone</th><th>AIS</th><th>Worst open risk</th><th>Alerts</th><th>Source</th></tr>
    ${list.map(a => { const ai = S.ais(a.crit, a.purdue), w = worst(a.id); return `<tr data-f="${esc((a.name + a.type + a.vendor + a.model + a.ip + a.zone).toLowerCase())}"><td><a href="#/asset/${esc(a.id)}">${esc(a.name)}</a></td><td>${esc(a.type)}</td><td>${esc(a.vendor)}<div class="mute small">${esc(a.model)}</div></td><td>${esc(a.firmware)}</td><td>${esc(a.ip)}</td><td>${esc(a.purdue)}${a.purdueGuessed ? ' <span class="tag warn">guess</span>' : ''}</td><td>${esc(a.zone)}</td><td>${ai.score} <span class="mute small">${ai.level}</span></td><td>${w ? pill(w.r) : '<span class="mute">—</span>'}</td><td>${(n => n ? `<a href="#/asset/${esc(a.id)}"><span class="conf Medium">${n} possible</span></a>` : '<span class="mute">—</span>')(openMatches().filter(m => m.assetId === a.id).length)}</td><td><span class="tag">${esc(a.source)}</span></td></tr>`; }).join('')}</table></div>`);
    $('#flt').oninput = e => { const q = e.target.value.toLowerCase(); document.querySelectorAll('#atab tr[data-f]').forEach(tr => tr.style.display = tr.dataset.f.includes(q) ? '' : 'none'); };
    $('#addA').onclick = () => editAsset(null);
  }
  function editAsset(a) {
    const isNew = !a; a = a || { id: uid('a'), siteId: site().id, name: '', type: '', vendor: '', model: '', firmware: '', ip: '', mac: '', purdue: 'L1', zone: '', crit: { op: 2, sa: 1, rd: 2, rc: 1 }, owner: '', notes: '', source: 'manual', lastSeen: today() };
    const f = (k, l, t = 'text') => `<div><label>${l}</label><input name="${k}" type="${t}" value="${esc(a[k])}"></div>`;
    const c = S.AIS_CRITERIA.map(cr => `<div><label>${cr.name}</label><select name="crit.${cr.key}">${cr.opts.map((t, j) => `<option value="${j + 1}" ${a.crit[cr.key] == j + 1 ? 'selected' : ''}>${j + 1} – ${esc(t)}</option>`).join('')}</select></div>`).join('');
    modal(`<h2 style="margin-top:0">${isNew ? 'Add' : 'Edit'} asset</h2><form id="af"><div class="form">${f('name', 'Name / tag')}${f('type', 'Type (PLC, HMI, EWS…)')}${f('vendor', 'Vendor')}${f('model', 'Model')}${f('firmware', 'Firmware / OS version ' + tip('firmware'))}${f('ip', 'IP address')}${f('mac', 'MAC')}
      <div><label>Purdue level</label><select name="purdue">${Object.entries(S.PURDUE).map(([k, p]) => `<option value="${k}" ${a.purdue === k ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></div>
      ${f('zone', 'Zone / cell')}${f('owner', 'Owner')}</div><p class="small mute">Vendor, model (catalog number if you have it) and firmware let the nightly feeds find advisories for this asset.</p><h3>Criticality criteria (AIS) ${tip('criticality')}</h3><div class="form">${c}</div>
      <label>Notes</label><textarea name="notes" rows="2">${esc(a.notes)}</textarea>
      <div class="row" style="margin-top:12px"><button class="pri" type="submit">Save</button><button type="button" id="cx">Cancel</button>${isNew ? '' : '<button type="button" class="danger right" id="del">Delete asset</button>'}</div></form>`, el => {
      $('#cx', el).onclick = closeModal;
      if (!isNew) $('#del', el).onclick = () => { if (confirm('Delete asset and its vulnerabilities?')) { D.assets = D.assets.filter(x => x.id !== a.id); D.vulns = D.vulns.filter(v => v.assetId !== a.id); save(); closeModal(); location.hash = '#/assets'; } };
      $('#af', el).onsubmit = e => {
        e.preventDefault(); const fd = new FormData(e.target);
        for (const [k, v] of fd) { if (k.startsWith('crit.')) a.crit[k.slice(5)] = +v; else a[k] = v; }
        a.purdueGuessed = false; a.critReviewed = true; if (isNew) D.assets.push(a); save(); closeModal(); processFeeds(); route();
      };
    });
  }
  function assetDetail(id) {
    const a = assetById(id); if (!a) return view('<p>Asset not found. <a href="#/assets">Back</a></p>');
    const ai = S.ais(a.crit, a.purdue), rows = scored(false).filter(x => x.a.id === a.id);
    view(`<p><a href="#/assets">← Assets</a></p><div class="row"><h1>${esc(a.name)}</h1><span class="tag">${esc(a.purdue)}</span><span class="tag">${esc(a.zone)}</span><button class="right" id="ea">Edit asset</button></div>
    <div class="grid g2"><div class="card"><table>
      <tr><td class="mute">Type</td><td>${esc(a.type)}</td></tr><tr><td class="mute">Vendor / model</td><td>${esc(a.vendor)} ${esc(a.model)}</td></tr><tr><td class="mute">Firmware</td><td>${esc(a.firmware)}</td></tr>
      <tr><td class="mute">IP / MAC</td><td>${esc(a.ip)} ${esc(a.mac)}</td></tr><tr><td class="mute">Owner</td><td>${esc(a.owner)}</td></tr><tr><td class="mute">Source / last seen</td><td>${esc(a.source)} · ${esc(a.lastSeen)}</td></tr><tr><td class="mute">Notes</td><td>${esc(a.notes)}</td></tr></table></div>
      <div class="card"><h3 style="margin-top:0">Asset Importance Score: ${ai.score} (${ai.level})</h3><table>${S.AIS_CRITERIA.map(c => `<tr><td>${c.name}</td><td>${a.crit[c.key]} – ${esc(c.opts[a.crit[c.key] - 1])}</td></tr>`).join('')}<tr><td>Purdue modifier</td><td>+${ai.purdueMod}</td></tr></table></div></div>
    <div class="row" style="margin-top:14px"><h2>Vulnerabilities</h2><button class="pri right" id="av">+ Add vulnerability</button></div>
    <div class="card" style="overflow:auto"><table><tr><th>Risk</th><th>CVE</th><th>CVSS</th><th>KEV ${tip('kev')}</th><th>EPSS ${tip('epss')}</th><th>R ${tip('reach')}</th><th>RCIS</th><th>Status ${tip('status')}</th><th>Due</th><th></th></tr>
    ${rows.map(x => `<tr><td>${pill(x.r)}${x.r.floored ? '<div class="small mute">KEV floor</div>' : ''}${x.v.rescored ? `<div><span class="tag chg" title="${esc(x.v.rescored.why)}">re-scored</span></div>` : ''}</td><td><a href="#/vuln/${esc(x.v.id)}">${esc(x.v.cve)}</a><div class="small mute">${esc(x.v.title)}</div></td><td>${esc(x.v.cvss)}</td><td>${x.v.kev ? '<span class="tag kev">KEV</span>' : '—'}</td><td>${x.v.epss ?? '—'}</td><td>${x.r.reach}</td><td>${x.r.rcis}</td><td>${esc(x.v.status)}</td><td>${dueCell(x)}</td>
      <td class="row"><a class="btn pri" href="#/vuln/${esc(x.v.id)}">Fix guide</a><button data-ev="${esc(x.v.id)}">Edit</button><a class="btn" href="${calcFromVuln(a, x.v)}">Calc</a></td></tr>`).join('') || '<tr><td colspan=10 class="mute">None recorded.</td></tr>'}</table></div>
    ${(ms => ms.length ? `<div class="row" style="margin-top:14px"><h2>Possible matches from CISA feeds (${ms.length})</h2>${tip('confidence')}<a class="right" href="#/alerts">All alerts →</a></div><div class="card" style="overflow:auto"><table><tr><th>Asset</th><th>Advisory &amp; reason</th><th>Confidence</th><th></th></tr>${ms.map(m => matchRow(m, false)).join('')}</table></div>` : '')(openMatches().filter(m => m.assetId === a.id).slice(0, 40))}`);
    bindMatchButtons($('#view'), route);
    $('#ea').onclick = () => editAsset(a); $('#av').onclick = () => editVuln(null, a);
    document.querySelectorAll('[data-ev]').forEach(b => b.onclick = () => editVuln(D.vulns.find(v => v.id === b.dataset.ev), a));
  }
  function editVuln(v, a) {
    const isNew = !v; v = v || { id: uid('v'), assetId: a.id, cve: '', title: '', cvss: '', kev: false, epss: '', publicExploit: false, reach: 2, rcis: 1.0, status: 'Open', found: today(), owner: '', decision: '', compensating: '', fair: null };
    const fr = v.fair || { lef: ['', '', ''], lm: ['', '', ''] };
    modal(`<h2 style="margin-top:0">${isNew ? 'Add' : 'Edit'} vulnerability – ${esc(a.name)}</h2><form id="vf"><div class="form">
      <div><label>CVE</label><div class="row"><input name="cve" value="${esc(v.cve)}" style="flex:1"><button type="button" id="lk">Look up</button></div><div id="lkm" class="small mute"></div>${lookupNote()}</div>
      <div><label>Title / description</label><input name="title" value="${esc(v.title)}"></div>
      <div><label>CVSS base</label><input name="cvss" type="number" step="0.1" value="${esc(v.cvss)}"></div>
      <div><label>KEV listed</label><select name="kev"><option value="0">No</option><option value="1" ${v.kev ? 'selected' : ''}>Yes</option></select></div>
      <div><label>EPSS (0–1)</label><input name="epss" type="number" step="0.0001" value="${esc(v.epss)}"></div>
      <div><label>Public exploit</label><select name="publicExploit"><option value="0">No/unknown</option><option value="1" ${v.publicExploit ? 'selected' : ''}>Yes</option></select></div>
      <div><label>Reachability (R) ${tip('reach')}</label><select name="reach">${[[3, '3 – Internet/IT/remote path'], [2, '2 – OT only'], [1, '1 – Local/isolated']].map(([k, t]) => `<option value="${k}" ${v.reach == k ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div><label>RCIS</label><select name="rcis">${['1.0', '1.2', '1.5'].map(k => `<option ${(+v.rcis).toFixed(1) === k ? 'selected' : ''}>${k}</option>`).join('')}</select></div>
      <div><label>Status ${tip('status')}</label><select name="status">${['Open', 'Contained', 'Remediated', 'Accepted'].map(k => `<option ${v.status === k ? 'selected' : ''}>${k}</option>`).join('')}</select></div>
      <div><label>Date found</label><input name="found" type="date" value="${esc(v.found)}"></div><div><label>Owner</label><input name="owner" value="${esc(v.owner)}"></div></div>
      <label>Compensating controls in place</label><textarea name="compensating" rows="2">${esc(v.compensating)}</textarea>
      <label>Decision / rationale (risk register)</label><textarea name="decision" rows="2">${esc(v.decision)}</textarea>
      <h3>Optional FAIR estimate ${tip('fair')}</h3><div class="form"><div><label>Events/yr min · likely · max</label><div class="row">${[0, 1, 2].map(i => `<input name="lef${i}" value="${esc(fr.lef[i])}" style="width:30%">`).join('')}</div></div>
      <div><label>$ per event min · likely · max</label><div class="row">${[0, 1, 2].map(i => `<input name="lm${i}" value="${esc(fr.lm[i])}" style="width:30%">`).join('')}</div></div></div>
      <div class="row" style="margin-top:12px"><button class="pri" type="submit">Save</button><button type="button" id="cx">Cancel</button>${isNew ? '' : '<button type="button" class="danger right" id="del">Delete</button>'}</div></form>`, el => {
      $('#cx', el).onclick = closeModal;
      if (!isNew) $('#del', el).onclick = () => { D.vulns = D.vulns.filter(x => x.id !== v.id); save(); closeModal(); route(); };
      $('#lk', el).onclick = async () => {
        const f = $('#vf', el), id = f.cve.value.trim().toUpperCase(); f.cve.value = id; $('#lkm', el).textContent = 'Looking up…';
        const info = await lookupCVE(id); if (info.cvss != null) f.cvss.value = info.cvss; f.kev.value = info.kev ? 1 : 0; if (info.epss != null) f.epss.value = info.epss; if (info.title && !f.title.value) f.title.value = info.title; $('#lkm', el).textContent = info.msg;
      };
      $('#vf', el).onsubmit = e => {
        e.preventDefault(); const f = e.target;
        Object.assign(v, { cve: f.cve.value.trim().toUpperCase(), title: f.title.value, cvss: f.cvss.value === '' ? '' : +f.cvss.value, kev: f.kev.value === '1', epss: f.epss.value === '' ? '' : +f.epss.value, publicExploit: f.publicExploit.value === '1', reach: +f.reach.value, rcis: +f.rcis.value, status: f.status.value, found: f.found.value, owner: f.owner.value, compensating: f.compensating.value, decision: f.decision.value });
        const lef = [0, 1, 2].map(i => f['lef' + i].value), lm = [0, 1, 2].map(i => f['lm' + i].value);
        v.fair = lef.every(x => x !== '') && lm.every(x => x !== '') ? { lef: lef.map(Number), lm: lm.map(Number) } : null;
        if (isNew) D.vulns.push(v); save(); closeModal(); processFeeds(); route();
      };
    });
  }

  // ---------- risk register ----------
  function register() {
    const all = scored();
    view(`<div class="row"><h1>Risk Register</h1>${tip('register')}<span class="mute">${esc(site().name)} · maturity: ${esc(matLevel(site()) || 'not assessed (Reasonably assumed)')}</span>
      <span class="right row"><select id="fs" style="width:auto"><option value="">All statuses</option><option selected value="active">Open + Contained</option><option>Open</option><option>Contained</option><option>Remediated</option><option>Accepted</option></select>
      <select id="fb" style="width:auto"><option value="">All levels</option><option>Critical</option><option>High</option><option>Moderate</option><option>Low</option></select><button id="csv">Export CSV</button></span></div>
      <div class="card" style="overflow:auto;margin-top:10px"><table id="rt"></table></div>
      <p class="small mute">Sorted by v2 risk score. Due dates come from Table 3: containment by risk level, remediation window by site maturity. Overdue items need a documented exception.</p>${disc()}`);
    const draw = () => {
      const fs = $('#fs').value, fb = $('#fb').value;
      const rows = all.filter(x => (!fs || (fs === 'active' ? ['Open', 'Contained'].includes(x.v.status) : x.v.status === fs)) && (!fb || x.r.level === fb));
      $('#rt').innerHTML = `<tr><th>#</th><th>Risk</th><th>Asset</th><th>Vulnerability</th><th>AIS·VSS·LF·RCIS</th><th>Status</th><th>Due</th><th>Owner</th><th>Compensating control / decision</th></tr>` +
        rows.map((x, i) => `<tr><td>${i + 1}</td><td>${pill(x.r)}${x.r.floored ? '<div class="small mute">KEV floor</div>' : ''}</td><td><a href="#/asset/${esc(x.a.id)}">${esc(x.a.name)}</a><div class="small mute">${esc(x.a.purdue)} · ${esc(x.a.zone)}</div></td>
        <td><a href="#/vuln/${esc(x.v.id)}">${esc(x.v.cve)}</a> ${x.v.kev ? '<span class="tag kev">KEV</span>' : ''}${x.v.rescored ? ` <span class="tag chg" title="${esc(x.v.rescored.why)}">re-scored</span>` : ''}<div class="small mute">${esc(x.v.title)}</div><a class="small" href="#/vuln/${esc(x.v.id)}">Fix guide →</a></td><td class="small">${x.r.ais.score} · ${x.r.vss.score} · ${x.r.lf} · ${x.r.rcis}<div><a href="${calcFromVuln(x.a, x.v)}">open in calculator</a></div></td>
        <td>${esc(x.v.status)}</td><td>${dueCell(x)}</td><td>${esc(x.v.owner)}</td><td class="small">${esc(x.v.compensating)}${x.v.compensating && x.v.decision ? '<br>' : ''}<i>${esc(x.v.decision)}</i></td></tr>`).join('');
      $('#csv').onclick = () => {
        const h = ['rank', 'risk_score', 'risk_level', 'asset', 'ip', 'purdue', 'zone', 'cve', 'cvss', 'kev', 'epss', 'ais', 'vss', 'lf', 'rcis', 'status', 'contain_by', 'remediate_by', 'overdue', 'owner', 'compensating', 'decision'];
        const q = s => '"' + String(s ?? '').replace(/"/g, '""') + '"';
        const lines = [h.join(',')].concat(rows.map((x, i) => [i + 1, x.r.score, x.r.level, x.a.name, x.a.ip, x.a.purdue, x.a.zone, x.v.cve, x.v.cvss, x.v.kev, x.v.epss, x.r.ais.score, x.r.vss.score, x.r.lf, x.r.rcis, x.v.status, x.sla.containBy, x.sla.remediateBy, x.overdue, x.v.owner, x.v.compensating, x.v.decision].map(q).join(',')));
        download('risk-register-' + today() + '.csv', lines.join('\n'), 'text/csv');
      };
    };
    $('#fs').onchange = draw; $('#fb').onchange = draw; draw();
  }
  function download(name, text, type) { const b = new Blob([text], { type }); const u = URL.createObjectURL(b); const l = document.createElement('a'); l.href = u; l.download = name; l.click(); setTimeout(() => URL.revokeObjectURL(u), 1000); }

  // ---------- import ----------
  let pending = null;
  function importView() {
    view(`<div class="row"><h1>Import assets</h1>${tip('import')}<a class="right" href="#/help" onclick="setTimeout(()=>document.getElementById('help-import')&&document.getElementById('help-import').scrollIntoView(),50)">How to import safely →</a></div>
    <div class="note"><b>Recommended:</b> export an asset/inventory CSV from a passive or vendor tool you already run: <b>Claroty, Nozomi Networks, Dragos, Microsoft Defender for IoT, Tenable OT</b>, or switch <b>ARP/MAC and CDP/LLDP</b> tables, DHCP leases, or PLC project I/O lists. These never send a packet to your controllers.</div>
    <div class="note warnbox" style="margin-top:8px"><b>Nmap XML / active scans:</b> only from a scan with written OT/process-owner sign-off, inside a planned maintenance window with the process in a safe state, <b>one host at a time</b>, slow rate, and <b>never during production</b>. Active scans can freeze or crash PLCs, drives and older HMIs. No <code>-sV</code>/<code>-O</code> or subnet sweeps against Level 0–2.</div>
    <div class="note" style="margin-top:8px">This site never scans your network. Import results from a scan or tool you already ran <b>safely</b>, e.g. a passive capture, a switch/ARP export, an OT monitoring tool's CSV, or an Nmap XML from a <b>planned</b> scan of Level 3+ networks or an approved maintenance-window scan of control networks with OT-safe scripts. Active scanning can crash PLCs. Get operations sign-off first.</div>
    <div class="grid g2" style="margin-top:14px"><div class="card"><div class="drop" id="drop">Drop an Nmap XML, CSV, or collector JSON file here<br><br><input type="file" id="file" accept=".xml,.csv,.json,.txt" style="width:auto"></div>
      <p class="small mute">Try the samples: <a href="samples/plant2-nmap-sample.xml" download>Nmap XML</a> · <a href="samples/plant2-assets-sample.csv" download>CSV</a> · <a href="samples/collector-sample.json" download>collector JSON</a></p></div>
    <div class="card small"><h3 style="margin-top:0">Supported formats</h3><ul>
      <li><b>Nmap XML</b> (<code>-oX</code>). Reads IP, MAC/vendor, hostnames, open ports, and OT NSE output (<code>enip-info</code>, <code>s7-info</code>, <code>modbus-discover</code>, <code>bacnet-info</code>). It suggests type and Purdue level from OT ports (102, 502, 44818, 47808, 20000, 4840…), and marks suggestions as <span class="tag warn">guess</span>.</li>
      <li><b>CSV</b> with headers such as Name, IP, MAC, Vendor, Model, Firmware, Type, Purdue, Zone, Owner, CVE. Common export header names are recognized, and listed CVEs are created as vulnerabilities and auto-tagged with KEV.</li>
      <li><b>Collector JSON</b> (<code>otrisk.collector.v1</code>), the format a future on-site passive collector will push. See <code>docs/COLLECTOR-SPEC.md</code>.</li></ul>
      <p>Matching: an existing asset with the same IP or MAC gets updated (firmware, vendor/model, last seen). Your criticality ratings and Purdue choices are never overwritten.</p></div></div>
    <div id="prev"></div>`);
    const fi = $('#file'), dr = $('#drop');
    const handle = file => file.text().then(t => { try { const res = OTImport.detectAndParse(file.name, t); preview(res, file.name); } catch (e) { $('#prev').innerHTML = `<div class="card" style="margin-top:14px;color:#ffb3b5">Import error: ${esc(e.message)}</div>`; } });
    fi.onchange = () => fi.files[0] && handle(fi.files[0]);
    dr.ondragover = e => { e.preventDefault(); dr.classList.add('over'); }; dr.ondragleave = () => dr.classList.remove('over');
    dr.ondrop = e => { e.preventDefault(); dr.classList.remove('over'); e.dataTransfer.files[0] && handle(e.dataTransfer.files[0]); };
  }
  function preview(res, fname) {
    const ex = siteAssets();
    const items = res.assets.map(n => { const m = ex.find(a => (n.ip && a.ip === n.ip) || (n.mac && a.mac && a.mac.toLowerCase() === n.mac.toLowerCase())); return { n, m }; });
    pending = { items, fname, kind: res.kind };
    $('#prev').innerHTML = `<div class="card" style="margin-top:14px"><div class="row"><h2 style="margin:0">Preview: ${esc(res.kind)} · ${esc(fname)}</h2><span class="mute">${items.filter(i => !i.m).length} new · ${items.filter(i => i.m).length} matched</span>
      <span class="right row"><label class="inl">Default zone for new <input id="dz" placeholder="e.g. Paint Line" style="width:140px"></label><button class="pri" id="commit">Import into ${esc(site().name)}</button></span></div>
      <div style="overflow:auto;margin-top:8px"><table><tr><th><input type="checkbox" id="all" checked style="width:auto"></th><th>Action</th><th>Name</th><th>IP</th><th>MAC</th><th>Vendor / model</th><th>Firmware</th><th>Type</th><th>Purdue</th><th>CVEs</th><th>Notes</th></tr>
      ${items.map((it, i) => `<tr><td><input type="checkbox" class="ck" data-i="${i}" checked style="width:auto"></td><td>${it.m ? `<span class="tag">update ${esc(it.m.name)}</span>` : '<span class="tag warn">new</span>'}</td><td>${esc(it.n.name)}</td><td>${esc(it.n.ip)}</td><td>${esc(it.n.mac)}</td><td>${esc(it.n.vendor)}<div class="small mute">${esc(it.n.model)}</div></td><td>${esc(it.n.firmware)}</td><td>${esc(it.n.type)}</td><td>${esc(it.n.purdue)}${it.n.purdueGuessed ? ' <span class="tag warn">guess</span>' : ''}</td><td class="small">${esc((it.n.cves || []).join(', '))}</td><td class="small mute">${esc(it.n.notes)}</td></tr>`).join('')}</table></div></div>`;
    $('#all').onchange = e => document.querySelectorAll('.ck').forEach(c => c.checked = e.target.checked);
    $('#commit').onclick = () => {
      let added = 0, updated = 0, vulns = 0; const dz = $('#dz').value.trim(); const src = pending.kind === 'Nmap XML' ? 'nmap' : pending.kind === 'CSV' ? 'csv' : 'collector';
      document.querySelectorAll('.ck').forEach(c => {
        if (!c.checked) return; const { n, m } = pending.items[+c.dataset.i]; let a = m;
        if (m) { ['vendor', 'model', 'firmware', 'mac'].forEach(k => { if (n[k]) m[k] = n[k]; }); m.lastSeen = today(); if (n.notes) m.notes = (m.notes ? m.notes + ' | ' : '') + n.notes; updated++; }
        else { a = { id: uid('a'), siteId: site().id, name: n.name, type: n.type, vendor: n.vendor, model: n.model, firmware: n.firmware, ip: n.ip, mac: n.mac, purdue: n.purdue || 'L3', purdueGuessed: !!n.purdueGuessed, zone: n.zone || dz, crit: { op: 2, sa: 1, rd: 2, rc: 1 }, owner: n.owner || '', notes: n.notes || '', source: src, lastSeen: today() }; D.assets.push(a); added++; }
        (n.cves || []).forEach(cve => { if (D.vulns.some(v => v.assetId === a.id && v.cve === cve)) return; D.vulns.push({ id: uid('v'), assetId: a.id, cve, title: 'Imported – look up CVSS/EPSS', cvss: '', kev: !!KEV[cve], epss: '', publicExploit: false, reach: 2, rcis: 1.0, status: 'Open', found: today(), owner: '', decision: '', compensating: '', fair: null }); vulns++; });
      });
      save(); processFeeds(); $('#prev').innerHTML = `<div class="card" style="margin-top:14px">Imported: <b>${added}</b> new assets, <b>${updated}</b> updated, <b>${vulns}</b> vulnerabilities. New assets get default criticality (2/1/2/1). <a href="#/assets">Review them in the inventory →</a> and confirm Purdue levels marked <span class="tag warn">guess</span>. New feed matches: <a href="#/alerts">${newMatches().length} on the Alerts screen →</a></div>`;
    };
  }

  // ---------- maturity wizard ----------
  function maturity(stepArg) {
    const s = site(); s.maturity = s.maturity || Array(9).fill(0);
    const step = Math.min(9, Math.max(0, parseInt(stepArg || '0', 10) || 0));
    if (step === 9 || (stepArg === '' && s.maturity.every(x => x))) {
      const t = matTotal(s), l = matLevel(s);
      const focus = { Poorly: 'Establish a formal security policy, create asset inventories, apply basic security controls.', Reasonably: 'Implement structured remediation timelines, increase scanning frequency, enforce risk-based patching.', Highly: 'Automate threat detection, integrate real-time vulnerability tracking, adopt predictive risk modeling.' };
      if (!t) return view(`<h1>Security Maturity</h1><p>Some factors are unanswered. <a href="#/maturity/0">Start the assessment →</a></p>`);
      return view(`<h1>Security Maturity – ${esc(s.name)}</h1><div class="grid g2"><div class="card"><div class="gauge ${l === 'Poorly' ? 'crit' : l === 'Reasonably' ? 'mod' : 'low'}"><div class="big">${t}<span style="font-size:22px">/27</span></div><div class="lvl">${l} Secured</div></div>
        <table class="small" style="margin-top:10px">${S.MATURITY_FACTORS.map((f, i) => `<tr><td>${esc(f[0])}</td><td>${s.maturity[i]}</td><td class="mute">${esc(f[s.maturity[i]])}</td></tr>`).join('')}</table><p><a class="btn" href="#/maturity/0">Re-assess</a></p></div>
        <div class="card"><h2 style="margin-top:0">What this level drives (v2)</h2><p class="small mute">Maturity is not part of the risk score. It sets how fast and how you respond.</p>
        <h3>VMP focus</h3><p>${esc(focus[l])}</p><h3>Remediation windows</h3><table class="small"><tr><th>Risk</th><th>Contain</th><th>Remediate (${l})</th></tr>
        ${['Critical', 'High', 'Moderate', 'Low'].map(k => `<tr><td>${k}</td><td>${S.SLA[k].contain ? S.SLA[k].contain + ' days' : k === 'Moderate' ? 'next maint. window' : 'monitor'}</td><td>${S.SLA[k].remediate[l] ? S.SLA[k].remediate[l] + ' days' : 'lifecycle'}</td></tr>`).join('')}</table>
        <h3>Compensating-control expectation</h3><p>${esc(S.COMP_CONTROLS[l])}</p>${disc()}<h3>Lowest-scoring factors to improve first</h3><ul>${S.MATURITY_FACTORS.map((f, i) => [f[0], s.maturity[i]]).filter(x => x[1] === Math.min(...s.maturity)).map(x => `<li>${esc(x[0])}</li>`).join('')}</ul></div></div>`);
    }
    const f = S.MATURITY_FACTORS[step];
    view(`<h1>Security Maturity Assessment ${tip('maturity')}</h1><div class="mute">${esc(s.name)} · factor ${step + 1} of 9</div><div class="progress"><span style="width:${(step) / 9 * 100}%"></span></div>
      <div class="card"><h2 style="margin-top:0">${esc(f[0])}</h2><p class="mute">Pick the description that best fits this site today. Be honest; this sets realistic SLAs, not a grade.</p>
      <div class="choice">${[1, 2, 3].map(p => `<button data-p="${p}" class="${s.maturity[step] === p ? 'sel' : ''}"><b>${['Poorly', 'Reasonably', 'Highly'][p - 1]} (${p})</b><br><span class="small">${esc(f[p])}</span></button>`).join('')}</div>
      <div class="row" style="margin-top:14px">${step > 0 ? `<a class="btn" href="#/maturity/${step - 1}">← Back</a>` : ''}<span class="right mute small">Running total: ${s.maturity.reduce((a, b) => a + b, 0)}</span></div></div>`);
    document.querySelectorAll('[data-p]').forEach(b => b.onclick = () => { s.maturity[step] = +b.dataset.p; save(); location.hash = '#/maturity/' + (step + 1); });
  }

  // ---------- company & sites ----------
  function company() {
    const c = D.company;
    view(`<h1>Company & Sites</h1><div class="grid g2"><div class="card"><h2 style="margin-top:0">Company profile</h2><form id="cf">
      <label>Company name</label><input name="name" value="${esc(c.name)}"><label>Industry / products</label><input name="industry" value="${esc(c.industry)}">
      <label>Headquarters</label><input name="hq" value="${esc(c.hq)}"><label>Security contact</label><input name="contact" value="${esc(c.contact)}">
      <div style="margin-top:10px"><button class="pri">Save</button> <span id="cs" class="mute small"></span></div></form></div>
      <div class="card"><div class="row"><h2 style="margin:0">Sites</h2><button class="right" id="ns">+ Add site</button></div><table style="margin-top:8px"><tr><th>Site</th><th>Location</th><th>Assets</th><th>Maturity</th><th></th></tr>
      ${D.sites.map(s => `<tr><td>${esc(s.name)}<div class="small mute">${esc(s.notes)}</div></td><td>${esc(s.location)}</td><td>${D.assets.filter(a => a.siteId === s.id).length}</td><td>${matLevel(s) ? esc(matLevel(s)) + ' (' + matTotal(s) + ')' : '<span class="mute">—</span>'}</td>
        <td class="row"><button data-use="${esc(s.id)}">${s.id === D.activeSiteId ? 'Active ✓' : 'Use'}</button><button data-es="${esc(s.id)}">Edit</button></td></tr>`).join('')}</table></div></div>`);
    $('#cf').onsubmit = e => { e.preventDefault(); const fd = new FormData(e.target); for (const [k, v] of fd) c[k] = v; save(); $('#cs').textContent = 'Saved'; };
    document.querySelectorAll('[data-use]').forEach(b => b.onclick = () => { D.activeSiteId = b.dataset.use; save(); route(); });
    const editSite = s => {
      const isNew = !s; s = s || { id: uid('s'), name: '', location: '', headcount: '', notes: '', maturity: Array(9).fill(0) };
      modal(`<h2 style="margin-top:0">${isNew ? 'Add' : 'Edit'} site</h2><form id="sf"><label>Name</label><input name="name" value="${esc(s.name)}" required><label>Location</label><input name="location" value="${esc(s.location)}"><label>Headcount</label><input name="headcount" value="${esc(s.headcount)}"><label>Notes</label><textarea name="notes">${esc(s.notes)}</textarea>
        <div class="row" style="margin-top:10px"><button class="pri">Save</button><button type="button" id="cx">Cancel</button>${isNew || D.sites.length < 2 ? '' : '<button type="button" class="danger right" id="del">Delete site</button>'}</div></form>`, el => {
        $('#cx', el).onclick = closeModal;
        if ($('#del', el)) $('#del', el).onclick = () => { if (!confirm('Delete site, its assets and vulnerabilities?')) return; const ids = new Set(D.assets.filter(a => a.siteId === s.id).map(a => a.id)); D.vulns = D.vulns.filter(v => !ids.has(v.assetId)); D.assets = D.assets.filter(a => a.siteId !== s.id); D.sites = D.sites.filter(x => x.id !== s.id); D.activeSiteId = D.sites[0].id; save(); closeModal(); route(); };
        $('#sf', el).onsubmit = e => { e.preventDefault(); const fd = new FormData(e.target); for (const [k, v] of fd) s[k] = v; if (isNew) { D.sites.push(s); D.activeSiteId = s.id; } save(); closeModal(); route(); };
      });
    };
    $('#ns').onclick = () => editSite(null);
    document.querySelectorAll('[data-es]').forEach(b => b.onclick = () => editSite(D.sites.find(s => s.id === b.dataset.es)));
  }

  // ---------- alerts (feed matches) ----------
  function alerts() {
    if (!F.ok()) return view(`<h1>Alerts</h1><div class="note">${F.status === 'loading' ? 'Loading nightly feeds…' : 'Nightly feeds could not be loaded (' + esc(F.error || 'offline') + '). Equipment matching needs data/ics.json from the site. If you opened index.html from disk, run a local web server instead (see README).'}</div>`);
    const q = { conf: D.settings.showLow ? 'all' : 'hm', scope: 'site', show: 'open' };
    view(`<div class="row"><h1>Alerts</h1>${tip('alerts')}<span class="mute small">Nightly feeds ${esc((F.meta.updated || '').slice(0, 16).replace('T', ' '))} UTC</span></div>
      <p class="small">These are <b>possible matches</b> between your assets and CISA ICS advisories / the KEV catalog, based on vendor, model and firmware text. A person has to confirm each one. ${tip('confidence')}</p>
      <div class="row"><select id="fConf" style="width:auto"><option value="hm">High + Medium</option><option value="h">High only</option><option value="all">All, including Low</option></select>
      <select id="fScope" style="width:auto"><option value="site">This site</option><option value="all">All sites</option></select>
      <select id="fShow" style="width:auto"><option value="open">Open</option><option value="new">New only</option><option value="dismissed">Dismissed</option><option value="confirmed">Confirmed</option></select>
      <input id="fTxt" placeholder="Filter by asset, vendor, CVE…" style="width:240px"><span id="fCnt" class="mute small right"></span></div>
      <div class="card" style="overflow:auto;margin-top:10px"><table id="mt"></table></div>
      <div id="chg"></div>`);
    $('#fConf').value = q.conf;
    const draw = () => {
      const c = $('#fConf').value, sc = $('#fScope').value, sh = $('#fShow').value, tx = $('#fTxt').value.toLowerCase();
      let rows = MATCHES.filter(m => c === 'all' || (c === 'h' ? m.confidence === 'High' : m.confidence !== 'Low'));
      if (sc === 'site') rows = rows.filter(siteMatchFilter);
      rows = rows.filter(m => sh === 'dismissed' ? D.feed.dismissed[m.key] : sh === 'confirmed' ? D.feed.confirmed[m.key] : !D.feed.dismissed[m.key] && !D.feed.confirmed[m.key] && (sh !== 'new' || D.feed.newKeys[m.key]));
      if (tx) rows = rows.filter(m => { const a = assetById(m.assetId); return (a.name + ' ' + a.vendor + ' ' + a.model + ' ' + m.title + ' ' + (m.advId || '') + ' ' + m.cves.join(' ')).toLowerCase().includes(tx); });
      $('#fCnt').textContent = rows.length + ' shown';
      $('#mt').innerHTML = `<tr><th>Asset</th><th>Advisory &amp; reason</th><th>Confidence</th><th></th></tr>` + (rows.slice(0, 300).map(m => matchRow(m, false)).join('') || '<tr><td colspan=4 class="mute">Nothing here. Add vendor, model and firmware to your assets to get matches.</td></tr>');
      bindMatchButtons($('#mt'), draw);
      const ch = D.feed.changes.filter(x => D.vulns.some(v => v.id === x.vulnId)).slice(0, 50);
      $('#chg').innerHTML = ch.length ? `<h2>Re-scored from feed changes</h2><div class="card"><table class="small"><tr><th>When</th><th>Asset</th><th>CVE</th><th>Change</th><th>Score</th><th></th></tr>${ch.map(x => { const a = assetById(x.assetId); return `<tr><td>${esc(x.at)}</td><td>${a ? esc(a.name) : ''}</td><td><a href="#/vuln/${esc(x.vulnId)}">${esc(x.cve)}</a></td><td>${esc(x.why)}</td><td>${esc(x.fromLevel)} ${x.from} → <b>${esc(x.toLevel)} ${x.to}</b></td><td>${x.ack ? '<span class="mute">ack</span>' : '<span class="tag chg">new</span>'}</td></tr>`; }).join('')}</table></div>` : '';
    };
    ['#fConf', '#fScope', '#fShow'].forEach(i => $(i).onchange = draw); $('#fTxt').oninput = draw; draw();
  }

  // ---------- vulnerability detail + fix guidance ----------
  function vulnDetail(id) {
    const v = D.vulns.find(x => x.id === id); const a = v && assetById(v.assetId);
    if (!v || !a) return view('<p>Vulnerability not found. <a href="#/register">Risk register</a></p>');
    const s0 = site(); const vs = D.sites.find(x => x.id === a.siteId) || s0;
    const mat = matLevel(vs); const r = S.score(a, v), sla = S.slaFor(r.level, mat, v.found);
    const k = KEV[v.cve], ctl = G.isController(a);
    const advs = (v.advisories && v.advisories.length ? v.advisories : F.advisoriesFor(v.cve).map(x => ({ id: x.id, t: x.t, u: x.u }))).slice(0, 6);
    const comps = G.compensating(a, v, r.level, mat || 'Reasonably');
    view(`<p><a href="#/asset/${esc(a.id)}">← ${esc(a.name)}</a></p>
      <div class="row"><h1>${esc(v.cve || 'Vulnerability')}</h1>${pill(r)}${v.kev ? '<span class="tag kev">KEV</span>' : ''}${v.rescored ? `<span class="tag chg">re-scored ${esc(v.rescored.at)}</span>` : ''}<span class="right row"><button id="ev">Edit</button><a class="btn" href="${calcFromVuln(a, v)}">Open in calculator</a></span></div>
      <p class="mute">${esc(v.title)}</p>
      <div class="grid g2"><div class="card small"><h3 style="margin-top:0">Why this score</h3><table class="break"><tr><td>Asset importance (AIS) ${tip('ais')}</td><td>${r.ais.score}</td></tr><tr><td>Severity (VSS, CVSS ${esc(v.cvss || '—')}) ${tip('vss')}</td><td>${r.vss.score}</td></tr>
        <tr><td>Likelihood LF: ${esc(r.threat.why)}, reach ${r.reach} ${tip('lf')}</td><td>× ${r.lf}</td></tr><tr><td>Regulatory (RCIS) ${tip('rcis')}</td><td>× ${r.rcis}</td></tr><tr><td><b>Risk score</b>${r.floored ? ' (KEV floor)' : ''}</td><td>${r.score}</td></tr></table>
        <p>Status <b>${esc(v.status)}</b> ${tip('status')} · EPSS ${esc(v.epss === '' ? '—' : v.epss)} ${tip('epss')} · owner ${esc(v.owner || '—')}</p>
        <p>${sla.containBy ? `Contain by <b>${sla.containBy}</b> · ` : ''}${sla.remediateBy ? `Fix by <b>${sla.remediateBy}</b>` : 'Fix at lifecycle/next window'} <span class="mute">(${esc(r.level)} × ${esc(mat || 'Reasonably')} Secured)</span></p>${disc()}
        ${v.rescored ? `<p class="small">Re-scored ${esc(v.rescored.at)}: ${esc(v.rescored.why)} (${esc(v.rescored.fromLevel)} ${v.rescored.from} → ${esc(v.rescored.toLevel)} ${v.rescored.to}).</p>` : ''}</div>
      <div class="card small"><h3 style="margin-top:0">Sources</h3>
        ${advs.length ? advs.map(x => `<div><a href="${esc(x.u)}" target="_blank" rel="noopener">${esc(x.id)}</a> ${esc(x.t)}</div>`).join('') : '<p class="mute">No CISA ICS advisory lists this CVE in the nightly feed.</p>'}
        ${v.cve ? `<div style="margin-top:6px"><a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve)}" target="_blank" rel="noopener">NVD entry</a>${k ? ' · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + esc(v.cve) + '" target="_blank" rel="noopener">CISA KEV entry</a>' : ''}</div>` : ''}
        ${k ? `<div class="note" style="margin-top:8px"><b>CISA KEV required action</b> (federal due date ${esc(k[4] || '—')}${k[3] ? ', used in ransomware' : ''}): ${esc(k[6] || 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.')}</div>` : ''}</div></div>
      <h2>Fix guidance ${tip('fix')}</h2>
      ${ctl ? `<div class="note warnbox">${esc(G.MW_CAVEAT)}</div>` : ''}
      <div class="grid g2" style="margin-top:10px"><div class="card"><h3 style="margin-top:0">1 · What the vendor says</h3><div id="vfix" class="small mute">${advs.length ? 'Loading vendor remediation…' : 'No advisory text available. Check the vendor\'s security portal and the NVD entry for the fix.'}</div></div>
      <div class="card"><h3 style="margin-top:0">2 · If you can't patch yet: OT-safe compensating controls</h3><p class="small mute">Tick what's in place (or planned) and add it to the record. Then set status to <b>Contained</b>.</p>
        <div id="comps">${comps.map((c, i) => `<label class="inl" style="align-items:flex-start;margin:8px 0"><input type="checkbox" data-c="${i}" style="margin-top:3px"><span><b>${esc(c.title)}</b><br><span class="small">${esc(c.how)}</span><br><span class="small mute">Why: ${esc(c.why)}</span></span></label>`).join('')}</div>
        <div class="row"><button class="pri" id="addC">Add ticked to compensating controls</button><label class="inl small"><input type="checkbox" id="setC"> and set status to Contained</label></div><div id="cMsg" class="small"></div>
        <p class="small"><b>Expected at ${esc(mat || 'Reasonably')} Secured:</b> ${esc(S.COMP_CONTROLS[mat || 'Reasonably'])}</p>${disc()}</div></div>
      <div class="card small" style="margin-top:12px"><b>Recorded compensating controls:</b> ${esc(v.compensating || '—')}<br><b>Decision:</b> ${esc(v.decision || '—')}</div>`);
    $('#ev').onclick = () => editVuln(v, a);
    $('#addC').onclick = () => {
      const picked = [...document.querySelectorAll('#comps [data-c]')].filter(c => c.checked).map(c => comps[+c.dataset.c].title);
      if (!picked.length) { $('#cMsg').textContent = 'Tick at least one control.'; return; }
      const line = today() + ': ' + picked.join('; ') + '.';
      v.compensating = v.compensating ? v.compensating + '\n' + line : line;
      if ($('#setC').checked && v.status === 'Open') v.status = 'Contained';
      save(); route();
    };
    if (advs.length) F.loadFixes().then(fx => {
      const el = $('#vfix'); if (!el) return;
      const parts = advs.map(x => {
        const g = G.groupFixes(fx[x.id], v.cve);
        const sec = (cls, title, list) => list.length ? `<div class="fixsec ${cls}"><b>${title}</b>${list.map(f => `<p style="margin:4px 0">${esc(f.x)}${f.u ? ` <a href="${esc(f.u)}" target="_blank" rel="noopener">link</a>` : ''}</p>`).join('')}</div>` : '';
        const body = sec('nf', 'No fix available / planned', g.none) + sec('vf', 'Vendor fix', g.vendor_fix) + sec('mi', 'Mitigations & workarounds', g.mitigation.concat(g.workaround)) + sec('mi', 'Vendor general recommendations', g.general);
        return `<div style="margin-bottom:10px"><a href="${esc(x.u)}" target="_blank" rel="noopener"><b>${esc(x.id)}</b></a> <span class="mute">${esc(x.t)}</span>${body || '<p class="mute">No remediation text in this advisory; open the link.</p>'}</div>`;
      });
      el.classList.remove('mute'); el.innerHTML = parts.join('') + disc(ctl ? 'Controller updates need a maintenance window.' : '');
    });
  }

  // ---------- help ----------
  function help() {
    view(H.html());
    document.querySelectorAll('.toc a').forEach(l => l.onclick = e => { e.preventDefault(); const t = document.getElementById(l.getAttribute('href').slice(1)); t && t.scrollIntoView({ behavior: 'smooth' }); });
  }

  // ---------- data / settings ----------
  function settings() {
    const m = F.meta;
    view(`<div class="row"><h1>Data</h1>${tip('data')}</div><div class="grid g2"><div class="card"><h2 style="margin-top:0">Backup & restore</h2><p class="small mute">Everything is stored in this browser only (localStorage). Export a JSON backup to move between computers or share with a teammate.${D.ui.lastBackup ? ' Last export: ' + esc(D.ui.lastBackup) + '.' : ' <b style="color:#f5d48a">No backup exported yet.</b>'}</p>
      <div class="row"><button class="pri" id="exp">Export JSON backup</button><label class="btn" style="margin:0;color:var(--ink)">Restore from JSON<input type="file" id="imp" accept=".json" hidden></label></div><div id="im" class="small"></div>
      <h2>Reset</h2><div class="row"><button id="smp">Reload sample plant</button><button class="danger" id="clr">Start empty</button></div>
      <h2>Privacy: CVE look-ups</h2>
      <label class="switch"><input type="checkbox" id="fo" ${D.settings.feedsOnly ? 'checked' : ''}> Use only the nightly feeds (no live look-ups) ${tip('feedsOnly')}</label>
      <p class="small ${D.settings.feedsOnly ? 'mute' : ''}" style="${D.settings.feedsOnly ? '' : 'color:#f5d48a'}">${D.settings.feedsOnly ? 'On: Look up reads KEV, EPSS and CVSS from data files hosted with this site. Nothing about your equipment or CVEs leaves the browser.' : 'Off: Look up also sends the CVE ID to api.first.org (EPSS) and services.nvd.nist.gov (CVSS). Those services can see which CVEs you are tracking.'}</p>
      <h2>Alerts</h2><label class="switch"><input type="checkbox" id="sl" ${D.settings.showLow ? 'checked' : ''}> Show Low-confidence matches on the dashboard and badge ${tip('confidence')}</label>
      <div class="row" style="margin-top:8px"><button id="undis">Restore ${Object.keys(D.feed.dismissed).length} dismissed matches</button><button id="rematch">Re-run matching now</button></div><div id="am" class="small"></div></div>
      <div class="card small"><h2 style="margin-top:0">Threat data</h2>
      ${F.ok() ? `<p>Nightly feeds loaded from <code>data/</code>, built <b>${esc(m.updated)}</b> by the GitHub Action.</p><table><tr><td>CISA KEV</td><td>catalog ${esc(m.kev.version)} · ${esc(m.kev.count)} CVEs</td></tr><tr><td>FIRST EPSS</td><td>scores of ${esc(String(m.epss.date).slice(0, 10))} · ${esc(m.epss.count)} CVEs (${esc(m.epss.scope)})</td></tr><tr><td>CISA ICS advisories</td><td>${m.ics ? esc(m.ics.count) + ' advisories, newest ' + esc(m.ics.newest) : '—'} (CSAF)</td></tr></table>`
        : `<p>Nightly feeds not loaded (${esc(F.error || F.status)}). Using the bundled CISA KEV snapshot: catalog <b>${esc(KEV_META.version)}</b> (${esc(KEV_META.count)} CVEs).</p>`}
      <button id="rek">Re-check KEV/EPSS on all vulnerabilities</button> <span id="rkm" class="mute"></span>
      <h2>About</h2><p>OT Risk v0.2 is a test build of the v2 scoring framework from <i>Securing the Shop Floor</i>. It is a static app with no backend and no accounts, and it does no network scanning. Scores, deadlines, loss estimates and fix guidance are decision support, not engineering advice; validate with the OEM and process safety.</p></div></div>`);
    $('#exp').onclick = () => { D.ui.lastBackup = today(); save(); download('otrisk-backup-' + today() + '.json', JSON.stringify(D, null, 1), 'application/json'); };
    $('#imp').onchange = e => e.target.files[0].text().then(t => { try { const j = JSON.parse(t); if (!j.sites || !j.assets) throw 0; D = migrate(j); save(); processFeeds(); $('#im').textContent = 'Restored ✓'; renderSiteSel(); } catch (x) { $('#im').textContent = 'Not an OT Risk backup file.'; } });
    $('#smp').onclick = () => { if (confirm('Replace current data with the sample plant?')) { D = migrate(SAMPLE_DATA()); save(); processFeeds(); location.hash = '#/'; route(); } };
    $('#clr').onclick = () => { if (confirm('Delete all data in this browser and start empty?')) { D = migrate({ version: 1, company: { name: 'My Company', industry: '', hq: '', contact: '' }, sites: [{ id: 's1', name: 'Plant 1', location: '', headcount: '', notes: '', maturity: Array(9).fill(0) }], activeSiteId: 's1', assets: [], vulns: [] }); save(); processFeeds(); location.hash = '#/company'; route(); } };
    $('#fo').onchange = e => { D.settings.feedsOnly = e.target.checked; save(); settings(); };
    $('#sl').onchange = e => { D.settings.showLow = e.target.checked; save(); renderFeedStat(); };
    $('#undis').onclick = () => { D.feed.dismissed = {}; save(); processFeeds(); settings(); };
    $('#rematch').onclick = () => { processFeeds(); $('#am').textContent = MATCHES.length + ' possible matches across all sites (' + openMatches().length + ' open at the current confidence setting).'; };
    $('#rek').onclick = () => {
      const before = D.feed.changes.length; let n = 0;
      if (!F.ok()) D.vulns.forEach(v => { const k = !!KEV[v.cve]; if (k !== v.kev) { v.kev = k; n++; } });
      processFeeds(); save(); $('#rkm').textContent = F.ok() ? (D.feed.changes.length - before) + ' re-scored' : n + ' changed';
    };
  }

  route();
  F.load().then(() => { processFeeds(); const h = location.hash.replace(/^#\/?/, '').split('/')[0]; if (['', 'alerts', 'vuln', 'asset', 'assets', 'settings'].includes(h) && !$('#modal:not(.hidden)')) route(); });
})();
