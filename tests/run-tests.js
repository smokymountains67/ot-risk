// Run: node tests/run-tests.js   (no dependencies; uses data/*.json if present)
const assert = require('assert');
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const S = require(path.join(root, 'js/scoring.js'));
const M = require(path.join(root, 'js/matcher.js'));
const G = require(path.join(root, 'js/guidance.js'));
let pass = 0; const t = (name, fn) => { try { fn(); pass++; console.log('ok  ', name); } catch (e) { console.error('FAIL', name, '\n   ', e.message); process.exitCode = 1; } };

// ---- scoring (Framework v2 worked examples) ----
t('paint-line PLC CVE-2021-22681 = 57.8 Critical', () => {
  const r = S.score({ crit: { op: 3, sa: 2, rd: 3, rc: 2 }, purdue: 'L1' }, { cvss: 9.8, kev: true, epss: 0.6363, reach: 2, rcis: 1.2 });
  assert.strictEqual(r.score, 57.8); assert.strictEqual(r.level, 'Critical');
});
t('Win7 EWS BlueKeep = 40 High', () => {
  const r = S.score({ crit: { op: 2, sa: 2, rd: 2, rc: 1 }, purdue: 'L2' }, { cvss: 9.8, kev: true, epss: 0.99, reach: 3, rcis: 1.0 });
  assert.strictEqual(r.score, 40); assert.strictEqual(r.level, 'High');
});
t('reachable KEV is floored at High', () => {
  const r = S.score({ crit: { op: 1, sa: 1, rd: 1, rc: 1 }, purdue: 'L4' }, { cvss: 5, kev: true, reach: 2, rcis: 1 });
  assert.ok(r.floored); assert.strictEqual(r.level, 'High');
});
t('EPSS crossing 0.10 raises threat tier', () => {
  assert.strictEqual(S.threat(false, 0.09).t, 1); assert.strictEqual(S.threat(false, 0.1).t, 2); assert.strictEqual(S.threat(true, 0).t, 3);
});
t('SLA dates', () => { const s = S.slaFor('Critical', 'Reasonably', '2026-11-01'); assert.strictEqual(s.containBy, '2026-11-04'); assert.strictEqual(s.remediateBy, '2026-12-01'); });

// ---- version ranges ----
const R = (e, fw, pn) => M.parseRange(e, pn).test(fw);
t('vers:intdot/<4.3.8', () => { assert.strictEqual(R('vers:intdot/<4.3.8', '4.3.7'), true); assert.strictEqual(R('vers:intdot/<4.3.8', '4.3.8'), false); });
t('<= 1.2.1.23 and V-prefixed firmware', () => { assert.strictEqual(R('<= 1.2.1.23', 'V1.2.1.20'), true); assert.strictEqual(R('<V2.2.28', 'V2.0.20'), true); assert.strictEqual(R('<V2.2.28', '3.0'), false); });
t('range with lower bound', () => { assert.strictEqual(R('>=R1.02.00|<R1.02.02', 'R1.02.01'), true); assert.strictEqual(R('>=R1.02.00|<R1.02.02', 'R1.01.09'), false); });
t('all versions', () => { assert.strictEqual(R('vers:all/*', 'anything'), true); });
t('"and prior" in product name', () => { assert.strictEqual(R('', '33.011', 'Armor GuardLogix: Versions 33 and prior'), true); });
t('unknown text -> null', () => { assert.strictEqual(R('<=LG', '1.0'), null); assert.strictEqual(R('PM554-TP-ETH', '1.0'), null); });
t('exact version prefix', () => { assert.strictEqual(R('2.08', '2.08'), true); assert.strictEqual(R('13', '13.0'), true); assert.strictEqual(R('2.08', '2.09'), false); });

// ---- vendor normalisation ----
t('vendor aliases', () => {
  assert.strictEqual(M.normVendor('Allen-Bradley'), 'rockwell automation');
  assert.strictEqual(M.normVendor('Mitsubishi Electric Corporation'), 'mitsubishi electric');
  assert.deepStrictEqual(M.vendorKeys('Dell / Microsoft'), ['microsoft']);
  assert.deepStrictEqual(M.vendorKeys('Generic'), []);
});

// ---- matcher on a synthetic feed ----
const feed = {
  kev: { 'CVE-2099-0001': ['2099-01-01', 'Rockwell Automation', '1756-EN2T', false, '2099-01-21', 'Test KEV', 'Apply updates'], 'CVE-2099-0100': ['2099-01-02', 'Microsoft', 'Windows', false, '', 'Win bug', ''] },
  epss: { 'CVE-2099-0001': [0.5, 0.99] },
  ics: { adv: [
    { id: 'ICSA-99-001-01', t: 'Rockwell Automation Comm Modules', d: '2099-01-01', r: '2099-01-01', u: 'u1', v: ['Rockwell Automation'], p: [['Rockwell Automation', '1756-EN2T Series D', '<= 11.002'], ['Rockwell Automation', '1756-EN2TR', '<=11.002']], c: ['CVE-2099-0001', 'CVE-2099-0002'], s: { 'CVE-2099-0001': 9.8 } },
    { id: 'ICSA-99-002-01', t: 'Rockwell PanelView 5510', d: '2099-01-02', r: '2099-01-02', u: 'u2', v: ['Rockwell Automation'], p: [['Rockwell Automation', 'PanelView 5510', '<5.002']], c: ['CVE-2099-0003'], s: {} },
    { id: 'ICSA-99-003-01', t: 'Siemens S7-1500', d: '2099-01-03', r: '2099-01-03', u: 'u3', v: ['Siemens'], p: [['Siemens', 'SIMATIC S7-1500 CPU 1515-2 PN (6ES7515-2AM01-0AB0)', 'vers:intdot/<2.9.2']], c: ['CVE-2099-0004'], s: {} },
  ] },
};
const A = (id, vendor, model, firmware) => ({ id, vendor, model, firmware, name: id });
t('catalog number + firmware in range = High', () => {
  const m = M.matchAsset(A('x1', 'Allen-Bradley', '1756-EN2T', '10.010'), feed).find(x => x.advId === 'ICSA-99-001-01');
  assert.ok(m); assert.strictEqual(m.confidence, 'High'); assert.ok(m.kevCves.includes('CVE-2099-0001')); assert.match(m.reason, /inside the affected range/);
});
t('firmware newer than range = Low with reason', () => {
  const m = M.matchAsset(A('x2', 'Rockwell Automation', '1756-EN2T', '12.001'), feed).find(x => x.advId === 'ICSA-99-001-01');
  assert.strictEqual(m.confidence, 'Low'); assert.match(m.reason, /outside the affected range/);
});
t('no firmware = Medium', () => {
  const m = M.matchAsset(A('x3', 'Rockwell Automation', '1756-EN2T', ''), feed).find(x => x.advId === 'ICSA-99-001-01');
  assert.strictEqual(m.confidence, 'Medium');
});
t('same family, different model number = no match', () => {
  const ms = M.matchAsset(A('x4', 'Rockwell Automation', 'PanelView 800', '4.0'), feed);
  assert.ok(!ms.some(x => x.advId === 'ICSA-99-002-01'));
});
t('Siemens CPU exact = High; older CPU fw', () => {
  const m = M.matchAsset(A('x5', 'Siemens', 'S7-1500 CPU 1515-2 PN', '2.8.1'), feed).find(x => x.advId === 'ICSA-99-003-01');
  assert.strictEqual(m.confidence, 'High');
});
t('KEV grouped match for Windows is Low', () => {
  const m = M.matchAsset(A('x6', 'Microsoft', 'Windows 7 SP1', 'SP1'), feed).find(x => x.type === 'kev');
  assert.ok(m); assert.strictEqual(m.confidence, 'Low'); assert.deepStrictEqual(m.cves, ['CVE-2099-0100']);
});
t('generic vendor gives nothing', () => { assert.strictEqual(M.matchAsset(A('x7', 'Generic', 'MES', '1.0'), feed).length, 0); });
t('matchAll hides matches whose CVEs are all recorded', () => {
  const assets = [A('x1', 'Rockwell Automation', '1756-EN2T', '10.010')];
  assert.strictEqual(M.matchAll(assets, [{ assetId: 'x1', cve: 'CVE-2099-0001' }], feed)[0].missing.length, 1);
  assert.strictEqual(M.matchAll(assets, [{ assetId: 'x1', cve: 'CVE-2099-0001' }, { assetId: 'x1', cve: 'CVE-2099-0002' }], feed).filter(m => m.advId === 'ICSA-99-001-01').length, 0);
});
t('feedChanges flags KEV add and EPSS change', () => {
  const ch = M.feedChanges([{ id: 'v1', cve: 'CVE-2099-0001', kev: false, epss: 0.01 }, { id: 'v2', cve: 'CVE-2099-0009', kev: false, epss: '' }], Object.assign({ kevAuthoritative: true }, feed));
  assert.strictEqual(ch.length, 1); assert.strictEqual(ch[0].kevTo, true); assert.strictEqual(ch[0].epssTo, 0.5);
});

// ---- guidance ----
t('controller gets maintenance-window caveat + protection control', () => {
  const a = { type: 'PLC', purdue: 'L1', name: 'P' };
  assert.ok(G.isController(a));
  assert.ok(G.compensating(a, { title: 'web server overflow' }, 'Critical', 'Poorly').some(c => c.id === 'protect'));
  assert.ok(G.compensating(a, { title: 'web server overflow', kev: true }, 'Critical', 'Poorly').some(c => c.id === 'isolate'));
  assert.ok(!G.isController({ type: 'Engineering workstation', purdue: 'L2' }));
});

// ---- real feed smoke test (if data/ exists) ----
const dataDir = path.join(root, 'data');
if (fs.existsSync(path.join(dataDir, 'ics.json'))) {
  const real = { kev: require(path.join(dataDir, 'kev.json')).kev, epss: require(path.join(dataDir, 'epss.json')).epss, ics: require(path.join(dataDir, 'ics.json')) };
  t('real feed: sample 1756-EN2T fw 10.010 has High matches', () => {
    const ms = M.matchAsset(A('r1', 'Rockwell Automation', '1756-EN2T', '10.010'), real);
    assert.ok(ms.filter(m => m.confidence === 'High').length >= 3);
  });
  t('real feed sizes sane', () => { assert.ok(real.ics.adv.length > 3000); assert.ok(Object.keys(real.kev).length > 1500); assert.ok(Object.keys(real.epss).length > 10000); });
}
console.log(`\n${pass} passed${process.exitCode ? ', some FAILED' : ''}`);
