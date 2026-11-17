// OT Risk – import parsers. All parsing happens in the browser; no network probing.
// Supported: Nmap XML (-oX), CSV (generic + common OT tool export headers), OT Risk collector JSON (otrisk.collector.v1).
(function (g) {
  // Port → OT protocol hints (used only to suggest type / Purdue level; user confirms)
  const PORT_HINTS = {
    102: { proto: 'S7comm (Siemens)', type: 'PLC', purdue: 'L1', vendor: 'Siemens' },
    502: { proto: 'Modbus/TCP', type: 'PLC / controller', purdue: 'L1' },
    44818: { proto: 'EtherNet/IP (CIP)', type: 'PLC / CIP device', purdue: 'L1' },
    2222: { proto: 'EtherNet/IP I/O', type: 'CIP I/O device', purdue: 'L1' },
    20000: { proto: 'DNP3', type: 'RTU / controller', purdue: 'L1' },
    47808: { proto: 'BACnet/IP', type: 'Building controller', purdue: 'L1' },
    4840: { proto: 'OPC UA', type: 'OPC UA server', purdue: 'L2' },
    1911: { proto: 'Niagara Fox', type: 'Building automation', purdue: 'L2' },
    4911: { proto: 'Niagara Fox TLS', type: 'Building automation', purdue: 'L2' },
    9600: { proto: 'OMRON FINS', type: 'PLC', purdue: 'L1', vendor: 'OMRON' },
    5007: { proto: 'MELSEC (Mitsubishi)', type: 'PLC', purdue: 'L1', vendor: 'Mitsubishi' },
    18245: { proto: 'GE SRTP', type: 'PLC', purdue: 'L1', vendor: 'GE' },
    1962: { proto: 'PCWorx (Phoenix Contact)', type: 'PLC', purdue: 'L1', vendor: 'Phoenix Contact' },
    789: { proto: 'Red Lion Crimson', type: 'HMI', purdue: 'L2', vendor: 'Red Lion' },
    2404: { proto: 'IEC 60870-5-104', type: 'RTU', purdue: 'L1' },
    3389: { proto: 'RDP', type: 'Windows host', purdue: 'L2' },
    5900: { proto: 'VNC', type: 'HMI / panel PC', purdue: 'L2' },
  };
  function guess(ports) {
    const hits = ports.map(p => PORT_HINTS[p.port]).filter(Boolean);
    if (!hits.length) return { type: 'Unknown', purdue: 'L3', protos: [] };
    const best = hits.find(h => h.purdue === 'L1') || hits[0];
    return { type: best.type, purdue: best.purdue, vendor: best.vendor || '', protos: hits.map(h => h.proto) };
  }
  function txt(el, sel) { const n = el.querySelector(sel); return n ? n.textContent.trim() : ''; }

  function parseNmapXML(xmlText) {
    const doc = new DOMParser().parseFromString(xmlText, 'application/xml');
    if (doc.querySelector('parsererror') || !doc.querySelector('nmaprun')) throw new Error('Not a valid Nmap XML file (expected <nmaprun>, from nmap -oX).');
    const out = [];
    doc.querySelectorAll('host').forEach(h => {
      const st = h.querySelector('status'); if (st && st.getAttribute('state') !== 'up') return;
      const a = { ip: '', mac: '', vendor: '', model: '', firmware: '', name: '', type: '', purdue: '', notes: [], ports: [] };
      h.querySelectorAll('address').forEach(ad => {
        const t = ad.getAttribute('addrtype');
        if (t === 'ipv4' || (t === 'ipv6' && !a.ip)) a.ip = ad.getAttribute('addr');
        if (t === 'mac') { a.mac = ad.getAttribute('addr'); a.vendor = ad.getAttribute('vendor') || ''; }
      });
      const hn = h.querySelector('hostnames hostname'); if (hn) a.name = hn.getAttribute('name');
      h.querySelectorAll('ports port').forEach(p => {
        const state = p.querySelector('state'); if (state && state.getAttribute('state') !== 'open') return;
        const sv = p.querySelector('service');
        a.ports.push({ port: +p.getAttribute('portid'), proto: p.getAttribute('protocol'), service: sv ? sv.getAttribute('name') : '', product: sv ? (sv.getAttribute('product') || '') : '', version: sv ? (sv.getAttribute('version') || '') : '' });
        // OT NSE script output (enip-info, s7-info, modbus-discover, bacnet-info)
        p.querySelectorAll('script').forEach(sc => {
          const id = sc.getAttribute('id'); const elem = k => { const e = sc.querySelector(`elem[key="${k}"]`); return e ? e.textContent.trim() : ''; };
          const out = sc.getAttribute('output') || '';
          const line = re => { const m = out.match(re); return m ? m[1].trim() : ''; };
          if (id === 'enip-info') {
            a.vendor = elem('Vendor') || line(/Vendor:\s*(.+)/) || a.vendor;
            a.model = elem('Product Name') || line(/Product Name:\s*(.+)/) || a.model;
            a.firmware = elem('Revision') || line(/Revision:\s*(.+)/) || a.firmware;
            a.type = a.type || (line(/Device Type:\s*(.+)/) || 'CIP device');
          } else if (id === 's7-info') {
            a.vendor = 'Siemens';
            a.model = elem('Module') || line(/Module:\s*(.+)/) || line(/Module Type:\s*(.+)/) || a.model;
            a.firmware = elem('Version') || line(/Version:\s*(.+)/) || a.firmware;
            a.name = a.name || line(/System Name:\s*(.+)/);
          } else if (id === 'modbus-discover') {
            const dev = line(/Device identification:\s*(.+)/); if (dev) a.model = a.model || dev;
          } else if (id === 'bacnet-info') {
            a.vendor = line(/Vendor Name:\s*(.+)/) || a.vendor; a.model = line(/Model Name:\s*(.+)/) || a.model;
            a.firmware = line(/Firmware:\s*(.+)/) || a.firmware;
          }
        });
      });
      const os = h.querySelector('os osmatch'); if (os) a.notes.push('OS guess: ' + os.getAttribute('name'));
      const clean = v => String(v || '').replace(/\s*\(\d+\)\s*$/, '').trim();
      a.vendor = clean(a.vendor); a.type = clean(a.type);
      const g2 = guess(a.ports);
      a.type = a.type || g2.type; a.purdue = g2.purdue; if (!a.vendor && g2.vendor) a.vendor = g2.vendor;
      if (g2.protos.length) a.notes.push('OT protocols: ' + g2.protos.join(', '));
      if (!a.model) { const pr = a.ports.find(p => p.product); if (pr) a.model = (pr.product + ' ' + pr.version).trim(); }
      a.notes.push('Open ports: ' + a.ports.map(p => p.port + '/' + p.proto + (p.service ? ' ' + p.service : '')).join(', '));
      a.notes = a.notes.join(' | '); a.name = a.name || a.ip; a.purdueGuessed = true;
      out.push(a);
    });
    return out;
  }

  function parseCSVText(text) {
    const rows = []; let row = [], f = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
      else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
      else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; }
      else f += c;
    }
    if (f.length || row.length) { row.push(f); rows.push(row); }
    return rows.filter(r => r.some(x => x.trim() !== ''));
  }
  // Header aliases cover typical exports from asset tools (names vary by product/version – map manually if needed)
  const ALIASES = {
    name: ['name', 'asset name', 'hostname', 'host name', 'device name', 'asset'],
    ip: ['ip', 'ip address', 'ipaddress', 'ipv4', 'address', 'ip addresses'],
    mac: ['mac', 'mac address', 'macaddress'],
    vendor: ['vendor', 'manufacturer', 'make'],
    model: ['model', 'product', 'product name', 'model name'],
    firmware: ['firmware', 'firmware version', 'fw', 'version', 'os version'],
    type: ['type', 'asset type', 'device type', 'category', 'class'],
    purdue: ['purdue', 'purdue level', 'level'],
    zone: ['zone', 'network zone', 'segment', 'cell', 'area', 'site area'],
    line: ['line', 'production line', 'process line'],
    vlan: ['vlan', 'vlan id', 'subnet', 'network'],
    switchPort: ['switch port', 'switch', 'switchport', 'port', 'access port'],
    gateway: ['gateway', 'parent', 'parent device', 'connected via', 'upstream'],
    connType: ['connection', 'connection type', 'connectivity', 'network type', 'exposure'],
    method: ['connection method', 'media', 'link type', 'interface'],
    remote: ['remote access', 'remote access path', 'remote'],
    protocols: ['protocols', 'protocol', 'ot protocols', 'industrial protocols'],
    owner: ['owner', 'asset owner', 'responsible'],
    cve: ['cve', 'cves', 'cve id', 'vulnerabilities'],
  };
  function normPurdue(v) {
    v = String(v || '').trim().toUpperCase().replace(/^LEVEL\s*/, 'L').replace(/^L?\s*/, 'L');
    if (/^L3\.5|DMZ/.test(v)) return 'L3.5';
    const m = v.match(/^L([0-5])/); return m ? 'L' + m[1] : '';
  }
  function parseCSV(text) {
    const rows = parseCSVText(text); if (rows.length < 2) throw new Error('CSV needs a header row and at least one data row.');
    const hdr = rows[0].map(h => h.trim().toLowerCase());
    const idx = {}; for (const k in ALIASES) idx[k] = hdr.findIndex(h => ALIASES[k].includes(h));
    if (idx.ip < 0 && idx.name < 0) throw new Error('CSV must have an IP or Name column. Found: ' + rows[0].join(', '));
    return rows.slice(1).map(r => {
      const get = k => idx[k] >= 0 ? (r[idx[k]] || '').trim() : '';
      const a = { name: get('name') || get('ip'), ip: get('ip'), mac: get('mac'), vendor: get('vendor'), model: get('model'), firmware: get('firmware'), type: get('type') || 'Unknown', purdue: normPurdue(get('purdue')), zone: get('zone') || get('vlan'), line: get('line'), owner: get('owner'), notes: 'Imported from CSV',
        vlan: get('vlan'), switchPort: get('switchPort'), gateway: get('gateway'), connType: get('connType'), method: get('method'), remote: get('remote'), protocols: get('protocols').split(/[;,|]+/).map(x => x.trim()).filter(Boolean), cves: (get('cve').match(/CVE-\d{4}-\d{4,}/gi) || []).map(x => x.toUpperCase()) };
      if (!a.purdue) { a.purdue = 'L3'; a.purdueGuessed = true; }
      return a;
    });
  }
  // Future on-site collector feed. See docs/COLLECTOR-SPEC.md
  function parseCollectorJSON(text) {
    const j = JSON.parse(text);
    if (j.schema !== 'otrisk.collector.v1' || !Array.isArray(j.assets)) throw new Error('Expected {"schema":"otrisk.collector.v1","assets":[...]}');
    return j.assets.map(x => ({ name: x.name || x.ip, ip: x.ip || '', mac: x.mac || '', vendor: x.vendor || '', model: x.model || '', firmware: x.firmware || '', type: x.type || 'Unknown', purdue: normPurdue(x.purdue) || 'L3', purdueGuessed: !x.purdue, zone: x.zone || '', ports: (x.ports || []).map(p => ({ port: +p.port || +p })), protocols: x.protocols || [], vlan: x.vlan || '', switchPort: x.switchPort || '', gateway: x.gateway || '', connType: x.connection || '', notes: 'Collector ' + (j.collector && j.collector.id || '') + ' (' + (j.collector && j.collector.method || 'passive') + ') at ' + (j.collectedAt || ''), cves: x.cves || [] }));
  }
  function detectAndParse(fileName, text) {
    const t = text.trim();
    if (t.startsWith('<')) return { kind: 'Nmap XML', assets: parseNmapXML(t) };
    if (t.startsWith('{')) return { kind: 'Collector JSON', assets: parseCollectorJSON(t) };
    return { kind: 'CSV', assets: parseCSV(t) };
  }
  g.OTImport = { parseNmapXML, parseCSV, parseCollectorJSON, detectAndParse, PORT_HINTS, normPurdue };
})(window);
