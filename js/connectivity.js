// OT Risk – per-asset network connectivity: vocabularies, import prefill (marked as guesses),
// and helpers for the dashboard tile and the network view. Browser (window.OTConn) + Node.
(function (g) {
  const S = g.OTScore || (typeof require !== 'undefined' ? require('./scoring.js') : null);
  const METHODS = { ethernet: 'Wired Ethernet', wifi: 'Wi-Fi', serial: 'Serial / fieldbus via gateway', usb: 'USB-only' };
  const FIREWALL = { yes: 'Yes', no: 'No', unknown: 'Unknown' };
  const PROTOCOLS = ['EtherNet/IP (CIP)', 'Modbus/TCP', 'Modbus RTU', 'S7comm', 'PROFINET', 'PROFIBUS', 'BACnet/IP', 'OPC UA', 'OPC DA', 'DNP3', 'IEC 60870-5-104', 'MQTT',
    'DeviceNet', 'CC-Link', 'OMRON FINS', 'MELSEC', 'GE SRTP', 'Niagara Fox', 'HTTP/HTTPS', 'SSH', 'Telnet', 'FTP', 'RDP', 'VNC', 'SMB', 'SNMP'];
  const PORT_PROTO = {
    44818: 'EtherNet/IP (CIP)', 2222: 'EtherNet/IP (CIP)', 502: 'Modbus/TCP', 102: 'S7comm', 34962: 'PROFINET', 34963: 'PROFINET', 34964: 'PROFINET',
    47808: 'BACnet/IP', 4840: 'OPC UA', 135: 'OPC DA', 20000: 'DNP3', 2404: 'IEC 60870-5-104', 1883: 'MQTT', 8883: 'MQTT', 9600: 'OMRON FINS', 5007: 'MELSEC',
    18245: 'GE SRTP', 1911: 'Niagara Fox', 4911: 'Niagara Fox', 80: 'HTTP/HTTPS', 443: 'HTTP/HTTPS', 8080: 'HTTP/HTTPS', 22: 'SSH', 23: 'Telnet', 21: 'FTP',
    3389: 'RDP', 5900: 'VNC', 445: 'SMB', 139: 'SMB', 161: 'SNMP', 5938: 'TeamViewer',
  };
  const REMOTE_PORTS = { 5938: 'TeamViewer', 3389: 'RDP', 5900: 'VNC' };
  const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i.test(ip || '');
  const subnet24 = ip => { const m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(ip || ''); return m ? m[1] + '.0/24' : ''; };

  // n: parsed import row {ip, ports:[{port}], purdue, protocols:[], connType, remote, vlan, switchPort, gateway, method}
  function fromImport(n) {
    const c = { type: '', method: '', switchPort: '', vlan: '', gateway: '', remote: '', firewall: 'unknown', fwNote: '', protocols: [], verified: '', guessed: [] };
    const set = (k, v, guessed) => { if (v == null || v === '' || (Array.isArray(v) && !v.length)) return; c[k] = v; if (guessed && !c.guessed.includes(k)) c.guessed.push(k); };
    // explicit values from the file (CSV columns / collector) are not guesses
    set('type', normType(n.connType)); set('vlan', n.vlan); set('switchPort', n.switchPort); set('gateway', n.gateway); set('remote', n.remote);
    set('method', normMethod(n.method));
    if (n.protocols && n.protocols.length) set('protocols', n.protocols.map(normProto).filter(Boolean));
    // inferred values are guesses
    const ports = (n.ports || []).map(p => +p.port || +p);
    if (!c.protocols.length && ports.length) set('protocols', [...new Set(ports.map(p => PORT_PROTO[p]).filter(Boolean))], true);
    if (!c.method && n.ip) set('method', 'ethernet', true);
    if (!c.type && n.ip) {
      if (!isPrivate(n.ip)) set('type', 'internet', true);
      else if (['L4', 'L5'].includes(n.purdue)) set('type', 'it', true);
      else set('type', 'plant', true);
    }
    if (!c.remote) { const rp = ports.find(p => REMOTE_PORTS[p] && p === 5938); if (rp) set('remote', REMOTE_PORTS[rp] + ' (port open)', true); }
    if (!c.vlan && n.ip && isPrivate(n.ip)) set('vlan', 'subnet ' + subnet24(n.ip), true);
    return c;
  }
  function normType(v) {
    v = String(v || '').toLowerCase(); if (!v) return '';
    if (/air|none|standalone|not networked|offline/.test(v)) return 'airgap';
    if (/internet|public/.test(v)) return 'internet';
    if (/cell|modem|lte|4g|5g/.test(v)) return 'cellular';
    if (/vendor|remote|teamviewer|ewon|vpn/.test(v)) return 'vendor';
    if (/isolat|cell network|island/.test(v)) return 'cell';
    if (/\bit\b|corp|enterprise|business|routed/.test(v)) return 'it';
    if (/ot|plant|control|process/.test(v)) return 'plant';
    return '';
  }
  function normMethod(v) {
    v = String(v || '').toLowerCase(); if (!v) return '';
    if (/wi-?fi|wireless|wlan/.test(v)) return 'wifi'; if (/usb/.test(v)) return 'usb'; if (/serial|rs-?232|rs-?485|fieldbus|profibus|devicenet/.test(v)) return 'serial';
    if (/ether|wired|copper|fiber/.test(v)) return 'ethernet'; return '';
  }
  function normProto(p) {
    p = String(p || '').trim(); if (!p) return '';
    const l = p.toLowerCase().replace(/[^a-z0-9]/g, '');
    const hit = PROTOCOLS.find(x => x.toLowerCase().replace(/[^a-z0-9]/g, '').startsWith(l) || l.startsWith(x.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 5)));
    if (/^(enip|cip|ethernetip)/.test(l)) return 'EtherNet/IP (CIP)';
    if (/^s7/.test(l)) return 'S7comm';
    if (/^modbus(tcp)?$/.test(l)) return 'Modbus/TCP';
    return hit || p;
  }
  // Fill empty fields of an existing conn from an import, never overwriting what a person entered.
  function merge(existing, incoming) {
    if (!existing || !existing.type) return incoming;
    const out = Object.assign({}, existing, { guessed: (existing.guessed || []).slice() });
    for (const k of ['type', 'method', 'switchPort', 'vlan', 'gateway', 'remote']) if (!out[k] && incoming[k]) { out[k] = incoming[k]; if (incoming.guessed.includes(k)) out.guessed.push(k); }
    if ((!out.protocols || !out.protocols.length) && incoming.protocols.length) { out.protocols = incoming.protocols; if (incoming.guessed.includes('protocols')) out.guessed.push('protocols'); }
    return out;
  }
  const typeLabel = t => (S.CONN_TYPES[t] || { label: 'Not recorded' }).label;
  function exposure(asset) {
    const c = asset && asset.conn; if (!c) return null;
    const rr = S.connReach(c); if (!rr) return null;
    if (['internet', 'cellular', 'vendor'].includes(c.type)) return typeLabel(c.type);
    const remote = String(c.remote || '').trim();
    if (remote && !/^(none|n\/a|no)$/i.test(remote)) return 'Remote access: ' + remote;
    return null;
  }
  // Group assets for the network view: zone → gateway/parent → assets
  function topology(assets) {
    const byId = new Map(assets.map(a => [a.id, a]));
    const zones = new Map();
    for (const a of assets) {
      const z = a.zone || '(no zone)';
      if (!zones.has(z)) zones.set(z, new Map());
      const gw = (a.conn && a.conn.gateway) || '';
      const gwName = byId.has(gw) ? byId.get(gw).name : gw;
      const key = gwName || '(direct / not recorded)';
      if (!zones.get(z).has(key)) zones.get(z).set(key, []);
      zones.get(z).get(key).push(a);
    }
    return zones;
  }
  g.OTConn = { METHODS, FIREWALL, PROTOCOLS, PORT_PROTO, isPrivate, fromImport, merge, normType, normMethod, normProto, typeLabel, exposure, topology };
  if (typeof module !== 'undefined') module.exports = g.OTConn;
})(typeof window !== 'undefined' ? window : globalThis);
