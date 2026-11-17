// OT Risk – fix guidance helpers: vendor remediation grouping + OT-safe compensating controls.
// Decision support only. Not engineering advice; validate with the OEM and process safety.
(function (g) {
  const DISCLAIMER = 'Decision support, not engineering advice. Validate with the OEM and your process-safety owner before changing anything.';
  const MW_CAVEAT = 'Controller caveat: firmware updates, patches, reboots and config changes on PLCs, drives, robots, HMIs and other controllers belong in a planned maintenance window with the process in a safe state, a verified backup of the program/config, a tested rollback, and operations sign-off.';
  const CONTROLLER_RE = /plc|controller|rtu|drive|vfd|robot|hmi|comm|cpu|i\/o|safety|dcs|relay|panel|module|processor|skid/i;
  const WINDOWS_RE = /windows|win\s?\d|server|workstation|ews|scada|historian|mes|jump|pc/i;
  const isController = a => !!a && (['L0', 'L1'].includes(a.purdue) || (a.purdue === 'L2' && CONTROLLER_RE.test(a.type || '')) || CONTROLLER_RE.test(a.type || '') && !WINDOWS_RE.test(a.type || ''));
  const KIND_LABEL = { vendor_fix: 'Vendor fix', mitigation: 'Mitigation', workaround: 'Workaround', none_available: 'No fix available', no_fix_planned: 'No fix planned', general: 'Vendor general recommendation' };

  // fixes: [{k, x, u, c?}] from data/ics-fixes.json for one advisory; cve narrows to entries for that CVE.
  function groupFixes(fixes, cve) {
    const out = { vendor_fix: [], mitigation: [], workaround: [], none: [], general: [] };
    for (const f of fixes || []) {
      if (cve && f.c && f.c.length && !f.c.includes(cve)) continue;
      const k = f.k === 'none_available' || f.k === 'no_fix_planned' ? 'none' : (out[f.k] ? f.k : 'mitigation');
      out[k].push(f);
    }
    return out;
  }

  // OT-safe compensating controls for when patching can't happen yet.
  // asset: {type, purdue, vendor, model}; v: {title, reach, kev}; level: risk level; maturity: Poorly|Reasonably|Highly
  function compensating(asset, v, level, maturity) {
    asset = asset || {}; v = v || {};
    const t = (v.title || '') + ' ' + (v.cve || '');
    const ctl = isController(asset), win = WINDOWS_RE.test((asset.type || '') + ' ' + (asset.model || '') + ' ' + (asset.vendor || ''));
    const list = [];
    const add = (id, title, how, why) => list.push({ id, title, how, why });
    add('segment', 'Restrict who can reach it (segmentation / ACL)',
      `Allow only named engineering/HMI hosts to talk to ${asset.name || 'this asset'}${asset.ip ? ' (' + asset.ip + ')' : ''} on the ports it needs; block everything else at the cell/zone firewall or switch ACL. Log denies.`,
      'Most ICS exploits need network reach. Cutting reach lowers R (reachability) in the score.');
    if (+v.reach === 3 || /remote|vpn|internet|cellular|modem|default (admin|password)|credential/i.test(t + ' ' + (asset.notes || '')))
      add('remote', 'Lock down remote access',
        'Remove direct internet/vendor-modem paths. Route vendor access through the OT DMZ jump host with MFA, named accounts, session recording, and access enabled only for scheduled sessions.',
        'Remote paths are how most opportunistic attacks reach OT.');
    if (/web|http|ftp|telnet|snmp|smb|rdp|remote desktop|ssh|dns|upnp|opc|service|server/i.test(t))
      add('service', 'Disable the vulnerable service if the process doesn\'t need it',
        `Turn off the affected service/port (${(t.match(/web server|http|ftp|telnet|snmp|smbv?1?|rdp|remote desktop|ssh|upnp|opc ua|opc/ig) || ['the affected service']).slice(0, 3).join(', ')}) or block it at the firewall. Confirm with the OEM and controls engineer that operations don't depend on it.`,
        'Removes the attack surface without touching firmware.');
    if (/password|credential|authentication|default/i.test(t))
      add('creds', 'Change default / shared credentials',
        'Set unique strong passwords, remove unused accounts, and store them in the plant password vault. Enable any built-in access-protection levels.',
        'Default and shared passwords are the easiest way in.');
    if (ctl)
      add('protect', 'Use the controller\'s own protection features',
        'Keep the physical mode switch in RUN (not REMOTE/PROG) outside of maintenance, and enable the controller\'s program/know-how/access protection and any secure-protocol option (e.g. CIP Security, S7 access levels) the OEM supports.',
        'Blocks remote program changes even if the network is reached.');
    if (win || !ctl)
      add('allowlist', 'Application allowlisting & device control',
        'Enable allowlisting (e.g. AppLocker/WDAC or the OT vendor\'s qualified tool), block USB mass storage except approved devices, and remove local admin rights for operators.',
        'Stops malware from running even if the host is reachable.');
    if (win && /windows 7|win7|xp|2008|2012|eol|end of life/i.test((asset.model || '') + ' ' + (asset.firmware || '')))
      add('eol', 'Isolate unsupported Windows',
        'Treat as end-of-life: no internet or email, no domain admin logons, RDP/SMBv1 disabled or limited to the jump host, and a funded replacement date in the risk register.',
        'No more security patches are coming for this OS.');
    add('monitor', 'Monitor for exploitation',
      'Add a passive OT IDS signature/alert for this CVE where available, alert on new connections to the asset, and log controller mode/program changes. Review weekly until fixed.',
      'If prevention fails, you find out fast.');
    add('backup', 'Verified offline backup',
      `Keep a current, tested offline copy of the ${ctl ? 'controller program, configuration and firmware file' : 'system image and configuration'} so you can restore quickly.`,
      'Turns a bad day into a short outage.');
    if ((level === 'Critical' || v.kev) && maturity === 'Poorly')
      add('isolate', 'Consider temporary isolation',
        'If the process allows, disconnect the asset from shared networks (or put it behind a dedicated firewall) until the fix is installed. Agree on the impact with operations first.',
        'At Poorly Secured sites the framework defaults to isolation for Critical/KEV items.');
    add('exception', 'Record the exception',
      'If the fix waits for a shutdown, record the compensating controls, owner and an expiry date in the risk register so it gets reviewed.',
      'Keeps the risk visible and owned.');
    return list;
  }

  g.OTGuide = { DISCLAIMER, MW_CAVEAT, KIND_LABEL, isController, groupFixes, compensating };
  if (typeof module !== 'undefined') module.exports = g.OTGuide;
})(typeof window !== 'undefined' ? window : globalThis);
