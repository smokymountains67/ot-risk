// Fictional sample plant. Company, sites, assets, IPs, owners and dollar figures are invented.
// CVE IDs, CVSS (NVD), KEV membership and EPSS values are real as of 15 Nov 2026.
window.SAMPLE_DATA = function () {
  const A = (id, siteId, name, type, vendor, model, firmware, ip, purdue, zone, crit, extra = {}) =>
    Object.assign({ id, siteId, name, type, vendor, model, firmware, ip, mac: '', purdue, zone, crit, owner: '', notes: '', source: 'sample', lastSeen: '2026-11-10' }, extra);
  const V = (id, assetId, cve, title, cvss, kev, epss, reach, rcis, status, extra = {}) =>
    Object.assign({ id, assetId, cve, title, cvss, kev, epss, publicExploit: false, reach, rcis, status, found: '2026-11-03', owner: '', decision: '', compensating: '', fair: null }, extra);
  return {
    version: 1,
    company: { name: 'Northfield Air Systems (fictional)', industry: 'HVAC equipment manufacturing – fans, dampers, energy-recovery units', hq: 'Northfield, USA', contact: '' },
    sites: [
      { id: 's2', name: 'Plant 2 – Fabrication & Paint', location: 'Northfield, USA', headcount: 410, notes: 'Powder-coat paint line with gas cure oven, 8 laser/punch cells, robotic weld area.', maturity: [2, 2, 2, 2, 2, 2, 2, 2, 1] },
      { id: 's1', name: 'Plant 1 – Fan Assembly', location: 'Riverton, USA', headcount: 260, notes: 'Final assembly and balancing. Flat network.', maturity: [1, 1, 1, 1, 2, 2, 1, 2, 1] },
    ],
    activeSiteId: 's2',
    assets: [
      A('a1', 's2', 'PL-PLC-01', 'PLC', 'Rockwell Automation', 'ControlLogix 1756-L71', '20.054', '10.20.10.10', 'L1', 'Paint Line', { op: 3, sa: 2, rd: 3, rc: 2 }, { owner: 'Controls Eng.', notes: 'Conveyor, booth and cure-oven sequencing.' }),
      A('a2', 's2', 'PL-ENET-01', 'Comm module', 'Rockwell Automation', '1756-EN2T', '10.010', '10.20.10.11', 'L1', 'Paint Line', { op: 3, sa: 2, rd: 3, rc: 1 }),
      A('a3', 's2', 'PL-HMI-01', 'HMI', 'Rockwell Automation', 'PanelView Plus 7', '12.0', '10.20.10.20', 'L2', 'Paint Line', { op: 2, sa: 1, rd: 2, rc: 1 }),
      A('a4', 's2', 'PL-OVEN-TC', 'Temperature controller', 'Watlow', 'F4T', '7.0', '10.20.10.30', 'L1', 'Paint Line', { op: 2, sa: 3, rd: 3, rc: 2 }),
      A('a5', 's2', 'PL-VFD-01', 'Drive', 'Rockwell Automation', 'PowerFlex 755', '14.002', '10.20.10.40', 'L0', 'Paint Line', { op: 2, sa: 2, rd: 2, rc: 1 }),
      A('a6', 's2', 'WC-PLC-01', 'PLC', 'Siemens', 'S7-1500 CPU 1515-2 PN', '2.8.1', '10.20.20.10', 'L1', 'Weld Cell', { op: 3, sa: 3, rd: 2, rc: 1 }),
      A('a7', 's2', 'WC-CP-01', 'Comm processor', 'Siemens', 'SIMATIC CP 1543-1', '2.0.20', '10.20.20.11', 'L1', 'Weld Cell', { op: 3, sa: 2, rd: 2, rc: 1 }),
      A('a8', 's2', 'WC-ROBOT-01', 'Robot controller', 'FANUC', 'R-30iB Plus', 'V9.30', '10.20.20.20', 'L1', 'Weld Cell', { op: 2, sa: 3, rd: 2, rc: 1 }),
      A('a9', 's2', 'LP-PLC-02', 'PLC', 'Rockwell Automation', 'CompactLogix 5380', '33.011', '10.20.30.10', 'L1', 'Laser/Punch', { op: 2, sa: 2, rd: 2, rc: 1 }),
      A('a10', 's2', 'UT-PLC-01', 'PLC/HMI', 'Unitronics', 'Vision V570', '9.8.65', '10.20.40.10', 'L1', 'Utilities', { op: 2, sa: 2, rd: 3, rc: 1 }, { notes: 'Compressed-air skid. Vendor cellular modem for remote support.' }),
      A('a11', 's2', 'SUP-EWS-01', 'Engineering workstation', 'Dell / Microsoft', 'Windows 7 SP1 – Studio 5000, RSLinx', 'Win7 SP1', '10.20.50.15', 'L2', 'Supervisory', { op: 2, sa: 2, rd: 2, rc: 1 }, { owner: 'Controls Eng.' }),
      A('a12', 's2', 'SUP-SCADA-01', 'SCADA server', 'Rockwell Automation', 'FactoryTalk View SE on Win Server 2016', '13.0', '10.20.50.20', 'L2', 'Supervisory', { op: 3, sa: 1, rd: 2, rc: 1 }),
      A('a13', 's2', 'SW-OT-CORE', 'Network switch', 'Cisco', 'IE-3400 (Stratix 5800)', '17.9.4', '10.20.50.2', 'L2', 'Supervisory', { op: 3, sa: 1, rd: 3, rc: 1 }),
      A('a14', 's2', 'OPS-HIST-01', 'Historian', 'Generic', 'Java-based historian / reporting', '4.2', '10.20.60.10', 'L3', 'Operations', { op: 1, sa: 1, rd: 2, rc: 2 }, { notes: 'Holds cure-oven temperature records used for quality and air-permit reporting.' }),
      A('a15', 's2', 'OPS-MES-01', 'MES server', 'Generic', 'MES', '2025.2', '10.20.60.20', 'L3', 'Operations', { op: 2, sa: 1, rd: 2, rc: 2 }),
      A('a16', 's2', 'DMZ-JUMP-01', 'Jump server', 'Microsoft', 'Windows Server 2022 RDS', '2022', '10.20.99.10', 'L3.5', 'OT DMZ', { op: 2, sa: 1, rd: 2, rc: 1 }),
      A('a17', 's2', 'DMZ-FW-01', 'Firewall', 'Fortinet', 'FortiGate 100F', '7.2.8', '10.20.99.1', 'L3.5', 'OT DMZ', { op: 3, sa: 1, rd: 3, rc: 1 }),
      A('a18', 's2', 'ERP-APP-01', 'ERP app server', 'Generic', 'ERP', '—', '10.10.5.20', 'L4', 'Enterprise', { op: 2, sa: 1, rd: 1, rc: 2 }),
      A('a19', 's1', 'FA-PLC-01', 'PLC', 'Allen-Bradley', 'MicroLogix 1400', '21.007', '10.30.10.10', 'L1', 'Assembly', { op: 3, sa: 2, rd: 3, rc: 1 }),
      A('a20', 's1', 'FA-BAL-PC', 'Balancing station PC', 'Generic', 'Windows 10 IoT', '1809', '10.30.10.50', 'L2', 'Assembly', { op: 2, sa: 1, rd: 2, rc: 1 }),
      A('a21', 's1', 'FA-HMI-01', 'HMI', 'Rockwell Automation', 'PanelView 800', '4.0', '10.30.10.20', 'L2', 'Assembly', { op: 2, sa: 1, rd: 2, rc: 1 }),
    ],
    vulns: [
      V('v1', 'a1', 'CVE-2021-22681', 'Logix controllers: insufficiently protected credentials allow unauthenticated connection', 9.8, true, 0.6363, 2, 1.2, 'Open', { owner: 'Controls Eng.', fair: { lef: [0.02, 0.05, 0.15], lm: [150000, 350000, 1200000] } }),
      V('v2', 'a1', 'CVE-2022-1161', 'ControlLogix: user program code can be modified without detection', 10.0, false, 0.0521, 2, 1.2, 'Open'),
      V('v3', 'a2', 'CVE-2023-3595', '1756-EN2*/EN3* comm modules: out-of-bounds write → RCE via crafted CIP', 9.8, false, 0.0553, 2, 1.0, 'Contained', { compensating: 'CIP traffic to module restricted to HMI + EWS by DMZ-FW-01 policy 14; IDS rule enabled.', decision: 'Firmware upgrade at Dec shutdown.' }),
      V('v4', 'a6', 'CVE-2020-15782', 'S7-1200/1500: memory protection bypass allows code execution', 9.8, false, 0.0518, 2, 1.0, 'Open'),
      V('v5', 'a7', 'CVE-2016-8562', 'SIMATIC CP 1543-1: improper privilege management', 7.5, true, 0.0361, 2, 1.0, 'Open'),
      V('v6', 'a10', 'CVE-2023-6448', 'Unitronics Vision: default administrative password', 9.8, true, 0.0209, 3, 1.0, 'Open', { decision: 'Change default password; remove cellular modem or put behind vendor VPN.' }),
      V('v7', 'a11', 'CVE-2019-0708', 'BlueKeep – RDP pre-auth remote code execution', 9.8, true, 0.99999, 3, 1.0, 'Open', { owner: 'OT/IT', fair: { lef: [0.05, 0.15, 0.4], lm: [40000, 120000, 600000] } }),
      V('v8', 'a11', 'CVE-2017-0144', 'EternalBlue – SMBv1 remote code execution', 8.8, true, 0.9923, 2, 1.0, 'Open'),
      V('v9', 'a14', 'CVE-2021-44228', 'Log4Shell – Apache Log4j2 JNDI remote code execution', 10.0, true, 0.99999, 2, 1.2, 'Remediated', { decision: 'Upgraded to log4j 2.17.1 on 2026-11-08.' }),
    ],
  };
};
