const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const path    = require('path');
const dgram   = require('dgram');
const os      = require('os');
const fs      = require('fs');
const { exec } = require('child_process');

let win;
let tray              = null;
let dhcpServer        = null;
let linkPoller        = null;
let leaseTable        = {};   // mac -> { ip, expires, vendor, hostname, tentative }
let serverActive      = false;
let activeAdapter     = null;
let leaseCleanupTimer = null;

// ── Config persistence path ───────────────────────────────────────────────────
const CONFIG_DIR  = path.join(app.getPath('userData'));
const CONFIG_FILE = path.join(CONFIG_DIR, 'dhcp-config.json');

function loadSavedConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {}
  return null;
}

function saveConfig(cfg) {
  try {
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  } catch {}
}

// ── OUI vendor lookup (75+ prefixes) ──────────────────────────────────────────
const OUI = {
  // Axis
  '00:03:7a': 'Axis', '00:40:8c': 'Axis', 'ac:cc:8e': 'Axis', 'b8:a4:4f': 'Axis',
  // Hikvision
  '00:23:ac': 'Hikvision', 'd0:c0:bf': 'Hikvision', 'c8:02:8f': 'Hikvision',
  'e8:b4:c8': 'Hikvision', '28:57:be': 'Hikvision', '44:19:b6': 'Hikvision',
  'c0:51:7e': 'Hikvision', '54:c4:15': 'Hikvision',
  // Dahua
  '00:1a:07': 'Dahua', 'a4:dc:be': 'Dahua', '70:9f:2d': 'Dahua',
  '3c:ef:8c': 'Dahua', 'e0:50:8b': 'Dahua',
  // Hanwha (Samsung Techwin)
  '00:02:d1': 'Hanwha', '00:09:18': 'Hanwha', '00:16:63': 'Hanwha',
  // Bosch
  '00:0f:7c': 'Bosch', '00:04:63': 'Bosch', '00:07:5f': 'Bosch',
  // Pelco
  '00:e0:91': 'Pelco',
  // Verkada
  'b4:a2:eb': 'Verkada',
  // Honeywell
  '00:d0:2c': 'Honeywell', '00:40:84': 'Honeywell',
  // Motorola / Avigilon
  '00:18:85': 'Motorola', '00:1a:1e': 'Motorola', 'b4:a8:b9': 'Avigilon',
  // Genetec
  'b4:a4:e3': 'Genetec',
  // Lenel / LenelS2
  '2c:f0:ee': 'Lenel', '00:60:35': 'Lenel',
  // HID Global
  '00:06:8e': 'HID Global',
  // Ubiquiti
  'b4:fb:e4': 'Ubiquiti', 'dc:9f:db': 'Ubiquiti', '78:8a:20': 'Ubiquiti',
  'f4:92:bf': 'Ubiquiti', '24:a4:3c': 'Ubiquiti', 'fc:ec:da': 'Ubiquiti',
  '74:83:c2': 'Ubiquiti', '68:d7:9a': 'Ubiquiti', '80:2a:a8': 'Ubiquiti',
  // Cisco / Meraki
  '00:1c:c4': 'Cisco', '00:1b:54': 'Cisco', 'a8:9d:21': 'Cisco',
  '00:18:74': 'Cisco', '00:1e:13': 'Cisco', '88:15:44': 'Meraki',
  '0c:8d:db': 'Meraki', 'ac:17:c8': 'Meraki',
  // Aruba / HPE
  '00:0b:86': 'Aruba', '24:de:c6': 'Aruba', 'd8:c7:c8': 'Aruba', '20:4c:03': 'Aruba',
  // Dell
  '00:26:b9': 'Dell', '14:18:77': 'Dell', 'f8:db:88': 'Dell',
  // HP / HPE
  '3c:d9:2b': 'HP', '1c:98:ec': 'HP', 'fc:15:b4': 'HP', '94:18:82': 'HP', '98:e7:f4': 'HP',
  // TP-Link
  '50:c7:bf': 'TP-Link', 'ec:08:6b': 'TP-Link', '60:32:b1': 'TP-Link',
  'b0:4e:26': 'TP-Link', '30:de:4b': 'TP-Link',
  // Netgear
  '28:c6:8e': 'Netgear', 'a4:2b:8c': 'Netgear', 'c4:04:15': 'Netgear',
  '44:94:fc': 'Netgear', '6c:b0:ce': 'Netgear',
  // Intel
  '00:07:e9': 'Intel', '00:1b:21': 'Intel', '3c:97:0e': 'Intel',
  '68:05:ca': 'Intel', 'a4:bb:6d': 'Intel',
  // Apple
  '00:1c:b3': 'Apple', 'f8:1e:df': 'Apple', '3c:22:fb': 'Apple',
  'a8:60:b6': 'Apple', 'dc:a4:ca': 'Apple',
  // VMware / VirtualBox
  '00:50:56': 'VMware', '00:0c:29': 'VMware', '08:00:27': 'VirtualBox',
  // Ruckus
  'c4:01:7c': 'Ruckus', '74:91:1a': 'Ruckus',
  // Juniper
  '00:05:85': 'Juniper', '88:e0:f3': 'Juniper',
  // Fortinet
  '00:09:0f': 'Fortinet', '70:4c:a5': 'Fortinet',
  // Lenovo
  '98:fa:9b': 'Lenovo', '8c:ec:4b': 'Lenovo',
  // Raspberry Pi
  'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
  // Samsung
  '00:07:ab': 'Samsung', '00:16:32': 'Samsung', 'f8:04:2e': 'Samsung',
  // FLIR / Teledyne
  '00:40:7f': 'FLIR',
  // Panasonic i-PRO
  '00:80:f0': 'Panasonic', '70:6b:b9': 'Panasonic',
  // March Networks
  '00:18:82': 'March Networks',
  // Altronix
  '00:1d:ba': 'Altronix',
};

function vendorFromMac(mac) {
  const prefix = mac.toLowerCase().substring(0, 8);
  return OUI[prefix] || 'Unknown';
}

// ── Window ────────────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  win = new BrowserWindow({
    width: 720,
    height: 960,
    frame: false,
    resizable: false,
    backgroundColor: '#060810',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    }
  });
  win.loadFile('index.html');

  // ── Tray ──
  const iconPath = path.join(__dirname, 'assets', 'icon.ico');
  const trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  tray = new Tray(trayIcon);
  updateTrayTooltip();
  tray.on('click', () => {
    if (win.isVisible()) { win.hide(); } else { win.show(); win.focus(); }
  });
  tray.on('right-click', () => {
    const leaseCount = Object.keys(leaseTable).filter(m => !leaseTable[m].tentative).length;
    const menu = Menu.buildFromTemplate([
      { label: 'NET//DHCP v' + app.getVersion(), enabled: false },
      { type: 'separator' },
      { label: serverActive ? `■ Active — ${leaseCount} lease${leaseCount !== 1 ? 's' : ''}` : '⚡ Stopped', enabled: false },
      { type: 'separator' },
      { label: 'Show', click: () => { win.show(); win.focus(); } },
      { label: 'Quit', click: () => { stopDhcpServer(); removeFirewallRule(); app.quit(); } },
    ]);
    menu.popup({ window: win });
  });

  // Minimize to tray instead of taskbar
  win.on('minimize', (e) => {
    e.preventDefault();
    win.hide();
  });

  startLinkPoller();
});

app.on('window-all-closed', () => {
  stopDhcpServer();
  removeFirewallRule();
  app.quit();
});

ipcMain.on('win-minimize', () => win.minimize());
ipcMain.on('win-close',    () => { stopDhcpServer(); removeFirewallRule(); app.quit(); });

// ── Get app version ───────────────────────────────────────────────────────────
ipcMain.handle('get-version', async () => app.getVersion());

// ── Get adapters ──────────────────────────────────────────────────────────────
ipcMain.handle('get-adapters', async () => getPhysicalAdapters());

// ── Auto-populate config from selected adapter ────────────────────────────────
ipcMain.handle('get-adapter-config', async (_e, adapterName) => {
  const adapters = getPhysicalAdapters();
  const a = adapters.find(x => x.name === adapterName);
  if (!a || !a.ip || !a.netmask) return null;

  const ipParts  = a.ip.split('.').map(Number);
  const nmParts  = a.netmask.split('.').map(Number);
  const netParts = ipParts.map((b, i) => b & nmParts[i]);
  const poolBase = netParts.slice(0, 3).join('.');

  return {
    serverIp:   a.ip,
    subnet:     a.netmask,
    rangeStart: poolBase + '.100',
    rangeEnd:   poolBase + '.200',
    gateway:    a.ip,
    dns:        '',
  };
});

// ── Config persistence ────────────────────────────────────────────────────────
ipcMain.handle('load-config', async () => loadSavedConfig());
ipcMain.handle('save-config', async (_e, cfg) => { saveConfig(cfg); return { ok: true }; });

// ── Validate config ───────────────────────────────────────────────────────────
ipcMain.handle('validate-config', async (_e, cfg) => {
  const { adapterIp, subnet, rangeStart, rangeEnd, gateway, dns } = cfg;
  const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

  for (const [label, val] of [
    ['Server IP', adapterIp], ['Subnet', subnet],
    ['Pool Start', rangeStart], ['Pool End', rangeEnd]
  ]) {
    if (!ipRe.test(val)) return { ok: false, msg: `${label}: invalid IP format` };
    const parts = val.split('.').map(Number);
    if (parts.some(p => p < 0 || p > 255))
      return { ok: false, msg: `${label}: octet out of range` };
  }

  // Optional gateway — validate only if provided
  if (gateway && gateway.trim()) {
    if (!ipRe.test(gateway)) return { ok: false, msg: 'Gateway: invalid IP format' };
  }

  // Optional DNS — validate only if provided
  if (dns && dns.trim()) {
    if (!ipRe.test(dns)) return { ok: false, msg: 'DNS: invalid IP format' };
  }

  // Validate subnet mask is contiguous
  const maskNum = ipToNum(subnet);
  const inverted = (~maskNum) >>> 0;
  if (maskNum !== 0 && (inverted & (inverted + 1)) !== 0)
    return { ok: false, msg: 'Subnet: not a valid contiguous mask' };

  if (ipToNum(rangeStart) > ipToNum(rangeEnd))
    return { ok: false, msg: 'Pool Start must be less than Pool End' };

  const serverNet = ipToNum(adapterIp) & maskNum;
  const startNet  = ipToNum(rangeStart) & maskNum;
  const endNet    = ipToNum(rangeEnd) & maskNum;
  if (serverNet !== startNet || serverNet !== endNet)
    return { ok: false, msg: 'Pool appears to be on a different subnet than the server IP' };

  const poolSize = ipToNum(rangeEnd) - ipToNum(rangeStart) + 1;
  if (poolSize > 253) return { ok: false, msg: 'Pool too large (max 253 addresses)' };

  return { ok: true };
});

// ── Start DHCP ────────────────────────────────────────────────────────────────
ipcMain.handle('start-dhcp', async (_e, opts) => {
  if (serverActive) stopDhcpServer();
  const { adapterIp, subnet, rangeStart, rangeEnd, lease } = opts;
  const gateway      = (opts.gateway && opts.gateway.trim()) || adapterIp;
  const dns          = (opts.dns && opts.dns.trim()) || null;
  const leaseSeconds = Math.max(30, Math.min(86400, parseInt(lease) || 300));
  activeAdapter = opts;

  // Persist config
  saveConfig({
    adapter: opts.adapterName, adapterIp, subnet,
    rangeStart, rangeEnd, gateway: opts.gateway, dns: opts.dns, lease
  });

  try {
    await addFirewallRule();
    await startDhcpServer({ adapterIp, subnet, rangeStart, rangeEnd, gateway, dns, leaseSeconds });
    return { ok: true };
  } catch(e) {
    return { ok: false, msg: e.message };
  }
});

// ── Stop DHCP ─────────────────────────────────────────────────────────────────
ipcMain.handle('stop-dhcp', async () => {
  stopDhcpServer();
  removeFirewallRule();
  return { ok: true };
});

// ── Release All ───────────────────────────────────────────────────────────────
ipcMain.handle('release-all', async () => {
  const count = Object.keys(leaseTable).length;
  leaseTable = {};
  if (count > 0) {
    log(`RELEASE ALL — cleared ${count} lease${count !== 1 ? 's' : ''}`);
    win && win.webContents.send('leases-updated', buildLeaseList());
    updateTrayTooltip();
  }
  return count;
});

// ── Revoke single lease ───────────────────────────────────────────────────────
ipcMain.handle('revoke-lease', async (_e, mac) => {
  if (leaseTable[mac]) {
    const ip = leaseTable[mac].ip;
    delete leaseTable[mac];
    log(`REVOKE — ${ip}  ${mac}`);
    win && win.webContents.send('leases-updated', buildLeaseList());
    updateTrayTooltip();
    return { ok: true, ip };
  }
  return { ok: false };
});

// ── Export leases as CSV ──────────────────────────────────────────────────────
ipcMain.handle('export-leases-csv', async () => {
  const list = buildLeaseList();
  if (!list.length) return '';
  const header = 'IP,MAC,Vendor,Hostname,Expires';
  const rows = list.map(l => {
    const exp = new Date(l.expires).toLocaleString();
    return `${l.ip},${l.mac},${l.vendor},"${(l.hostname || '').replace(/"/g, '""')}",${exp}`;
  });
  return header + '\n' + rows.join('\n');
});

// ── Export log ────────────────────────────────────────────────────────────────
ipcMain.handle('export-log', async () => LOG_HISTORY.join('\n'));

// ── Open browser ──────────────────────────────────────────────────────────────
ipcMain.handle('open-browser', async (_e, ip) => {
  shell.openExternal('http://' + ip);
  return { ok: true };
});

// ── Windows Firewall ──────────────────────────────────────────────────────────
const FW_RULE_NAME = 'NET-DHCP-Server-UDP67';

function addFirewallRule() {
  return new Promise((resolve) => {
    const del = `netsh advfirewall firewall delete rule name="${FW_RULE_NAME}" >nul 2>&1`;
    const add = `netsh advfirewall firewall add rule name="${FW_RULE_NAME}" dir=in action=allow protocol=UDP localport=67 >nul 2>&1`;
    exec(`cmd /c ${del} & ${add}`, (err) => {
      if (err) log('Warning: could not add firewall rule — packets may be blocked');
      else     log('Firewall: inbound UDP 67 allowed');
      resolve();
    });
  });
}

function removeFirewallRule() {
  exec(`cmd /c netsh advfirewall firewall delete rule name="${FW_RULE_NAME}" >nul 2>&1`, () => {});
}

// ── Tray tooltip ──────────────────────────────────────────────────────────────
function updateTrayTooltip() {
  if (!tray) return;
  const count = Object.keys(leaseTable).filter(m => !leaseTable[m].tentative).length;
  if (serverActive) {
    tray.setToolTip(`NET//DHCP — ${count} lease${count !== 1 ? 's' : ''} · serving`);
  } else {
    tray.setToolTip('NET//DHCP — stopped');
  }
}

// ── Link state poller ─────────────────────────────────────────────────────────
let lastAdapterState = {};

function startLinkPoller() {
  pollAdapters();
  linkPoller = setInterval(pollAdapters, 2000);
}

function pollAdapters() {
  const adapters = getPhysicalAdapters();
  const current = {};
  for (const a of adapters) current[a.name] = a.connected;

  for (const name of Object.keys(current)) {
    const wasConnected = lastAdapterState[name];
    const isConnected  = current[name];
    if (wasConnected === false && isConnected === true) {
      win && win.webContents.send('adapter-state', { name, event: 'link-up' });
      log(`Link UP: ${name}`);
    } else if (wasConnected === true && isConnected === false) {
      win && win.webContents.send('adapter-state', { name, event: 'link-down' });
      log(`Link DOWN: ${name}`);
    }
  }
  lastAdapterState = current;
  win && win.webContents.send('adapter-state', { adapters, event: 'poll' });
}

function getPhysicalAdapters() {
  const ifaces = os.networkInterfaces();
  const results = [];
  const skipPatterns = /loopback|vmware|virtualbox|vethernet|vbox|tap-|tun\d|tunnel|isatap|teredo|6to4|bluetooth|pseudo|wan\s*miniport|miniport|wireguard|pangp|sonicwall|globalprotect|cisco\s*vpn|fortinet|juniper|nordvpn|expressvpn|openvpn|checkpoint|palo.alto/i;

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (skipPatterns.test(name)) continue;
    if (!addrs) continue;
    const v4 = addrs.find(a => a.family === 'IPv4' && !a.internal);
    results.push({
      name,
      ip:      v4 ? v4.address  : null,
      netmask: v4 ? v4.netmask  : null,
      connected: !!v4,
    });
  }
  return results;
}

// ── Lease expiry cleanup (runs every 15s) ─────────────────────────────────────
function startLeaseCleanup() {
  leaseCleanupTimer = setInterval(() => {
    const now = Date.now();
    let changed = false;
    for (const mac of Object.keys(leaseTable)) {
      if (leaseTable[mac].expires < now) {
        log(`Lease expired: ${leaseTable[mac].ip}  ${mac}`);
        delete leaseTable[mac];
        changed = true;
      }
    }
    if (changed) {
      win && win.webContents.send('leases-updated', buildLeaseList());
      updateTrayTooltip();
    }
  }, 15000);
}

function stopLeaseCleanup() {
  if (leaseCleanupTimer) { clearInterval(leaseCleanupTimer); leaseCleanupTimer = null; }
}

function buildLeaseList() {
  return Object.entries(leaseTable)
    .filter(([, l]) => !l.tentative)
    .map(([mac, l]) => ({ mac, ip: l.ip, vendor: l.vendor, hostname: l.hostname || '', expires: l.expires }));
}

// ── Pure Node DHCP Server (RFC 2131) ─────────────────────────────────────────
function startDhcpServer({ adapterIp, subnet, rangeStart, rangeEnd, gateway, dns, leaseSeconds }) {
  return new Promise((resolve, reject) => {
    const server = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const pool   = buildIpPool(rangeStart, rangeEnd);
    leaseTable   = {};

    server.on('error', (err) => {
      log('DHCP socket error: ' + err.message);
      if (!serverActive) reject(err);
    });

    server.on('message', (msg) => {
      try {
        handleDhcpMessage(msg, server, { adapterIp, subnet, gateway, dns, leaseSeconds, pool });
      } catch(e) {
        log('DHCP parse error: ' + e.message);
      }
    });

    server.bind(67, '0.0.0.0', () => {
      server.setBroadcast(true);
      dhcpServer   = server;
      serverActive = true;
      startLeaseCleanup();
      updateTrayTooltip();
      log(`DHCP server active on ${adapterIp} — pool ${rangeStart}–${rangeEnd}`);
      win && win.webContents.send('dhcp-status', { active: true, adapterIp, rangeStart, rangeEnd });
      resolve();
    });
  });
}

function stopDhcpServer() {
  stopLeaseCleanup();
  if (dhcpServer) {
    try { dhcpServer.close(); } catch(e) {}
    dhcpServer   = null;
    serverActive = false;
    leaseTable   = {};
    updateTrayTooltip();
    win && win.webContents.send('dhcp-status', { active: false });
    log('DHCP server stopped');
  }
}

// ── DHCP message handler ──────────────────────────────────────────────────────
function handleDhcpMessage(msg, server, cfg) {
  if (msg.length < 240) return;
  if (msg[0] !== 1) return;

  const xid    = msg.slice(4, 8);
  const chaddr = msg.slice(28, 34);
  const mac    = Array.from(chaddr).map(b => b.toString(16).padStart(2,'0')).join(':');

  let msgType     = 0;
  let hostname    = '';
  let requestedIp = null;
  let i = 240;
  while (i < msg.length - 1) {
    const opt = msg[i++];
    if (opt === 255) break;
    if (opt === 0)   continue;
    const len = msg[i++];
    if (i + len > msg.length) break;
    if (opt === 53 && len === 1) msgType     = msg[i];
    if (opt === 12 && len > 0)  hostname    = msg.slice(i, i + len).toString('utf8').replace(/[^\x20-\x7E]/g, '').trim();
    if (opt === 50 && len === 4) requestedIp = `${msg[i]}.${msg[i+1]}.${msg[i+2]}.${msg[i+3]}`;
    i += len;
  }

  if (msgType === 1) {
    const ip = assignIp(mac, cfg, true, requestedIp);
    if (!ip) { log('Pool exhausted — cannot offer'); return; }
    log(`DISCOVER from ${mac} → offering ${ip}`);
    const offer = buildDhcpPacket(2, xid, chaddr, ip, cfg);
    server.send(offer, 0, offer.length, 68, '255.255.255.255');

  } else if (msgType === 3) {
    const ip = assignIp(mac, cfg, false, requestedIp);
    if (!ip) {
      log(`Pool exhausted — sending NAK to ${mac}`);
      const nak = buildNakPacket(xid, chaddr, cfg.adapterIp);
      server.send(nak, 0, nak.length, 68, '255.255.255.255');
      return;
    }
    const vendor = leaseTable[mac] ? leaseTable[mac].vendor : vendorFromMac(mac);
    const host   = hostname || (leaseTable[mac] ? leaseTable[mac].hostname : '') || '';
    leaseTable[mac] = { ip, expires: Date.now() + cfg.leaseSeconds * 1000, vendor, hostname: host, tentative: false };
    log(`REQUEST from ${mac} → ACK ${ip}  [${vendor}]${host ? '  ' + host : ''}`);
    const ack = buildDhcpPacket(5, xid, chaddr, ip, cfg);
    server.send(ack, 0, ack.length, 68, '255.255.255.255');
    win && win.webContents.send('dhcp-lease', {
      mac, ip, vendor, hostname: host, expires: leaseTable[mac].expires,
      time: new Date().toLocaleTimeString(),
    });
    updateTrayTooltip();

  } else if (msgType === 7) {
    if (leaseTable[mac]) {
      log(`RELEASE from ${mac}  ${leaseTable[mac].ip}`);
      delete leaseTable[mac];
      win && win.webContents.send('leases-updated', buildLeaseList());
      updateTrayTooltip();
    }

  } else if (msgType === 4) {
    if (leaseTable[mac]) {
      log(`DECLINE from ${mac}  ${leaseTable[mac].ip} — IP conflict, removing lease`);
      delete leaseTable[mac];
      win && win.webContents.send('leases-updated', buildLeaseList());
      updateTrayTooltip();
    }
  }
}

function assignIp(mac, cfg, tentative, requestedIp) {
  if (leaseTable[mac]) return leaseTable[mac].ip;
  const used = new Set(Object.values(leaseTable).map(l => l.ip));

  if (requestedIp && cfg.pool.includes(requestedIp) && !used.has(requestedIp)) {
    if (tentative) {
      leaseTable[mac] = { ip: requestedIp, expires: Date.now() + 30000, vendor: vendorFromMac(mac), tentative: true };
    }
    return requestedIp;
  }

  for (const ip of cfg.pool) {
    if (!used.has(ip)) {
      if (tentative) {
        leaseTable[mac] = { ip, expires: Date.now() + 30000, vendor: vendorFromMac(mac), tentative: true };
      }
      return ip;
    }
  }
  return null;
}

function buildDhcpPacket(msgType, xid, chaddr, offeredIp, cfg) {
  const pkt = Buffer.alloc(548, 0);
  pkt[0] = 2; pkt[1] = 1; pkt[2] = 6; pkt[3] = 0;
  xid.copy(pkt, 4);
  ipToBytes(offeredIp).copy(pkt, 16);
  ipToBytes(cfg.adapterIp).copy(pkt, 20);
  chaddr.copy(pkt, 28);
  pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;

  let o = 240;
  const opt = (code, ...vals) => {
    if (o + vals.length + 2 > pkt.length) return;
    pkt[o++] = code; pkt[o++] = vals.length; vals.forEach(v => pkt[o++] = v);
  };

  opt(53, msgType);
  opt(54, ...ipToBytes(cfg.adapterIp));
  opt(51, ...uint32Bytes(cfg.leaseSeconds));
  opt(58, ...uint32Bytes(Math.floor(cfg.leaseSeconds * 0.5)));
  opt(59, ...uint32Bytes(Math.floor(cfg.leaseSeconds * 0.875)));
  opt(1,  ...ipToBytes(cfg.subnet));
  opt(3,  ...ipToBytes(cfg.gateway));
  if (cfg.dns) opt(6, ...ipToBytes(cfg.dns));
  pkt[o++] = 255;

  return pkt.slice(0, o);
}

function buildNakPacket(xid, chaddr, serverIp) {
  const pkt = Buffer.alloc(300, 0);
  pkt[0] = 2; pkt[1] = 1; pkt[2] = 6; pkt[3] = 0;
  xid.copy(pkt, 4);
  chaddr.copy(pkt, 28);
  pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
  let o = 240;
  pkt[o++] = 53; pkt[o++] = 1; pkt[o++] = 6;
  pkt[o++] = 54; pkt[o++] = 4; ipToBytes(serverIp).copy(pkt, o); o += 4;
  pkt[o++] = 255;
  return pkt.slice(0, o);
}

// ── IP helpers ────────────────────────────────────────────────────────────────
function ipToBytes(ip)  { return Buffer.from(ip.split('.').map(Number)); }
function uint32Bytes(n) { return [(n>>24)&0xff,(n>>16)&0xff,(n>>8)&0xff,n&0xff]; }
function ipToNum(ip)    { return ip.split('.').reduce((acc,o)=>(acc<<8)+parseInt(o),0)>>>0; }
function numToIp(n)     { return [(n>>>24),(n>>>16&255),(n>>>8&255),n&255].join('.'); }

function buildIpPool(start, end) {
  const pool = [];
  const s = ipToNum(start), e = ipToNum(end);
  for (let n = s; n <= e; n++) pool.push(numToIp(n));
  return pool;
}

const LOG_HISTORY = [];
const LOG_MAX = 150;

function log(msg) {
  const ts = new Date().toLocaleTimeString();
  console.log('[NET//DHCP]', msg);
  LOG_HISTORY.push(`[${ts}] ${msg}`);
  if (LOG_HISTORY.length > LOG_MAX) LOG_HISTORY.shift();
  win && win.webContents.send('dhcp-log', { msg, time: ts });
}
