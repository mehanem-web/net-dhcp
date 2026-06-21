const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const path    = require('path');
const dgram   = require('dgram');
const os      = require('os');
const fs      = require('fs');
const crypto  = require('crypto');
const { exec } = require('child_process');

let win;
let tray = null;

// ── Engine state ──────────────────────────────────────────────────────────────
// One socket, four modes. The socket binds once and survives mode changes —
// stopping "serve" drops back to "listen", never to blindness.
//   off            socket closed
//   listen         parse every DHCP packet on the wire, answer nothing
//   serve-all      answer every client (classic behaviour)
//   serve-targeted answer only MACs in the target set
let mode       = 'off';
let sock       = null;
let serveCfg   = null;          // active serving config (pool, gateway, extras…)
let previewCfg = null;          // config used for dry-run "would offer" in listen mode
let targets    = new Set();     // MACs answered in serve-targeted mode

// Device registry — every MAC heard on the wire, in any mode.
// mac -> { state: asking|offered|leased|declined|quiet,
//          ip, vendor, hostname, firstSeen, lastSeen, attempts,
//          expires, offerExpires, foreignServer, lastXid }
let devices = {};

let quarantinedIps   = new Set();   // DECLINEd or probe-conflicted this session
let probeCache       = {};          // ip -> { free: bool, ts }
let probing          = {};          // mac -> { xid } — coalesce DISCOVER storms mid-probe
let probeXids        = new Set();   // hex xids of our own in-flight scan packets — suppress self-echo
let relayCollector   = null;        // { xid: Buffer, found: {} } while a relay-style scan listens on 67
let scanDebug        = null;        // { rx67, matched67, rx68, logged, cap } during a scan — diagnostic counters
let foreignServers   = {};          // serverIp -> lastSeen (passive rogue detection)
let lastServeAction  = 0;           // last OFFER/ACK/NAK we sent (idle auto-stop)
let sweepTimer       = null;
let linkPoller       = null;
let emitTimer        = null;        // devices-updated throttle

const OFFER_HOLD_MS   = 30000;      // tentative offer lifetime
const QUIET_AFTER_MS  = 60000;      // asking → quiet when silent this long
const PURGE_QUIET_MS  = 300000;     // quiet rows age out of the table
const PROBE_CACHE_MS  = 30000;
const SWEEP_MS        = 5000;
const SCAN_WINDOW_MS  = 6000;       // active rogue-scan listen window — must outlast slow routers (~3.3s seen in the field)

// ── Config persistence ────────────────────────────────────────────────────────
const CONFIG_DIR  = path.join(app.getPath('userData'));
const CONFIG_FILE = path.join(CONFIG_DIR, 'dhcp-config.json');

function loadSavedConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {}
  return {};
}

function saveConfigFile(cfg) {
  try {
    if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  } catch {}
}

// Persistent store layout:
// { current: {…form fields…}, profiles: { name: {…} },
//   reservations: { mac: ip }, idleMinutes: 30, staticAssist: {…}|null }
let store = loadSavedConfig();
if (!store.profiles)     store.profiles = {};
if (!store.reservations) store.reservations = {};
if (store.idleMinutes === undefined) store.idleMinutes = 30;

function persist() { saveConfigFile(store); }

// ── OUI vendor lookup ─────────────────────────────────────────────────────────
// Layer 1: full IEEE registry (assets/oui.json, ~39k prefixes, compiled at build).
// Layer 2: curated field overrides — short names that beat the legal-entity ones.
let OUI_DB = {};
try {
  OUI_DB = JSON.parse(fs.readFileSync(path.join(__dirname, 'assets', 'oui.json'), 'utf8'));
} catch (e) { console.error('[NET//DHCP] OUI database failed to load:', e.message); }

const OUI_OVERRIDE = {
  // Field-tested short names — these win over the IEEE registry entry
  '00037a': 'Axis', '00408c': 'Axis', 'accc8e': 'Axis', 'b8a44f': 'Axis',
  '0023ac': 'Hikvision', 'd0c0bf': 'Hikvision', 'c8028f': 'Hikvision',
  'e8b4c8': 'Hikvision', '2857be': 'Hikvision', '4419b6': 'Hikvision',
  'c0517e': 'Hikvision', '54c415': 'Hikvision',
  '001a07': 'Dahua', 'a4dcbe': 'Dahua', '709f2d': 'Dahua',
  '3cef8c': 'Dahua', 'e0508b': 'Dahua',
  '0002d1': 'Hanwha', '000918': 'Hanwha', '001663': 'Hanwha',
  '000f7c': 'Bosch', '000463': 'Bosch', '00075f': 'Bosch',
  '00e091': 'Pelco', 'b4a2eb': 'Verkada',
  '00d02c': 'Honeywell', '004084': 'Honeywell',
  '001885': 'Motorola', '001a1e': 'Motorola', 'b4a8b9': 'Avigilon',
  'b4a4e3': 'Genetec', '2cf0ee': 'Lenel', '006035': 'Lenel', '00068e': 'HID Global',
  'b4fbe4': 'Ubiquiti', 'dc9fdb': 'Ubiquiti', '788a20': 'Ubiquiti',
  'f492bf': 'Ubiquiti', '24a43c': 'Ubiquiti', 'fcecda': 'Ubiquiti',
  '7483c2': 'Ubiquiti', '68d79a': 'Ubiquiti', '802aa8': 'Ubiquiti',
  '001cc4': 'Cisco', '001b54': 'Cisco', 'a89d21': 'Cisco',
  '001874': 'Cisco', '001e13': 'Cisco', '881544': 'Meraki',
  '0c8ddb': 'Meraki', 'ac17c8': 'Meraki',
  '000b86': 'Aruba', '24dec6': 'Aruba', 'd8c7c8': 'Aruba', '204c03': 'Aruba',
  'c4017c': 'Ruckus', '74911a': 'Ruckus',
  '005056': 'VMware', '000c29': 'VMware', '080027': 'VirtualBox',
  'b827eb': 'Raspberry Pi', 'dca632': 'Raspberry Pi', 'e45f01': 'Raspberry Pi',
  '00407f': 'FLIR', '0080f0': 'Panasonic', '706bb9': 'Panasonic',
  '001882': 'March Networks', '001dba': 'Altronix',
};

function vendorFromMac(mac) {
  const key = mac.toLowerCase().replace(/:/g, '').substring(0, 6);
  return OUI_OVERRIDE[key] || OUI_DB[key] || 'Unknown';
}

// ── Window & tray ─────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  win = new BrowserWindow({
    width: 1100,
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

  const iconPath = path.join(__dirname, 'assets', 'icon.ico');
  const trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  tray = new Tray(trayIcon);
  updateTray();
  tray.on('click', () => {
    if (win.isVisible()) { win.hide(); } else { win.show(); win.focus(); }
  });
  tray.on('right-click', () => {
    const leases = Object.values(devices).filter(d => d.state === 'leased').length;
    const asking = Object.values(devices).filter(d => d.state === 'asking').length;
    const modeLabel = { 'off': '○ Offline', 'listen': '◉ Listening', 'serve-all': '■ Serving all', 'serve-targeted': '■ Serving ' + targets.size + ' target' + (targets.size !== 1 ? 's' : '') }[mode];
    const menu = Menu.buildFromTemplate([
      { label: 'NET//DHCP v' + app.getVersion(), enabled: false },
      { type: 'separator' },
      { label: `${modeLabel} — ${leases} lease${leases !== 1 ? 's' : ''}, ${asking} asking`, enabled: false },
      { type: 'separator' },
      { label: 'Show', click: () => { win.show(); win.focus(); } },
      { label: 'Quit', click: () => shutdownAndQuit() },
    ]);
    menu.popup({ window: win });
  });

  win.on('minimize', (e) => { e.preventDefault(); win.hide(); });

  startLinkPoller();

  // Launch sequence: name any port-67 squatter, then open ears.
  const squatter = await checkPort67();
  if (squatter) {
    log(`WARNING — UDP 67 is held by ${squatter}. DHCP may not hear requests until it's stopped.`);
    win && win.webContents.send('port67-status', { squatter });
  }
  await setMode('listen').catch(e => log('Could not start listening: ' + e.message));

  // Crash recovery: a previous session changed an adapter IP and never reverted.
  if (store.staticAssist) {
    win && win.webContents.send('static-assist-pending', store.staticAssist);
  }
});

function updateTray() {
  if (!tray) return;
  const leases = Object.values(devices).filter(d => d.state === 'leased').length;
  const label = {
    'off':            'NET//DHCP — offline',
    'listen':         'NET//DHCP — listening',
    'serve-all':      `NET//DHCP — serving · ${leases} lease${leases !== 1 ? 's' : ''}`,
    'serve-targeted': `NET//DHCP — serving ${targets.size} target${targets.size !== 1 ? 's' : ''} · ${leases} lease${leases !== 1 ? 's' : ''}`,
  }[mode];
  tray.setToolTip(label);
}

async function shutdownAndQuit() {
  try { await revertStaticAssist(true); } catch {}
  try { await setMode('off'); } catch {}
  removeFirewallRule();
  app.exit(0);
}

let quitting = false;
app.on('window-all-closed', () => { if (!quitting) { quitting = true; shutdownAndQuit(); } });

ipcMain.on('win-minimize', () => win.minimize());
ipcMain.on('win-close',    () => { if (!quitting) { quitting = true; shutdownAndQuit(); } });

// ── Basic IPC ─────────────────────────────────────────────────────────────────
ipcMain.handle('get-version',  async () => app.getVersion());
ipcMain.handle('get-adapters', async () => getPhysicalAdapters());

// Auto-populate config from a selected adapter
ipcMain.handle('get-adapter-config', async (_e, adapterName) => {
  const a = getPhysicalAdapters().find(x => x.name === adapterName);
  if (!a || !a.ip || !a.netmask || isApipa(a.ip)) return null;
  return deriveCfgFromAdapter(a);
});

function deriveCfgFromAdapter(a) {
  const ipParts  = a.ip.split('.').map(Number);
  const nmParts  = a.netmask.split('.').map(Number);
  const netParts = ipParts.map((b, i) => b & nmParts[i]);
  const poolBase = netParts.slice(0, 3).join('.');
  return {
    adapterName: a.name,
    serverIp:    a.ip,
    subnet:      a.netmask,
    rangeStart:  poolBase + '.100',
    rangeEnd:    poolBase + '.200',
    gateway:     a.ip,
    dns:         '',
  };
}

// ── Config / profiles / reservations ──────────────────────────────────────────
ipcMain.handle('load-config', async () => store.current || null);
ipcMain.handle('save-config', async (_e, cfg) => { store.current = cfg; persist(); return { ok: true }; });

ipcMain.handle('profiles-list',   async () => Object.keys(store.profiles).sort());
ipcMain.handle('profiles-save',   async (_e, name, cfg) => {
  const clean = String(name || '').trim().substring(0, 40);
  if (!clean) return { ok: false, msg: 'Profile needs a name' };
  store.profiles[clean] = cfg; persist();
  return { ok: true, name: clean };
});
ipcMain.handle('profiles-load',   async (_e, name) => store.profiles[name] || null);
ipcMain.handle('profiles-delete', async (_e, name) => { delete store.profiles[name]; persist(); return { ok: true }; });

ipcMain.handle('get-reservations', async () => store.reservations);
ipcMain.handle('set-reservation', async (_e, mac, ip) => {
  if (!isValidIpAddr(ip)) return { ok: false, msg: 'Invalid IP' };
  const cfg = serveCfg || previewCfg;
  if (cfg) {
    const m = ipToNum(cfg.subnet);
    if ((ipToNum(ip) & m) !== (ipToNum(cfg.adapterIp) & m))
      return { ok: false, msg: 'Reserved IP is not on the server subnet' };
    if (ip === cfg.adapterIp) return { ok: false, msg: 'That is the server IP' };
    if (cfg.gateway && ip === cfg.gateway) return { ok: false, msg: 'That is the gateway IP' };
  }
  // One IP per MAC, one MAC per IP
  for (const [m2, ip2] of Object.entries(store.reservations)) {
    if (ip2 === ip && m2 !== mac) return { ok: false, msg: `Already reserved for ${m2}` };
  }
  store.reservations[mac] = ip; persist();
  log(`RESERVED ${ip} for ${mac}`);
  emitDevices();
  return { ok: true };
});
ipcMain.handle('clear-reservation', async (_e, mac) => {
  if (store.reservations[mac]) {
    log(`Reservation cleared for ${mac}`);
    delete store.reservations[mac]; persist(); emitDevices();
  }
  return { ok: true };
});

ipcMain.handle('set-idle-minutes', async (_e, n) => {
  const v = Math.max(0, Math.min(720, parseInt(n) || 0));
  store.idleMinutes = v; persist();
  log(v === 0 ? 'Idle auto-stop disabled' : `Idle auto-stop set to ${v} min`);
  return { ok: true, value: v };
});
ipcMain.handle('get-idle-minutes', async () => store.idleMinutes);

// ── Validate config ───────────────────────────────────────────────────────────
ipcMain.handle('validate-config', async (_e, cfg) => validateCfg(cfg));

function validateCfg(cfg) {
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

  if (gateway && gateway.trim() && !ipRe.test(gateway))
    return { ok: false, msg: 'Gateway: invalid IP format' };
  if (dns && dns.trim() && !ipRe.test(dns))
    return { ok: false, msg: 'DNS: invalid IP format' };

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

  if (gateway && gateway.trim() && ipRe.test(gateway)) {
    if ((ipToNum(gateway) & maskNum) !== serverNet)
      return { ok: false, msg: 'Gateway is not on the server subnet' };
  }

  const poolSize = ipToNum(rangeEnd) - ipToNum(rangeStart) + 1;
  if (poolSize > 253) return { ok: false, msg: 'Pool too large (max 253 addresses)' };

  // Advanced extras
  if (cfg.ntp && cfg.ntp.trim() && !ipRe.test(cfg.ntp))
    return { ok: false, msg: 'NTP server: invalid IP format' };
  if (cfg.opt43 && cfg.opt43.trim()) {
    const hex = cfg.opt43.replace(/[\s:.-]/g, '');
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 || hex.length / 2 > 255)
      return { ok: false, msg: 'Option 43: must be hex bytes (e.g. 01 04 C0 A8 01 0A), max 255 bytes' };
  }
  for (const [label, val] of [['Domain name', cfg.domainName], ['TFTP server', cfg.tftpServer], ['Boot file', cfg.bootFile]]) {
    if (val && val.length > 255) return { ok: false, msg: `${label}: too long (max 255)` };
  }
  return { ok: true };
}

// Normalise raw form fields into the engine config shape
function buildEngineCfg(opts) {
  const adapterIp    = opts.adapterIp;
  const gateway      = (opts.gateway && opts.gateway.trim()) || adapterIp;
  const dns          = (opts.dns && opts.dns.trim()) || null;
  const leaseSeconds = Math.max(30, Math.min(86400, parseInt(opts.lease) || 300));
  const extras = {
    domainName: (opts.domainName || '').trim().replace(/[^\x20-\x7E]/g, '').substring(0, 255) || null,
    ntp:        (opts.ntp || '').trim() || null,
    tftpServer: (opts.tftpServer || '').trim().replace(/[^\x20-\x7E]/g, '').substring(0, 255) || null,
    bootFile:   (opts.bootFile || '').trim().replace(/[^\x20-\x7E]/g, '').substring(0, 128) || null,
    opt43:      (opts.opt43 || '').replace(/[\s:.-]/g, '') || null,
  };
  return {
    adapterName: opts.adapterName, adapterIp,
    subnet: opts.subnet, rangeStart: opts.rangeStart, rangeEnd: opts.rangeEnd,
    gateway, dns, leaseSeconds, extras,
    pool: buildIpPool(opts.rangeStart, opts.rangeEnd),
  };
}

// ── Preview config (dry-run "would offer" while listening) ────────────────────
ipcMain.handle('set-preview-config', async (_e, opts) => {
  const v = validateCfg(opts);
  previewCfg = v.ok ? buildEngineCfg(opts) : null;
  emitDevices();
  return v;
});

// ── Mode control ──────────────────────────────────────────────────────────────
ipcMain.handle('serve-all', async (_e, opts) => {
  const v = validateCfg(opts);
  if (!v.ok) return v;
  store.current = opts; persist();
  serveCfg = buildEngineCfg(opts);
  try {
    await setMode('serve-all');
    const others = otherSubnetAdapters(serveCfg.adapterIp, serveCfg.subnet);
    const warning = others.length
      ? `Heads up: ${others.join(', ')} ${others.length > 1 ? 'are' : 'is'} also connected on another subnet. This server answers DHCP on all connected networks.`
      : null;
    if (warning) log('WARNING — ' + warning);
    return { ok: true, warning };
  } catch (e) { return { ok: false, msg: e.message }; }
});

ipcMain.handle('serve-device', async (_e, mac, opts) => {
  if (mode === 'serve-all') return { ok: false, msg: 'Already serving everyone' };
  if (opts) {
    const v = validateCfg(opts);
    if (!v.ok) return v;
    store.current = opts; persist();
    serveCfg = buildEngineCfg(opts);
  }
  if (!serveCfg) return { ok: false, msg: 'No valid configuration' };
  targets.add(mac);
  try {
    await setMode('serve-targeted');
    log(`TARGET — answering ${mac} only (${targets.size} target${targets.size !== 1 ? 's' : ''})`);
    emitDevices();
    return { ok: true, targets: [...targets] };
  } catch (e) { targets.delete(mac); return { ok: false, msg: e.message }; }
});

ipcMain.handle('unserve-device', async (_e, mac) => {
  targets.delete(mac);
  if (mode === 'serve-targeted' && targets.size === 0) {
    await setMode('listen');
    log('No targets left — back to listening');
  } else {
    log(`Target removed: ${mac}`);
  }
  emitDevices();
  return { ok: true, targets: [...targets] };
});

ipcMain.handle('stop-serving', async () => {
  if (mode === 'serve-all' || mode === 'serve-targeted') {
    targets.clear();
    await setMode('listen');
  }
  return { ok: true };
});

// ── Quick Start ───────────────────────────────────────────────────────────────
// Pick the best adapter (wired with a usable IPv4 wins), derive everything.
// If nothing is usable, report which adapter could be fixed with static assist.
ipcMain.handle('quick-start', async () => {
  const adapters = getPhysicalAdapters().filter(a => a.connected);
  if (!adapters.length) return { ok: false, reason: 'no-link', msg: 'No connected network adapter found. Check the cable.' };

  const wiredFirst = adapters.slice().sort((a, b) => {
    const aw = /ethernet|local area/i.test(a.name) ? 0 : 1;
    const bw = /ethernet|local area/i.test(b.name) ? 0 : 1;
    return aw - bw;
  });
  const usable = wiredFirst.find(a => a.ip && !isApipa(a.ip));
  if (usable) return { ok: true, cfg: deriveCfgFromAdapter(usable) };

  // Connected but no usable address — the chicken-and-egg case
  return { ok: false, reason: 'needs-static', adapter: wiredFirst[0].name,
           msg: `${wiredFirst[0].name} is connected but has no usable address.` };
});

// ── Static-IP assist ──────────────────────────────────────────────────────────
// Give the chosen adapter a static address so DHCP can be served on a dead
// segment. Tracks what was there before and reverts on demand or at quit.
const ASSIST_BASES = ['192.168.100', '192.168.150', '192.168.200', '10.10.10'];

function sanitizeAdapterName(name) {
  return String(name || '').replace(/["&|<>^%]/g, '').substring(0, 80);
}

ipcMain.handle('static-assist-apply', async (_e, adapterName) => {
  const name = sanitizeAdapterName(adapterName);
  if (!name) return { ok: false, msg: 'No adapter specified' };

  // Pick a base subnet no other adapter is already using
  const inUse = getPhysicalAdapters().filter(a => a.ip).map(a => a.ip.split('.').slice(0, 3).join('.'));
  const base = ASSIST_BASES.find(b => !inUse.includes(b)) || ASSIST_BASES[0];
  const newIp = base + '.1';

  // Record what's there now, for the revert
  const prev = await readAdapterIpConfig(name);
  store.staticAssist = { adapter: name, applied: newIp, prev };
  persist();

  return new Promise((resolve) => {
    const cmd = `netsh interface ipv4 set address name="${name}" static ${newIp} 255.255.255.0`;
    exec(cmd, { timeout: 15000 }, (err, _o, stderr) => {
      if (err) {
        store.staticAssist = null; persist();
        resolve({ ok: false, msg: 'netsh failed: ' + (stderr || err.message).trim() });
        return;
      }
      log(`STATIC ASSIST — ${name} set to ${newIp}/24 (will revert on quit)`);
      // Give Windows a beat to settle the address before we derive config
      setTimeout(() => resolve({ ok: true, adapter: name, ip: newIp, subnet: '255.255.255.0' }), 1500);
    });
  });
});

ipcMain.handle('static-assist-revert', async () => revertStaticAssist(false));
ipcMain.handle('static-assist-status', async () => store.staticAssist || null);

function readAdapterIpConfig(name) {
  return new Promise((resolve) => {
    exec(`netsh interface ipv4 show config name="${name}"`, { timeout: 10000 }, (err, stdout) => {
      if (err || !stdout) { resolve({ dhcp: true }); return; }
      const dhcpEnabled = /DHCP enabled:\s*Yes/i.test(stdout);
      if (dhcpEnabled) { resolve({ dhcp: true }); return; }
      const ip   = (stdout.match(/IP Address:\s*([\d.]+)/i) || [])[1] || null;
      const mask = (stdout.match(/(?:Subnet Prefix:.*?mask ([\d.]+)|Subnet Mask:\s*([\d.]+))/i) || []).slice(1).find(Boolean) || null;
      const gw   = (stdout.match(/Default Gateway:\s*([\d.]+)/i) || [])[1] || null;
      resolve({ dhcp: false, ip, mask, gw });
    });
  });
}

function revertStaticAssist(silent) {
  return new Promise((resolve) => {
    const rec = store.staticAssist;
    if (!rec) { resolve({ ok: true, none: true }); return; }
    const name = sanitizeAdapterName(rec.adapter);
    let cmd;
    if (!rec.prev || rec.prev.dhcp) {
      cmd = `netsh interface ipv4 set address name="${name}" dhcp`;
    } else if (rec.prev.ip && rec.prev.mask) {
      cmd = `netsh interface ipv4 set address name="${name}" static ${rec.prev.ip} ${rec.prev.mask}` + (rec.prev.gw ? ` ${rec.prev.gw}` : '');
    } else {
      cmd = `netsh interface ipv4 set address name="${name}" dhcp`;
    }
    exec(cmd, { timeout: 15000 }, (err) => {
      store.staticAssist = null; persist();
      if (!silent) log(err ? 'Static assist revert failed — check adapter settings manually'
                           : `STATIC ASSIST — ${name} reverted`);
      resolve({ ok: !err });
    });
  });
}

// ── Active rogue-DHCP probe ───────────────────────────────────────────────────
// Two channels fired together, answers collected for 2.5s:
//   A) RELAY  — DISCOVER with giaddr = our real IP (hops=1), broadcast to 67.
//      RFC 2131 servers reply UNICAST to giaddr:67 — straight into the socket
//      we already hold. Immune to the Windows DHCP Client owning port 68 and
//      to routers that ignore the broadcast flag and unicast OFFERs to a fake
//      MAC that can't receive them.
//   B) CLIENT — classic DISCOVER from port 68 with the broadcast flag, for the
//      rare server that won't answer a relay. Best effort; port 68 may be busy.
// Our own broadcasts echo back into the 67 listener — suppressed by xid.
ipcMain.handle('probe-dhcp', async () => activeRogueProbe());

function activeRogueProbe() {
  return new Promise((resolve) => {
    if (!sock) { resolve({ ok: false, msg: 'Engine is offline — cannot scan', servers: [] }); return; }

    const found = {};
    const notes = [];
    scanDebug = { rx67: 0, matched67: 0, rx68: 0, logged: 0, cap: 25, clients: new Set() };
    firewallRuleExists().then(ok => log(`SCAN · firewall inbound UDP 67 rule: ${ok ? 'present' : 'MISSING — replies may be dropped'}`, ok ? 'info' : 'warn'));
    const xidA = crypto.randomBytes(4);                      // relay channel
    const xidB = crypto.randomBytes(4);                      // client channel
    probeXids.add(xidA.toString('hex'));
    probeXids.add(xidB.toString('hex'));

    // Channel A — relay-style through the main socket
    const giaddr = probeSourceIp();
    if (giaddr) {
      relayCollector = { xid: xidA, found };
      try {
        const pktA = buildProbeDiscover(xidA, giaddr, false);
        sock.send(pktA, 0, pktA.length, 67, '255.255.255.255', (err) => {
          log(err ? `SCAN · relay send FAILED: ${err.code || err.message}`
                  : `SCAN · relay DISCOVER sent (${pktA.length}b, giaddr=${giaddr}, src :67)`, err ? 'err' : 'info');
        });
      } catch (e) { notes.push('relay probe failed: ' + e.message); }
    } else {
      notes.push('no usable local IP — relay probe skipped');
    }

    // Channel B — classic client-style on port 68, best effort
    let clientSock = null;
    try {
      clientSock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      clientSock.on('error', () => {
        notes.push('port 68 busy — client probe skipped');
        try { clientSock.close(); } catch {}
        clientSock = null;
      });
      clientSock.on('message', (msg, rinfo) => {
        if (msg.length < 240) return;
        if (scanDebug) {
          scanDebug.rx68++;
          if (scanDebug.logged < scanDebug.cap) {
            scanDebug.logged++;
            log(`SCAN · rx :68 from ${rinfo.address}:${rinfo.port} op=${msg[0]} xid=${msg.slice(4,8).toString('hex')}`, 'info');
          }
        }
        if (msg[0] !== 2) return;                            // BOOTREPLY only
        if (!msg.slice(4, 8).equals(xidB)) return;           // our transaction only
        const ip = parseReplyServerIp(msg) || rinfo.address;
        if (ip) found[ip] = true;
      });
      clientSock.bind(68, '0.0.0.0', () => {
        try {
          clientSock.setBroadcast(true);
          const pktB = buildProbeDiscover(xidB, null, true);
          clientSock.send(pktB, 0, pktB.length, 67, '255.255.255.255', (err) => {
            log(err ? `SCAN · client send FAILED: ${err.code || err.message}`
                    : `SCAN · client DISCOVER sent (${pktB.length}b, from :68, bcast flag)`, err ? 'err' : 'info');
          });
        } catch (e) { notes.push('client probe failed: ' + e.message); }
      });
    } catch (e) { notes.push('client probe unavailable: ' + e.message); }

    // Window must outlast the slowest server. A real capture showed a consumer
    // router taking ~3.3s to answer a relayed DISCOVER — the old 2.5s window
    // closed before the OFFER arrived and reported a false all-clear. 6s gives
    // margin without making the UI feel hung.
    setTimeout(() => {
      relayCollector = null;
      probeXids.delete(xidA.toString('hex'));
      probeXids.delete(xidB.toString('hex'));
      if (clientSock) { try { clientSock.close(); } catch {} }

      // Report only servers that aren't us
      const mine = localAdapterIps();
      const servers = Object.keys(found).filter(ip => !mine.has(ip));
      for (const s of servers) foreignServers[s] = Date.now();   // feed the passive list too

      let clientsHeard = 0;
      if (scanDebug) {
        clientsHeard = scanDebug.clients.size;
        log(`SCAN · summary — :67 saw ${scanDebug.rx67} pkt (${scanDebug.matched67} matched our probe), :68 saw ${scanDebug.rx68} pkt, ${clientsHeard} other device${clientsHeard !== 1 ? 's' : ''} asking`, 'info');
        scanDebug = null;
      }
      const suffix = (!servers.length && notes.length) ? '  (' + notes.join('; ') + ')' : '';
      log(servers.length
        ? `SCAN — ${servers.length} other DHCP server${servers.length > 1 ? 's' : ''} answered: ${servers.join(', ')}`
        : 'SCAN — no other DHCP server answered' + suffix);
      resolve({ ok: true, msg: notes.length ? notes.join('; ') : null, servers, clientsHeard });
    }, SCAN_WINDOW_MS);
  });
}

// Best local IPv4 to present as the relay (giaddr): live serving config first,
// then the preview config, then any connected adapter with a real address.
function probeSourceIp() {
  const live = getPhysicalAdapters().filter(a => a.connected && a.ip && !isApipa(a.ip)).map(a => a.ip);
  if (!live.length) return null;
  if (serveCfg && live.includes(serveCfg.adapterIp))     return serveCfg.adapterIp;
  if (previewCfg && live.includes(previewCfg.adapterIp)) return previewCfg.adapterIp;
  return live[0];
}

// Server identity from a BOOTREPLY: option 54, else siaddr, else null.
function parseReplyServerIp(msg) {
  let serverIp = null;
  let i = 240;
  while (i < msg.length - 1) {
    const opt = msg[i++];
    if (opt === 255) break;
    if (opt === 0)   continue;
    const len = msg[i++];
    if (i + len > msg.length) break;
    if (opt === 54 && len === 4) serverIp = `${msg[i]}.${msg[i+1]}.${msg[i+2]}.${msg[i+3]}`;
    i += len;
  }
  if (!serverIp) {
    const siaddr = `${msg[20]}.${msg[21]}.${msg[22]}.${msg[23]}`;
    if (siaddr !== '0.0.0.0') serverIp = siaddr;
  }
  return serverIp;
}

// Minimal DISCOVER for scanning. giaddrIp set → relay-style (hops=1, server
// unicasts the reply to giaddr:67). Otherwise client-style with the broadcast
// flag. Fake locally-administered MAC keeps real device leases untouched.
function buildProbeDiscover(xid, giaddrIp, useBroadcastFlag) {
  const pkt = Buffer.alloc(300, 0);
  pkt[0] = 1; pkt[1] = 1; pkt[2] = 6;
  pkt[3] = giaddrIp ? 1 : 0;                                 // hops — one relay hop
  xid.copy(pkt, 4);
  pkt[9] = 4;                                                // secs = 4, looks like a real retry
  if (useBroadcastFlag) pkt[10] = 0x80;
  if (giaddrIp) ipToBytes(giaddrIp).copy(pkt, 24);           // giaddr @ 24
  const fakeMac = Buffer.concat([Buffer.from([0x02]), crypto.randomBytes(5)]);
  fakeMac.copy(pkt, 28);
  pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
  let o = 240;
  pkt[o++] = 53; pkt[o++] = 1; pkt[o++] = 1;                 // DHCPDISCOVER
  pkt[o++] = 255;
  return pkt.slice(0, o);
}

ipcMain.handle('get-foreign-servers', async () => Object.keys(foreignServers));

// ── Port-67 squatter check ────────────────────────────────────────────────────
// reuseAddr means a squatter doesn't throw EADDRINUSE — packets just get stolen.
// So we look proactively: netstat for UDP :67, resolve the PID to a name.
function checkPort67() {
  return new Promise((resolve) => {
    exec('netstat -ano -p UDP', { timeout: 10000 }, (err, stdout) => {
      if (err || !stdout) { resolve(null); return; }
      const line = stdout.split('\n').find(l => /UDP\s+(0\.0\.0\.0|[\d.]+):67\s/.test(l));
      if (!line) { resolve(null); return; }
      const pid = (line.trim().split(/\s+/).pop() || '').trim();
      if (!pid || !/^\d+$/.test(pid) || pid === String(process.pid)) { resolve(null); return; }
      exec(`tasklist /svc /FI "PID eq ${pid}" /FO CSV /NH`, { timeout: 10000 }, (err2, out2) => {
        if (err2 || !out2) { resolve(`PID ${pid}`); return; }
        const cols = out2.trim().split('","').map(s => s.replace(/^"|"$/g, ''));
        const proc = cols[0] || `PID ${pid}`;
        const svcs = (cols[2] || '').trim();
        if (/svchost/i.test(proc) && /SharedAccess/i.test(svcs)) {
          resolve('Windows Internet Connection Sharing (ICS)');
        } else if (/svchost/i.test(proc) && svcs && svcs !== 'N/A') {
          resolve(`${proc} (services: ${svcs})`);
        } else {
          resolve(proc);
        }
      });
    });
  });
}

// ── Self-test ─────────────────────────────────────────────────────────────────
ipcMain.handle('self-test', async (_e, adapterName) => {
  const checks = [];
  const adapters = getPhysicalAdapters();
  const a = adapterName ? adapters.find(x => x.name === adapterName) : adapters.find(x => x.connected);

  if (!a) {
    checks.push({ label: 'Network adapter', ok: false, detail: 'No adapter found or selected' });
  } else if (!a.connected) {
    checks.push({ label: 'Network adapter', ok: false, detail: `${a.name}: no link — check the cable` });
  } else if (!a.ip || isApipa(a.ip)) {
    checks.push({ label: 'Network adapter', ok: false, detail: `${a.name}: connected but no usable address — use Quick Start to fix` });
  } else {
    checks.push({ label: 'Network adapter', ok: true, detail: `${a.name} — ${a.ip}` });
  }

  const squatter = await checkPort67();
  checks.push(squatter
    ? { label: 'DHCP port (UDP 67)', ok: false, detail: `Held by ${squatter} — NET//DHCP may not hear requests` }
    : { label: 'DHCP port (UDP 67)', ok: true, detail: mode !== 'off' ? 'Bound by NET//DHCP' : 'Free' });

  const fwOk = await firewallRuleExists();
  checks.push(fwOk
    ? { label: 'Firewall rule', ok: true, detail: 'Inbound UDP 67 allowed' }
    : { label: 'Firewall rule', ok: false, detail: 'Rule missing — added automatically when listening starts' });

  checks.push(mode !== 'off'
    ? { label: 'Listening', ok: true, detail: `Mode: ${mode}` }
    : { label: 'Listening', ok: false, detail: 'Engine is offline' });

  const foreign = Object.keys(foreignServers);
  checks.push(foreign.length
    ? { label: 'Other DHCP servers', ok: false, detail: `Heard on the wire: ${foreign.join(', ')}` }
    : { label: 'Other DHCP servers', ok: true, detail: 'None heard passively (use SCAN for an active check)' });

  return checks;
});

// ── Lease actions / exports ───────────────────────────────────────────────────
ipcMain.handle('release-all', async () => {
  let count = 0;
  for (const mac of Object.keys(devices)) {
    if (devices[mac].state === 'leased' || devices[mac].state === 'offered') {
      delete devices[mac]; count++;
    }
  }
  if (count > 0) {
    log(`RELEASE ALL — cleared ${count} lease${count !== 1 ? 's' : ''}`);
    emitDevices(); updateTray();
  }
  return count;
});

ipcMain.handle('revoke-lease', async (_e, mac) => {
  const d = devices[mac];
  if (d && (d.state === 'leased' || d.state === 'offered')) {
    const ip = d.ip;
    delete devices[mac];
    log(`REVOKE — ${ip}  ${mac}`);
    emitDevices(); updateTray();
    return { ok: true, ip };
  }
  return { ok: false };
});

ipcMain.handle('export-leases-csv', async () => {
  const list = Object.entries(devices)
    .filter(([, d]) => d.state === 'leased')
    .map(([mac, d]) => ({ mac, ...d }));
  if (!list.length) return '';
  const header = 'IP,MAC,Vendor,Hostname,Expires,Reserved';
  const rows = list.map(l => {
    const exp    = new Date(l.expires).toLocaleString();
    const vendor = csvSafe(l.vendor);
    const host   = csvSafe(l.hostname || '').replace(/"/g, '""');
    const res    = store.reservations[l.mac] ? 'yes' : '';
    return `${l.ip},${l.mac},"${csvEscape(vendor)}","${host}",${exp},${res}`;
  });
  return header + '\n' + rows.join('\n');
});

function csvEscape(s) { return String(s).replace(/"/g, '""'); }

ipcMain.handle('export-log', async () => LOG_HISTORY.join('\n'));

ipcMain.handle('open-browser', async (_e, ip) => {
  if (!isValidIpAddr(ip)) return { ok: false };
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

function firewallRuleExists() {
  return new Promise((resolve) => {
    exec(`netsh advfirewall firewall show rule name="${FW_RULE_NAME}"`, { timeout: 10000 }, (err, stdout) => {
      resolve(!err && /Enabled/i.test(stdout || ''));
    });
  });
}

// ── Adapters & link poller ────────────────────────────────────────────────────
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

function isApipa(ip) { return /^169\.254\./.test(ip || ''); }

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
      apipa: v4 ? isApipa(v4.address) : false,
    });
  }
  return results;
}

function otherSubnetAdapters(serverIp, mask) {
  if (!isValidIpAddr(serverIp) || !isValidIpAddr(mask)) return [];
  const m = ipToNum(mask);
  const myNet = ipToNum(serverIp) & m;
  return getPhysicalAdapters()
    .filter(a => a.connected && a.ip && !a.apipa && a.ip !== serverIp && ((ipToNum(a.ip) & m) !== myNet))
    .map(a => `${a.name} (${a.ip})`);
}

// ── Engine: socket & modes ────────────────────────────────────────────────────
function setMode(newMode) {
  return new Promise((resolve, reject) => {
    if (newMode === mode) { resolve(); return; }

    if (newMode === 'off') {
      stopSweeper();
      if (sock) { try { sock.close(); } catch {} sock = null; }
      mode = 'off';
      announceMode();
      resolve();
      return;
    }

    const activate = () => {
      const old = mode;
      mode = newMode;
      if (old === 'off') log('Listening — every DHCP request on the wire shows below');
      if (newMode === 'serve-all')      log(`SERVING ALL on ${serveCfg.adapterIp} — pool ${serveCfg.rangeStart}–${serveCfg.rangeEnd}`);
      if (newMode === 'serve-targeted') log(`SERVING TARGETS on ${serveCfg.adapterIp} — pool ${serveCfg.rangeStart}–${serveCfg.rangeEnd}`);
      if (newMode === 'listen' && (old === 'serve-all' || old === 'serve-targeted')) log('Serving stopped — still listening');
      lastServeAction = Date.now();
      startSweeper();
      announceMode();
      resolve();
    };

    if (sock) { activate(); return; }

    const s = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    s.on('error', (err) => {
      log('DHCP socket error: ' + err.message);
      if (mode === 'off') reject(err);
    });
    s.on('message', (msg, rinfo) => {
      handleDhcpMessage(msg, rinfo).catch(e => log('DHCP parse error: ' + e.message));
    });
    addFirewallRule().then(() => {
      s.bind(67, '0.0.0.0', () => {
        s.setBroadcast(true);
        sock = s;
        activate();
      });
    });
  });
}

function announceMode() {
  updateTray();
  win && win.webContents.send('mode-changed', {
    mode,
    targets: [...targets],
    serveCfg: serveCfg ? { adapterIp: serveCfg.adapterIp, rangeStart: serveCfg.rangeStart, rangeEnd: serveCfg.rangeEnd } : null,
  });
  emitDevices();
}

function isServing() { return mode === 'serve-all' || mode === 'serve-targeted'; }
function allowedToServe(mac) {
  return mode === 'serve-all' || (mode === 'serve-targeted' && targets.has(mac));
}
function localAdapterIps() {
  return new Set(getPhysicalAdapters().filter(a => a.ip).map(a => a.ip));
}

// ── Engine: message handler ───────────────────────────────────────────────────
async function handleDhcpMessage(msg, rinfo) {
  if (msg.length < 240) return;
  if (!(msg[236] === 99 && msg[237] === 130 && msg[238] === 83 && msg[239] === 99)) return;

  // Our own scan traffic: the echoed probe DISCOVER (op=1) must not become a
  // phantom table row, and a relayed reply (op=2, unicast to giaddr:67) is
  // harvested for the collector instead of being parsed as a client.
  const xidHex = msg.slice(4, 8).toString('hex');

  // Scan diagnostics: log EVERY packet seen on :67 during a scan window, whether
  // or not it matches our probe. Tells us if a reply is arriving and being
  // filtered (matched>0 but no server reported = bug) vs never arriving at all
  // (rx67=0 = router silent / firewall / send failed).
  if (scanDebug) {
    scanDebug.rx67++;
    if (probeXids.has(xidHex)) scanDebug.matched67++;
    // A real device asking mid-scan (op=1 client, not one of our probe echoes) —
    // collect it so the scan result can note who else is on the wire.
    else if (msg[0] === 1) {
      const cmac = Array.from(msg.slice(28, 34)).map(b => b.toString(16).padStart(2, '0')).join(':');
      scanDebug.clients.add(cmac);
    }
    if (scanDebug.logged < scanDebug.cap) {
      scanDebug.logged++;
      const src = rinfo ? `${rinfo.address}:${rinfo.port}` : '?';
      log(`SCAN · rx :67 from ${src} op=${msg[0]} xid=${xidHex}${probeXids.has(xidHex) ? ' [our probe]' : ''}`, 'info');
    }
  }

  if (probeXids.has(xidHex)) {
    if (msg[0] === 2 && relayCollector && msg.slice(4, 8).equals(relayCollector.xid)) {
      const ip = parseReplyServerIp(msg) || (rinfo && rinfo.address) || null;
      if (ip) relayCollector.found[ip] = true;
    }
    return;
  }

  if (msg[0] !== 1) return;                                  // BOOTREQUEST only

  const xid    = Buffer.from(msg.slice(4, 8));
  const ciaddr = `${msg[12]}.${msg[13]}.${msg[14]}.${msg[15]}`;
  const chaddr = Buffer.from(msg.slice(28, 34));
  const mac    = Array.from(chaddr).map(b => b.toString(16).padStart(2, '0')).join(':');

  let msgType     = 0;
  let hostname    = '';
  let requestedIp = null;
  let serverIdent = null;
  let i = 240;
  while (i < msg.length - 1) {
    const opt = msg[i++];
    if (opt === 255) break;
    if (opt === 0)   continue;
    const len = msg[i++];
    if (i + len > msg.length) break;
    if (opt === 53 && len === 1) msgType     = msg[i];
    if (opt === 12 && len > 0)   hostname    = msg.slice(i, i + len).toString('utf8').replace(/[^\x20-\x7E]/g, '').trim();
    if (opt === 50 && len === 4) requestedIp = `${msg[i]}.${msg[i+1]}.${msg[i+2]}.${msg[i+3]}`;
    if (opt === 54 && len === 4) serverIdent = `${msg[i]}.${msg[i+1]}.${msg[i+2]}.${msg[i+3]}`;
    i += len;
  }
  if (!msgType) return;

  // Renewal/rebind: no option-50, the client carries its address in ciaddr.
  if (!requestedIp && ciaddr !== '0.0.0.0') requestedIp = ciaddr;

  // ── Registry upsert: every packet feeds the table, in every mode ──
  const now = Date.now();
  let d = devices[mac];
  if (!d) {
    d = devices[mac] = {
      state: 'asking', ip: null, vendor: vendorFromMac(mac), hostname: '',
      firstSeen: now, lastSeen: now, attempts: 0,
      expires: null, offerExpires: null, foreignServer: null, lastXid: null,
    };
  }
  d.lastSeen = now;
  d.lastXid  = xid;
  if (hostname) d.hostname = hostname;
  if (d.state === 'quiet' || d.state === 'declined') { d.state = 'asking'; d.firstSeen = now; d.attempts = 0; }
  if (msgType === 1 || msgType === 3) d.attempts++;

  // ── Passive rogue detection: a REQUEST naming a server that isn't us ──
  if (serverIdent && !localAdapterIps().has(serverIdent)) {
    d.foreignServer = serverIdent;
    if (!foreignServers[serverIdent]) {
      foreignServers[serverIdent] = now;
      log(`OTHER DHCP SERVER on the wire — clients are requesting from ${serverIdent}`);
      win && win.webContents.send('rogue-detected', { server: serverIdent, how: 'passive' });
    } else {
      foreignServers[serverIdent] = now;
    }
  }

  // ── DISCOVER ──
  if (msgType === 1) {
    if (d.state === 'leased') { d.state = 'asking'; }        // device restarted discovery
    if (isServing() && allowedToServe(mac)) {
      await offerWithProbe(mac, requestedIp);
    }
    emitDevices();

  // ── REQUEST ──
  } else if (msgType === 3) {
    // SELECTING-state REQUEST names the chosen server. Not us → let go silently.
    if (serverIdent && serveCfg && serverIdent !== serveCfg.adapterIp) {
      if (d.state === 'offered') { d.state = 'asking'; d.ip = null; d.offerExpires = null; }
      emitDevices();
      return;
    }
    if (isServing() && allowedToServe(mac)) {
      await ackRequest(mac, chaddr, requestedIp);
    }
    emitDevices();

  // ── DECLINE — client found a conflict on the address we gave it ──
  } else if (msgType === 4) {
    if (isServing() && (!serverIdent || (serveCfg && serverIdent === serveCfg.adapterIp))) {
      const badIp = requestedIp || d.ip;
      if (badIp) {
        quarantinedIps.add(badIp);
        delete probeCache[badIp];
        log(`DECLINE from ${mac}  ${badIp} — IP conflict, quarantining address`);
      }
      d.state = 'declined'; d.ip = null; d.offerExpires = null; d.expires = null;
      emitDevices(); updateTray();
    }

  // ── RELEASE ──
  } else if (msgType === 7) {
    if (d.state === 'leased' || d.state === 'offered') {
      log(`RELEASE from ${mac}  ${d.ip || ''}`);
      delete devices[mac];
      emitDevices(); updateTray();
    }

  // ── INFORM — device just wants options; registry note only ──
  } else if (msgType === 8) {
    emitDevices();
  }
}

// ── Engine: offer with conflict probe ─────────────────────────────────────────
async function offerWithProbe(mac, requestedIp) {
  if (probing[mac]) { probing[mac].xid = devices[mac].lastXid; return; }  // coalesce storms
  probing[mac] = { xid: devices[mac].lastXid };

  try {
    const candidates = candidateList(mac, requestedIp);
    let chosen = null;
    let tried = 0;
    for (const ip of candidates) {
      if (tried >= 6) break;
      const cached = probeCache[ip];
      if (cached && (Date.now() - cached.ts) < PROBE_CACHE_MS) {
        if (cached.free) { chosen = ip; break; }
        continue;
      }
      tried++;
      const alive = await probeIp(ip);
      if (alive) {
        quarantinedIps.add(ip);
        log(`Probe: ${ip} is already in use — quarantined, trying next`);
        continue;
      }
      chosen = ip;
      break;
    }

    const d = devices[mac];
    if (!d) return;
    if (!chosen) { log('Pool exhausted — cannot offer'); return; }

    d.state = 'offered';
    d.ip = chosen;
    d.offerExpires = Date.now() + OFFER_HOLD_MS;
    log(`DISCOVER from ${mac} → offering ${chosen}`);
    const offer = buildDhcpPacket(2, probing[mac].xid, macToChaddr(mac), chosen, serveCfg);
    sock && sock.send(offer, 0, offer.length, 68, '255.255.255.255');
    lastServeAction = Date.now();
  } finally {
    delete probing[mac];
  }
}

async function ackRequest(mac, chaddr, requestedIp) {
  const d = devices[mac];
  if (!d) return;

  let ip = null;
  const renewal = (d.state === 'leased' || d.state === 'offered') && d.ip &&
                  (!requestedIp || requestedIp === d.ip);
  if (renewal) {
    ip = d.ip;                                               // our own grant — no probe
  } else {
    // INIT-REBOOT or a requested address we didn't just offer — verify before ACK
    const candidates = candidateList(mac, requestedIp);
    if (requestedIp && candidates[0] === requestedIp) {
      const cached = probeCache[requestedIp];
      const alive = (cached && (Date.now() - cached.ts) < PROBE_CACHE_MS)
        ? !cached.free
        : await probeIp(requestedIp);
      if (!alive) ip = requestedIp;
      else { quarantinedIps.add(requestedIp); log(`Probe: ${requestedIp} is in use — NAK to ${mac}`); }
    } else if (candidates.length) {
      ip = null;                                             // they asked for something we can't give
    }
  }

  if (!ip) {
    const nak = buildNakPacket(d.lastXid, chaddr, serveCfg.adapterIp);
    sock && sock.send(nak, 0, nak.length, 68, '255.255.255.255');
    log(`REQUEST from ${mac} → NAK${requestedIp ? ' (' + requestedIp + ' unavailable)' : ''}`);
    if (d.state === 'offered') { d.state = 'asking'; d.ip = null; d.offerExpires = null; }
    lastServeAction = Date.now();
    return;
  }

  d.state = 'leased';
  d.ip = ip;
  d.offerExpires = null;
  d.expires = Date.now() + serveCfg.leaseSeconds * 1000;
  log(`REQUEST from ${mac} → ACK ${ip}  [${d.vendor}]${d.hostname ? '  ' + d.hostname : ''}`);
  const ack = buildDhcpPacket(5, d.lastXid, chaddr, ip, serveCfg);
  sock && sock.send(ack, 0, ack.length, 68, '255.255.255.255');
  lastServeAction = Date.now();
  win && win.webContents.send('lease-granted', {
    mac, ip, vendor: d.vendor, hostname: d.hostname, expires: d.expires,
    time: new Date().toLocaleTimeString(),
  });
  updateTray();
}

// Ordered candidate IPs for a MAC: reservation → previous address → requested → pool.
function candidateList(mac, requestedIp) {
  const cfg = serveCfg;
  if (!cfg) return [];
  const maskNum   = ipToNum(cfg.subnet);
  const netAddr   = numToIp((ipToNum(cfg.adapterIp) & maskNum) >>> 0);
  const bcastAddr = numToIp(((ipToNum(cfg.adapterIp) & maskNum) | (~maskNum >>> 0)) >>> 0);

  const used = new Set([cfg.adapterIp, netAddr, bcastAddr]);
  if (cfg.gateway) used.add(cfg.gateway);
  if (cfg.dns)     used.add(cfg.dns);
  for (const q of quarantinedIps) used.add(q);
  for (const [m2, d2] of Object.entries(devices)) {
    if (m2 !== mac && d2.ip && (d2.state === 'offered' || d2.state === 'leased')) used.add(d2.ip);
  }
  for (const [m2, ip2] of Object.entries(store.reservations)) {
    if (m2 !== mac) used.add(ip2);                            // reserved for someone else
  }

  const onSubnet = (ip) => isValidIpAddr(ip) && ((ipToNum(ip) & maskNum) === (ipToNum(cfg.adapterIp) & maskNum));
  const out = [];
  const push = (ip) => { if (ip && onSubnet(ip) && !used.has(ip) && !out.includes(ip)) out.push(ip); };

  push(store.reservations[mac]);                              // their pin always wins
  const d = devices[mac];
  if (d && d.ip) push(d.ip);                                  // stick to what they had
  if (requestedIp && cfg.pool.includes(requestedIp)) push(requestedIp);
  for (const ip of cfg.pool) push(ip);
  return out;
}

// Ping-probe a candidate before offering. TTL in the reply means someone's there.
function probeIp(ip) {
  return new Promise((resolve) => {
    exec(`ping -n 1 -w 250 ${ip}`, { timeout: 2500 }, (err, stdout) => {
      const alive = !err && /ttl=/i.test(stdout || '');
      probeCache[ip] = { free: !alive, ts: Date.now() };
      resolve(alive);
    });
  });
}

function macToChaddr(mac) {
  return Buffer.from(mac.split(':').map(h => parseInt(h, 16)));
}

// ── Engine: sweeper (expiry, quiet, idle auto-stop) ───────────────────────────
function startSweeper() {
  if (sweepTimer) return;
  sweepTimer = setInterval(sweep, SWEEP_MS);
}
function stopSweeper() {
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
}

function sweep() {
  const now = Date.now();
  let changed = false;

  for (const mac of Object.keys(devices)) {
    const d = devices[mac];
    if (d.state === 'leased' && d.expires && d.expires < now) {
      log(`Lease expired: ${d.ip}  ${mac}`);
      delete devices[mac];
      changed = true;
    } else if (d.state === 'offered' && d.offerExpires && d.offerExpires < now) {
      d.state = 'asking'; d.offerExpires = null;              // offer lapsed, keep ip as a hint
      changed = true;
    } else if (d.state === 'asking' && (now - d.lastSeen) > QUIET_AFTER_MS) {
      d.state = 'quiet';                                       // stopped asking — answered elsewhere or gave up
      changed = true;
    } else if (d.state === 'quiet' && (now - d.lastSeen) > PURGE_QUIET_MS) {
      delete devices[mac];
      changed = true;
    }
  }

  // Idle auto-stop: served nothing for N minutes → drop to listen
  if (isServing() && store.idleMinutes > 0 &&
      (now - lastServeAction) > store.idleMinutes * 60000) {
    log(`AUTO-STOP — nothing served for ${store.idleMinutes} min, back to listening`);
    targets.clear();
    setMode('listen').catch(() => {});
    win && win.webContents.send('auto-stopped', { idleMinutes: store.idleMinutes });
  }

  if (changed) { emitDevices(); updateTray(); }
}

// ── Engine: device list emission (throttled) ──────────────────────────────────
function emitDevices() {
  if (emitTimer) return;
  emitTimer = setTimeout(() => {
    emitTimer = null;
    win && win.webContents.send('devices-updated', buildDeviceList());
  }, 150);
}

function buildDeviceList() {
  const preview = previewAssignments();
  return Object.entries(devices).map(([mac, d]) => ({
    mac,
    state:         d.state,
    ip:            (d.state === 'offered' || d.state === 'leased') ? d.ip : null,
    wouldOffer:    d.state === 'asking' ? (preview[mac] || null) : null,
    vendor:        d.vendor,
    hostname:      d.hostname || '',
    firstSeen:     d.firstSeen,
    lastSeen:      d.lastSeen,
    attempts:      d.attempts,
    expires:       d.state === 'leased' ? d.expires : null,
    targeted:      targets.has(mac),
    reserved:      store.reservations[mac] || null,
    foreignServer: d.foreignServer,
  }));
}

// Dry-run: what each asking device WOULD get, using the live or preview config.
function previewAssignments() {
  const cfg = serveCfg || previewCfg;
  if (!cfg) return {};
  const maskNum   = ipToNum(cfg.subnet);
  const netAddr   = numToIp((ipToNum(cfg.adapterIp) & maskNum) >>> 0);
  const bcastAddr = numToIp(((ipToNum(cfg.adapterIp) & maskNum) | (~maskNum >>> 0)) >>> 0);

  const used = new Set([cfg.adapterIp, netAddr, bcastAddr]);
  if (cfg.gateway) used.add(cfg.gateway);
  if (cfg.dns)     used.add(cfg.dns);
  for (const q of quarantinedIps) used.add(q);
  for (const d of Object.values(devices)) {
    if (d.ip && (d.state === 'offered' || d.state === 'leased')) used.add(d.ip);
  }

  const onSubnet = (ip) => isValidIpAddr(ip) && ((ipToNum(ip) & maskNum) === (ipToNum(cfg.adapterIp) & maskNum));
  const askers = Object.entries(devices)
    .filter(([, d]) => d.state === 'asking')
    .sort((a, b) => a[1].firstSeen - b[1].firstSeen);

  const result = {};
  for (const [mac, d] of askers) {
    let pick = null;
    const reserved = store.reservations[mac];
    if (reserved && onSubnet(reserved) && !used.has(reserved)) pick = reserved;
    else if (d.ip && onSubnet(d.ip) && !used.has(d.ip)) pick = d.ip;
    else {
      const otherRes = new Set(Object.entries(store.reservations).filter(([m]) => m !== mac).map(([, ip]) => ip));
      for (const ip of cfg.pool) {
        if (!used.has(ip) && !otherRes.has(ip)) { pick = ip; break; }
      }
    }
    if (pick) { result[mac] = pick; used.add(pick); }
  }
  return result;
}

// ── Engine: packet builders ───────────────────────────────────────────────────
function buildDhcpPacket(msgType, xid, chaddr, offeredIp, cfg) {
  const pkt = Buffer.alloc(576, 0);
  pkt[0] = 2; pkt[1] = 1; pkt[2] = 6; pkt[3] = 0;
  xid.copy(pkt, 4);
  ipToBytes(offeredIp).copy(pkt, 16);
  ipToBytes(cfg.adapterIp).copy(pkt, 20);
  chaddr.copy(pkt, 28);
  if (cfg.extras && cfg.extras.bootFile) {
    Buffer.from(cfg.extras.bootFile.substring(0, 127), 'ascii').copy(pkt, 108);   // BOOTP file field
  }
  pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;

  let o = 240;
  const opt = (code, ...vals) => {
    if (vals.length > 255 || o + vals.length + 3 > pkt.length) return;
    pkt[o++] = code; pkt[o++] = vals.length; vals.forEach(v => pkt[o++] = v & 0xff);
  };
  const optStr = (code, s) => opt(code, ...Buffer.from(String(s).substring(0, 255), 'ascii'));

  opt(53, msgType);
  opt(54, ...ipToBytes(cfg.adapterIp));
  opt(51, ...uint32Bytes(cfg.leaseSeconds));
  opt(58, ...uint32Bytes(Math.floor(cfg.leaseSeconds * 0.5)));
  opt(59, ...uint32Bytes(Math.floor(cfg.leaseSeconds * 0.875)));
  opt(1,  ...ipToBytes(cfg.subnet));
  opt(3,  ...ipToBytes(cfg.gateway));
  if (cfg.dns) opt(6, ...ipToBytes(cfg.dns));

  const x = cfg.extras || {};
  if (x.domainName) optStr(15, x.domainName);
  if (x.ntp && isValidIpAddr(x.ntp)) opt(42, ...ipToBytes(x.ntp));
  if (x.tftpServer) optStr(66, x.tftpServer);
  if (x.bootFile)   optStr(67, x.bootFile);
  if (x.opt43 && /^[0-9a-fA-F]+$/.test(x.opt43) && x.opt43.length % 2 === 0) {
    opt(43, ...Buffer.from(x.opt43, 'hex'));
  }
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
function isValidIpAddr(ip) {
  if (typeof ip !== 'string' || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  return ip.split('.').every(o => +o >= 0 && +o <= 255);
}
// Neutralise spreadsheet formula injection — device-supplied hostnames flow into
// the CSV export, and a value starting with = + - @ (or tab/CR) executes as a
// formula when the file is opened in Excel. Prefix those with a single quote.
function csvSafe(val) {
  const s = String(val == null ? '' : val);
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}
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
const LOG_MAX = 200;

function log(msg) {
  const ts = new Date().toLocaleTimeString();
  console.log('[NET//DHCP]', msg);
  LOG_HISTORY.push(`[${ts}] ${msg}`);
  if (LOG_HISTORY.length > LOG_MAX) LOG_HISTORY.shift();
  win && win.webContents.send('dhcp-log', { msg, time: ts });
}
