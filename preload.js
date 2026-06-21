const { contextBridge, ipcRenderer } = require('electron');

// Guard against listener stacking on renderer reload — one listener per channel
function safeOn(channel, handler) {
  ipcRenderer.removeAllListeners(channel);
  ipcRenderer.on(channel, handler);
}

contextBridge.exposeInMainWorld('api', {
  // window
  minimize:           ()           => ipcRenderer.send('win-minimize'),
  close:              ()           => ipcRenderer.send('win-close'),
  getVersion:         ()           => ipcRenderer.invoke('get-version'),

  // adapters & config
  getAdapters:        ()           => ipcRenderer.invoke('get-adapters'),
  getAdapterConfig:   (name)       => ipcRenderer.invoke('get-adapter-config', name),
  loadConfig:         ()           => ipcRenderer.invoke('load-config'),
  saveConfig:         (cfg)        => ipcRenderer.invoke('save-config', cfg),
  validateConfig:     (cfg)        => ipcRenderer.invoke('validate-config', cfg),
  setPreviewConfig:   (cfg)        => ipcRenderer.invoke('set-preview-config', cfg),

  // modes
  serveAll:           (opts)       => ipcRenderer.invoke('serve-all', opts),
  serveDevice:        (mac, opts)  => ipcRenderer.invoke('serve-device', mac, opts),
  unserveDevice:      (mac)        => ipcRenderer.invoke('unserve-device', mac),
  stopServing:        ()           => ipcRenderer.invoke('stop-serving'),

  // quick start & static assist
  quickStart:         ()           => ipcRenderer.invoke('quick-start'),
  staticAssistApply:  (adapter)    => ipcRenderer.invoke('static-assist-apply', adapter),
  staticAssistRevert: ()           => ipcRenderer.invoke('static-assist-revert'),
  staticAssistStatus: ()           => ipcRenderer.invoke('static-assist-status'),

  // probes & diagnostics
  probeDhcp:          ()           => ipcRenderer.invoke('probe-dhcp'),
  getForeignServers:  ()           => ipcRenderer.invoke('get-foreign-servers'),
  selfTest:           (adapter)    => ipcRenderer.invoke('self-test', adapter),

  // reservations & profiles & settings
  getReservations:    ()           => ipcRenderer.invoke('get-reservations'),
  setReservation:     (mac, ip)    => ipcRenderer.invoke('set-reservation', mac, ip),
  clearReservation:   (mac)        => ipcRenderer.invoke('clear-reservation', mac),
  profilesList:       ()           => ipcRenderer.invoke('profiles-list'),
  profilesSave:       (name, cfg)  => ipcRenderer.invoke('profiles-save', name, cfg),
  profilesLoad:       (name)       => ipcRenderer.invoke('profiles-load', name),
  profilesDelete:     (name)       => ipcRenderer.invoke('profiles-delete', name),
  setIdleMinutes:     (n)          => ipcRenderer.invoke('set-idle-minutes', n),
  getIdleMinutes:     ()           => ipcRenderer.invoke('get-idle-minutes'),

  // lease actions & exports
  releaseAll:         ()           => ipcRenderer.invoke('release-all'),
  revokeLease:        (mac)        => ipcRenderer.invoke('revoke-lease', mac),
  exportLeasesCsv:    ()           => ipcRenderer.invoke('export-leases-csv'),
  exportLog:          ()           => ipcRenderer.invoke('export-log'),
  openBrowser:        (ip)         => ipcRenderer.invoke('open-browser', ip),

  // events
  onModeChanged:        (cb) => safeOn('mode-changed',         (_e, d) => cb(d)),
  onDevicesUpdated:     (cb) => safeOn('devices-updated',      (_e, d) => cb(d)),
  onLeaseGranted:       (cb) => safeOn('lease-granted',        (_e, d) => cb(d)),
  onRogueDetected:      (cb) => safeOn('rogue-detected',       (_e, d) => cb(d)),
  onPort67Status:       (cb) => safeOn('port67-status',        (_e, d) => cb(d)),
  onAutoStopped:        (cb) => safeOn('auto-stopped',         (_e, d) => cb(d)),
  onStaticAssistPending:(cb) => safeOn('static-assist-pending',(_e, d) => cb(d)),
  onLog:                (cb) => safeOn('dhcp-log',             (_e, d) => cb(d)),
  onAdapterState:       (cb) => safeOn('adapter-state',        (_e, d) => cb(d)),
});
