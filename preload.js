const { contextBridge, ipcRenderer } = require('electron');

// Guard against listener stacking on renderer reload — one listener per channel
function safeOn(channel, handler) {
  ipcRenderer.removeAllListeners(channel);
  ipcRenderer.on(channel, handler);
}

contextBridge.exposeInMainWorld('api', {
  minimize:          ()         => ipcRenderer.send('win-minimize'),
  close:             ()         => ipcRenderer.send('win-close'),
  getVersion:        ()         => ipcRenderer.invoke('get-version'),
  getAdapters:       ()         => ipcRenderer.invoke('get-adapters'),
  getAdapterConfig:  (name)     => ipcRenderer.invoke('get-adapter-config', name),
  loadConfig:        ()         => ipcRenderer.invoke('load-config'),
  saveConfig:        (cfg)      => ipcRenderer.invoke('save-config', cfg),
  validateConfig:    (cfg)      => ipcRenderer.invoke('validate-config', cfg),
  startDhcp:         (opts)     => ipcRenderer.invoke('start-dhcp', opts),
  stopDhcp:          ()         => ipcRenderer.invoke('stop-dhcp'),
  releaseAll:        ()         => ipcRenderer.invoke('release-all'),
  revokeLease:       (mac)      => ipcRenderer.invoke('revoke-lease', mac),
  exportLeasesCsv:   ()         => ipcRenderer.invoke('export-leases-csv'),
  exportLog:         ()         => ipcRenderer.invoke('export-log'),
  openBrowser:       (ip)       => ipcRenderer.invoke('open-browser', ip),
  onStatus:          (cb)       => safeOn('dhcp-status',    (_e, d) => cb(d)),
  onLease:           (cb)       => safeOn('dhcp-lease',     (_e, d) => cb(d)),
  onLeasesUpdated:   (cb)       => safeOn('leases-updated', (_e, d) => cb(d)),
  onLog:             (cb)       => safeOn('dhcp-log',       (_e, d) => cb(d)),
  onAdapterState:    (cb)       => safeOn('adapter-state',  (_e, d) => cb(d)),
});
