'use strict';

/**
 * The only bridge between the renderer and Node. Everything is an explicit,
 * named channel - the renderer never sees ipcRenderer, fs or child_process.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cbomscan', {
  isDesktop: true,

  info: () => ipcRenderer.invoke('app:info'),
  backendPort: () => ipcRenderer.invoke('backend:port'),
  backendLog: () => ipcRenderer.invoke('backend:log'),

  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSettings: (settings) => ipcRenderer.invoke('settings:set', settings),

  setTheme: (theme) => ipcRenderer.invoke('theme:set', theme),
  resolvedTheme: () => ipcRenderer.invoke('theme:resolved'),

  pickFolder: () => ipcRenderer.invoke('dialog:pickFolder'),
  saveFile: (options) => ipcRenderer.invoke('dialog:save', options),

  reveal: (target) => ipcRenderer.invoke('shell:reveal', target),
  openTerminal: (dir) => ipcRenderer.invoke('shell:terminal', dir),
  openExternal: (url) => ipcRenderer.invoke('shell:external', url),

  onBackendReady: (callback) =>
    ipcRenderer.on('backend:ready', (_event, port) => callback(port)),
  onBackendFailed: (callback) =>
    ipcRenderer.on('backend:failed', (_event, message) => callback(message)),
});
