'use strict';

/**
 * CBOMScan desktop - Electron main process.
 *
 * Owns the Python backend lifecycle (spawn on start, kill on quit), the app
 * window, and the native integrations the renderer cannot do on its own:
 * folder pickers, save dialogs, opening a terminal or Explorer at a path, and
 * persisting settings.
 */

const { app, BrowserWindow, dialog, ipcMain, nativeTheme, shell, Menu } = require('electron');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');

const IS_WINDOWS = process.platform === 'win32';
const SETTINGS_FILE = path.join(app.getPath('userData'), 'settings.json');

let mainWindow = null;
let backend = null;
let backendPid = null;
let backendPort = 0;
let backendLog = [];

// ------------------------------------------------------------------ utils --

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch {
    return { theme: 'system', recents: [] };
  }
}

function writeSettings(settings) {
  try {
    fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
  } catch (err) {
    console.error('could not persist settings:', err.message);
  }
  return settings;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// --------------------------------------------------------------- backend --

/**
 * Resolve how to start the Python backend.
 *
 * A packaged build ships a self-contained backend executable; a development
 * checkout falls back to the module on the developer's interpreter.
 */
function backendCommand(port) {
  // --exit-with-parent makes the engine shut itself down when this process's
  // stdin pipe closes, which is the only signal available if the app is
  // force-killed and no exit handler ever runs.
  const args = [
    'serve',
    '--host',
    '127.0.0.1',
    '--port',
    String(port),
    '--no-browser',
    '--exit-with-parent',
  ];

  if (process.env.CBOMSCAN_BACKEND) {
    return { command: process.env.CBOMSCAN_BACKEND, args };
  }

  const bundled = path.join(process.resourcesPath || '', 'backend', 'CBOMScan-Backend.exe');
  if (fs.existsSync(bundled)) {
    return { command: bundled, args };
  }

  const python = process.env.CBOMSCAN_PYTHON || (IS_WINDOWS ? 'python' : 'python3');
  return { command: python, args: ['-m', 'cbomscan', ...args] };
}

function waitForHealth(port, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;

  return new Promise((resolve, reject) => {
    const attempt = () => {
      const req = http.get(
        { host: '127.0.0.1', port, path: '/api/health', timeout: 1500 },
        (res) => {
          res.resume();
          if (res.statusCode === 200) return resolve(port);
          retry();
        }
      );
      req.on('error', retry);
      req.on('timeout', () => {
        req.destroy();
        retry();
      });
    };

    const retry = () => {
      if (Date.now() > deadline) {
        return reject(
          new Error(
            'The CBOMScan backend did not start.\n\n' + backendLog.slice(-12).join('\n')
          )
        );
      }
      setTimeout(attempt, 300);
    };

    attempt();
  });
}

async function startBackend() {
  backendPort = await freePort();
  const { command, args } = backendCommand(backendPort);
  backendLog = [`starting: ${command} ${args.join(' ')}`];

  backend = spawn(command, args, {
    cwd: app.isPackaged ? process.resourcesPath : path.join(__dirname, '..'),
    windowsHide: true,
    // stdin must be a pipe we hold open - closing it is the engine's cue to quit.
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: !IS_WINDOWS,
  });

  const record = (chunk) => {
    const text = chunk.toString().trim();
    if (text) backendLog.push(text);
    if (backendLog.length > 200) backendLog.shift();
  };
  backendPid = backend.pid;
  backend.stdout.on('data', record);
  backend.stderr.on('data', record);
  backend.on('error', (err) => backendLog.push(`spawn failed: ${err.message}`));
  backend.on('exit', (code) => backendLog.push(`backend exited with code ${code}`));

  return waitForHealth(backendPort);
}

function stopBackend() {
  if (!backendPid) return;

  // Must be synchronous: an async kill loses the race with app quit and
  // leaves the engine orphaned. /t takes the whole tree, which matters
  // because the packaged backend is a bootloader that forks a worker.
  try {
    if (IS_WINDOWS) {
      spawnSync('taskkill', ['/pid', String(backendPid), '/f', '/t'], {
        windowsHide: true,
        timeout: 5000,
      });
    } else {
      process.kill(-backendPid, 'SIGTERM');
    }
  } catch {
    // Already gone, or never started - either way there is nothing to clean up.
  }

  backendPid = null;
  backend = null;
}

// ---------------------------------------------------------------- window --

function createWindow() {
  const settings = readSettings();

  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 940,
    minHeight: 640,
    show: false,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0d1117' : '#ffffff',
    title: 'CBOMScan',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  Menu.setApplicationMenu(null);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // External links open in the user's browser, never inside the app shell.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  nativeTheme.themeSource = settings.theme || 'system';
}

// ------------------------------------------------------------------- IPC --

ipcMain.handle('app:info', () => ({
  version: app.getVersion(),
  electron: process.versions.electron,
  node: process.versions.node,
  platform: process.platform,
  backendPort,
  packaged: app.isPackaged,
}));

ipcMain.handle('backend:port', () => backendPort);
ipcMain.handle('backend:log', () => backendLog.slice(-60));

ipcMain.handle('settings:get', () => readSettings());
ipcMain.handle('settings:set', (_event, settings) => writeSettings(settings));

ipcMain.handle('theme:set', (_event, theme) => {
  nativeTheme.themeSource = theme;
  const settings = readSettings();
  settings.theme = theme;
  writeSettings(settings);
  return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
});

ipcMain.handle('theme:resolved', () => (nativeTheme.shouldUseDarkColors ? 'dark' : 'light'));

ipcMain.handle('dialog:pickFolder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select a repository to scan',
    properties: ['openDirectory'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('dialog:save', async (_event, { defaultName, content, filters }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save',
    defaultPath: defaultName,
    filters,
  });
  if (result.canceled || !result.filePath) return null;
  fs.writeFileSync(result.filePath, content, 'utf8');
  return result.filePath;
});

ipcMain.handle('shell:reveal', (_event, target) => {
  if (!fs.existsSync(target)) return false;
  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    shell.openPath(target);
  } else {
    shell.showItemInFolder(target);
  }
  return true;
});

ipcMain.handle('shell:external', (_event, url) => shell.openExternal(url));

/**
 * Open a terminal already changed into the given directory.
 *
 * Windows Terminal is preferred when present; cmd.exe is the fallback that
 * always exists. `start` needs a shell, and its first quoted argument is the
 * window title - hence the empty "" before the command.
 */
ipcMain.handle('shell:terminal', (_event, dir) => {
  if (!fs.existsSync(dir)) return { ok: false, error: 'Path no longer exists' };

  try {
    if (IS_WINDOWS) {
      spawn('cmd.exe', ['/c', 'start', '""', 'cmd.exe', '/K', `cd /d "${dir}"`], {
        detached: true,
        stdio: 'ignore',
        windowsHide: false,
      }).unref();
    } else if (process.platform === 'darwin') {
      spawn('open', ['-a', 'Terminal', dir], { detached: true, stdio: 'ignore' }).unref();
    } else {
      spawn('x-terminal-emulator', [], { cwd: dir, detached: true, stdio: 'ignore' }).unref();
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// ----------------------------------------------------------- app startup --

app.whenReady().then(async () => {
  createWindow();

  try {
    await startBackend();
    mainWindow?.webContents.send('backend:ready', backendPort);
  } catch (err) {
    mainWindow?.webContents.send('backend:failed', err.message);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', stopBackend);
process.on('exit', stopBackend);
