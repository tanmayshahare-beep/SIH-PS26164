'use strict';

/** Launches the real app and saves screenshots of each page in both themes. */

require('./main.js');

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');

const OUT = process.env.CBOMSCAN_SHOTS || path.join(__dirname, 'screenshots');
const FIXTURES = path.join(__dirname, '..', 'fixtures');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(win, expr, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await win.webContents.executeJavaScript(expr)) return true;
    } catch {
      /* still loading */
    }
    await sleep(250);
  }
  throw new Error(`timed out: ${expr}`);
}

async function run() {
  fs.mkdirSync(OUT, { recursive: true });

  let win = BrowserWindow.getAllWindows()[0];
  while (!win) {
    await sleep(200);
    win = BrowserWindow.getAllWindows()[0];
  }
  if (win.webContents.isLoading()) {
    await new Promise((r) => win.webContents.once('did-finish-load', r));
  }
  const js = (e) => win.webContents.executeJavaScript(e);

  await waitFor(win, "document.getElementById('backend-dot').classList.contains('ok')");
  await waitFor(win, "document.querySelectorAll('#tools .tool').length > 0");
  await waitFor(win, "document.querySelectorAll('#kb-rows tr').length > 0");

  await js(`document.getElementById('repo-path').value = ${JSON.stringify(FIXTURES)}`);
  await js("document.getElementById('btn-scan').click()");
  await waitFor(win, "document.querySelectorAll('#artifact-rows tr').length > 0");
  await sleep(700);

  for (const theme of ['light', 'dark']) {
    await js(`document.querySelector('[data-theme-choice="${theme}"]').click()`);
    await sleep(700);

    for (const page of ['scan', 'results', 'tools', 'kb', 'cli', 'settings']) {
      await js(`document.querySelector('.nav-item[data-page="${page}"]').click()`);
      await sleep(450);
      const image = await win.webContents.capturePage();
      fs.writeFileSync(path.join(OUT, `${page}-${theme}.png`), image.toPNG());
    }
  }

  fs.writeFileSync(path.join(OUT, 'done.txt'), 'captured\n', 'utf8');
}

app.whenReady().then(async () => {
  let code = 0;
  try {
    await run();
  } catch (err) {
    fs.mkdirSync(OUT, { recursive: true });
    fs.writeFileSync(path.join(OUT, 'error.txt'), String(err && err.stack), 'utf8');
    code = 1;
  }
  app.exit(code);
});
