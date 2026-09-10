'use strict';

/**
 * Headless smoke test for the desktop app.
 *
 * Runs with `electron smoke-test.js`. It requires the real main.js, so the
 * app boots exactly as a user's launch would - same backend spawn, same
 * window, same preload - and then drives the renderer through
 * executeJavaScript and asserts on what it finds.
 */

require('./main.js');

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'py-sample');
// Electron builds for Windows are GUI-subsystem binaries, so main-process
// stdout never reaches the launching shell. Results go to a file instead.
const REPORT = process.env.CBOMSCAN_SMOKE_REPORT || path.join(__dirname, 'smoke-report.txt');
const lines = [];
const results = [];
let failures = 0;

function log(text) {
  lines.push(text);
  fs.writeFileSync(REPORT, lines.join('\n') + '\n', 'utf8');
}

function check(name, passed, detail) {
  results.push({ name, passed, detail });
  if (!passed) failures += 1;
  log(`  ${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? `  -> ${detail}` : ''}`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(win, expression, timeoutMs = 60000, label = 'condition') {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await win.webContents.executeJavaScript(expression)) return true;
    } catch {
      /* renderer may still be loading */
    }
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function run() {
  console.log('\nCBOMScan desktop smoke test\n');

  const deadline = Date.now() + 30000;
  let win = BrowserWindow.getAllWindows()[0];
  while (!win && Date.now() < deadline) {
    await sleep(200);
    win = BrowserWindow.getAllWindows()[0];
  }
  check('window is created', Boolean(win));
  if (!win) return;

  if (win.webContents.isLoading()) {
    await new Promise((resolve) => win.webContents.once('did-finish-load', resolve));
  }

  const rendererErrors = [];
  // Electron 30+ passes a single event object; older builds pass positionals.
  win.webContents.on('console-message', (event, level, message) => {
    const lvl = typeof event === 'object' && 'level' in event ? event.level : level;
    const text = typeof event === 'object' && 'message' in event ? event.message : message;
    if (lvl === 'error' || lvl >= 3) rendererErrors.push(text);
  });

  const js = (expr) => win.webContents.executeJavaScript(expr);

  check('renderer loaded', (await js('document.title')) === 'CBOMScan');

  // ---------------------------------------------------------- backend --
  try {
    await waitFor(win, "document.getElementById('backend-dot').classList.contains('ok')",
      90000, 'backend health');
    check('python backend started', true, await js("document.getElementById('backend-status').textContent"));
  } catch (err) {
    const log = await js("document.getElementById('backend-log').textContent");
    check('python backend started', false, `${err.message}\n${log}`);
    return;
  }

  // ------------------------------------------------------------ pages --
  await waitFor(win, "document.querySelectorAll('#tools .tool').length > 0", 20000, 'tools');
  const toolCount = await js("document.querySelectorAll('#tools .tool').length");
  check('diagnostic tools page lists all 5 detectors', toolCount === 5, `${toolCount} cards`);

  const toolTitles = await js(
    "Array.from(document.querySelectorAll('#tools .tool-title')).map(n=>n.textContent).join(' | ')"
  );
  check('tool cards carry their descriptions', toolTitles.includes('Certificate Detector'), toolTitles);

  await waitFor(win, "document.querySelectorAll('#kb-rows tr').length > 0", 20000, 'knowledge base');
  const kbRows = await js("document.querySelectorAll('#kb-rows tr').length");
  check('knowledge base page renders algorithms', kbRows >= 20, `${kbRows} rows`);

  const cliCount = await js("document.querySelectorAll('#cli-content .code').length");
  check('command line page documents the CLI', cliCount >= 10, `${cliCount} commands`);

  // ------------------------------------------------------------ theme --
  await js("document.querySelector('[data-theme-choice=\"dark\"]').click()");
  await sleep(400);
  check('dark theme applies', (await js('document.documentElement.dataset.theme')) === 'dark');

  await js("document.querySelector('[data-theme-choice=\"light\"]').click()");
  await sleep(400);
  check('light theme applies', (await js('document.documentElement.dataset.theme')) === 'light');

  // Read the --bg token rather than the computed background-color: custom
  // properties update synchronously, while background-color is mid-transition.
  const readToken = (theme) =>
    js(
      `(() => {
         const root = document.documentElement;
         const previous = root.dataset.theme;
         root.dataset.theme = '${theme}';
         const value = getComputedStyle(root).getPropertyValue('--bg').trim();
         root.dataset.theme = previous;
         return value;
       })()`
    );

  const lightBg = await readToken('light');
  const darkBg = await readToken('dark');
  check('themes resolve to different palettes', darkBg !== lightBg, `light ${lightBg} / dark ${darkBg}`);

  // ------------------------------------------------------------- scan --
  const target = FIXTURES.replace(/\\/g, '\\\\');
  await js(`document.getElementById('repo-path').value = "${target}"`);
  await js("document.getElementById('btn-scan').click()");

  await waitFor(win, "document.querySelectorAll('#artifact-rows tr').length > 0", 90000, 'scan');
  const rowCount = await js("document.querySelectorAll('#artifact-rows tr').length");
  check('scan populates the artifact table', rowCount === 21, `${rowCount} rows`);

  const activePage = await js("document.querySelector('.page.active').id");
  check('app navigates to results after a scan', activePage === 'page-results', activePage);

  const statValues = await js(
    "Array.from(document.querySelectorAll('.stat-value')).map(n=>n.textContent).join(',')"
  );
  check('summary tiles render', statValues.startsWith('21,'), statValues);

  const segments = await js("document.querySelectorAll('#distribution span').length");
  check('verdict distribution bar renders', segments >= 3, `${segments} segments`);

  // ----------------------------------------------------------- filter --
  await js("document.getElementById('filter-verdict').value='vulnerable';" +
    "document.getElementById('filter-verdict').dispatchEvent(new Event('input'))");
  await sleep(300);
  const filtered = await js("document.querySelectorAll('#artifact-rows tr').length");
  check('verdict filter narrows the table', filtered > 0 && filtered < rowCount, `${filtered} rows`);

  await js("document.getElementById('filter-verdict').value='';" +
    "document.getElementById('filter-verdict').dispatchEvent(new Event('input'))");
  await sleep(200);

  // ----------------------------------------------------------- drawer --
  await js("document.querySelector('#artifact-rows tr').click()");
  await sleep(300);
  const drawerOpen = await js("document.getElementById('drawer').classList.contains('open')");
  const drawerTitle = await js("document.getElementById('drawer-title').textContent");
  check('artifact detail drawer opens', drawerOpen, drawerTitle);
  await js("document.getElementById('drawer-close').click()");

  // ----------------------------------------------------------- export --
  // Driven from inside the page so this also proves the renderer's CSP
  // permits reaching the local backend.
  const cbomOk = await js(`(async () => {
    const port = document.getElementById('backend-status').textContent.split(':')[1].trim();
    const base = 'http://127.0.0.1:' + port;
    const scan = await fetch(base + '/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: ${JSON.stringify(FIXTURES)} })
    });
    if (!scan.ok) return 'scan status ' + scan.status;
    const { artifacts } = await scan.json();
    const res = await fetch(base + '/api/cbom', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifacts })
    });
    if (!res.ok) return 'cbom status ' + res.status;
    const bom = JSON.parse(await res.text());
    return bom.bomFormat + ' ' + bom.specVersion + ' / ' + bom.components.length + ' components';
  })()`);
  check('CBOM export reachable from the app origin', String(cbomOk).startsWith('CycloneDX 1.7'), String(cbomOk));

  const reportOk = await js(`(async () => {
    const port = document.getElementById('backend-status').textContent.split(':')[1].trim();
    const base = 'http://127.0.0.1:' + port;
    const scan = await fetch(base + '/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: ${JSON.stringify(FIXTURES)} })
    });
    const { artifacts } = await scan.json();
    const res = await fetch(base + '/api/report', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifacts })
    });
    const text = await res.text();
    return res.status + ' ' + text.slice(0, 18);
  })()`);
  check('Markdown report export reachable', String(reportOk).includes('# CBOMScan Report'), String(reportOk));

  check('no renderer errors', rendererErrors.length === 0, rendererErrors.join(' | '));

  console.log(
    `\n${results.length - failures}/${results.length} checks passed\n` +
      (failures ? 'RESULT: FAIL\n' : 'RESULT: PASS\n')
  );
}

app.whenReady().then(async () => {
  try {
    await run();
  } catch (err) {
    failures += 1;
    log(`smoke test crashed: ${err && err.stack ? err.stack : err}`);
  }
  app.exit(failures ? 1 : 0);
});
