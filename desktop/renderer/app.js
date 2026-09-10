'use strict';

/**
 * CBOMScan desktop renderer.
 *
 * Talks to the local Python backend over HTTP - the same API the web dashboard
 * uses - and to the Electron main process through the `window.cbomscan`
 * bridge for anything native (dialogs, terminal, theme, settings).
 */

const bridge = window.cbomscan;

const state = {
  port: null,
  ready: false,
  artifacts: [],
  summary: null,
  target: '',
  sort: { key: 'verdict', dir: 1 },
  settings: { theme: 'system', recents: [] },
};

const VERDICT_ORDER = { broken: 0, vulnerable: 1, weakened: 2, safe: 3 };
const CRITICALITY_ORDER = { high: 0, medium: 1, low: 2 };

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const child of children.flat()) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
};

// --------------------------------------------------------------- helpers --

function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => node.classList.remove('show'), 2600);
}

function api(path, options) {
  if (!state.port) return Promise.reject(new Error('Backend is not running yet'));
  return fetch(`http://127.0.0.1:${state.port}${path}`, options).then(async (response) => {
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `Request failed (${response.status})`);
    }
    return response;
  });
}

const getJSON = (path) => api(path).then((r) => r.json());

const postJSON = (path, body) =>
  api(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

function banner(container, kind, message) {
  const node = $(container);
  node.innerHTML = '';
  if (message) node.append(el('div', { className: `banner ${kind}`, textContent: message }));
}

function basename(filePath) {
  return String(filePath).split(/[\\/]/).filter(Boolean).pop() || filePath;
}

// ------------------------------------------------------------ navigation --

document.querySelectorAll('.nav-item').forEach((button) => {
  button.addEventListener('click', () => showPage(button.dataset.page));
});

function showPage(page) {
  document.querySelectorAll('.nav-item').forEach((b) => {
    b.classList.toggle('active', b.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach((p) => {
    p.classList.toggle('active', p.id === `page-${page}`);
  });
  $('main-scroll-anchor')?.scrollIntoView();
  document.querySelector('.main').scrollTop = 0;
}

// ----------------------------------------------------------------- theme --

async function applyTheme(choice) {
  state.settings.theme = choice;
  document.querySelectorAll('[data-theme-choice]').forEach((b) => {
    b.classList.toggle('active', b.dataset.themeChoice === choice);
  });

  let resolved = choice;
  if (bridge) {
    resolved = await bridge.setTheme(choice);
  } else if (choice === 'system') {
    resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.dataset.theme = resolved;
}

document.querySelectorAll('[data-theme-choice]').forEach((button) => {
  button.addEventListener('click', () => applyTheme(button.dataset.themeChoice));
});

// Keep "system" honest when Windows flips appearance while the app is open.
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (state.settings.theme === 'system') applyTheme('system');
});

// ----------------------------------------------------------------- scan --

function readOptions() {
  return {
    horizon_year: Number($('horizon-year').value),
    migration_years: Number($('migration-years').value),
    data_lifetime: Number($('data-lifetime').value),
  };
}

[
  ['horizon-year', (v) => v],
  ['migration-years', (v) => Number(v).toFixed(1)],
  ['data-lifetime', (v) => v],
].forEach(([id, format]) => {
  const input = $(id);
  const label = $(`${id}-value`);
  const sync = () => (label.textContent = format(input.value));
  input.addEventListener('input', sync);
  sync();
});

$('btn-browse').addEventListener('click', async () => {
  if (!bridge) return toast('Folder picker is only available in the desktop app');
  const chosen = await bridge.pickFolder();
  if (chosen) $('repo-path').value = chosen;
});

$('btn-scan').addEventListener('click', runScan);
$('repo-path').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runScan();
});

async function runScan() {
  const target = $('repo-path').value.trim();
  if (!target) return banner('scan-banner', 'error', 'Choose a repository folder first.');
  if (!state.ready) return banner('scan-banner', 'error', 'The backend is not ready yet.');

  const button = $('btn-scan');
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> Scanning…';
  banner('scan-banner', 'info', `Scanning ${target}…`);

  try {
    const response = await postJSON('/api/scan', { path: target, ...readOptions() });
    const data = await response.json();

    state.artifacts = data.artifacts;
    state.summary = data.summary;
    state.target = target;

    rememberRecent(target);
    renderResults();
    banner('scan-banner', '', '');
    showPage('results');
    toast(`Found ${data.summary.total} cryptographic assets`);
  } catch (err) {
    banner('scan-banner', 'error', err.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Run scan';
  }
}

// --------------------------------------------------------------- recents --

function rememberRecent(target) {
  const recents = [target, ...state.settings.recents.filter((r) => r !== target)].slice(0, 6);
  state.settings.recents = recents;
  bridge?.setSettings(state.settings);
  renderRecents();
}

function renderRecents() {
  const container = $('recents');
  const recents = state.settings.recents || [];
  $('recents-section').style.display = recents.length ? 'block' : 'none';
  container.innerHTML = '';

  for (const item of recents) {
    container.append(
      el(
        'div',
        { className: 'recent' },
        el('div', { className: 'recent-path', textContent: item, title: item }),
        el('button', {
          className: 'ghost',
          textContent: 'Scan',
          onclick: () => {
            $('repo-path').value = item;
            runScan();
          },
        }),
        el('button', {
          className: 'ghost',
          textContent: 'Terminal',
          onclick: () => openTerminal(item),
        }),
        el('button', {
          className: 'ghost',
          textContent: 'Folder',
          onclick: () => bridge?.reveal(item),
        })
      )
    );
  }
}

// ------------------------------------------------------- native actions --

async function openTerminal(dir) {
  if (!bridge) return toast('Terminal is only available in the desktop app');
  const target = dir || $('repo-path').value.trim();
  if (!target) return toast('Choose a repository folder first');
  const result = await bridge.openTerminal(target);
  toast(result.ok ? 'Terminal opened' : `Could not open terminal: ${result.error}`);
}

$('btn-terminal').addEventListener('click', () => openTerminal());
$('btn-results-terminal').addEventListener('click', () => openTerminal(state.target));
$('btn-reveal').addEventListener('click', async () => {
  const target = $('repo-path').value.trim();
  if (!target) return toast('Choose a repository folder first');
  const ok = await bridge?.reveal(target);
  if (!ok) toast('That path no longer exists');
});

// --------------------------------------------------------------- results --

function renderResults() {
  const has = state.artifacts.length > 0;
  $('results-empty').style.display = has ? 'none' : 'block';
  $('results-content').style.display = has ? 'block' : 'none';
  if (!has) return;

  const s = state.summary;
  $('results-sub').textContent = `${state.target} — ${s.total} unique assets`;

  const verdicts = s.by_verdict || {};
  const safeCount = Math.max(0, (verdicts.safe || 0) - s.needs_review);
  const tiles = [
    { value: s.total, label: 'Total assets', tone: '' },
    { value: verdicts.broken || 0, label: 'Already broken', tone: 'danger' },
    { value: verdicts.vulnerable || 0, label: 'Quantum-vulnerable', tone: 'danger' },
    { value: verdicts.weakened || 0, label: 'Quantum-weakened', tone: 'warning' },
    { value: safeCount, label: 'Quantum-safe', tone: 'success' },
    { value: s.needs_review, label: 'Needs manual review', tone: 'neutral' },
  ];

  const stats = $('stats');
  stats.innerHTML = '';
  for (const tile of tiles) {
    stats.append(
      el(
        'div',
        { className: `stat ${tile.tone}` },
        el('div', { className: 'stat-value', textContent: String(tile.value) }),
        el('div', { className: 'stat-label', textContent: tile.label })
      )
    );
  }

  const segments = [
    { key: 'broken', count: verdicts.broken || 0, color: 'var(--danger)' },
    { key: 'vulnerable', count: verdicts.vulnerable || 0, color: 'var(--danger)' },
    { key: 'weakened', count: verdicts.weakened || 0, color: 'var(--warning)' },
    { key: 'safe', count: safeCount, color: 'var(--success)' },
    { key: 'review', count: s.needs_review, color: 'var(--neutral)' },
  ].filter((seg) => seg.count > 0);

  const total = segments.reduce((sum, seg) => sum + seg.count, 0) || 1;
  const bar = $('distribution');
  const legend = $('legend');
  bar.innerHTML = '';
  legend.innerHTML = '';

  for (const seg of segments) {
    bar.append(
      el('span', {
        style: `width:${(seg.count / total) * 100}%;background:${seg.color}`,
        title: `${seg.key}: ${seg.count}`,
      })
    );
    legend.append(
      el(
        'div',
        { className: 'legend-item' },
        el('span', { className: 'swatch', style: `background:${seg.color}` }),
        `${seg.key} ${seg.count}`
      )
    );
  }

  renderTable();
}

function sortedFiltered() {
  const text = $('filter-text').value.trim().toLowerCase();
  const verdict = $('filter-verdict').value;
  const confidence = $('filter-confidence').value;

  const rows = state.artifacts.filter((a) => {
    if (verdict && a.verdict !== verdict) return false;
    if (confidence && a.confidence !== confidence) return false;
    if (!text) return true;
    const haystack = [
      a.name,
      a.primitive,
      a.recommendation,
      ...a.occurrences.map((o) => `${o.file} ${o.symbol || ''}`),
    ]
      .join(' ')
      .toLowerCase();
    return haystack.includes(text);
  });

  const { key, dir } = state.sort;
  rows.sort((a, b) => {
    let x;
    let y;
    if (key === 'verdict') {
      x = VERDICT_ORDER[a.verdict] ?? 9;
      y = VERDICT_ORDER[b.verdict] ?? 9;
    } else if (key === 'criticality') {
      x = CRITICALITY_ORDER[a.criticality] ?? 9;
      y = CRITICALITY_ORDER[b.criticality] ?? 9;
    } else if (key === 'occurrences') {
      x = a.occurrences.length;
      y = b.occurrences.length;
    } else {
      x = String(a[key] ?? '').toLowerCase();
      y = String(b[key] ?? '').toLowerCase();
    }
    if (x < y) return -dir;
    if (x > y) return dir;
    return a.name.localeCompare(b.name);
  });

  return rows;
}

function renderTable() {
  const rows = sortedFiltered();
  const body = $('artifact-rows');
  body.innerHTML = '';
  $('filter-count').textContent = `${rows.length} of ${state.artifacts.length}`;

  for (const artifact of rows) {
    const first = artifact.occurrences[0];
    const where = first
      ? `${basename(first.file)}${first.line ? ':' + first.line : ''}` +
        (artifact.occurrences.length > 1 ? `  +${artifact.occurrences.length - 1}` : '')
      : '—';

    const row = el(
      'tr',
      { onclick: () => openDrawer(artifact) },
      el('td', { className: 'name', textContent: artifact.name }),
      el('td', { className: 'mono', textContent: artifact.asset_type }),
      el(
        'td',
        {},
        el('span', { className: `badge ${artifact.verdict}`, textContent: artifact.verdict })
      ),
      el(
        'td',
        {},
        el('span', {
          className: `badge ${artifact.confidence}`,
          textContent: artifact.confidence,
        })
      ),
      el('td', { className: 'mono', textContent: artifact.criticality }),
      el('td', { className: 'mono', textContent: where, title: first ? first.file : '' })
    );
    body.append(row);
  }
}

['filter-text', 'filter-verdict', 'filter-confidence'].forEach((id) => {
  $(id).addEventListener('input', renderTable);
});

document.querySelectorAll('th[data-sort]').forEach((th) => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
    renderTable();
  });
});

// ---------------------------------------------------------------- drawer --

function openDrawer(artifact) {
  $('drawer-title').textContent = artifact.name;
  const body = $('drawer-body');
  body.innerHTML = '';

  const detail = (key, value) =>
    value == null || value === ''
      ? null
      : el(
          'div',
          { className: 'detail-row' },
          el('div', { className: 'detail-key', textContent: key }),
          el('div', { className: 'detail-value', textContent: String(value) })
        );

  [
    detail('Asset type', artifact.asset_type),
    detail('Primitive', artifact.primitive),
    detail('Key size', artifact.key_size),
    detail('Curve', artifact.curve),
    detail('Verdict', artifact.verdict),
    detail('Confidence', artifact.confidence),
    detail('Criticality', artifact.criticality),
    detail('Migration years (X)', artifact.migration_years),
    detail('Data lifetime (Y)', artifact.data_lifetime_years),
  ]
    .filter(Boolean)
    .forEach((node) => body.append(node));

  if (artifact.recommendation) {
    body.append(el('div', { className: 'section-title', textContent: 'Recommendation' }));
    body.append(el('div', { textContent: artifact.recommendation }));
  }

  if (artifact.notes) {
    body.append(el('div', { className: 'section-title', textContent: 'Risk assessment' }));
    body.append(el('div', { className: 'hint', textContent: artifact.notes.replace(/^\s*\|\s*/, '') }));
  }

  if (artifact.occurrences.length) {
    body.append(
      el('div', {
        className: 'section-title',
        textContent: `Occurrences (${artifact.occurrences.length})`,
      })
    );
    for (const occ of artifact.occurrences) {
      body.append(
        el('div', {
          className: 'occurrence',
          textContent:
            `${occ.file}${occ.line ? ':' + occ.line : ''}` +
            (occ.symbol ? `  ${occ.symbol}` : ''),
        })
      );
    }
  }

  $('drawer').classList.add('open');
  $('drawer-backdrop').classList.add('open');
}

function closeDrawer() {
  $('drawer').classList.remove('open');
  $('drawer-backdrop').classList.remove('open');
}

$('drawer-close').addEventListener('click', closeDrawer);
$('drawer-backdrop').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
});

// ---------------------------------------------------------------- export --

async function exportFile(endpoint, defaultName, filters) {
  if (!state.artifacts.length) return toast('Run a scan first');
  try {
    const response = await postJSON(endpoint, { artifacts: state.artifacts });
    const content = await response.text();
    if (!bridge) return toast('Saving is only available in the desktop app');
    const saved = await bridge.saveFile({ defaultName, content, filters });
    toast(saved ? `Saved to ${saved}` : 'Save cancelled');
  } catch (err) {
    toast(err.message);
  }
}

const stamp = () => new Date().toISOString().slice(0, 10);
const projectName = () => basename(state.target) || 'scan';

$('btn-export-cbom').addEventListener('click', () =>
  exportFile('/api/cbom', `cbom-${projectName()}-${stamp()}.json`, [
    { name: 'CycloneDX CBOM', extensions: ['json'] },
  ])
);

$('btn-export-report').addEventListener('click', () =>
  exportFile('/api/report', `report-${projectName()}-${stamp()}.md`, [
    { name: 'Markdown report', extensions: ['md'] },
  ])
);

// ----------------------------------------------------------------- tools --

async function loadTools() {
  const container = $('tools');
  try {
    const tools = await getJSON('/api/detectors');
    container.innerHTML = '';

    for (const tool of tools) {
      container.append(
        el(
          'div',
          { className: 'tool' },
          el(
            'div',
            { className: 'tool-head' },
            el('span', { className: 'tool-title', textContent: tool.title }),
            el('span', { className: 'tool-id', textContent: tool.name }),
            el('span', {
              className: `badge ${tool.typical_confidence}`,
              textContent: tool.typical_confidence,
            })
          ),
          el('div', { className: 'tool-summary', textContent: tool.summary }),
          el('div', { className: 'tool-detail', textContent: tool.detail }),
          el(
            'div',
            { className: 'tool-meta' },
            tool.inputs.map((input) => el('span', { className: 'chip', textContent: input }))
          ),
          el('ul', {}, tool.detects.map((item) => el('li', { textContent: item })))
        )
      );
    }
  } catch (err) {
    container.innerHTML = '';
    container.append(el('div', { className: 'banner error', textContent: err.message }));
  }
}

// ------------------------------------------------------------------- kb --

let kbEntries = [];

async function loadKnowledgeBase() {
  try {
    kbEntries = await getJSON('/api/knowledge-base');
    renderKB();
  } catch (err) {
    $('kb-rows').innerHTML = '';
    $('kb-rows').append(el('tr', {}, el('td', { colSpan: 5, textContent: err.message })));
  }
}

function renderKB() {
  const text = $('kb-filter').value.trim().toLowerCase();
  const rows = kbEntries.filter((e) =>
    !text || JSON.stringify(e).toLowerCase().includes(text)
  );

  $('kb-count').textContent = `${rows.length} of ${kbEntries.length} algorithms`;
  const body = $('kb-rows');
  body.innerHTML = '';

  for (const entry of rows) {
    body.append(
      el(
        'tr',
        {},
        el('td', { className: 'name', textContent: entry.algorithm }),
        el(
          'td',
          {},
          el('span', { className: `badge ${entry.verdict}`, textContent: entry.verdict })
        ),
        el('td', { textContent: entry.reason || '—' }),
        el('td', { textContent: entry.replacement || '—' }),
        el('td', { className: 'mono', textContent: entry.maturity || '—' })
      )
    );
  }
}

$('kb-filter').addEventListener('input', renderKB);

// ------------------------------------------------------------------ cli --

const CLI_COMMANDS = [
  {
    command: 'cbomscan scan <path>',
    description: 'Scan a folder and write a CycloneDX 1.7 CBOM to cbom.json.',
  },
  {
    command: 'cbomscan scan . -f md -o report.md',
    description: 'Write a human-readable Markdown report instead.',
  },
  {
    command: 'cbomscan scan . --horizon-year 2035',
    description: 'Move Z in Mosca’s inequality - the same slider as the Scan page.',
  },
  {
    command: 'cbomscan scan . --migration-years 3 --data-lifetime 25',
    description: 'Override X and Y for a repository with unusual constraints.',
  },
  {
    command: 'cbomscan scan . --json',
    description: 'Emit the summary as JSON on stdout, for CI pipelines.',
  },
  {
    command: 'cbomscan scan . --no-validate',
    description: 'Skip CBOM schema validation (validation is on by default and runs offline).',
  },
  { command: 'cbomscan detectors', description: 'List the diagnostic tools shown on this app’s Tools page.' },
  { command: 'cbomscan detectors --json', description: 'The same listing, machine-readable.' },
  { command: 'cbomscan serve', description: 'Run the API and web dashboard on http://127.0.0.1:8000.' },
  { command: 'cbomscan app', description: 'Launch this desktop application.' },
  { command: 'cbomscan wizard', description: 'Launch the step-by-step setup wizard.' },
  { command: 'cbomscan version', description: 'Print the installed version.' },
];

function renderCLI() {
  const container = $('cli-content');
  container.innerHTML = '';

  container.append(
    el('div', { className: 'banner info' },
      'The `cbomscan` command is installed globally, so it works from any terminal - ' +
      'including the one this app opens for you on the Scan page.')
  );

  container.append(el('div', { className: 'section-title', textContent: 'Commands' }));

  for (const entry of CLI_COMMANDS) {
    container.append(
      el(
        'div',
        { className: 'cli-entry' },
        el('p', { className: 'cli-desc', textContent: entry.description }),
        el(
          'div',
          { className: 'code' },
          el('code', { textContent: entry.command }),
          el('button', {
            className: 'ghost',
            textContent: 'Copy',
            onclick: () => {
              navigator.clipboard.writeText(entry.command);
              toast('Copied to clipboard');
            },
          })
        )
      )
    );
  }

  container.append(el('div', { className: 'section-title', textContent: 'Exit codes' }));
  container.append(
    el('pre', {
      className: 'block',
      textContent:
        '0   success\n' +
        '1   an I/O error occurred while writing output\n' +
        '2   the path or knowledge base could not be read\n' +
        '130 interrupted with Ctrl+C',
    })
  );
}

// ------------------------------------------------------------- settings --

async function renderAbout() {
  const container = $('about');
  container.innerHTML = '';

  let info = { version: '0.1.0', platform: navigator.platform, packaged: false };
  if (bridge) info = await bridge.info();

  let backend = {};
  try {
    backend = await getJSON('/api/config');
  } catch {
    backend = {};
  }

  const rows = [
    ['App version', info.version],
    ['Engine version', backend.version || 'unavailable'],
    ['Electron', info.electron || 'n/a'],
    ['Platform', info.platform],
    ['Backend port', state.port || 'not running'],
    ['Knowledge base', backend.knowledge_base_entries ? `${backend.knowledge_base_entries} algorithms` : '—'],
  ];

  for (const [key, value] of rows) {
    container.append(
      el(
        'div',
        { className: 'detail-row' },
        el('div', { className: 'detail-key', textContent: key }),
        el('div', { className: 'detail-value', textContent: String(value) })
      )
    );
  }
}

$('btn-refresh-log').addEventListener('click', async () => {
  if (!bridge) return;
  const lines = await bridge.backendLog();
  $('backend-log').textContent = lines.join('\n') || '—';
});

// ----------------------------------------------------------------- boot --

function setBackendStatus(kind, text) {
  $('backend-dot').className = `dot ${kind}`;
  $('backend-status').textContent = text;
}

async function onBackendReady(port) {
  state.port = port;
  state.ready = true;
  setBackendStatus('ok', `engine :${port}`);

  try {
    const config = await getJSON('/api/config');
    $('brand-version').textContent = `v${config.version}`;
    $('horizon-year').value = config.horizon_year;
    $('migration-years').value = config.default_migration_years;
    $('data-lifetime').value = config.default_data_lifetime_years;
    $('horizon-year').dispatchEvent(new Event('input'));
    $('migration-years').dispatchEvent(new Event('input'));
    $('data-lifetime').dispatchEvent(new Event('input'));
  } catch {
    /* defaults in the markup remain */
  }

  loadTools();
  loadKnowledgeBase();
  renderAbout();
}

async function boot() {
  renderCLI();

  if (bridge) {
    state.settings = await bridge.getSettings();
    renderRecents();
    await applyTheme(state.settings.theme || 'system');

    bridge.onBackendReady(onBackendReady);
    bridge.onBackendFailed((message) => {
      setBackendStatus('bad', 'engine failed');
      banner('scan-banner', 'error', message);
      $('backend-log').textContent = message;
    });

    // The ready event may have fired before this listener was attached.
    const port = await bridge.backendPort();
    if (port) {
      try {
        await fetch(`http://127.0.0.1:${port}/api/health`);
        onBackendReady(port);
      } catch {
        /* the event will arrive shortly */
      }
    }
  } else {
    // Running in a plain browser against `cbomscan serve`.
    state.port = Number(location.port) || 8000;
    await applyTheme('system');
    onBackendReady(state.port);
  }
}

boot();
