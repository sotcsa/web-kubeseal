import {
  importPublicKey,
  certificateInfo,
  encryptValue,
  SCOPES,
  scopeLabel,
  dockerConfigJson,
  buildSealedSecret,
  toYaml,
} from './kubeseal.js';
import { parseSealedSecret, updatedYaml } from './existing.js';
import { fetchCertificate } from './cert-url.js';

const $ = (id) => document.getElementById(id);
const els = {
  mode: $('mode'),
  existingCard: $('existingCard'),
  existing: $('existing'),
  existingFile: $('existingFile'),
  existingStatus: $('existingStatus'),
  existingDropzone: $('existingDropzone'),
  lockNote: $('lockNote'),
  namespace: $('namespace'),
  name: $('name'),
  cert: $('cert'),
  certFile: $('certFile'),
  certStatus: $('certStatus'),
  certUrl: $('certUrl'),
  certUrlForm: $('certUrlForm'),
  certUrlLoad: $('certUrlLoad'),
  dropzone: $('dropzone'),
  type: $('type'),
  opaqueFields: $('opaqueFields'),
  dockerFields: $('dockerFields'),
  dockerEditHint: $('dockerEditHint'),
  pairs: $('pairs'),
  addPair: $('addPair'),
  dockerServer: $('dockerServer'),
  dockerUsername: $('dockerUsername'),
  dockerPassword: $('dockerPassword'),
  dockerEmail: $('dockerEmail'),
  revealPassword: $('revealPassword'),
  output: $('output'),
  empty: $('empty'),
  emptyText: document.querySelector('#empty p'),
  checklist: $('checklist'),
  errors: $('errors'),
  changes: $('changes'),
  meta: $('meta'),
  liveDot: $('liveDot'),
  copy: $('copy'),
  download: $('download'),
  toast: $('toast'),
};

const DOCKER_TYPE = 'kubernetes.io/dockerconfigjson';
const DOCKER_KEY = '.dockerconfigjson';
const DNS_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const SECRET_KEY = /^[-._a-zA-Z0-9]+$/;
const CERT_HINT = 'Lekérése: <code>kubeseal --fetch-cert &gt; cert.pem</code>';
const EXISTING_HINT = 'A kulcsok értékei titkosítva maradnak, csak a módosítottak titkosítódnak újra.';

const CHECKLISTS = {
  new: [
    ['namespace', 'Namespace'],
    ['name', 'Name'],
    ['cert', 'Érvényes tanúsítvány'],
    ['data', 'Legalább egy titok'],
  ],
  edit: [
    ['existing', 'Meglévő SealedSecret'],
    ['cert', 'Érvényes tanúsítvány (ugyanabból a clusterből)'],
  ],
};

// Keep ciphertexts stable while only unrelated fields change: cache per (label, value).
let keyCache = { pem: null, key: null };
let cipherCache = new Map();
let generation = 0;
let currentYaml = '';
let mode = 'new';
let existing = null; // parsed SealedSecret in edit mode
let existingText = null;

async function getKey(pem) {
  if (keyCache.pem !== pem) {
    keyCache = { pem, key: importPublicKey(pem) };
    cipherCache = new Map();
  }
  return keyCache.key;
}

function encryptCached(key, value, scope, namespace, name) {
  const id = `${scopeLabel(scope, namespace, name)}\u0000${value}`;
  if (!cipherCache.has(id)) cipherCache.set(id, encryptValue(key, value, { scope, namespace, name }));
  return cipherCache.get(id);
}

// ---------- segmented controls ----------

function segmentedValue(group) {
  return group.querySelector('[aria-checked="true"]').dataset.value;
}

function setSegmented(group, value) {
  for (const b of group.querySelectorAll('button')) b.setAttribute('aria-checked', String(b.dataset.value === value));
}

function setupSegmented(group, onChange) {
  group.addEventListener('click', (e) => {
    const button = e.target.closest('button[data-value]');
    if (!button || button.disabled || button.getAttribute('aria-checked') === 'true') return;
    setSegmented(group, button.dataset.value);
    onChange?.(button.dataset.value);
    schedule();
  });
}

function setDisabled(group, disabled) {
  for (const b of group.querySelectorAll('button')) b.disabled = disabled;
}

function applyType(value) {
  const docker = value === DOCKER_TYPE;
  els.dockerFields.hidden = !docker;
  els.opaqueFields.hidden = docker;
}

// ---------- key/value pairs ----------

function autosize(textarea) {
  textarea.style.height = 'auto';
  textarea.style.height = `${textarea.scrollHeight + 2}px`;
}

function addPair(key = '', value = '') {
  const node = $('pairTemplate').content.firstElementChild.cloneNode(true);
  const keyInput = node.querySelector('.pair-key');
  const valueInput = node.querySelector('.pair-value');
  keyInput.value = key;
  valueInput.value = value;
  valueInput.addEventListener('input', () => autosize(valueInput));
  keyInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      valueInput.focus();
    }
  });
  node.querySelector('.remove').addEventListener('click', () => {
    node.remove();
    if (mode === 'new' && !els.pairs.children.length) addPair();
    schedule();
  });
  els.pairs.append(node);
  autosize(valueInput);
  return node;
}

function setRowState(row, state) {
  row.dataset.state = state;
  const value = row.querySelector('.pair-value');
  value.hidden = state !== 'replaced';
  row.querySelector('.locked').hidden = state === 'replaced';
  row.querySelector('.locked-text').textContent =
    state === 'deleted' ? 'törlésre jelölve' : 'titkosítva · változatlan';
  row.querySelector('.replace').hidden = state !== 'kept';
  row.querySelector('.cancel').hidden = state !== 'replaced';
  row.querySelector('.undo').hidden = state !== 'deleted';
  row.querySelector('.remove').hidden = state === 'deleted';
  if (state !== 'replaced') value.value = '';
  schedule();
}

function addExistingPair(key) {
  const row = $('existingPairTemplate').content.firstElementChild.cloneNode(true);
  row.dataset.key = key;
  row.querySelector('.pair-key').value = key;
  const value = row.querySelector('.pair-value');
  value.addEventListener('input', () => autosize(value));
  row.querySelector('.replace').addEventListener('click', () => {
    setRowState(row, 'replaced');
    autosize(value);
    value.focus();
  });
  row.querySelector('.cancel').addEventListener('click', () => setRowState(row, 'kept'));
  row.querySelector('.remove').addEventListener('click', () => setRowState(row, 'deleted'));
  row.querySelector('.undo').addEventListener('click', () => setRowState(row, 'kept'));
  els.pairs.append(row);
  return row;
}

function dockerInput() {
  const server = els.dockerServer.value.trim();
  const username = els.dockerUsername.value;
  const password = els.dockerPassword.value;
  if (!server || !username || !password) return null;
  return dockerConfigJson({ server, username, password, email: els.dockerEmail.value.trim() });
}

// New mode: plaintext values to encrypt, keyed by secret key.
function collectData(errors) {
  if (segmentedValue(els.type) === DOCKER_TYPE) {
    const json = dockerInput();
    return json ? { [DOCKER_KEY]: json } : {};
  }
  return collectNewPairs(errors, new Set());
}

function collectNewPairs(errors, taken) {
  const data = {};
  for (const row of els.pairs.querySelectorAll('.pair:not(.existing)')) {
    const keyInput = row.querySelector('.pair-key');
    const key = keyInput.value.trim();
    const value = row.querySelector('.pair-value').value;
    keyInput.classList.remove('invalid');
    if (!key && !value) continue;
    if (!SECRET_KEY.test(key)) {
      keyInput.classList.add('invalid');
      errors.push(key ? `Érvénytelen kulcs: „${key}” (betűk, számok, - _ . engedélyezett)` : 'Egy értékhez hiányzik a kulcs');
      continue;
    }
    if (key in data || taken.has(key)) {
      keyInput.classList.add('invalid');
      errors.push(
        taken.has(key)
          ? `A(z) „${key}” kulcs már létezik – a meglévő sorában válaszd az „Új érték” gombot`
          : `Ismétlődő kulcs: „${key}”`,
      );
      continue;
    }
    data[key] = value;
  }
  return data;
}

// Edit mode: which existing keys stay, change or go, plus new keys.
function collectEdit(errors) {
  const kept = [];
  const replaced = {};
  const deleted = [];
  if (existing.type === DOCKER_TYPE) {
    const json = dockerInput();
    if (json) replaced[DOCKER_KEY] = json;
    for (const k of Object.keys(existing.encryptedData)) if (!(k in replaced)) kept.push(k);
    return { kept, replaced, deleted, added: {} };
  }
  for (const row of els.pairs.querySelectorAll('.pair.existing')) {
    const key = row.querySelector('.pair-key').value;
    if (row.dataset.state === 'replaced') replaced[key] = row.querySelector('.pair-value').value;
    else if (row.dataset.state === 'deleted') deleted.push(key);
    else kept.push(key);
  }
  const added = collectNewPairs(errors, new Set(Object.keys(existing.encryptedData)));
  return { kept, replaced, deleted, added };
}

// ---------- rendering ----------

const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function highlightYaml(yaml, marks = {}) {
  let inData = false;
  return yaml
    .split('\n')
    .map((line) => {
      const indent = line.length - line.trimStart().length;
      if (/^\s*encryptedData:\s*$/.test(line)) inData = true;
      else if (inData && line.trim() && indent <= 2) inData = false;
      const m = /^(\s*)([^:\s][^:]*):( ?)(.*)$/.exec(line);
      if (!m) return escapeHtml(line);
      const [, pad, key, space, value] = m;
      const cls = value.length > 80 ? 'cipher' : 's';
      const html = `${pad}<span class="k">${escapeHtml(key)}</span><span class="p">:</span>${space}${
        value ? `<span class="${cls}">${escapeHtml(value)}</span>` : ''
      }`;
      const mark = inData && indent > 2 ? marks[key] : null;
      if (mark) return `<span class="line-${mark}">${html}</span>`;
      if (Object.keys(marks).length && inData && indent > 2) return `<span class="dim">${html}</span>`;
      return html;
    })
    .join('\n');
}

function renderChecklist() {
  els.checklist.innerHTML = CHECKLISTS[mode]
    .map(([id, label]) => `<li data-check="${id}">${escapeHtml(label)}</li>`)
    .join('');
}

function setChecklist(state) {
  for (const li of els.checklist.children) li.classList.toggle('done', Boolean(state[li.dataset.check]));
}

function showOutput(yaml, meta, marks) {
  const changed = yaml !== currentYaml;
  currentYaml = yaml;
  els.output.firstElementChild.innerHTML = highlightYaml(yaml, marks);
  els.output.hidden = false;
  els.empty.hidden = true;
  els.copy.disabled = false;
  els.download.disabled = false;
  els.liveDot.className = 'live on';
  els.meta.textContent = `· ${meta}`;
  if (changed) {
    els.output.classList.remove('flash');
    void els.output.offsetWidth; // restart animation
    els.output.classList.add('flash');
  }
}

function showEmpty() {
  currentYaml = '';
  els.output.hidden = true;
  els.empty.hidden = false;
  els.copy.disabled = true;
  els.download.disabled = true;
  els.liveDot.className = 'live idle';
  els.meta.textContent = '';
  els.changes.hidden = true;
}

function showChanges(edit) {
  const chips = [
    ...Object.keys(edit.replaced).map((k) => `<span class="c-changed" title="Módosítva">~ ${escapeHtml(k)}</span>`),
    ...Object.keys(edit.added).map((k) => `<span class="c-added" title="Új">+ ${escapeHtml(k)}</span>`),
    ...edit.deleted.map((k) => `<span class="c-deleted" title="Törölve">− ${escapeHtml(k)}</span>`),
  ];
  els.changes.innerHTML = chips.length ? chips.join('') : '<span class="c-none">Még nincs változás</span>';
  els.changes.hidden = false;
}

function formatDate(d) {
  return d.toLocaleDateString('hu-HU', { year: 'numeric', month: 'short', day: 'numeric' });
}

function setStatus(el, kind, html) {
  el.className = `cert-status ${kind}`;
  el.innerHTML = html;
}

async function loadCert(pem) {
  if (!pem) {
    setStatus(els.certStatus, 'muted', CERT_HINT);
    els.cert.classList.remove('invalid');
    return null;
  }
  try {
    const key = await getKey(pem);
    let detail = `RSA ${key.algorithm.modulusLength} bit`;
    const info = certificateInfo(pem);
    if (info) {
      const expired = info.notAfter < new Date();
      if (info.subject) detail = `${escapeHtml(info.subject)} · ${detail}`;
      detail += expired
        ? ` · <strong>lejárt: ${formatDate(info.notAfter)}</strong>`
        : ` · érvényes eddig: ${formatDate(info.notAfter)}`;
      if (expired) {
        setStatus(els.certStatus, 'error', `⚠ Tanúsítvány betöltve <span class="detail">${detail}</span>`);
        els.cert.classList.remove('invalid');
        return key;
      }
    }
    setStatus(els.certStatus, 'ok', `✓ Tanúsítvány betöltve <span class="detail">${detail}</span>`);
    els.cert.classList.remove('invalid');
    return key;
  } catch (e) {
    keyCache = { pem: null, key: null };
    setStatus(els.certStatus, 'error', `✕ ${escapeHtml(e.message)}`);
    els.cert.classList.add('invalid');
    return null;
  }
}

async function render() {
  return mode === 'edit' ? renderEdit() : renderNew();
}

async function renderNew() {
  const gen = ++generation;
  const errors = [];
  const namespace = els.namespace.value.trim();
  const name = els.name.value.trim();
  const scope = SCOPES.strict;
  const type = segmentedValue(els.type);

  const nsOk = DNS_LABEL.test(namespace) && namespace.length <= 63;
  const nameOk = DNS_SUBDOMAIN.test(name) && name.length <= 253;
  els.namespace.classList.toggle('invalid', Boolean(namespace) && !nsOk);
  els.name.classList.toggle('invalid', Boolean(name) && !nameOk);
  if (namespace && !nsOk) errors.push('A namespace csak kisbetűt, számot és kötőjelet tartalmazhat');
  if (name && !nameOk) errors.push('A name csak kisbetűt, számot, kötőjelet és pontot tartalmazhat');

  const key = await loadCert(els.cert.value.trim());
  if (gen !== generation) return;

  const data = collectData(errors);
  const count = Object.keys(data).length;
  els.errors.innerHTML = errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('');
  setChecklist({ namespace: nsOk, name: nameOk, cert: key, data: count > 0 });

  if (!nsOk || !nameOk || !key || errors.length || !count) {
    showEmpty();
    return;
  }

  els.liveDot.className = 'live busy';
  try {
    const entries = await Promise.all(
      Object.entries(data).map(async ([k, v]) => [k, await encryptCached(key, v, scope, namespace, name)]),
    );
    if (gen !== generation) return;
    const manifest = buildSealedSecret({ name, namespace, type, scope, encryptedData: Object.fromEntries(entries) });
    showOutput(`${toYaml(manifest)}\n`, `${count} titkosított kulcs`);
  } catch (e) {
    if (gen !== generation) return;
    els.errors.innerHTML = `<li>Titkosítási hiba: ${escapeHtml(e.message)}</li>`;
    showEmpty();
  }
}

async function renderEdit() {
  const gen = ++generation;
  const errors = [];
  const key = await loadCert(els.cert.value.trim());
  if (gen !== generation) return;

  if (!existing) {
    els.errors.innerHTML = '';
    setChecklist({ existing: false, cert: key });
    showEmpty();
    return;
  }

  const edit = collectEdit(errors);
  const toEncrypt = { ...edit.replaced, ...edit.added };
  const needsKey = Object.keys(toEncrypt).length > 0;
  els.errors.innerHTML = errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('');
  setChecklist({ existing: true, cert: key });

  if (errors.length || (needsKey && !key)) {
    showEmpty();
    return;
  }

  els.liveDot.className = 'live busy';
  try {
    const { scope, namespace, name } = existing;
    const fresh = Object.fromEntries(
      await Promise.all(
        Object.entries(toEncrypt).map(async ([k, v]) => [k, await encryptCached(key, v, scope, namespace, name)]),
      ),
    );
    if (gen !== generation) return;

    // Original key order first, new keys appended; untouched values are copied verbatim.
    const encryptedData = {};
    for (const [k, v] of Object.entries(existing.encryptedData)) {
      if (edit.deleted.includes(k)) continue;
      encryptedData[k] = k in fresh ? fresh[k] : v;
    }
    for (const k of Object.keys(edit.added)) encryptedData[k] = fresh[k];

    const marks = {};
    for (const k of Object.keys(edit.replaced)) marks[k] = 'changed';
    for (const k of Object.keys(edit.added)) marks[k] = 'added';

    const changes = Object.keys(edit.replaced).length + Object.keys(edit.added).length + edit.deleted.length;
    showOutput(
      updatedYaml(existing.manifest, encryptedData),
      changes ? `${changes} változás · ${edit.kept.length} változatlan kulcs` : 'nincs változás',
      marks,
    );
    showChanges(edit);
  } catch (e) {
    if (gen !== generation) return;
    els.errors.innerHTML = `<li>Titkosítási hiba: ${escapeHtml(e.message)}</li>`;
    showEmpty();
  }
}

let timer;
function schedule() {
  clearTimeout(timer);
  timer = setTimeout(render, 120);
}

// ---------- modes ----------

function lockTarget(locked) {
  els.namespace.readOnly = locked;
  els.name.readOnly = locked;
  els.lockNote.hidden = !locked;
  setDisabled(els.type, locked);
}

function loadExisting(text) {
  if (text === existingText) return;
  existingText = text;
  existing = null;
  els.pairs.replaceChildren();
  els.existing.classList.remove('invalid');
  if (!text.trim()) {
    setStatus(els.existingStatus, 'muted', EXISTING_HINT);
    lockTarget(false);
    return;
  }
  try {
    existing = parseSealedSecret(text);
    if (existing.scope !== SCOPES.strict) {
      throw new Error(`Csak strict scope-ú SealedSecret módosítható, ez ${existing.scope}.`);
    }
  } catch (e) {
    existing = null;
    setStatus(els.existingStatus, 'error', `✕ ${escapeHtml(e.message)}`);
    els.existing.classList.add('invalid');
    lockTarget(false);
    return;
  }
  const keys = Object.keys(existing.encryptedData);
  els.namespace.value = existing.namespace;
  els.name.value = existing.name;
  const docker = existing.type === DOCKER_TYPE;
  setSegmented(els.type, docker ? DOCKER_TYPE : 'Opaque');
  applyType(docker ? DOCKER_TYPE : 'Opaque');
  els.dockerEditHint.hidden = !docker;
  if (!docker) for (const k of keys) addExistingPair(k);
  lockTarget(true);
  setStatus(
    els.existingStatus,
    'ok',
    `✓ Betöltve <span class="detail">${escapeHtml(existing.name)}${
      existing.namespace ? ` · ${escapeHtml(existing.namespace)}` : ''
    } · ${keys.length} kulcs</span>`,
  );
}

function setMode(value) {
  mode = value;
  document.body.classList.toggle('editing', mode === 'edit');
  els.existingCard.hidden = mode !== 'edit';
  els.pairs.replaceChildren();
  els.dockerEditHint.hidden = true;
  existingText = null;
  existing = null;
  els.changes.hidden = true;
  if (mode === 'edit') {
    loadExisting(els.existing.value);
    els.emptyText.textContent = 'Illeszd be a meglévő SealedSecretet. Az eredmény itt jelenik meg:';
  } else {
    lockTarget(false);
    addPair();
    els.emptyText.textContent = 'Az eredmény itt jelenik meg, amint minden adat megvan:';
  }
  renderChecklist();
}

// ---------- misc UI ----------

let toastTimer;
function toast(message) {
  els.toast.textContent = message;
  els.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove('show'), 1800);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for browsers/contexts without the async clipboard API.
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

function setupDropzone(zone, onFile) {
  for (const evt of ['dragenter', 'dragover']) {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add('dragging');
    });
  }
  for (const evt of ['dragleave', 'drop']) zone.addEventListener(evt, () => zone.classList.remove('dragging'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    onFile(e.dataTransfer.files[0]);
  });
}

function setupFileInput(input, onFile) {
  input.addEventListener('change', async () => {
    await onFile(input.files[0]);
    input.value = '';
  });
}

async function readCertFile(file) {
  if (!file) return;
  els.cert.value = (await file.text()).trim();
  schedule();
}

const CERT_URL_KEY = 'web-kubeseal.certUrl';

function remember(key, value) {
  try {
    if (value) localStorage.setItem(key, value);
    else localStorage.removeItem(key);
  } catch {}
}

function recall(key) {
  try {
    return localStorage.getItem(key) || '';
  } catch {
    return '';
  }
}

// The certificate is public, so fetching it from a URL is fine; nothing secret is sent.
async function loadCertFromUrl() {
  const url = els.certUrl.value.trim();
  if (!url) return;
  els.certUrlLoad.disabled = true;
  els.certUrl.classList.remove('invalid');
  setStatus(els.certStatus, 'muted', 'Letöltés…');
  try {
    els.cert.value = await fetchCertificate(url);
    remember(CERT_URL_KEY, url);
    schedule();
  } catch (e) {
    els.certUrl.classList.add('invalid');
    setStatus(els.certStatus, 'error', `✕ ${escapeHtml(e.message)}`);
  } finally {
    els.certUrlLoad.disabled = false;
  }
}

async function readExistingFile(file) {
  if (!file) return;
  els.existing.value = await file.text();
  loadExisting(els.existing.value);
  schedule();
}

// ---------- wiring ----------

document.querySelector('main').addEventListener('input', (e) => {
  if (e.target === els.certUrl) {
    els.certUrl.classList.remove('invalid');
    return;
  }
  if (e.target === els.existing) loadExisting(els.existing.value);
  schedule();
});

setupSegmented(els.mode, setMode);
setupSegmented(els.type, applyType);

els.addPair.addEventListener('click', () => {
  addPair().querySelector('.pair-key').focus();
});

els.revealPassword.addEventListener('click', () => {
  const show = els.dockerPassword.type === 'password';
  els.dockerPassword.type = show ? 'text' : 'password';
  els.revealPassword.classList.toggle('on', show);
});

els.certUrlForm.addEventListener('submit', (e) => {
  e.preventDefault();
  loadCertFromUrl();
});

setupFileInput(els.certFile, readCertFile);
setupFileInput(els.existingFile, readExistingFile);
setupDropzone(els.dropzone, readCertFile);
setupDropzone(els.existingDropzone, readExistingFile);

els.copy.addEventListener('click', async () => {
  await copyText(currentYaml);
  toast('YAML a vágólapra másolva');
});

els.download.addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([currentYaml], { type: 'application/yaml' }));
  const a = Object.assign(document.createElement('a'), {
    href: url,
    download: `${els.name.value.trim() || 'sealedsecret'}.sealedsecret.yaml`,
  });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

setMode('new');
// ?cert=<url> lets a team share a link that preloads their controller certificate.
els.certUrl.value = new URLSearchParams(location.search).get('cert') || recall(CERT_URL_KEY);
if (els.certUrl.value) loadCertFromUrl();
render();
