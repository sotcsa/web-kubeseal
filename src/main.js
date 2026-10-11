import {
  importPublicKey,
  certificateInfo,
  encryptValue,
  scopeLabel,
  dockerConfigJson,
  buildSealedSecret,
  toYaml,
} from './kubeseal.js';

const $ = (id) => document.getElementById(id);
const els = {
  namespace: $('namespace'),
  name: $('name'),
  scope: $('scope'),
  cert: $('cert'),
  certFile: $('certFile'),
  certStatus: $('certStatus'),
  dropzone: $('dropzone'),
  type: $('type'),
  opaqueFields: $('opaqueFields'),
  dockerFields: $('dockerFields'),
  pairs: $('pairs'),
  addPair: $('addPair'),
  dockerServer: $('dockerServer'),
  dockerUsername: $('dockerUsername'),
  dockerPassword: $('dockerPassword'),
  dockerEmail: $('dockerEmail'),
  revealPassword: $('revealPassword'),
  output: $('output'),
  empty: $('empty'),
  checklist: $('checklist'),
  errors: $('errors'),
  meta: $('meta'),
  liveDot: $('liveDot'),
  copy: $('copy'),
  download: $('download'),
  toast: $('toast'),
};

const DOCKER_TYPE = 'kubernetes.io/dockerconfigjson';
const DNS_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const SECRET_KEY = /^[-._a-zA-Z0-9]+$/;
const CERT_HINT = 'Lekérése: <code>kubeseal --fetch-cert &gt; cert.pem</code>';

// Keep ciphertexts stable while only unrelated fields change: cache per (label, value).
let keyCache = { pem: null, key: null };
let cipherCache = new Map();
let generation = 0;
let currentYaml = '';

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

function setupSegmented(group, onChange) {
  group.addEventListener('click', (e) => {
    const button = e.target.closest('button[data-value]');
    if (!button || button.getAttribute('aria-checked') === 'true') return;
    for (const b of group.querySelectorAll('button')) b.setAttribute('aria-checked', String(b === button));
    onChange?.(button.dataset.value);
    schedule();
  });
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
    if (!els.pairs.children.length) addPair();
    schedule();
  });
  els.pairs.append(node);
  autosize(valueInput);
  return node;
}

function collectData(errors) {
  if (segmentedValue(els.type) === DOCKER_TYPE) {
    const server = els.dockerServer.value.trim();
    const username = els.dockerUsername.value;
    const password = els.dockerPassword.value;
    if (!server || !username || !password) return {};
    return {
      '.dockerconfigjson': dockerConfigJson({ server, username, password, email: els.dockerEmail.value.trim() }),
    };
  }

  const data = {};
  for (const row of els.pairs.querySelectorAll('.pair')) {
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
    if (key in data) {
      keyInput.classList.add('invalid');
      errors.push(`Ismétlődő kulcs: „${key}”`);
      continue;
    }
    data[key] = value;
  }
  return data;
}

// ---------- rendering ----------

const escapeHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function highlightYaml(yaml) {
  return yaml
    .split('\n')
    .map((line) => {
      const m = /^(\s*)([^:\s][^:]*):( ?)(.*)$/.exec(line);
      if (!m) return escapeHtml(line);
      const [, indent, key, space, value] = m;
      const cls = value.length > 80 ? 'cipher' : 's';
      return `${indent}<span class="k">${escapeHtml(key)}</span><span class="p">:</span>${space}${
        value ? `<span class="${cls}">${escapeHtml(value)}</span>` : ''
      }`;
    })
    .join('\n');
}

function setChecklist(state) {
  for (const li of els.checklist.children) li.classList.toggle('done', Boolean(state[li.dataset.check]));
}

function showOutput(yaml, count) {
  const changed = yaml !== currentYaml;
  currentYaml = yaml;
  els.output.firstElementChild.innerHTML = highlightYaml(yaml);
  els.output.hidden = false;
  els.empty.hidden = true;
  els.copy.disabled = false;
  els.download.disabled = false;
  els.liveDot.className = 'live on';
  els.meta.textContent = `· ${count} titkosított kulcs`;
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
}

function formatDate(d) {
  return d.toLocaleDateString('hu-HU', { year: 'numeric', month: 'short', day: 'numeric' });
}

function setCertStatus(kind, html) {
  els.certStatus.className = `cert-status ${kind}`;
  els.certStatus.innerHTML = html;
}

async function loadCert(pem) {
  if (!pem) {
    setCertStatus('muted', CERT_HINT);
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
        setCertStatus('error', `⚠ Tanúsítvány betöltve <span class="detail">${detail}</span>`);
        els.cert.classList.remove('invalid');
        return key;
      }
    }
    setCertStatus('ok', `✓ Tanúsítvány betöltve <span class="detail">${detail}</span>`);
    els.cert.classList.remove('invalid');
    return key;
  } catch (e) {
    keyCache = { pem: null, key: null };
    setCertStatus('error', `✕ ${escapeHtml(e.message)}`);
    els.cert.classList.add('invalid');
    return null;
  }
}

async function render() {
  const gen = ++generation;
  const errors = [];
  const namespace = els.namespace.value.trim();
  const name = els.name.value.trim();
  const scope = segmentedValue(els.scope);
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
    showOutput(`${toYaml(manifest)}\n`, count);
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

async function readCertFile(file) {
  if (!file) return;
  els.cert.value = (await file.text()).trim();
  schedule();
}

// ---------- wiring ----------

document.querySelector('main').addEventListener('input', schedule);

setupSegmented(els.scope);
setupSegmented(els.type, (value) => {
  const docker = value === DOCKER_TYPE;
  els.dockerFields.hidden = !docker;
  els.opaqueFields.hidden = docker;
});

els.addPair.addEventListener('click', () => {
  addPair().querySelector('.pair-key').focus();
});

els.revealPassword.addEventListener('click', () => {
  const show = els.dockerPassword.type === 'password';
  els.dockerPassword.type = show ? 'text' : 'password';
  els.revealPassword.classList.toggle('on', show);
});

els.certFile.addEventListener('change', async () => {
  await readCertFile(els.certFile.files[0]);
  els.certFile.value = '';
});

for (const evt of ['dragenter', 'dragover']) {
  els.dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    els.dropzone.classList.add('dragging');
  });
}
for (const evt of ['dragleave', 'drop']) {
  els.dropzone.addEventListener(evt, () => els.dropzone.classList.remove('dragging'));
}
els.dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  readCertFile(e.dataTransfer.files[0]);
});

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

addPair();
render();
