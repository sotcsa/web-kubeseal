import {
  importPublicKey,
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
  cert: $('cert'),
  certFile: $('certFile'),
  certStatus: $('certStatus'),
  type: $('type'),
  scope: $('scope'),
  opaqueFields: $('opaqueFields'),
  dockerFields: $('dockerFields'),
  pairs: $('pairs'),
  addPair: $('addPair'),
  dockerServer: $('dockerServer'),
  dockerUsername: $('dockerUsername'),
  dockerPassword: $('dockerPassword'),
  dockerEmail: $('dockerEmail'),
  output: $('output'),
  errors: $('errors'),
  copy: $('copy'),
  download: $('download'),
};

const DNS_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const SECRET_KEY = /^[-._a-zA-Z0-9]+$/;

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

async function encryptCached(key, value, scope, namespace, name) {
  const id = `${scopeLabel(scope, namespace, name)}\u0000${value}`;
  if (!cipherCache.has(id)) cipherCache.set(id, encryptValue(key, value, { scope, namespace, name }));
  return cipherCache.get(id);
}

function addPair(key = '', value = '') {
  const node = $('pairTemplate').content.firstElementChild.cloneNode(true);
  node.querySelector('.pair-key').value = key;
  node.querySelector('.pair-value').value = value;
  node.querySelector('.remove').addEventListener('click', () => {
    node.remove();
    schedule();
  });
  els.pairs.append(node);
  return node;
}

function collectData(errors) {
  if (els.type.value === 'kubernetes.io/dockerconfigjson') {
    const server = els.dockerServer.value.trim();
    const username = els.dockerUsername.value;
    const password = els.dockerPassword.value;
    if (!server || !username || !password) {
      errors.push('Add meg a registry szervert, a felhasználónevet és a jelszót.');
      return null;
    }
    return { '.dockerconfigjson': dockerConfigJson({ server, username, password, email: els.dockerEmail.value.trim() }) };
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
      errors.push(`Érvénytelen kulcs: "${key}" (megengedett: betűk, számok, "-", "_", ".").`);
      continue;
    }
    if (key in data) {
      keyInput.classList.add('invalid');
      errors.push(`Ismétlődő kulcs: "${key}".`);
      continue;
    }
    data[key] = value;
  }
  return data;
}

function setOutput(text, ok) {
  currentYaml = ok ? text : '';
  els.output.firstElementChild.textContent = text;
  els.output.classList.toggle('placeholder', !ok);
  els.copy.disabled = !ok;
  els.download.disabled = !ok;
}

async function render() {
  const gen = ++generation;
  const errors = [];
  const namespace = els.namespace.value.trim();
  const name = els.name.value.trim();
  const pem = els.cert.value.trim();
  const scope = els.scope.value;
  const type = els.type.value;

  if (namespace && !DNS_LABEL.test(namespace)) errors.push('A namespace érvénytelen (kisbetűk, számok és "-").');
  if (name && !DNS_SUBDOMAIN.test(name)) errors.push('A name érvénytelen (kisbetűk, számok, "-" és ".").');

  let key = null;
  els.certStatus.textContent = '';
  els.certStatus.className = 'status';
  if (pem) {
    try {
      key = await getKey(pem);
      els.certStatus.textContent = '✓ Tanúsítvány betöltve';
      els.certStatus.classList.add('ok');
    } catch (e) {
      keyCache = { pem: null, key: null };
      els.certStatus.textContent = e.message;
      els.certStatus.classList.add('error');
    }
  }

  const data = collectData(errors);
  if (gen !== generation) return;
  els.errors.textContent = errors.join('\n');

  if (!namespace || !name || !key || errors.length || !data) {
    setOutput('Add meg a namespace-t, a nevet és a tanúsítványt.', false);
    return;
  }

  try {
    const entries = await Promise.all(
      Object.entries(data).map(async ([k, v]) => [k, await encryptCached(key, v, scope, namespace, name)]),
    );
    if (gen !== generation) return;
    const manifest = buildSealedSecret({ name, namespace, type, scope, encryptedData: Object.fromEntries(entries) });
    setOutput(`${toYaml(manifest)}\n`, true);
  } catch (e) {
    if (gen !== generation) return;
    els.errors.textContent = `Titkosítási hiba: ${e.message}`;
    setOutput('', false);
  }
}

let timer;
function schedule() {
  clearTimeout(timer);
  timer = setTimeout(render, 150);
}

document.querySelector('main').addEventListener('input', schedule);
document.querySelector('main').addEventListener('change', schedule);

els.type.addEventListener('change', () => {
  const docker = els.type.value === 'kubernetes.io/dockerconfigjson';
  els.dockerFields.hidden = !docker;
  els.opaqueFields.hidden = docker;
});

els.addPair.addEventListener('click', () => {
  addPair().querySelector('.pair-key').focus();
});

els.certFile.addEventListener('change', async () => {
  const file = els.certFile.files[0];
  if (!file) return;
  els.cert.value = await file.text();
  els.certFile.value = '';
  schedule();
});

els.copy.addEventListener('click', async () => {
  await navigator.clipboard.writeText(currentYaml);
  els.copy.textContent = 'Másolva ✓';
  setTimeout(() => (els.copy.textContent = 'Másolás'), 1500);
});

els.download.addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([currentYaml], { type: 'application/yaml' }));
  const a = Object.assign(document.createElement('a'), {
    href: url,
    download: `${els.name.value.trim() || 'sealedsecret'}.sealedsecret.yaml`,
  });
  a.click();
  URL.revokeObjectURL(url);
});

addPair();
render();
