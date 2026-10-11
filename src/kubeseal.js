// Client-side reimplementation of kubeseal's encryption, using WebCrypto only.
//
// Format (see sealed-secrets pkg/crypto/crypto.go, HybridEncrypt):
//   uint16 BE length of the RSA ciphertext
//   RSA-OAEP(SHA-256, label = scope label) encrypted 32-byte AES session key
//   AES-256-GCM(session key, nonce = 12 zero bytes) ciphertext + 16-byte tag

export const SCOPES = {
  strict: 'strict',
  namespaceWide: 'namespace-wide',
  clusterWide: 'cluster-wide',
};

const subtle = () => globalThis.crypto.subtle;

/** Label that binds the ciphertext to its namespace/name, as kubeseal does. */
export function scopeLabel(scope, namespace, name) {
  switch (scope) {
    case SCOPES.clusterWide:
      return '';
    case SCOPES.namespaceWide:
      return namespace;
    default:
      return `${namespace}/${name}`;
  }
}

/** Template annotations kubeseal adds for non-strict scopes. */
export function scopeAnnotations(scope) {
  if (scope === SCOPES.clusterWide) return { 'sealedsecrets.bitnami.com/cluster-wide': 'true' };
  if (scope === SCOPES.namespaceWide) return { 'sealedsecrets.bitnami.com/namespace-wide': 'true' };
  return {};
}

// ---------- PEM / DER helpers ----------

export function pemToDer(pem) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(pem);
  if (!match) throw new Error('Nem található PEM blokk (-----BEGIN ...-----).');
  const b64 = match[2].replace(/[^A-Za-z0-9+/=]/g, '');
  return { type: match[1], der: base64ToBytes(b64) };
}

// Minimal DER reader: returns { tag, start (of content), end (of content), next (after element) }.
function readTlv(bytes, offset) {
  const tag = bytes[offset];
  let len = bytes[offset + 1];
  let pos = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Érvénytelen DER hosszkódolás.');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[pos++];
  }
  if (pos + len > bytes.length) throw new Error('Csonka DER adat.');
  return { tag, start: pos, end: pos + len, next: pos + len, headerStart: offset };
}

/** Extracts the SubjectPublicKeyInfo DER bytes from an X.509 certificate DER. */
export function spkiFromCertificate(der) {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30) throw new Error('A tanúsítvány nem DER SEQUENCE.');
  const tbs = readTlv(der, cert.start);
  if (tbs.tag !== 0x30) throw new Error('Hiányzó tbsCertificate.');
  let pos = tbs.start;
  let el = readTlv(der, pos);
  if (el.tag === 0xa0) el = readTlv(der, el.next); // optional [0] version
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  for (let i = 0; i < 5; i++) el = readTlv(der, el.next);
  if (el.tag !== 0x30) throw new Error('Hiányzó SubjectPublicKeyInfo.');
  return der.slice(el.headerStart, el.end);
}

/** Imports a sealed-secrets controller certificate (or a PUBLIC KEY PEM) for RSA-OAEP. */
export async function importPublicKey(pem) {
  const { type, der } = pemToDer(pem);
  let spki;
  if (type === 'CERTIFICATE') spki = spkiFromCertificate(der);
  else if (type === 'PUBLIC KEY') spki = der;
  else throw new Error(`Nem támogatott PEM típus: ${type}. Tanúsítvány (CERTIFICATE) szükséges.`);
  try {
    return await subtle().importKey('spki', spki, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
      'encrypt',
    ]);
  } catch {
    throw new Error('A kulcs nem importálható – RSA nyilvános kulcs szükséges.');
  }
}

// ---------- encryption ----------

/** kubeseal HybridEncrypt: returns the raw ciphertext bytes. */
export async function hybridEncrypt(publicKey, plaintext, label) {
  const enc = new TextEncoder();
  const data = typeof plaintext === 'string' ? enc.encode(plaintext) : plaintext;
  const sessionKey = globalThis.crypto.getRandomValues(new Uint8Array(32));

  const rsaCipher = new Uint8Array(
    await subtle().encrypt({ name: 'RSA-OAEP', label: enc.encode(label) }, publicKey, sessionKey),
  );
  const aesKey = await subtle().importKey('raw', sessionKey, 'AES-GCM', false, ['encrypt']);
  // A fresh session key per value makes the all-zero nonce safe (same as kubeseal).
  const aesCipher = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, aesKey, data),
  );

  const out = new Uint8Array(2 + rsaCipher.length + aesCipher.length);
  out[0] = rsaCipher.length >> 8;
  out[1] = rsaCipher.length & 0xff;
  out.set(rsaCipher, 2);
  out.set(aesCipher, 2 + rsaCipher.length);
  return out;
}

/** Encrypts one secret value, returning the base64 string used in spec.encryptedData. */
export async function encryptValue(publicKey, value, { scope = SCOPES.strict, namespace, name }) {
  return bytesToBase64(await hybridEncrypt(publicKey, value, scopeLabel(scope, namespace, name)));
}

// ---------- docker config ----------

export function dockerConfigJson({ server, username, password, email }) {
  const entry = { username, password };
  if (email) entry.email = email;
  entry.auth = bytesToBase64(new TextEncoder().encode(`${username}:${password}`));
  return JSON.stringify({ auths: { [server]: entry } });
}

// ---------- SealedSecret manifest ----------

/**
 * Builds the SealedSecret manifest object.
 * @param {object} p
 * @param {Record<string,string>} p.encryptedData key -> base64 ciphertext
 */
export function buildSealedSecret({ name, namespace, type, scope = SCOPES.strict, encryptedData }) {
  const annotations = scopeAnnotations(scope);
  const metadata = { name, namespace };
  if (Object.keys(annotations).length) metadata.annotations = annotations;
  const templateMetadata = { name, namespace };
  if (Object.keys(annotations).length) templateMetadata.annotations = annotations;
  return {
    apiVersion: 'bitnami.com/v1alpha1',
    kind: 'SealedSecret',
    metadata,
    spec: {
      encryptedData,
      template: { metadata: templateMetadata, type },
    },
  };
}

// Small YAML emitter, sufficient for the manifest above (maps of strings).
export function toYaml(value, indent = 0) {
  const pad = ' '.repeat(indent);
  return Object.entries(value)
    .map(([k, v]) => {
      const key = yamlScalar(k);
      if (v && typeof v === 'object') {
        if (Object.keys(v).length === 0) return `${pad}${key}: {}`;
        return `${pad}${key}:\n${toYaml(v, indent + 2)}`;
      }
      return `${pad}${key}: ${yamlScalar(String(v))}`;
    })
    .join('\n');
}

function yamlScalar(s) {
  if (/^[A-Za-z0-9_./+=-]+$/.test(s) && !/^(true|false|null|yes|no|on|off|~|[-+]?[0-9.]+)$/i.test(s) && !s.startsWith('-')) {
    return s;
  }
  return JSON.stringify(s);
}

// ---------- base64 ----------

export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
