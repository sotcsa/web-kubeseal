import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createPrivateKey, privateDecrypt, createDecipheriv, constants } from 'node:crypto';
import {
  importPublicKey,
  hybridEncrypt,
  encryptValue,
  scopeLabel,
  SCOPES,
  dockerConfigJson,
  buildSealedSecret,
  toYaml,
  base64ToBytes,
} from '../src/kubeseal.js';

const fixture = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8');
const certPem = fixture('tls.crt');
const privateKey = createPrivateKey(fixture('tls.key'));

// Reference decryption following sealed-secrets' HybridDecrypt.
function hybridDecrypt(bytes, label) {
  const buf = Buffer.from(bytes);
  const rsaLen = buf.readUInt16BE(0);
  const sessionKey = privateDecrypt(
    {
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: Buffer.from(label),
    },
    buf.subarray(2, 2 + rsaLen),
  );
  const rest = buf.subarray(2 + rsaLen);
  const decipher = createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(12));
  decipher.setAuthTag(rest.subarray(rest.length - 16));
  return Buffer.concat([decipher.update(rest.subarray(0, rest.length - 16)), decipher.final()]).toString('utf8');
}

describe('kubeseal hybrid encryption', () => {
  it('round-trips with the controller private key (strict scope)', async () => {
    const key = await importPublicKey(certPem);
    const b64 = await encryptValue(key, 's3cr3t – ékezet', { namespace: 'prod', name: 'db' });
    const bytes = base64ToBytes(b64);
    expect((bytes[0] << 8) | bytes[1]).toBe(512); // 4096-bit RSA
    expect(hybridDecrypt(bytes, 'prod/db')).toBe('s3cr3t – ékezet');
  });

  it('binds the ciphertext to the scope label', async () => {
    const key = await importPublicKey(certPem);
    const bytes = await hybridEncrypt(key, 'x', 'prod/db');
    expect(() => hybridDecrypt(bytes, 'prod/other')).toThrow();
  });

  it('uses the right label for each scope', () => {
    expect(scopeLabel(SCOPES.strict, 'ns', 'n')).toBe('ns/n');
    expect(scopeLabel(SCOPES.namespaceWide, 'ns', 'n')).toBe('ns');
    expect(scopeLabel(SCOPES.clusterWide, 'ns', 'n')).toBe('');
  });

  it('accepts a bare PUBLIC KEY PEM too', async () => {
    const key = await importPublicKey(fixture('tls.pub'));
    const bytes = await hybridEncrypt(key, 'v', '');
    expect(hybridDecrypt(bytes, '')).toBe('v');
  });

  it('rejects garbage input', async () => {
    await expect(importPublicKey('nope')).rejects.toThrow();
  });
});

describe('manifest', () => {
  it('builds a dockerconfigjson payload', () => {
    const json = JSON.parse(dockerConfigJson({ server: 'ghcr.io', username: 'u', password: 'p', email: 'e@x' }));
    expect(json.auths['ghcr.io']).toEqual({ username: 'u', password: 'p', email: 'e@x', auth: btoa('u:p') });
  });

  it('renders SealedSecret YAML', () => {
    const yaml = toYaml(
      buildSealedSecret({
        name: 'regcred',
        namespace: 'default',
        type: 'kubernetes.io/dockerconfigjson',
        encryptedData: { '.dockerconfigjson': 'AgB+/=' },
      }),
    );
    expect(yaml).toBe(`apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: regcred
  namespace: default
spec:
  encryptedData:
    .dockerconfigjson: AgB+/=
  template:
    metadata:
      name: regcred
      namespace: default
    type: kubernetes.io/dockerconfigjson`);
  });

  it('adds scope annotations and quotes ambiguous scalars', () => {
    const yaml = toYaml(
      buildSealedSecret({ name: 'true', namespace: '123', type: 'Opaque', scope: SCOPES.clusterWide, encryptedData: {} }),
    );
    expect(yaml).toContain('name: "true"');
    expect(yaml).toContain('namespace: "123"');
    expect(yaml).toContain('sealedsecrets.bitnami.com/cluster-wide: "true"');
    expect(yaml).toContain('encryptedData: {}');
  });
});
