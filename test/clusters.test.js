import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseClusters, loadClusters } from '../src/clusters.js';
import { importPublicKey } from '../src/kubeseal.js';

const cert = readFileSync(new URL('./fixtures/tls.crt', import.meta.url), 'utf8').trim();
const indent = (s) => s.split('\n').map((l) => `  ${l}`).join('\n');

describe('parseClusters', () => {
  it('reads name -> PEM pairs in file order', () => {
    const yaml = `zeta: |\n${indent(cert)}\nalpha: |\n${indent(cert)}\n`;
    expect(parseClusters(yaml)).toEqual([
      { name: 'zeta', pem: cert },
      { name: 'alpha', pem: cert },
    ]);
  });

  it('every certificate in the shipped clusters.yaml is a usable RSA key', async () => {
    const shipped = parseClusters(readFileSync(new URL('../clusters.yaml', import.meta.url), 'utf8'));
    for (const { name, pem } of shipped) {
      const key = await importPublicKey(pem).catch((e) => expect.fail(`${name}: ${e.message}`));
      expect(key.algorithm.name).toBe('RSA-OAEP');
    }
  });

  it('accepts empty files and comments', () => {
    expect(parseClusters('')).toEqual([]);
    expect(parseClusters('{}')).toEqual([]);
    expect(parseClusters('# semmi\n')).toEqual([]);
  });

  it('explains bad input', () => {
    expect(() => parseClusters('- a\n- b')).toThrow('név → tanúsítvány');
    expect(() => parseClusters('prod: nem cert')).toThrow('„prod”: nem PEM');
    expect(() => parseClusters('a: [')).toThrow('nem érvényes YAML');
  });
});

describe('loadClusters', () => {
  it('treats a missing file as no clusters and reports other HTTP errors', async () => {
    expect(await loadClusters(async () => new Response('', { status: 404 }))).toEqual([]);
    await expect(loadClusters(async () => new Response('', { status: 500 }))).rejects.toThrow('HTTP 500');
  });
});
