import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseRegistries, loadRegistries } from '../src/registries.js';

describe('parseRegistries', () => {
  it('reads name -> host pairs in file order', () => {
    expect(parseRegistries('# x\nPublikus OCI: fra.ocir.io\nhelyi: "registry.local:5000/team"\n')).toEqual([
      { name: 'Publikus OCI', host: 'fra.ocir.io' },
      { name: 'helyi', host: 'registry.local:5000/team' },
    ]);
  });

  it('the shipped registries.yaml is valid', () => {
    parseRegistries(readFileSync(new URL('../registries.yaml', import.meta.url), 'utf8'));
  });

  it('accepts empty files and explains bad input', () => {
    expect(parseRegistries('# semmi\n')).toEqual([]);
    expect(() => parseRegistries('- a')).toThrow('név → registry host');
    expect(() => parseRegistries('DRCC:')).toThrow('„DRCC”: nem registry host');
    expect(() => parseRegistries('x: https://ghcr.io')).toThrow('„x”: nem registry host');
  });
});

describe('loadRegistries', () => {
  it('reads registries.yaml, or the embedded copy when fetch is blocked', async () => {
    let asked;
    const ok = async (url) => { asked = url; return new Response('a: ghcr.io\n'); };
    expect(await loadRegistries(ok)).toEqual([{ name: 'a', host: 'ghcr.io' }]);
    expect(asked).toBe('./registries.yaml');
    expect(await loadRegistries(async () => new Response('', { status: 404 }))).toEqual([]);

    const blocked = async () => { throw new TypeError('Failed to fetch'); };
    const doc = { getElementById: (id) => (id === 'registries-config' ? { textContent: 'b: quay.io' } : null) };
    expect(await loadRegistries(blocked, doc)).toEqual([{ name: 'b', host: 'quay.io' }]);
  });
});
