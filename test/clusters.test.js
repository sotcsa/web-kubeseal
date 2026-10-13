import { describe, it, expect } from 'vitest';
import { PRESETS, savedClusters, saveCluster, removeCluster } from '../src/clusters.js';

function memoryStore() {
  const data = new Map();
  return { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => data.set(k, String(v)) };
}

describe('clusters', () => {
  it('ships no presets with internal hostnames', () => {
    for (const p of PRESETS) expect(p.url).toMatch(/^https:\/\//);
  });

  it('saves, sorts, replaces by URL or name, and removes', () => {
    const s = memoryStore();
    expect(savedClusters(s)).toEqual([]);
    saveCluster('zeta', 'https://z.example/v1/cert.pem', s);
    saveCluster(' alpha ', 'https://a.example/v1/cert.pem', s);
    expect(savedClusters(s).map((c) => c.name)).toEqual(['alpha', 'zeta']);
    saveCluster('alpha-renamed', 'https://a.example/v1/cert.pem', s);
    saveCluster('zeta', 'https://z2.example/v1/cert.pem', s);
    expect(savedClusters(s)).toEqual([
      { name: 'alpha-renamed', url: 'https://a.example/v1/cert.pem' },
      { name: 'zeta', url: 'https://z2.example/v1/cert.pem' },
    ]);
    expect(removeCluster('https://z2.example/v1/cert.pem', s)).toHaveLength(1);
  });

  it('rejects bad input and ignores corrupt storage', () => {
    const s = memoryStore();
    expect(() => saveCluster('', 'https://a', s)).toThrow();
    expect(() => saveCluster('x', 'file:///a', s)).toThrow();
    s.setItem('web-kubeseal.clusters', '{nope');
    expect(savedClusters(s)).toEqual([]);
    expect(savedClusters(null)).toEqual([]);
  });
});
