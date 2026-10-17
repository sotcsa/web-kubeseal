// The cluster picker reads ../clusters.yaml: a map of cluster name -> controller certificate (PEM).
import { parseMap, loadConfig } from './config.js';

const PEM = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** Parses clusters.yaml into [{ name, pem }], keeping the file's order. */
export function parseClusters(text) {
  return parseMap(text, 'clusters.yaml', 'név → tanúsítvány').map(([name, value]) => {
    const pem = typeof value === 'string' && PEM.exec(value);
    if (!pem) throw new Error(`„${name}”: nem PEM tanúsítvány.`);
    return { name, pem: pem[0] };
  });
}

export async function loadClusters(fetchImpl, doc) {
  return parseClusters(await loadConfig('clusters.yaml', fetchImpl, doc));
}
