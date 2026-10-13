// The cluster picker reads ../clusters.yaml: a map of cluster name -> controller certificate (PEM).
import { parseAllDocuments } from './vendor/yaml.js';

const PEM = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

/** Parses clusters.yaml into [{ name, pem }], keeping the file's order. */
export function parseClusters(text) {
  const docs = parseAllDocuments(text);
  if (docs.length > 1) throw new Error('A clusters.yaml csak egy dokumentumot tartalmazhat.');
  const doc = docs[0];
  if (!doc) return [];
  if (doc.errors.length) throw new Error(`A clusters.yaml nem érvényes YAML: ${doc.errors[0].message.split('\n')[0]}`);
  const data = doc.toJS();
  if (data == null) return [];
  if (typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('A clusters.yaml név → tanúsítvány párokat várt.');
  }
  return Object.entries(data).map(([name, value]) => {
    const pem = typeof value === 'string' && PEM.exec(value);
    if (!pem) throw new Error(`„${name}”: nem PEM tanúsítvány.`);
    return { name, pem: pem[0] };
  });
}

/**
 * Reads the config from next to the page; a missing file means no clusters. Opened from
 * disk (file://) fetch is blocked, so the build also embeds the config in the page.
 */
export async function loadClusters(fetchImpl = globalThis.fetch, doc = globalThis.document) {
  let res;
  try {
    res = await fetchImpl('./clusters.yaml', { cache: 'no-cache' });
  } catch (e) {
    const embedded = doc?.getElementById('clusters-config');
    if (embedded) return parseClusters(embedded.textContent);
    if (globalThis.location?.protocol === 'file:') {
      throw new Error('Fájlként megnyitva a cluster lista csak a buildelt dist/index.html-ben érhető el.');
    }
    throw e;
  }
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`A clusters.yaml nem tölthető be: HTTP ${res.status}.`);
  return parseClusters(await res.text());
}
