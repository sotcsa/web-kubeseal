// Small YAML config files shipped next to the page (clusters.yaml, registries.yaml).
import { parseAllDocuments } from './vendor/yaml.js';

/** Parses a `name: value` map, keeping the file's order. */
export function parseMap(text, file, expected) {
  const docs = parseAllDocuments(text);
  if (docs.length > 1) throw new Error(`A ${file} csak egy dokumentumot tartalmazhat.`);
  const doc = docs[0];
  if (!doc) return [];
  if (doc.errors.length) throw new Error(`A ${file} nem érvényes YAML: ${doc.errors[0].message.split('\n')[0]}`);
  const data = doc.toJS();
  if (data == null) return [];
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error(`A ${file} ${expected} párokat várt.`);
  return Object.entries(data);
}

/**
 * Reads a config from next to the page; a missing file means an empty one. Opened from
 * disk (file://) fetch is blocked, so the build also embeds the config in the page as
 * <script type="text/yaml" id="<name>-config">.
 */
export async function loadConfig(file, fetchImpl = globalThis.fetch, doc = globalThis.document) {
  let res;
  try {
    res = await fetchImpl(`./${file}`, { cache: 'no-cache' });
  } catch (e) {
    const embedded = doc?.getElementById(configId(file));
    if (embedded) return embedded.textContent;
    if (globalThis.location?.protocol === 'file:') {
      throw new Error(`Fájlként megnyitva a ${file} csak a buildelt dist/index.html-ben érhető el.`);
    }
    throw e;
  }
  if (res.status === 404) return '';
  if (!res.ok) throw new Error(`A ${file} nem tölthető be: HTTP ${res.status}.`);
  return res.text();
}

export const configId = (file) => `${file.replace(/\.ya?ml$/, '')}-config`;
