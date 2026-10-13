// Controller certificate URLs offered in the cluster picker.
//
// PRESETS ships with the app, so anything listed here is public (this repo and the
// GitHub Pages site are public). Keep internal hostnames out of it; save them in the
// browser instead (the "Mentés" button), or share a ?cert=<url> link.
//
// Format: { name: 'prod-cluster', url: 'https://sealed-secrets.example.com/v1/cert.pem' }
export const PRESETS = [];

const STORAGE_KEY = 'web-kubeseal.clusters';

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

function valid(c) {
  return c && typeof c.name === 'string' && c.name.trim() && typeof c.url === 'string' && /^https?:\/\//.test(c.url);
}

/** Clusters saved in this browser. */
export function savedClusters(store = storage()) {
  try {
    const list = JSON.parse(store?.getItem(STORAGE_KEY) || '[]');
    return Array.isArray(list) ? list.filter(valid) : [];
  } catch {
    return [];
  }
}

function write(list, store) {
  try {
    store?.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch {}
}

/** Saves (or renames, by URL) a cluster in this browser; returns the new list. */
export function saveCluster(name, url, store = storage()) {
  const entry = { name: name.trim(), url: url.trim() };
  if (!valid(entry)) throw new Error('Név és http(s) URL szükséges.');
  const list = savedClusters(store).filter((c) => c.url !== entry.url && c.name !== entry.name);
  list.push(entry);
  list.sort((a, b) => a.name.localeCompare(b.name, 'hu'));
  write(list, store);
  return list;
}

export function removeCluster(url, store = storage()) {
  const list = savedClusters(store).filter((c) => c.url !== url);
  write(list, store);
  return list;
}
