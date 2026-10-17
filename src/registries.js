// The image pull secret's registry picker reads ../registries.yaml: a map of name -> registry host.
import { parseMap, loadConfig } from './config.js';

const HOST = /^[a-z0-9.-]+(:\d+)?(\/\S*)?$/i;

/** Parses registries.yaml into [{ name, host }], keeping the file's order. */
export function parseRegistries(text) {
  return parseMap(text, 'registries.yaml', 'név → registry host').map(([name, value]) => {
    const host = typeof value === 'string' ? value.trim() : '';
    if (!HOST.test(host)) throw new Error(`„${name}”: nem registry host (pl. ghcr.io).`);
    return { name, host };
  });
}

export async function loadRegistries(fetchImpl, doc) {
  return parseRegistries(await loadConfig('registries.yaml', fetchImpl, doc));
}
