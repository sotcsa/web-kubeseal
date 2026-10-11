// Downloads a controller certificate from a URL, straight from the browser.
// Works only if the server allows cross-origin reads (CORS), e.g. a raw file
// on GitHub/GitLab or an object storage bucket.

const MAX_BYTES = 64 * 1024;

export async function fetchCertificate(url, fetchImpl = globalThis.fetch) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('Érvénytelen URL.');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Csak http(s) URL adható meg.');
  }

  let res;
  try {
    res = await fetchImpl(parsed.href, { credentials: 'omit', cache: 'no-store', redirect: 'follow' });
  } catch {
    throw new Error(
      'Nem sikerült letölteni. A szerver nem érhető el, vagy nem engedi a böngészőből való olvasást (CORS).',
    );
  }
  if (!res.ok) throw new Error(`A szerver hibát adott: HTTP ${res.status}.`);

  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error('A válasz túl nagy egy tanúsítványhoz.');
  const pem = /-----BEGIN (CERTIFICATE|PUBLIC KEY)-----[\s\S]*?-----END \1-----/.exec(text);
  if (!pem) throw new Error('A letöltött tartalomban nincs PEM tanúsítvány.');
  return pem[0];
}
