import { describe, it, expect } from 'vitest';
import { fetchCertificate } from '../src/cert-url.js';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
const respond = (body, status = 200) => async () => new Response(body, { status });

describe('fetchCertificate', () => {
  it('returns the PEM block from the response', async () => {
    expect(await fetchCertificate('https://example.com/cert.pem', respond(`junk\n${PEM}\n`))).toBe(PEM);
  });

  it('omits credentials and bypasses the cache', async () => {
    let opts;
    await fetchCertificate('https://example.com/c', async (_u, o) => ((opts = o), new Response(PEM)));
    expect(opts).toMatchObject({ credentials: 'omit', cache: 'no-store' });
  });

  it('rejects invalid and non-http URLs', async () => {
    await expect(fetchCertificate('nem url')).rejects.toThrow('Érvénytelen URL');
    await expect(fetchCertificate('file:///etc/cert.pem')).rejects.toThrow('http(s)');
  });

  it('explains network and CORS failures', async () => {
    const fail = async () => { throw new TypeError('Failed to fetch'); };
    await expect(fetchCertificate('https://example.com/c', fail)).rejects.toThrow('CORS');
  });

  it('reports HTTP errors and non-PEM content', async () => {
    await expect(fetchCertificate('https://example.com/c', respond('x', 404))).rejects.toThrow('HTTP 404');
    await expect(fetchCertificate('https://example.com/c', respond('<html>'))).rejects.toThrow('nincs PEM');
  });
});
