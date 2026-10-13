import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, privateDecrypt, createDecipheriv, constants } from 'node:crypto';

const fixture = (f) => readFileSync(new URL(`../test/fixtures/${f}`, import.meta.url), 'utf8');
const certPem = fixture('tls.crt');
const privateKey = createPrivateKey(fixture('tls.key'));

function unseal(b64, label) {
  const buf = Buffer.from(b64, 'base64');
  const rsaLen = buf.readUInt16BE(0);
  const sessionKey = privateDecrypt(
    { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from(label) },
    buf.subarray(2, 2 + rsaLen),
  );
  const rest = buf.subarray(2 + rsaLen);
  const d = createDecipheriv('aes-256-gcm', sessionKey, Buffer.alloc(12));
  d.setAuthTag(rest.subarray(rest.length - 16));
  return Buffer.concat([d.update(rest.subarray(0, rest.length - 16)), d.final()]).toString('utf8');
}

// Reads `key: value` pairs under spec.encryptedData from the rendered YAML.
function encryptedData(yaml) {
  const block = yaml.split('encryptedData:\n')[1].split('\n  template:')[0];
  return Object.fromEntries(block.trim().split('\n').map((l) => l.trim().split(': ')));
}

const output = (page) => page.locator('#output');

async function fillTarget(page, ns = 'prod', name = 'app') {
  await page.fill('#namespace', ns);
  await page.fill('#name', name);
  await page.fill('#cert', certPem);
}

test.beforeEach(async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('./');
  await expect(page.locator('#certStatus')).toBeVisible();
  // Styles and scripts must load (fails when assets 404 under the sub-path).
  await expect(page.locator('.pair')).toHaveCount(1);
  expect(await page.locator('.card').first().evaluate((el) => getComputedStyle(el).borderRadius)).not.toBe('0px');
  page.errors = errors;
});

test.afterEach(async ({ page }) => {
  expect(page.errors).toEqual([]);
});

test('adds and removes key/value pairs, output unseals', async ({ page }) => {
  await fillTarget(page);
  await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');

  await page.locator('.pair-key').nth(0).fill('DB_PASSWORD');
  await page.locator('.pair-value').nth(0).fill('hunter2');
  await page.click('#addPair');
  await expect(page.locator('.pair')).toHaveCount(2);
  await expect(page.locator('.pair-key').nth(1)).toBeFocused();
  await page.keyboard.type('api.token');
  await page.keyboard.press('Enter');
  await expect(page.locator('.pair-value').nth(1)).toBeFocused();
  await page.keyboard.type('line1\nline2');
  await page.click('#addPair');
  await page.locator('.pair-key').nth(2).fill('TEMP');
  await page.locator('.pair-value').nth(2).fill('x');

  await expect(output(page)).toContainText('TEMP:');
  await page.locator('.pair .remove').nth(2).click();
  await expect(page.locator('.pair')).toHaveCount(2);
  await expect(output(page)).not.toContainText('TEMP:');

  const yaml = await output(page).innerText();
  expect(yaml).toContain('kind: SealedSecret');
  expect(yaml).toContain('type: Opaque');
  const data = encryptedData(yaml);
  expect(Object.keys(data)).toEqual(['DB_PASSWORD', 'api.token']);
  expect(unseal(data.DB_PASSWORD, 'prod/app')).toBe('hunter2');
  expect(unseal(data['api.token'], 'prod/app')).toBe('line1\nline2');
  await expect(page.locator('#meta')).toContainText('2');
});

test('removing the last pair leaves an empty row', async ({ page }) => {
  await page.locator('.pair .remove').click();
  await expect(page.locator('.pair')).toHaveCount(1);
  await expect(page.locator('.pair-key')).toHaveValue('');
});

test('image pull secret', async ({ page }) => {
  await fillTarget(page, 'default', 'regcred');
  await page.getByRole('radio', { name: 'Image pull secret' }).click();
  await expect(page.locator('#opaqueFields')).toBeHidden();
  await page.fill('#dockerServer', 'ghcr.io');
  await page.fill('#dockerUsername', 'csaba');
  await page.fill('#dockerPassword', 's3cret');
  await page.fill('#dockerEmail', 'a@b.hu');

  await expect(output(page)).toContainText('type: kubernetes.io/dockerconfigjson');
  const data = encryptedData(await output(page).innerText());
  expect(JSON.parse(unseal(data['.dockerconfigjson'], 'default/regcred'))).toEqual({
    auths: { 'ghcr.io': { username: 'csaba', password: 's3cret', email: 'a@b.hu', auth: btoa('csaba:s3cret') } },
  });

  await page.click('#revealPassword');
  await expect(page.locator('#dockerPassword')).toHaveAttribute('type', 'text');
});

test('always strict scope: no selector, no scope annotations', async ({ page }) => {
  await expect(page.locator('#scope')).toHaveCount(0);
  await fillTarget(page);
  await page.locator('.pair-key').fill('k');
  await page.locator('.pair-value').fill('v');
  await expect(page.locator('#meta')).toContainText('1 titkosított');
  const yaml = await output(page).innerText();
  expect(yaml).not.toContain('sealedsecrets.bitnami.com/');
  expect(unseal(encryptedData(yaml).k, 'prod/app')).toBe('v');
});

test('validation and checklist', async ({ page }) => {
  await expect(page.locator('#empty')).toBeVisible();
  await expect(page.locator('#copy')).toBeDisabled();

  await page.fill('#namespace', 'Prod_NS');
  await expect(page.locator('#errors')).toContainText('namespace');
  await expect(page.locator('#namespace')).toHaveClass(/invalid/);
  await page.fill('#namespace', 'prod');
  await expect(page.locator('[data-check="namespace"]')).toHaveClass(/done/);

  await page.fill('#cert', '-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----');
  await expect(page.locator('#certStatus')).toHaveClass(/error/);

  await fillTarget(page);
  await page.locator('.pair-key').fill('bad key');
  await page.locator('.pair-value').fill('v');
  await expect(page.locator('#errors')).toContainText('Érvénytelen kulcs');
  await page.locator('.pair-key').fill('ok');
  await page.click('#addPair');
  await page.locator('.pair-key').nth(1).fill('ok');
  await expect(page.locator('#errors')).toContainText('Ismétlődő kulcs');
  await expect(page.locator('#output')).toBeHidden();
  await page.locator('.pair-key').nth(1).fill('ok2');
  await expect(page.locator('#errors')).toBeEmpty();
  await expect(page.locator('#output')).toBeVisible();
  await expect(page.locator('#copy')).toBeEnabled();
});

test('certificate from file shows details', async ({ page }) => {
  await page.setInputFiles('#certFile', { name: 'cert.pem', mimeType: 'text/plain', buffer: Buffer.from(certPem) });
  await expect(page.locator('#cert')).toHaveValue(certPem.trim());
  await expect(page.locator('#certStatus')).toContainText('O=sealed-secret');
  await expect(page.locator('#certStatus')).toContainText('RSA 4096');
});

test('copy and download', async ({ page, context, browserName }, testInfo) => {
  test.skip(testInfo.project.name === 'mobile', 'clipboard permissions are desktop-only');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await fillTarget(page);
  await page.locator('.pair-key').fill('k');
  await page.locator('.pair-value').fill('v');
  await expect(page.locator('#copy')).toBeEnabled();
  await page.click('#copy');
  await expect(page.locator('#toast')).toHaveClass(/show/);
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip).toBe(`${await output(page).innerText()}\n`.replace(/\n\n$/, '\n'));

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
  expect(download.suggestedFilename()).toBe('app.sealedsecret.yaml');
});

test.describe('certificate from URL', () => {
  const CERT_URL = 'https://certs.example.test/cert.pem';

  test('downloads, remembers and preloads via ?cert=', async ({ page }) => {
    await page.route(CERT_URL, (route) =>
      route.fulfill({ body: certPem, headers: { 'Access-Control-Allow-Origin': '*' } }),
    );
    await page.fill('#namespace', 'prod');
    await page.fill('#name', 'app');
    await page.locator('.pair-key').first().fill('K');
    await page.locator('.pair-value').first().fill('v');
    await page.fill('#certUrl', CERT_URL);
    await page.press('#certUrl', 'Enter');
    await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');
    await expect(page.locator('#cert')).toHaveValue(certPem.trim());
    const data = encryptedData(await output(page).innerText());
    expect(unseal(data.K, 'prod/app')).toBe('v');

    // Remembered for the next visit.
    await page.reload();
    await expect(page.locator('#certUrl')).toHaveValue(CERT_URL);
    await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');

    // A shared link wins over the remembered URL.
    const other = 'https://other.example.test/c.pem';
    await page.route(other, (route) =>
      route.fulfill({ body: certPem, headers: { 'Access-Control-Allow-Origin': '*' } }),
    );
    await page.goto(`./?cert=${encodeURIComponent(other)}`);
    await expect(page.locator('#certUrl')).toHaveValue(other);
    await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');
  });

  test('explains CORS and HTTP failures', async ({ page }) => {
    // Real cross-origin request to a server that sends no CORS header (127.0.0.1 ≠ localhost).
    await page.fill('#certUrl', 'http://127.0.0.1:4802/web-kubeseal/test/fixtures/tls.crt');
    await page.click('#certUrlLoad');
    await expect(page.locator('#certStatus')).toContainText('CORS');
    await expect(page.locator('#certUrl')).toHaveClass(/invalid/);

    await page.route(CERT_URL, (route) =>
      route.fulfill({ status: 404, body: 'nope', headers: { 'Access-Control-Allow-Origin': '*' } }),
    );
    await page.fill('#certUrl', CERT_URL);
    await expect(page.locator('#certUrl')).not.toHaveClass(/invalid/);
    await page.click('#certUrlLoad');
    await expect(page.locator('#certStatus')).toContainText('HTTP 404');
    await expect(page.locator('#cert')).toHaveValue('');
  });
});

test('cluster picker from clusters.yaml', async ({ page }) => {
  // The shipped config is empty, so the picker stays hidden.
  await expect(page.locator('#cluster')).toBeHidden();

  const indent = certPem.trim().split('\n').map((l) => `  ${l}`).join('\n');
  await page.route('**/clusters.yaml', (route) =>
    route.fulfill({ body: `# config\nalpha-cluster: |\n${indent}\nbeta-cluster: |\n${indent}\n` }),
  );
  await page.goto('./');
  await expect(page.locator('#cluster option')).toHaveText(['Cluster választása…', 'alpha-cluster', 'beta-cluster']);

  await page.fill('#namespace', 'prod');
  await page.fill('#name', 'app');
  await page.locator('.pair-key').first().fill('K');
  await page.locator('.pair-value').first().fill('v');
  await page.selectOption('#cluster', 'beta-cluster');
  await expect(page.locator('#cert')).toHaveValue(certPem.trim());
  await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');
  expect(unseal(encryptedData(await output(page).innerText()).K, 'prod/app')).toBe('v');

  // Remembered for the next visit; a shared ?cluster= link wins.
  await page.reload();
  await expect(page.locator('#cluster')).toHaveValue('beta-cluster');
  await expect(page.locator('#certStatus')).toContainText('Tanúsítvány betöltve');
  await page.goto('./?cluster=alpha-cluster');
  await expect(page.locator('#cluster')).toHaveValue('alpha-cluster');

  // Editing the certificate by hand deselects the cluster.
  await page.locator('#cert').press('End');
  await page.locator('#cert').type('x');
  await expect(page.locator('#cluster')).toHaveValue('');
});

test('broken clusters.yaml is reported', async ({ page }) => {
  await page.route('**/clusters.yaml', (route) => route.fulfill({ body: 'prod: nem tanúsítvány\n' }));
  await page.goto('./');
  await expect(page.locator('#clusterError')).toContainText('„prod”: nem PEM');
  await expect(page.locator('#cluster')).toBeHidden();
});
