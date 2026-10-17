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

function encryptedData(yaml) {
  const block = yaml.split('encryptedData:\n')[1].split('\n  template:')[0];
  return Object.fromEntries(block.trim().split('\n').map((l) => l.trim().split(': ')));
}

const output = (page) => page.locator('#output');
const row = (page, key) => page.locator(`.pair.existing[data-key="${key}"]`);

// Creates a SealedSecret in "new" mode and returns its YAML.
async function createSecret(page, { ns = 'prod', name = 'app', pairs }) {
  await page.fill('#namespace', ns);
  await page.fill('#name', name);
  await page.fill('#cert', certPem);
  for (const [i, [k, v]] of pairs.entries()) {
    if (i) await page.click('#addPair');
    await page.locator('.pair-key').nth(i).fill(k);
    await page.locator('.pair-value').nth(i).fill(v);
  }
  await expect(page.locator('#meta')).toContainText(`${pairs.length} titkosított`);
  return output(page).innerText();
}

async function openEdit(page, yaml) {
  await page.getByRole('radio', { name: 'Meglévő módosítása' }).click();
  await page.fill('#existing', yaml);
  await expect(page.locator('#existingStatus')).toContainText('Betöltve');
}

test.beforeEach(async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('./');
  page.errors = errors;
});

test.afterEach(async ({ page }) => {
  expect(page.errors).toEqual([]);
});

test('replace one key, delete one, add one; the rest stays byte-identical', async ({ page }) => {
  const original = await createSecret(page, {
    pairs: [
      ['DB_HOST', 'db.local'],
      ['DB_PASSWORD', 'old-pass'],
      ['OLD_TOKEN', 'x'],
    ],
  });
  const before = encryptedData(original);
  await openEdit(page, original);

  await expect(page.locator('#namespace')).toHaveValue('prod');
  await expect(page.locator('#namespace')).toHaveJSProperty('readOnly', true);
  await expect(page.locator('#lockNote')).toBeVisible();
  await expect(page.locator('.pair.existing')).toHaveCount(3);
  // Nothing changed yet: output equals the input.
  await expect(page.locator('#changes')).toContainText('Még nincs változás');
  expect(encryptedData(await output(page).innerText())).toEqual(before);

  await row(page, 'DB_PASSWORD').getByRole('button', { name: 'Új érték' }).click();
  await expect(row(page, 'DB_PASSWORD').locator('.pair-value')).toBeFocused();
  await page.keyboard.type('new-pass');
  await row(page, 'OLD_TOKEN').getByRole('button', { name: 'Kulcs törlése' }).click();
  await page.click('#addPair');
  await page.locator('.pair:not(.existing) .pair-key').fill('REDIS_URL');
  await page.locator('.pair:not(.existing) .pair-value').fill('redis://cache:6379');

  await expect(page.locator('#changes')).toContainText('~ DB_PASSWORD');
  await expect(page.locator('#changes')).toContainText('+ REDIS_URL');
  await expect(page.locator('#changes')).toContainText('− OLD_TOKEN');
  await expect(page.locator('#output .line-changed')).toContainText('DB_PASSWORD');
  await expect(page.locator('#output .line-added')).toContainText('REDIS_URL');

  const after = encryptedData(await output(page).innerText());
  expect(Object.keys(after)).toEqual(['DB_HOST', 'DB_PASSWORD', 'REDIS_URL']);
  expect(after.DB_HOST).toBe(before.DB_HOST);
  expect(unseal(after.DB_PASSWORD, 'prod/app')).toBe('new-pass');
  expect(unseal(after.REDIS_URL, 'prod/app')).toBe('redis://cache:6379');

  // Undo and cancel bring the original back.
  await row(page, 'OLD_TOKEN').getByRole('button', { name: 'Visszavon' }).click();
  await row(page, 'DB_PASSWORD').getByRole('button', { name: 'Mégse' }).click();
  await page.locator('.pair:not(.existing) .remove').click();
  await expect(page.locator('#changes')).toContainText('Még nincs változás');
  expect(encryptedData(await output(page).innerText())).toEqual(before);
});

test('rejects a SealedSecret that is not strict scope', async ({ page }) => {
  const strict = await createSecret(page, { pairs: [['K', 'v1']] });
  const clusterWide = strict.replace(
    'metadata:\n  name: app',
    'metadata:\n  annotations:\n    sealedsecrets.bitnami.com/cluster-wide: "true"\n  name: app',
  );
  expect(clusterWide).not.toBe(strict);
  await page.getByRole('radio', { name: 'Meglévő módosítása' }).click();
  await page.fill('#existing', clusterWide);
  await expect(page.locator('#existingStatus')).toContainText('Csak strict scope-ú');
  await expect(page.locator('#existing')).toHaveClass(/invalid/);
  await expect(page.locator('.pair.existing')).toHaveCount(0);
  await expect(page.locator('#namespace')).toHaveJSProperty('readOnly', false);
});

test('reads kubectl output and drops server-side fields', async ({ page }) => {
  const original = await createSecret(page, { pairs: [['A', '1']] });
  const cipher = encryptedData(original).A;
  const kubectl = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  creationTimestamp: "2026-10-11T10:00:00Z"
  generation: 3
  name: app
  namespace: prod
  resourceVersion: "999"
  uid: 11111111-2222-3333-4444-555555555555
spec:
  encryptedData:
    A: ${cipher}
  template:
    metadata:
      name: app
      namespace: prod
    type: Opaque
status:
  observedGeneration: 3
`;
  await openEdit(page, kubectl);
  await page.click('#addPair');
  await page.locator('.pair:not(.existing) .pair-key').fill('B');
  await page.locator('.pair:not(.existing) .pair-value').fill('2');
  await expect(page.locator('#changes')).toContainText('+ B');
  const yaml = await output(page).innerText();
  expect(yaml).not.toMatch(/status|resourceVersion|uid:|generation|creationTimestamp/);
  expect(encryptedData(yaml).A).toBe(cipher);
});

test('image pull secret: new credentials replace .dockerconfigjson', async ({ page }) => {
  await page.fill('#namespace', 'prod');
  await page.fill('#name', 'regcred');
  await page.fill('#cert', certPem);
  await page.getByRole('radio', { name: 'Image pull secret' }).click();
  await page.fill('#dockerServer', 'ghcr.io');
  await page.fill('#dockerUsername', 'old');
  await page.fill('#dockerPassword', 'old');
  await expect(output(page)).toContainText('.dockerconfigjson');
  const original = await output(page).innerText();

  await openEdit(page, original);
  await expect(page.locator('#dockerEditHint')).toBeVisible();
  await expect(page.locator('#opaqueFields')).toBeHidden();
  await page.fill('#dockerServer', 'ghcr.io');
  await page.fill('#dockerUsername', 'csaba');
  await page.fill('#dockerPassword', 'new-token');
  await expect(page.locator('#changes')).toContainText('~ .dockerconfigjson');
  // The username alone already changes the secret, so a render can land between the two
  // fills: wait for the one that carries the new password.
  const password = async () =>
    JSON.parse(unseal(encryptedData(await output(page).innerText())['.dockerconfigjson'], 'prod/regcred')).auths['ghcr.io'].password;
  await expect.poll(password).toBe('new-token');
});

test('errors: invalid YAML, duplicate key, missing certificate', async ({ page }) => {
  await page.getByRole('radio', { name: 'Meglévő módosítása' }).click();
  await page.fill('#existing', 'kind: Secret\nmetadata:\n  name: x');
  await expect(page.locator('#existingStatus')).toContainText('Nem található SealedSecret');
  await expect(page.locator('#existing')).toHaveClass(/invalid/);

  const yaml = `kind: SealedSecret
apiVersion: bitnami.com/v1alpha1
metadata:
  name: app
  namespace: prod
spec:
  encryptedData:
    A: AgAAAA==
  template:
    metadata:
      name: app
      namespace: prod
`;
  await page.fill('#existing', yaml);
  await expect(page.locator('#existingStatus')).toContainText('1 kulcs');
  // No certificate: viewing works, changing needs it.
  await expect(output(page)).toBeVisible();
  await row(page, 'A').getByRole('button', { name: 'Új érték' }).click();
  await page.keyboard.type('x');
  await expect(output(page)).toBeHidden();
  await expect(page.locator('[data-check="cert"]')).not.toHaveClass(/done/);
  await page.fill('#cert', certPem);
  await expect(output(page)).toBeVisible();

  await page.click('#addPair');
  await page.locator('.pair:not(.existing) .pair-key').fill('A');
  await page.locator('.pair:not(.existing) .pair-value').fill('y');
  await expect(page.locator('#errors')).toContainText('már létezik');
});

test('switching back to new mode unlocks the form', async ({ page }) => {
  await page.getByRole('radio', { name: 'Meglévő módosítása' }).click();
  await expect(page.locator('#existingCard')).toBeVisible();
  await page.getByRole('radio', { name: 'Új secret' }).click();
  await expect(page.locator('#existingCard')).toBeHidden();
  await expect(page.locator('.pair')).toHaveCount(1);
  await expect(page.locator('#namespace')).toHaveJSProperty('readOnly', false);
});
