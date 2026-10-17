// Opening the page straight from disk (file://), where module scripts and fetch are blocked.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const certPem = readFileSync(new URL('test/fixtures/tls.crt', root), 'utf8');
const names = (file) => readFileSync(new URL(file, root), 'utf8').match(/^[^\s#][^:]*(?=:)/gm) ?? [];

test('the built dist/index.html works from file://', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(new URL('dist/index.html', root).href);
  await expect(page.locator('.pair')).toHaveCount(1);
  await expect(page.locator('.file-warning')).toHaveCount(0);
  // clusters.yaml and registries.yaml are embedded in the page.
  await expect(page.locator('#cluster option')).toHaveCount(names('clusters.yaml').length + 1);
  await expect(page.locator('#dockerRegistry option')).toHaveCount(names('registries.yaml').length + 1);

  await page.fill('#namespace', 'prod');
  await page.fill('#name', 'app');
  await page.fill('#cert', certPem);
  await page.locator('.pair-key').fill('K');
  await page.locator('.pair-value').fill('v');
  await expect(page.locator('#meta')).toContainText('1 titkosított');
  expect(errors).toEqual([]);
});

test('the source index.html explains itself when Chromium blocks it on file://', async ({ page }) => {
  await page.goto(new URL('index.html', root).href);
  await expect(page.locator('.file-warning')).toContainText('npm run build');
});
