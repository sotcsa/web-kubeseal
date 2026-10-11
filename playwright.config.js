import { defineConfig, devices } from '@playwright/test';

const launchOptions = process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {};

// The app is served under a sub-path, as on GitHub Pages, in two ways:
// the Vite build (Pages "GitHub Actions" source) and the raw sources (Pages "branch" source).
export default defineConfig({
  testDir: 'e2e',
  use: { ...devices['Desktop Chrome'], launchOptions },
  projects: [
    { name: 'build', use: { baseURL: 'http://localhost:4801/web-kubeseal/' } },
    { name: 'source', use: { baseURL: 'http://localhost:4802/web-kubeseal/' } },
    { name: 'mobile', use: { ...devices['Pixel 7'], launchOptions, baseURL: 'http://localhost:4801/web-kubeseal/' } },
  ],
  webServer: [
    { command: 'npm run build && node e2e/serve.mjs dist 4801', url: 'http://localhost:4801/web-kubeseal/' },
    { command: 'node e2e/serve.mjs . 4802', url: 'http://localhost:4802/web-kubeseal/' },
  ],
});
