import { defineConfig, devices } from '@playwright/test';

const launchOptions = process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {};

// The app is served under a sub-path, as on GitHub Pages, in two ways:
// the Vite build (Pages "GitHub Actions" source) and the raw sources (Pages "branch" source),
// plus the build opened straight from disk.
export default defineConfig({
  testDir: 'e2e',
  use: { ...devices['Desktop Chrome'], launchOptions },
  projects: [
    { name: 'build', testIgnore: 'file.spec.js', use: { baseURL: 'http://localhost:4801/web-kubeseal/' } },
    { name: 'source', testIgnore: 'file.spec.js', use: { baseURL: 'http://localhost:4802/web-kubeseal/' } },
    { name: 'mobile', testIgnore: 'file.spec.js', use: { ...devices['Pixel 7'], launchOptions, baseURL: 'http://localhost:4801/web-kubeseal/' } },
    // Opened from disk; the build web server below produces dist/ first.
    { name: 'file', testMatch: 'file.spec.js' },
  ],
  webServer: [
    { command: 'npm run build && node e2e/serve.mjs dist 4801', url: 'http://localhost:4801/web-kubeseal/' },
    { command: 'node e2e/serve.mjs . 4802', url: 'http://localhost:4802/web-kubeseal/' },
  ],
});
