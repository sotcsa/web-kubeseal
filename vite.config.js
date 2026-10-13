import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';

export default defineConfig({
  // Relative asset paths so the build works from any sub-path (e.g. GitHub Pages).
  base: './',
  plugins: [
    {
      // The cluster picker fetches ./clusters.yaml at runtime, so ship it as-is.
      name: 'clusters-config',
      generateBundle() {
        this.emitFile({ type: 'asset', fileName: 'clusters.yaml', source: readFileSync('clusters.yaml', 'utf8') });
      },
    },
  ],
});
