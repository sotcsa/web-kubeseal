import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { configId } from './src/config.js';

// Editable configs shipped next to the page; see src/config.js.
const CONFIGS = ['clusters.yaml', 'registries.yaml'];

// Script content is raw text: only a closing tag could break out of it.
const scriptSafe = (s) => s.replace(/<\/(script)/gi, '<\\/$1');

export default defineConfig({
  // Relative asset paths so the build works from any sub-path (e.g. GitHub Pages).
  base: './',
  plugins: [
    // One self-contained index.html: it also works opened straight from disk (file://),
    // where browsers refuse to load module scripts and fetch files.
    viteSingleFile(),
    {
      // Ship the configs next to the page and embed them too, for when fetch is blocked (file://).
      name: 'configs',
      transformIndexHtml: {
        order: 'post',
        handler(html, ctx) {
          if (!ctx.bundle) return html; // dev server: fetched at runtime
          const scripts = CONFIGS.map(
            (file) => `<script type="text/yaml" id="${configId(file)}">${scriptSafe(readFileSync(file, 'utf8'))}</script>\n`,
          );
          return html.replace('</body>', `${scripts.join('')}</body>`);
        },
      },
      generateBundle() {
        for (const file of CONFIGS) this.emitFile({ type: 'asset', fileName: file, source: readFileSync(file, 'utf8') });
      },
    },
  ],
});
