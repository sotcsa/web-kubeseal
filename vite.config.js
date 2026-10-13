import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';
import { viteSingleFile } from 'vite-plugin-singlefile';

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
      // Ship clusters.yaml next to the page and embed it too, for when fetch is blocked (file://).
      name: 'clusters-config',
      transformIndexHtml: {
        order: 'post',
        handler(html, ctx) {
          if (!ctx.bundle) return html; // dev server: fetched at runtime
          const yaml = readFileSync('clusters.yaml', 'utf8');
          return html.replace(
            '</body>',
            `<script type="text/yaml" id="clusters-config">${scriptSafe(yaml)}</script>\n</body>`,
          );
        },
      },
      generateBundle() {
        this.emitFile({ type: 'asset', fileName: 'clusters.yaml', source: readFileSync('clusters.yaml', 'utf8') });
      },
    },
  ],
});
