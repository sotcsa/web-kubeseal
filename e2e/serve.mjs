// Minimal static server that mounts a directory under /web-kubeseal/, like GitHub Pages does.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const [root, port] = process.argv.slice(2);
const PREFIX = '/web-kubeseal/';
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (!url.pathname.startsWith(PREFIX)) {
    res.writeHead(404).end();
    return;
  }
  let path = normalize(url.pathname.slice(PREFIX.length)).replace(/^(\.\.[/\\])+/, '');
  if (!path || path.endsWith('/') || path === '.') path = join(path, 'index.html');
  try {
    const body = await readFile(join(root, path));
    res.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(Number(port));
