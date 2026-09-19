// Intentionally vulnerable. For testing ClayScan locally only. Do not deploy.
import { createServer } from 'node:http';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const PORT = process.env.PORT || 4610;
const PUBLIC = path.join(process.cwd(), 'examples', 'public');
const comments = [];
const ACCOUNTS = {
  1: { id: 1, user: 'alice', email: 'alice@example.com', balance: 4200, ssn: '111-11-1111' },
  2: { id: 2, user: 'bob', email: 'bob@example.com', balance: 88, ssn: '222-22-2222' },
  3: { id: 3, user: 'carol', email: 'carol@example.com', balance: 15230, ssn: '333-33-3333' },
};

const home = () => `<!doctype html><html><head><title>Vuln Range</title></head><body>
<h1>Range</h1>
<a href="/ping?host=localhost">ping</a>
<a href="/download?file=readme.txt">download</a>
<a href="/account?id=1">account</a>
<a href="/fetch?url=http://example.com">fetch</a>
<a href="/xml">xml</a>
<h2>Guestbook</h2>
<form action="/comment" method="POST"><input name="message" placeholder="message"><button>Post</button></form>
<ul>${comments.map((c) => `<li>${c}</li>`).join('')}</ul>
</body></html>`;

createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;

  if (p === '/') {
    res.setHeader('Content-Type', 'text/html');
    return res.end(home());
  }

  if (p === '/ping') {
    const host = url.searchParams.get('host') || 'localhost';
    res.setHeader('Content-Type', 'text/plain');
    try {
      const out = execSync('echo pong ' + host, { shell: 'bash', timeout: 12000 });
      return res.end(out.toString());
    } catch (e) {
      res.statusCode = 500;
      return res.end(String(e).slice(0, 500));
    }
  }

  if (p === '/download') {
    const file = url.searchParams.get('file') || 'readme.txt';
    res.setHeader('Content-Type', 'text/plain');
    try {
      return res.end(readFileSync(path.join(PUBLIC, file)));
    } catch {
      res.statusCode = 404;
      return res.end('not found');
    }
  }

  if (p === '/account') {
    const id = url.searchParams.get('id') || '1';
    res.setHeader('Content-Type', 'application/json');
    const acct = ACCOUNTS[id];
    if (!acct) { res.statusCode = 404; return res.end('{"error":"not found"}'); }
    return res.end(JSON.stringify(acct));
  }

  if (p === '/fetch') {
    const u = url.searchParams.get('url') || '';
    res.setHeader('Content-Type', 'text/plain');
    fetch(u, { signal: AbortSignal.timeout(5000) })
      .then((r) => r.text().then((t) => res.end(`fetched ${u}: ${r.status} (${t.length} bytes)`)))
      .catch((e) => { res.statusCode = 502; res.end('fetch failed: ' + String(e).slice(0, 120)); });
    return;
  }

  if (p === '/xml') {
    if (req.method !== 'POST') {
      res.setHeader('Content-Type', 'text/html');
      return res.end('<form action="/xml" method="POST"><textarea name="data"></textarea><button>Send</button></form>');
    }
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 50000) req.destroy(); });
    req.on('end', async () => {
      res.setHeader('Content-Type', 'text/plain');
      const ent = body.match(/<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"/i);
      let expanded = '';
      if (ent) {
        const uri = ent[1];
        try {
          if (uri.startsWith('file://')) {
            expanded = readFileSync(uri.replace(/^file:\/\//, '').replace(/^\/([a-z]:)/i, '$1'), 'utf8').slice(0, 2000);
          } else if (/^https?:/i.test(uri)) {
            expanded = await fetch(uri, { signal: AbortSignal.timeout(5000) }).then((r) => r.text()).catch(() => '');
          }
        } catch {  }
      }
      res.end('parsed xml. ' + expanded);
    });
    return;
  }

  if (p === '/comment' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 20000) req.destroy(); });
    req.on('end', () => {
      const msg = new URLSearchParams(body).get('message') || '';
      if (msg) { comments.push(msg); if (comments.length > 50) comments.shift(); }
      res.setHeader('Content-Type', 'text/html');
      res.end(home());
    });
    return;
  }

  res.statusCode = 404;
  res.end('nope');
}).listen(PORT, () => {
  console.log('Intentionally vulnerable range on http://localhost:' + PORT);
});
