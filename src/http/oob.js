import http from 'node:http';
import os from 'node:os';

export async function startCollector(target, opts = {}) {
  const hits = new Map();

  const server = http.createServer((req, res) => {
    const m = req.url.match(/\/oob\/([a-z0-9]+)/i);
    if (m) {
      const t = m[1].toLowerCase();
      const arr = hits.get(t) || [];
      arr.push({ time: Date.now(), path: req.url, method: req.method, ua: req.headers['user-agent'] || '' });
      hits.set(t, arr);
    }
    res.setHeader('Content-Type', 'text/plain');
    res.end('clayscan-oob');
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '0.0.0.0', resolve);
  });

  const port = server.address().port;
  const host = opts.oobHost || detectHost(target);

  return {
    host,
    port,
    token() { return 'c' + Math.random().toString(36).slice(2, 10); },
    url(token) { return `http://${host}:${port}/oob/${token}`; },
    hit(token) { return hits.has(String(token).toLowerCase()); },
    hits(token) { return hits.get(String(token).toLowerCase()) || []; },
    async wait(ms) { await new Promise((r) => setTimeout(r, ms)); },
    async close() { await new Promise((r) => server.close(r)); },
  };
}

function detectHost(target) {
  try {
    const h = new URL(target).hostname;
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return '127.0.0.1';
  } catch {  }
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const ni of ifaces[name] || []) {
      if (ni.family === 'IPv4' && !ni.internal) return ni.address;
    }
  }
  return '127.0.0.1';
}
