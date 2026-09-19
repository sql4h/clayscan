// Intentionally vulnerable. For testing ClayScan locally only. Do not deploy.

import { createServer } from 'node:http';

const PORT = process.env.PORT || 4599;

const page = (body) => `<!doctype html><html><head><title>ClayScan Demo Shop</title>
<script src="https://cdn.example.com/jquery-3.3.1.min.js"></script>
<!-- TODO remove before prod: AWS key AKIAIOSFODNN7EXAMPLE -->
</head><body>
<h1>Demo Shop</h1>
${body}
<p><a href="/search?q=hello">Search</a> · <a href="/product?id=1">Product</a> ·
<a href="/go?url=/home">Go home</a> · <a href="/login">Login</a></p>
</body></html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;

  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Set-Cookie', 'sessionid=abc123; Path=/');

  if (p === '/') {
    return res.end(page('<p>Welcome to the demo.</p>'));
  }

  if (p === '/search') {
    const q = url.searchParams.get('q') || '';
    return res.end(page(`<p>Results for: ${q}</p>`));
  }

  if (p === '/product') {
    const id = url.searchParams.get('id') || '';
    if (id.includes("'")) {
      res.statusCode = 500;
      return res.end(page(`<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near "'${id}'"</pre>`));
    }
    return res.end(page(`<p>Product #${id}</p>`));
  }

  if (p === '/go') {
    const dest = url.searchParams.get('url') || '/';
    res.statusCode = 302;
    res.setHeader('Location', dest);
    return res.end();
  }

  if (p === '/login') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; if (body.length > 10000) req.destroy(); });
      req.on('end', () => {
        const email = new URLSearchParams(body).get('email') || '';
        if (email.includes("'")) {
          res.statusCode = 500;
          return res.end(page(`<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near "'${email}'"</pre>`));
        }
        res.statusCode = 401;
        return res.end(page('<p>Invalid credentials.</p>'));
      });
      return;
    }
    return res.end(page(`
      <form action="/login" method="POST">
        <input name="email" type="email" placeholder="email">
        <input name="password" type="password" placeholder="password">
        <button>Sign in</button>
      </form>`));
  }

  if (p === '/.env') {
    res.setHeader('Content-Type', 'text/plain');
    return res.end('DB_PASSWORD=supersecret\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\n');
  }

  res.statusCode = 404;
  res.end(page('<p>Not found</p>'));
});

server.listen(PORT, () => {
  console.log(`⚠️  Intentionally vulnerable demo app on http://localhost:${PORT}`);
  console.log('   Scan it:  node bin/clayscan.js http://localhost:' + PORT +
    ' --yes --consent "I am authorized to test this target" --approve-active --headless');
});
