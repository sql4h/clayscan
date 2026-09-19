import crypto from 'node:crypto';

const WEAK_SECRETS = [
  'secret', 'secretkey', 'secret_key', 'password', 'changeme', 'admin', 'jwt', 'jwtsecret',
  'key', 'private', 'token', '123456', 'qwerty', 'test', 'dev', 'default', 'supersecret',
  'your-256-bit-secret', 'your_jwt_secret', 'mysecret', 'shhhh', 'root', 'pass', 'secret123',
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}/g;

export default {
  id: 'jwt',
  name: 'JSON Web Token weaknesses',
  phase: 'passive',
  run({ site, findings }) {
    const tokens = collectTokens(site);
    const seen = new Set();

    for (const { token, where } of tokens) {
      if (seen.has(token)) continue;
      seen.add(token);
      const parts = token.split('.');
      if (parts.length < 2) continue;
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      if (!header) continue;

      const alg = (header.alg || '').toString();

      if (/^none$/i.test(alg)) {
        add(findings, 'jwt-alg-none', 'JWT accepts "alg: none"', 'critical', where,
          `Token header uses alg=none: ${trunc(token)}`,
          'A token signed with alg=none is unsigned; anyone can forge one and impersonate any user.',
          'Reject alg=none; pin the expected algorithm server-side.', 'CWE-347');
      }

      if (/^HS(256|384|512)$/i.test(alg) && parts.length === 3 && parts[2]) {
        const secret = crack(parts[0], parts[1], parts[2], alg);
        if (secret != null) {
          add(findings, 'jwt-weak-secret', 'JWT signed with a weak/guessable secret', 'critical', where,
            `HMAC secret recovered by dictionary: "${secret}"`,
            'The signing secret is guessable, so an attacker can forge valid tokens for any user (full auth bypass).',
            'Use a long, random, high-entropy secret from a secrets manager; rotate immediately.', 'CWE-798');
        }
      }

      if (payload && payload.exp == null) {
        add(findings, 'jwt-no-exp', 'JWT without an expiry claim', 'low', where,
          `Token payload has no "exp" claim: ${trunc(token)}`,
          'Tokens without expiry stay valid forever once leaked.',
          'Set a short exp and support revocation.', 'CWE-613');
      }
    }
  },
};

function collectTokens(site) {
  const out = [];
  for (const c of site.cookies || []) {
    const m = (c.value || '').match(JWT_RE);
    if (m) for (const t of m) out.push({ token: t, where: `cookie ${c.name}` });
  }
  for (const r of site.responses || []) {
    const h = r.headers || {};
    for (const k of ['authorization', 'x-auth-token', 'set-cookie']) {
      if (h[k]) { const m = h[k].match(JWT_RE); if (m) for (const t of m) out.push({ token: t, where: `${k} header` }); }
    }
  }
  for (const b of site.apiBodies || []) {
    const m = (b.body || '').match(JWT_RE);
    if (m) for (const t of m.slice(0, 3)) out.push({ token: t, where: b.url });
  }
  return out;
}

function crack(h, p, sig, alg) {
  const algo = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }[alg.toUpperCase()];
  const data = `${h}.${p}`;
  for (const secret of WEAK_SECRETS) {
    const mac = crypto.createHmac(algo, secret).update(data).digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (mac === sig) return secret;
  }
  return null;
}

function decode(seg) {
  try {
    const b = Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(b);
  } catch {
    return null;
  }
}

function trunc(t) {
  return t.length > 40 ? t.slice(0, 20) + '…' + t.slice(-8) : t;
}

function add(findings, id, title, severity, url, evidence, impact, remediation, cwe) {
  findings.add({
    id, title, severity, url, evidence, impact, remediation, cwe,
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
    confidence: id === 'jwt-weak-secret' ? 0.95 : 0.7,
  });
}
