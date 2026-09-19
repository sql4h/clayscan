const CRED_PATTERNS = [
  {
    id: 'hardcoded-password',
    name: 'Hardcoded password',
    re: /\b(?:password|passwd|pass|pwd|passphrase)\s*[:=]\s*["'`]([^"'`\s]{3,80})["'`]/gi,
    severity: 'critical',
    cwe: 'CWE-798',
  },
  {
    id: 'client-side-auth',
    name: 'Client-side credential comparison',

    re: /\b(?:password|passwd|passphrase|pwd|pincode|passcode|accesscode)\s*(?:===?|!==?)\s*["'`]([^"'`]{3,80})["'`]/gi,
    severity: 'critical',
    cwe: 'CWE-603',
  },
  {
    id: 'client-side-auth-rev',
    name: 'Client-side credential comparison',
    re: /["'`]([^"'`]{3,80})["'`]\s*(?:===?|!==?)\s*\b(?:password|passwd|passphrase|pwd|pincode|passcode|accesscode)\b/gi,
    severity: 'critical',
    cwe: 'CWE-603',
  },
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded secret / API token',
    re: /\b(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{6,120})["'`]/gi,
    severity: 'high',
    cwe: 'CWE-798',
  },
  {
    id: 'basic-auth-inline',
    name: 'Embedded HTTP Basic credentials',
    re: /https?:\/\/[^/:@\s"'`]+:[^/@\s"'`]+@/g,
    severity: 'high',
    cwe: 'CWE-522',
  },
  {
    id: 'firebase-apikey',
    name: 'Firebase/Google client apiKey',
    re: /apiKey\s*:\s*["'`](AIza[0-9A-Za-z\-_]{20,})["'`]/g,
    severity: 'low',
    cwe: 'CWE-200',
  },
];

const IGNORE_VALUES = /^(?:true|false|null|undefined|nan)$/i;

const FIELD_NAMES = new Set([
  'access_token', 'refresh_token', 'id_token', 'token_type', 'expires_in', 'expires_at',
  'apikey', 'api_key', 'authorization', 'bearer', 'password', 'passwd', 'pwd', 'username',
  'email', 'token', 'secret', 'key', 'value', 'string', 'object', 'function', 'application/json',
  'content-type', 'x-client-info', 'grant_type', 'provider_token', 'not_authenticated',
]);

function isLiteralSecret(value) {
  if (!value) return false;
  const v = value.trim();
  if (v.includes('${') || v.includes('` +') || /["'`]\s*\+/.test(v)) return false;
  if (FIELD_NAMES.has(v.toLowerCase())) return false;
  return true;
}

export default {
  id: 'credentials',
  name: 'Hardcoded credentials / client-side auth',
  phase: 'passive',
  run({ site, findings }) {
    const sources = [];
    for (const page of site.pages) {
      sources.push({ url: page.url, text: page.html, kind: 'inline HTML/JS' });
    }
    for (const js of site.jsFiles || []) {
      sources.push({ url: js.url, text: js.body, kind: 'JavaScript file' });
    }

    const seen = new Set();
    for (const { url, text, kind } of sources) {
      if (!text) continue;
      for (const p of CRED_PATTERNS) {
        p.re.lastIndex = 0;
        let m;
        while ((m = p.re.exec(text)) !== null) {
          const value = m[1] || '';
          if (IGNORE_VALUES.test(value.trim())) continue;

          if (p.id !== 'basic-auth-inline' && !isLiteralSecret(value)) continue;
          const key = `${p.id}:${value}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.add({
            id: p.id,
            title: p.name,
            severity: p.severity,
            url,
            evidence: `${kind}: ${trimSnippet(m[0])}  (value: ${redact(value)})`,
            impact:
              'Any credential or authentication logic shipped to the browser is fully readable by every visitor. A "password gate" enforced in client-side JavaScript provides no security — anyone can read the value in DevTools and bypass it.',
            remediation:
              'Never embed passwords, secrets, or auth checks in client-side code. Move authentication server-side, rotate the exposed value immediately, and serve protected content only after the server validates the request.',
            cwe: p.cwe,
            poc: 'Open the page, then DevTools → Sources/Network, and read the value directly from the delivered JavaScript.',
            references: ['https://cwe.mitre.org/data/definitions/798.html'],
            confidence: p.id.startsWith('client-side-auth') ? 0.7 : 0.85,
          });
          if (seen.size > 200) return;
        }
      }
    }
  },
};

function trimSnippet(s) {
  return s.replace(/\s+/g, ' ').slice(0, 100);
}
function redact(v) {
  if (v.length <= 6) return v;
  return v.slice(0, 3) + '…' + v.slice(-2) + ` (${v.length} chars)`;
}
