const PATTERNS = [
  { id: 'password-hash', name: 'Password hash in API response', re: /(?:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$[^"\s]+|\$(?:1|5|6)\$[./A-Za-z0-9$]{8,})|"(?:password|passwd|pwd)(?:_?hash)?"\s*:\s*"[a-f0-9]{32,128}"/i, severity: 'high', cwe: 'CWE-256' },
  { id: 'password-plain', name: 'Password field in API response', re: /"(?:password|passwd|pwd)"\s*:\s*"[^"]{3,}"/i, severity: 'high', cwe: 'CWE-359' },
  { id: 'private-key', name: 'Private key in API response', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, severity: 'critical', cwe: 'CWE-321' },
  { id: 'aws-key', name: 'AWS access key in API response', re: /AKIA[0-9A-Z]{16}/, severity: 'critical', cwe: 'CWE-798' },
  { id: 'jwt', name: 'JWT in API response', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/, severity: 'low', cwe: 'CWE-522' },
  { id: 'credit-card', name: 'Possible credit-card number in API response', re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/, severity: 'high', cwe: 'CWE-311', luhn: true },
  { id: 'ssn', name: 'Possible US SSN in API response', re: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'medium', cwe: 'CWE-359' },
];

export default {
  id: 'sensitive-data-api',
  name: 'Sensitive data in API responses',
  phase: 'passive',
  run({ site, findings }) {
    const seen = new Set();
    for (const resp of site.apiBodies || []) {
      const body = resp.body || '';
      if (!body) continue;
      for (const p of PATTERNS) {
        p.re.lastIndex = 0;
        const m = p.re.exec(body);
        if (!m) continue;
        if (p.luhn && !luhn(m[0].replace(/\D/g, ''))) continue;
        const key = `${p.id}|${resp.url}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.add({
          id: `apidata-${p.id}`,
          title: p.name,
          severity: p.severity,
          url: resp.url,
          evidence: `${resp.status} ${resp.type} response exposed: ${redact(m[0])}`,
          impact:
            'The API returns sensitive data to the client. Depending on authorization, this can leak credentials, secrets, or personal data to unauthorized users.',
          remediation:
            'Never send secrets or password hashes to clients. Return only the fields a caller needs, and enforce authorization on every field.',
          cwe: p.cwe,
          poc: `Inspect the JSON response from ${resp.url}.`,
          confidence: 0.6,
        });
      }

      const emails = body.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
      const uniqEmails = [...new Set(emails)];
      if (uniqEmails.length >= 5 && !seen.has(`emails|${resp.url}`)) {
        seen.add(`emails|${resp.url}`);
        findings.add({
          id: 'apidata-email-list',
          title: 'Bulk email addresses in API response',
          severity: 'medium',
          url: resp.url,
          evidence: `${uniqEmails.length} distinct email addresses returned, e.g. ${uniqEmails.slice(0, 3).join(', ')}`,
          impact: 'Mass exposure of user email addresses enables enumeration, phishing, and privacy violations.',
          remediation: 'Do not expose other users’ email addresses; paginate and authorize user data endpoints.',
          cwe: 'CWE-359',
          confidence: 0.55,
        });
      }
    }
  },
};

function redact(s) {
  if (s.length <= 12) return s;
  return s.slice(0, 6) + '…' + s.slice(-4) + ` (${s.length} chars)`;
}

function luhn(num) {
  let sum = 0;
  let alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = parseInt(num[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return num.length >= 13 && sum % 10 === 0;
}
