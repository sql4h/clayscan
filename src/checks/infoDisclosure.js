const PATTERNS = [
  { id: 'aws-access-key', name: 'AWS access key ID', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical', cwe: 'CWE-798' },
  { id: 'google-api-key', name: 'Google API key', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high', cwe: 'CWE-798' },
  { id: 'slack-token', name: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: 'high', cwe: 'CWE-798' },
  { id: 'private-key', name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: 'critical', cwe: 'CWE-798' },
  { id: 'jwt', name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, severity: 'medium', cwe: 'CWE-522' },
  { id: 'stack-trace', name: 'Server stack trace / debug output', re: /(?:Traceback \(most recent call last\)|Exception in thread|at [\w.$]+\([\w.]+\.java:\d+\)|Warning: .+ in \/[^\s]+ on line \d+)/g, severity: 'medium', cwe: 'CWE-209' },
  { id: 'internal-ip', name: 'Internal IP / hostname leak', re: /\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/g, severity: 'low', cwe: 'CWE-200' },
];

export default {
  id: 'info-disclosure',
  name: 'Sensitive data / secret disclosure',
  phase: 'passive',
  run({ site, findings }) {
    const seenSecret = new Set();
    const sources = [
      ...site.pages.map((page) => ({
        url: page.url,
        haystacks: [
          { text: page.html, where: 'HTML body' },
          { text: page.comments.join('\n'), where: 'HTML comment' },
        ],
      })),
      ...(site.jsFiles || []).map((js) => ({
        url: js.url,
        haystacks: [{ text: js.body, where: 'JavaScript file' }],
      })),
    ];
    for (const page of sources) {
      const haystacks = page.haystacks;
      for (const { text, where } of haystacks) {
        if (!text) continue;
        for (const p of PATTERNS) {
          p.re.lastIndex = 0;
          const m = p.re.exec(text);
          if (m) {
            const secretKey = `${p.id}:${m[0]}`;
            if (seenSecret.has(secretKey)) continue;
            seenSecret.add(secretKey);
            findings.add({
              id: `leak-${p.id}`,
              title: `${p.name} exposed in page source`,
              severity: p.severity,
              url: page.url,
              evidence: `${where}: ${redact(m[0])}`,
              impact:
                'Secrets embedded in client-delivered content are readable by anyone and can grant direct access to backend systems or user data.',
              remediation:
                'Remove the secret from client-side code, rotate it immediately, and move it server-side behind an authenticated proxy.',
              cwe: p.cwe,
              confidence: 0.7,
            });
          }
        }
      }
    }
  },
};

function redact(s) {
  if (s.length <= 12) return s;
  return s.slice(0, 6) + '…' + s.slice(-4) + ` (${s.length} chars)`;
}
