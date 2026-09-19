export default {
  id: 'clickjacking',
  name: 'Clickjacking / framing protection',
  phase: 'passive',
  run({ site, findings, target }) {
    const main =
      site.responses.find((r) => r.url === target && r.type.includes('html')) ||
      site.responses.find((r) => r.type.includes('html'));
    if (!main) return;
    const h = main.headers || {};
    const xfo = h['x-frame-options'];
    const csp = h['content-security-policy'] || '';
    const cspFrames = /frame-ancestors/i.test(csp);

    if (!xfo && !cspFrames) {
      findings.add({
        id: 'clickjacking',
        title: 'No clickjacking protection (framing allowed)',
        severity: 'medium',
        url: main.url,
        evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
        impact:
          'The page can be embedded in an attacker-controlled iframe and overlaid with decoy UI to trick users into clicking sensitive actions (clickjacking).',
        remediation:
          "Send CSP frame-ancestors 'self' (preferred) and/or X-Frame-Options: DENY.",
        cwe: 'CWE-1021',
        poc:
          `<iframe src="${main.url}" style="opacity:.1"></iframe>  <!-- renders = framable -->`,
        references: ['https://owasp.org/www-community/attacks/Clickjacking'],
      });
    }
  },
};
