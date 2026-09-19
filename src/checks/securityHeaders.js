const CHECKS = [
  {
    header: 'content-security-policy',
    id: 'missing-csp',
    title: 'Missing Content-Security-Policy',
    severity: 'medium',
    impact:
      'Without a CSP, a single injected script (XSS) runs with full privileges. CSP is the strongest defense-in-depth control against script injection and data exfiltration.',
    remediation:
      "Add a Content-Security-Policy header, e.g. default-src 'self'; object-src 'none'; base-uri 'self'. Start in report-only mode, then enforce.",
    cwe: 'CWE-693',
  },
  {
    header: 'strict-transport-security',
    id: 'missing-hsts',
    title: 'Missing HTTP Strict-Transport-Security (HSTS)',
    severity: 'medium',
    impact:
      'Users can be downgraded to plaintext HTTP by an on-path attacker (SSL stripping), exposing cookies and credentials.',
    remediation:
      'Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS.',
    cwe: 'CWE-319',
    httpsOnly: true,
  },
  {
    header: 'x-content-type-options',
    id: 'missing-x-content-type-options',
    title: 'Missing X-Content-Type-Options: nosniff',
    severity: 'low',
    impact:
      'Browsers may MIME-sniff responses, turning a benign upload or endpoint into executable script or a drive-by.',
    remediation: 'Send X-Content-Type-Options: nosniff on all responses.',
    cwe: 'CWE-16',
  },
  {
    header: 'referrer-policy',
    id: 'missing-referrer-policy',
    title: 'Missing Referrer-Policy',
    severity: 'low',
    impact:
      'Full URLs (which may contain tokens or IDs) can leak to third-party sites via the Referer header.',
    remediation: 'Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).',
    cwe: 'CWE-200',
  },
  {
    header: 'permissions-policy',
    id: 'missing-permissions-policy',
    title: 'Missing Permissions-Policy',
    severity: 'info',
    impact:
      'Powerful browser features (camera, geolocation, microphone) are not explicitly restricted, widening the blast radius of an XSS.',
    remediation: 'Send a Permissions-Policy header disabling features you do not use.',
    cwe: 'CWE-16',
  },
];

export default {
  id: 'security-headers',
  name: 'Security response headers',
  phase: 'passive',
  run({ site, findings, target }) {
    const isHttps = new URL(target).protocol === 'https:';

    const main =
      site.responses.find((r) => r.url === target && r.type.includes('html')) ||
      site.responses.find((r) => r.type.includes('html')) ||
      site.responses[0];
    if (!main) return;
    const headers = main.headers || {};

    for (const c of CHECKS) {
      if (c.httpsOnly && !isHttps) continue;
      if (!headers[c.header]) {
        findings.add({
          id: c.id,
          title: c.title,
          severity: c.severity,
          url: main.url,
          evidence: `Response from ${main.url} did not include the "${c.header}" header.`,
          impact: c.impact,
          remediation: c.remediation,
          cwe: c.cwe,
          poc: `curl -sI "${main.url}" | grep -i "${c.header}"  # returns nothing`,
          references: ['https://owasp.org/www-project-secure-headers/'],
          confidence: 0.95,
        });
      }
    }

    if (headers['x-xss-protection'] && headers['x-xss-protection'].startsWith('1')) {
      findings.add({
        id: 'legacy-xss-protection',
        title: 'Legacy X-XSS-Protection enabled',
        severity: 'info',
        url: main.url,
        evidence: `X-XSS-Protection: ${headers['x-xss-protection']}`,
        impact: 'The buggy legacy XSS auditor can itself introduce vulnerabilities; modern browsers ignore it.',
        remediation: 'Set X-XSS-Protection: 0 and rely on Content-Security-Policy instead.',
        cwe: 'CWE-16',
      });
    }
    if (headers.server && /\d/.test(headers.server)) {
      findings.add({
        id: 'server-version-disclosure',
        title: 'Server version disclosed',
        severity: 'low',
        url: main.url,
        evidence: `Server: ${headers.server}`,
        impact: 'Exact software versions let an attacker map known CVEs to your stack quickly.',
        remediation: 'Suppress or genericize the Server header.',
        cwe: 'CWE-200',
      });
    }
    if (headers['x-powered-by']) {
      findings.add({
        id: 'x-powered-by',
        title: 'X-Powered-By technology disclosure',
        severity: 'info',
        url: main.url,
        evidence: `X-Powered-By: ${headers['x-powered-by']}`,
        impact: 'Reveals framework/runtime, aiding targeted attacks.',
        remediation: 'Remove the X-Powered-By header.',
        cwe: 'CWE-200',
      });
    }
  },
};
