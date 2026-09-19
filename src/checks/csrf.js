export default {
  id: 'csrf',
  name: 'Cross-Site Request Forgery (CSRF) token check',
  phase: 'passive',
  run({ site, findings }) {
    for (const form of site.forms) {
      if (form.method !== 'POST') continue;
      if (form.hasCsrfToken) continue;
      const isAuthy = form.inputs.some((i) => /password|current|old|new|email/i.test(i.name || i.type));
      findings.add({
        id: 'csrf-missing-token',
        title: 'POST form without anti-CSRF token',
        severity: isAuthy ? 'medium' : 'low',
        url: form.pageUrl,
        evidence: `Form action=${form.action} method=POST has no field matching csrf/token/nonce. Fields: ${form.inputs.map((i) => i.name).filter(Boolean).join(', ') || '(none named)'}`,
        impact:
          'A malicious site can auto-submit this form using the victim\'s session, performing the action without their consent (fund transfer, password change, etc.).',
        remediation:
          'Include a per-session/per-request CSRF token and validate it server-side; set SameSite=Lax/Strict on session cookies as defense-in-depth.',
        cwe: 'CWE-352',
        references: ['https://owasp.org/www-community/attacks/csrf'],
        confidence: 0.5,
      });
    }
  },
};
