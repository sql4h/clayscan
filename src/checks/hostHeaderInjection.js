const CANARY = 'clayscan-hhi.example';

export default {
  id: 'host-header-injection',
  name: 'Host header injection',
  phase: 'active',
  intrusive: 'low',
  async run({ target, findings, http }) {
    const res = await http.request(target, {
      headers: {
        'X-Forwarded-Host': CANARY,
        'X-Host': CANARY,
        'X-Forwarded-Server': CANARY,
      },
      redirect: 'manual',
    });
    if (!res.ok) return;

    const loc = res.headers['location'] || '';
    const inBody = (res.body || '').includes(CANARY);
    const inRedirect = loc.includes(CANARY);

    if (inRedirect || inBody) {
      findings.add({
        id: 'host-header-injection',
        title: 'Host header injection (X-Forwarded-Host reflected)',
        severity: inRedirect ? 'medium' : 'low',
        url: target,
        evidence: inRedirect
          ? `X-Forwarded-Host: ${CANARY} was reflected into the redirect Location: ${loc}`
          : `X-Forwarded-Host: ${CANARY} was reflected into the response body.`,
        impact:
          'Trusting the client-supplied host lets an attacker poison absolute links and password-reset emails, and can enable web cache poisoning.',
        remediation:
          'Derive absolute URLs from a fixed, server-configured hostname; validate Host/X-Forwarded-Host against an allowlist.',
        cwe: 'CWE-644',
        poc: `curl -s -i -H "X-Forwarded-Host: ${CANARY}" "${target}"`,
        confidence: 0.7,
      });
    }
  },
};
