export default {
  id: 'cors',
  name: 'CORS misconfiguration',
  phase: 'active',
  intrusive: 'low',
  async run({ target, findings, http }) {
    const evilOrigin = 'https://clayscan-cors-probe.example';
    const res = await http.request(target, {
      headers: { Origin: evilOrigin },
      redirect: 'manual',
    });
    if (!res.ok) return;
    const acao = res.headers['access-control-allow-origin'];
    const acac = res.headers['access-control-allow-credentials'];
    if (!acao) return;

    if (acao === '*' && acac === 'true') {
      findings.add({
        id: 'cors-wildcard-credentials',
        title: 'CORS allows any origin with credentials',
        severity: 'high',
        url: target,
        evidence: `Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true`,
        impact:
          'Any website can make authenticated cross-origin requests and read the response, exposing user data. (Browsers normally block *+credentials, but this signals a badly configured API.)',
        remediation: 'Never combine a wildcard origin with credentials; echo only a strict allowlist.',
        cwe: 'CWE-942',
      });
    } else if (acao === evilOrigin) {
      findings.add({
        id: 'cors-origin-reflection',
        title: 'CORS reflects arbitrary Origin',
        severity: acac === 'true' ? 'high' : 'medium',
        url: target,
        evidence: `Sent Origin: ${evilOrigin} → Access-Control-Allow-Origin: ${acao}${acac === 'true' ? ' + credentials' : ''}`,
        impact:
          'The server trusts any origin. A malicious site can read authenticated responses on behalf of a logged-in victim.',
        remediation: 'Validate Origin against a strict allowlist instead of reflecting it.',
        cwe: 'CWE-942',
        poc: `curl -s -H "Origin: ${evilOrigin}" -I "${target}"`,
      });
    }
  },
};
