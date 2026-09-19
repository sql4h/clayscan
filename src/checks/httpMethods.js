const DANGEROUS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];

export default {
  id: 'http-methods',
  name: 'Dangerous HTTP methods',
  phase: 'active',
  intrusive: 'low',
  async run({ target, findings, http, site }) {
    const origin = new URL(target).origin;
    const targets = new Set([target, origin + '/']);
    for (const r of (site.responses || []).slice(0, 20)) {
      if (r.type && /json|html/.test(r.type)) targets.add(r.url.split('?')[0]);
    }

    const checked = new Set();
    const reportedSets = new Set();
    let count = 0;
    for (const url of targets) {
      if (count >= 12) break;
      const path = new URL(url).pathname;
      if (checked.has(path)) continue;
      checked.add(path);
      count++;

      const res = await http.request(url, { method: 'OPTIONS', redirect: 'manual' });
      if (!res.ok) continue;
      const allow = res.headers['allow'] || res.headers['Allow'] || res.headers['access-control-allow-methods'] || '';
      if (!allow) continue;
      const methods = allow.toUpperCase();
      const bad = DANGEROUS.filter((m) => methods.includes(m));
      if (bad.length && !reportedSets.has(bad.join(','))) {
        reportedSets.add(bad.join(','));
        findings.add({
          id: 'dangerous-http-methods',
          title: `Write/dangerous HTTP methods advertised: ${bad.join(', ')}`,
          severity: bad.includes('PUT') || bad.includes('DELETE') ? 'medium' : 'low',
          url,
          evidence: `OPTIONS ${url} → Allow: ${allow}`,
          impact:
            'Methods like PUT/DELETE can allow uploading or removing resources; TRACE enables cross-site tracing. If not intended, they widen the attack surface.',
          remediation: 'Disable HTTP methods the endpoint does not need; restrict write methods to authenticated, authorized callers.',
          cwe: 'CWE-650',
          poc: `curl -s -i -X OPTIONS "${url}"`,
          confidence: 0.6,
        });
      }
    }
  },
};
