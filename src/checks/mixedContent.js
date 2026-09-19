export default {
  id: 'mixed-content',
  name: 'Mixed content over HTTPS',
  phase: 'passive',
  run({ site, findings, target }) {
    if (new URL(target).protocol !== 'https:') return;
    for (const page of site.pages) {
      if (!page.url.startsWith('https:')) continue;
      const hits = page.html.match(/(?:src|href|action)=["']http:\/\/[^"']+["']/gi) || [];
      const active = hits.filter((h) => /src=/i.test(h) && /\.(js|css)/i.test(h));
      if (hits.length) {
        findings.add({
          id: 'mixed-content',
          title: 'Mixed content on HTTPS page',
          severity: active.length ? 'medium' : 'low',
          url: page.url,
          evidence: `${hits.length} plaintext http:// resource reference(s), e.g. ${hits[0].slice(0, 120)}`,
          impact: active.length
            ? 'Active mixed content (scripts/styles over HTTP) can be tampered with on-path, compromising the whole page.'
            : 'Passive mixed content leaks browsing over plaintext and triggers browser warnings.',
          remediation: 'Load all resources over HTTPS; add upgrade-insecure-requests to your CSP.',
          cwe: 'CWE-311',
          confidence: 0.8,
        });
      }
    }
  },
};
