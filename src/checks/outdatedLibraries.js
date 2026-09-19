const RULES = [
  { name: 'jQuery', re: /jquery[.-]?(\d+\.\d+\.\d+)/i, badBelow: '3.5.0', note: 'jQuery < 3.5.0 has known XSS issues (CVE-2020-11022/11023).' },
  { name: 'AngularJS', re: /angular(?:js)?[.-]?(1\.\d+\.\d+)/i, badBelow: '1.8.0', note: 'AngularJS 1.x is end-of-life and unpatched.' },
  { name: 'Bootstrap', re: /bootstrap[.-]?(\d+\.\d+\.\d+)/i, badBelow: '4.3.1', note: 'Older Bootstrap has XSS in data-* attributes.' },
  { name: 'Lodash', re: /lodash[.-]?(\d+\.\d+\.\d+)/i, badBelow: '4.17.21', note: 'Lodash < 4.17.21 has prototype pollution (CVE-2020-8203).' },
  { name: 'Moment.js', re: /moment[.-]?(\d+\.\d+\.\d+)/i, badBelow: '2.29.2', note: 'Moment < 2.29.2 has a path traversal (CVE-2022-24785).' },
];

export default {
  id: 'outdated-libraries',
  name: 'Outdated JavaScript libraries',
  phase: 'passive',
  run({ site, findings }) {
    const sources = new Set([...site.jsUrls]);
    for (const page of site.pages) {
      const m = page.html.match(/<script[^>]+src=["']([^"']+)["']/gi) || [];
      for (const tag of m) {
        const src = tag.match(/src=["']([^"']+)["']/i);
        if (src) sources.add(src[1]);
      }
    }
    for (const src of sources) {
      for (const rule of RULES) {
        const m = src.match(rule.re);
        if (!m) continue;
        const version = m[1];
        if (cmpVersion(version, rule.badBelow) < 0) {
          findings.add({
            id: `outdated-${rule.name.toLowerCase()}`,
            title: `Outdated ${rule.name} ${version}`,
            severity: 'medium',
            url: src,
            evidence: `Loaded ${rule.name} v${version} (< ${rule.badBelow})`,
            impact: rule.note,
            remediation: `Upgrade ${rule.name} to a current, patched release and add dependency scanning to CI.`,
            cwe: 'CWE-1104',
            references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'],
            confidence: 0.6,
          });
        }
      }
    }
  },
};

function cmpVersion(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}
