const SENSITIVE = [
  { re: /\.(?:sql|bak|old|zip|tar\.gz|backup|save|swp|orig)$/i, sev: 'high', why: 'Backup/source archive — may contain full source code or a database dump.' },
  { re: /\.env|\.git|\.svn|\.ssh|id_rsa|\.aws|\.npmrc|credentials|secret|passwd|\.htpasswd/i, sev: 'critical', why: 'Configuration/secret file — likely exposes credentials or keys.' },
  { re: /admin|dashboard|cpanel|phpmyadmin|adminer|manage|console|actuator|panel/i, sev: 'medium', why: 'Administrative interface — a high-value target if reachable.' },
  { re: /api|graphql|swagger|openapi|api-docs|\.json$/i, sev: 'low', why: 'API surface / documentation — enumerate for authz and injection issues.' },
  { re: /phpinfo|server-status|server-info|debug|test|info\.php/i, sev: 'medium', why: 'Debug/info endpoint — leaks environment and internal details.' },
];

export default {
  id: 'discovered-endpoints',
  name: 'Discovered endpoints (content discovery)',
  phase: 'passive',
  run({ site, findings, target }) {
    const hits = site.discoveredPaths || [];
    for (const h of hits) {
      const match = h.status === 200 ? SENSITIVE.find((s) => s.re.test(h.url)) : null;
      const protectedButPresent = h.status === 401 || h.status === 403;
      const erroring = h.status >= 500;
      const severity = match ? match.sev : protectedButPresent ? 'low' : 'info';
      const why = match
        ? match.why
        : protectedButPresent
          ? 'Path exists but is access-controlled — confirms attack surface and may be bypassable.'
          : erroring
            ? 'Path returns a server error, which can indicate an unhandled route worth manual review.'
            : 'Reachable path not linked from the site; review whether it should be public.';
      findings.add({
        id: match ? `discovered-${match.sev}` : 'discovered-path',
        title: `Discovered ${describe(h)}: ${new URL(h.url).pathname}`,
        severity,
        url: h.url,
        evidence: `${h.status}${h.location ? ` → ${h.location}` : ''} (body ${h.length} bytes) found via wordlist.`,
        impact: why,
        remediation:
          'Remove or restrict this path if it should not be public; ensure backups, VCS metadata, and admin panels are never web-reachable.',
        cwe: 'CWE-538',
        poc: `curl -si "${h.url}"`,
        confidence: 0.6,
      });
    }
  },
};

function describe(h) {
  if (h.status === 401 || h.status === 403) return 'protected path';
  if ([301, 302, 303, 307, 308].includes(h.status)) return 'redirect';
  if (h.status >= 500) return 'erroring path';
  return 'endpoint';
}
