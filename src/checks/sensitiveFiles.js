const PATHS = [
  { path: '/.git/config', id: 'exposed-git', title: 'Exposed .git repository', severity: 'high', match: /\[core\]|repositoryformatversion/i, cwe: 'CWE-538', notHtml: true },
  { path: '/.env', id: 'exposed-env', title: 'Exposed .env file', severity: 'critical', match: /^[\w.]+=.*(?:\r?\n[\w.]+=.*)+/m, cwe: 'CWE-538', notHtml: true },
  { path: '/config.json', id: 'exposed-config', title: 'Exposed config.json', severity: 'medium', match: /^\s*[{[]/, cwe: 'CWE-538', notHtml: true, json: true },
  { path: '/backup.zip', id: 'exposed-backup', title: 'Exposed backup archive', severity: 'high', match: /PK\x03\x04/, cwe: 'CWE-530', notHtml: true },
  { path: '/.DS_Store', id: 'exposed-dsstore', title: 'Exposed .DS_Store', severity: 'low', match: /Bud1/, cwe: 'CWE-538', notHtml: true },
  { path: '/phpinfo.php', id: 'exposed-phpinfo', title: 'Exposed phpinfo()', severity: 'medium', match: /phpinfo\(\)|PHP Version/i, cwe: 'CWE-200' },
  { path: '/server-status', id: 'exposed-server-status', title: 'Exposed Apache server-status', severity: 'medium', match: /Apache Server Status/i, cwe: 'CWE-200' },
  { path: '/.svn/entries', id: 'exposed-svn', title: 'Exposed .svn metadata', severity: 'medium', match: /\d+\s*\n/, cwe: 'CWE-538', notHtml: true },
  { path: '/wp-config.php.bak', id: 'exposed-wpconfig-bak', title: 'Exposed wp-config backup', severity: 'critical', match: /DB_PASSWORD|DB_NAME/i, cwe: 'CWE-530', notHtml: true },
];

function looksHtml(res) {
  return /text\/html/i.test(res.headers?.['content-type'] || '') || /^\s*<(?:!doctype|html|\?xml|!--)/i.test(res.body || '');
}

export default {
  id: 'sensitive-files',
  name: 'Exposed sensitive files',
  phase: 'active',
  intrusive: 'low',
  async run({ target, findings, http }) {
    const origin = new URL(target).origin;
    for (const p of PATHS) {
      const url = origin + p.path;
      const res = await http.request(url, { redirect: 'manual' });
      if (!res.ok || res.status !== 200) continue;
      if (p.notHtml && looksHtml(res)) continue;
      if (p.match && !p.match.test(res.body)) continue;
      findings.add({
        id: p.id,
        title: p.title,
        severity: p.severity,
        url,
        evidence: `GET ${url} → 200 and body matched expected signature.`,
        impact:
          'This file exposes source code, credentials, or internal configuration that materially aids an attacker or directly leaks secrets.',
        remediation:
          'Block access to this path at the web server / CDN, and ensure such files are never deployed to the web root.',
        cwe: p.cwe,
        poc: `curl -s "${url}"`,
        confidence: 0.85,
      });
    }
  },
};
