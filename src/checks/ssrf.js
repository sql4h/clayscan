import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';
import { startCollector } from '../http/oob.js';

const URL_HINT = /url|uri|link|src|source|dest|destination|redirect|redir|callback|cb|webhook|hook|host|domain|site|feed|rss|proxy|fetch|load|image|img|avatar|file|target|to|next|return|continue|remote|upstream|endpoint|api|preview|thumbnail|import|open/i;

export default {
  id: 'ssrf',
  name: 'Server-side request forgery (out-of-band)',
  phase: 'active',
  intrusive: 'high',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method === 'GET' || r.method === 'POST');
    const cap = opts.maxActiveTargets ?? 40;

    let collector;
    try {
      collector = await startCollector(target, opts);
    } catch {
      return;
    }

    const injected = [];
    let n = 0;
    try {
      for (const req of corpus) {
        for (const point of insertionPoints(req)) {
          if (n >= cap) break;
          const name = point.name || (point.path ? point.path[point.path.length - 1] : '');
          const value = currentValue(req, point);
          const urlish = URL_HINT.test(name) || /^https?:\/\//i.test(String(value || ''));
          if (!urlish) continue;
          const token = collector.token();
          await send(http, mutate(req, point, collector.url(token)));
          injected.push({ req, point, token });
          n++;
        }
        if (n >= cap) break;
      }

      if (!injected.length) return;
      await collector.wait(opts.oobWaitMs ?? 5000);

      for (const inj of injected) {
        if (collector.hit(inj.token)) {
          findings.add({
            id: 'ssrf',
            title: `Server-side request forgery in ${pointLabel(inj.req, inj.point)}`,
            severity: 'high',
            url: inj.req.url,
            evidence: `The server fetched a ClayScan-controlled URL supplied via ${pointLabel(inj.req, inj.point)} (out-of-band callback received).`,
            impact:
              'The server makes requests to attacker-controlled destinations. SSRF can reach internal services and cloud metadata endpoints to steal credentials, and pivot into the internal network.',
            remediation:
              'Do not fetch user-supplied URLs. If you must, resolve and validate the host against an allowlist, block private/link-local ranges, and disable redirects.',
            cwe: 'CWE-918',
            poc: `Set ${pointLabel(inj.req, inj.point)} to an attacker URL; the server connects to it.`,
            references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
            confidence: 0.95,
          });
        }
      }
    } finally {
      await collector.close().catch(() => {});
    }
  },
};

function currentValue(req, point) {
  try {
    if (point.kind === 'query') return new URL(req.url).searchParams.get(point.name);
    if (point.kind === 'form') return new URLSearchParams(req.body || '').get(point.name);
    if (point.kind === 'json') {
      let cur = JSON.parse(req.body);
      for (const k of point.path) cur = cur?.[k];
      return cur;
    }
  } catch {  }
  return null;
}
