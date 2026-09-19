import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const NOSQL_ERRORS = [
  /MongoError/i,
  /Mongoose/i,
  /CastError/i,
  /BSONError/i,
  /\$where/i,
  /MongoServerError/i,
  /E11000 duplicate key/i,
  /couldn't find that document/i,
];

export default {
  id: 'nosql-injection',
  name: 'NoSQL injection',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const cap = opts.maxActiveTargets ?? 50;
    const seen = new Set();
    let tested = 0;

    for (const req of corpus) {
      for (const point of insertionPoints(req)) {
        if (tested >= cap) return;
        const pk = `${req.method} ${req.url.split('?')[0]} ${pointLabel(req, point)}`;
        if (seen.has(pk)) continue;
        seen.add(pk);
        tested++;

        const base = await send(http, mutate(req, point, 'clayscan1'));
        if (!base.ok || matchesError(base.body)) continue;

        let injected;
        if (point.kind === 'json') injected = mutate(req, point, { $gt: '' }, { raw: true });
        else injected = mutate(req, point, "clayscan1' || '1'=='1");
        const res = await send(http, injected);
        if (!res.ok) continue;

        const err = matchesError(res.body);
        if (err) {
          findings.add({
            id: 'nosql-injection',
            title: `NoSQL injection in ${pointLabel(req, point)}`,
            severity: 'high',
            url: req.url,
            evidence: `A NoSQL operator/payload in ${pointLabel(req, point)} produced a database error: "${err}"`,
            impact:
              'The application passes user input into a NoSQL query. This enables authentication bypass, data extraction, and query manipulation.',
            remediation:
              'Cast/validate input types, reject objects where strings are expected, and use an ODM with strict schemas.',
            cwe: 'CWE-943',
            poc: `Send ${req.method} ${req.url} with ${pointLabel(req, point)} set to a NoSQL operator (e.g. {"$gt":""}).`,
            references: ['https://owasp.org/www-community/attacks/NoSQL_injection'],
            confidence: 0.7,
          });
        }
      }
    }
  },
};

function matchesError(body) {
  for (const re of NOSQL_ERRORS) {
    const m = re.exec(body || '');
    if (m) return m[0].slice(0, 100);
  }
  return null;
}
