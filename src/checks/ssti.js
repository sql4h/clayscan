import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const A = 913;
const B = 7;
const PRODUCT = A * B;

export default {
  id: 'ssti',
  name: 'Server-side template injection',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const marker = 'cly' + Math.random().toString(36).slice(2, 6);
    const expect = `${marker}${PRODUCT}`;
    const payloads = [
      `${marker}{{${A}*${B}}}`,
      `${marker}\${${A}*${B}}`,
      `${marker}#{${A}*${B}}`,
      `${marker}<%= ${A}*${B} %>`,
      `${marker}*{${A}*${B}}`,
      `${marker}{${A}*${B}}`,
    ];

    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const cap = opts.maxActiveTargets ?? 60;
    const seen = new Set();
    let tested = 0;

    for (const req of corpus) {
      for (const point of insertionPoints(req)) {
        if (tested >= cap) return;
        const pk = `${req.method} ${req.url.split('?')[0]} ${pointLabel(req, point)}`;
        if (seen.has(pk)) continue;
        seen.add(pk);
        tested++;

        for (const payload of payloads) {
          const res = await send(http, mutate(req, point, payload));
          if (!res.ok || !res.body) continue;
          if (res.body.includes(expect)) {
            findings.add({
              id: 'ssti',
              title: `Server-side template injection in ${pointLabel(req, point)}`,
              severity: 'critical',
              url: req.url,
              evidence: `Payload with ${A}*${B} was evaluated server-side: response contained "${expect}".`,
              impact:
                'The application renders user input as a server-side template. This commonly leads to remote code execution via the template engine.',
              remediation:
                'Never pass user input into template source. Use a logic-less template and pass data only as bound context variables.',
              cwe: 'CWE-1336',
              poc: `Set ${pointLabel(req, point)} to ${payload} → response echoes ${expect}.`,
              references: ['https://owasp.org/www-community/attacks/Server_Side_Template_Injection'],
              confidence: 0.9,
            });
            return;
          }
        }
      }
    }
  },
};
