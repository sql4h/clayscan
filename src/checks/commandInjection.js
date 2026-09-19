import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const CALC = 1000 + 337;

export default {
  id: 'command-injection',
  name: 'OS command injection',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const marker = 'CLYCMD' + Math.random().toString(36).slice(2, 8).toUpperCase();
    const expect = `${marker}${CALC}`;
    const payloads = [
      `;echo ${marker}$((1000+337))`,
      `| echo ${marker}$((1000+337))`,
      `& echo ${marker}$((1000+337))`,
      `\`echo ${marker}$((1000+337))\``,
      `$(echo ${marker}$((1000+337)))`,
      `%0aecho ${marker}$((1000+337))`,
    ];

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

        const base = await send(http, mutate(req, point, `${marker}probe`));
        if (base.ok && (base.body || '').includes(expect)) continue;

        for (const payload of payloads) {
          const res = await send(http, mutate(req, point, payload));
          if (!res.ok) continue;
          if ((res.body || '').includes(expect)) {
            findings.add({
              id: 'command-injection',
              title: `OS command injection in ${pointLabel(req, point)}`,
              severity: 'critical',
              url: req.url,
              evidence: `Injecting a shell command into ${pointLabel(req, point)} made the server evaluate it: the response contained "${expect}" (the arithmetic result ${CALC}, not the literal payload).`,
              impact:
                'The application executes attacker-supplied input as an OS command — typically full remote code execution.',
              remediation:
                'Never pass user input to a shell. Use argument-array APIs (execFile/spawn without a shell) and strict allowlists.',
              cwe: 'CWE-78',
              poc: `Set ${pointLabel(req, point)} to a shell payload; the response echoes ${expect}.`,
              references: ['https://owasp.org/www-community/attacks/Command_Injection'],
              confidence: 0.95,
            });
            break;
          }
        }
      }
    }
  },
};
