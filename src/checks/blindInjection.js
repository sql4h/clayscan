import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const DELAY = 5;

const SQL_TEMPLATES = [
  (d) => `clayscan1' AND SLEEP(${d})-- -`,
  (d) => `clayscan1'||pg_sleep(${d})--`,
  (d) => `clayscan1';WAITFOR DELAY '0:0:${d}'--`,
  (d) => `1) AND SLEEP(${d})-- -`,
  (d) => `clayscan1" AND SLEEP(${d})-- -`,
];

const CMD_TEMPLATES = [
  (d) => `clayscan;sleep ${d}`,
  (d) => `clayscan|sleep ${d}`,
  (d) => `clayscan\`sleep ${d}\``,
  (d) => `clayscan$(sleep ${d})`,
  (d) => `clayscan&&sleep ${d}`,
];

export default {
  id: 'blind-injection',
  name: 'Blind (time-based) SQL / command injection',
  phase: 'active',
  intrusive: 'high',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const cap = opts.maxBlindTargets ?? 12;
    const seen = new Set();
    let tested = 0;

    for (const req of corpus) {
      for (const point of insertionPoints(req)) {
        if (tested >= cap) return;
        const pk = `${req.method} ${req.url.split('?')[0]} ${pointLabel(req, point)}`;
        if (seen.has(pk)) continue;
        seen.add(pk);

        const t1 = await timed(http, mutate(req, point, 'clayscan1'));
        const t2 = await timed(http, mutate(req, point, 'clayscan2'));
        if (t1 == null || t2 == null) continue;
        const baseline = Math.min(t1, t2);
        if (baseline > 8000) continue;
        tested++;

        const families = [
          { kind: 'SQL', cwe: 'CWE-89', name: 'time-based SQL injection', templates: SQL_TEMPLATES },
          { kind: 'command', cwe: 'CWE-78', name: 'time-based OS command injection', templates: CMD_TEMPLATES },
        ];

        let done = false;
        for (const fam of families) {
          if (done) break;
          for (const tpl of fam.templates) {
            const delayed = await timed(http, mutate(req, point, tpl(DELAY)));
            if (delayed == null) continue;
            if (delayed - baseline < DELAY * 1000 * 0.6) continue;

            const control = await timed(http, mutate(req, point, tpl(0)));
            if (control == null) continue;
            if (delayed - control >= DELAY * 1000 * 0.6 && control < baseline + 2500) {
              findings.add({
                id: `blind-${fam.kind === 'SQL' ? 'sqli' : 'cmdi'}`,
                title: `Blind ${fam.name} in ${pointLabel(req, point)}`,
                severity: 'critical',
                url: req.url,
                evidence: `${pointLabel(req, point)} with a ${DELAY}s delay payload took ${delayed}ms vs ${control}ms for the 0s control (baseline ${baseline}ms) — the injected time delay is controllable.`,
                impact:
                  fam.kind === 'SQL'
                    ? 'The parameter is injectable into a SQL query even though no error or data is reflected; an attacker can extract the database bit-by-bit (blind SQLi).'
                    : 'The parameter is injectable into an OS command even without visible output; an attacker can run commands and exfiltrate data blindly.',
                remediation:
                  fam.kind === 'SQL'
                    ? 'Use parameterized queries; never concatenate input into SQL.'
                    : 'Never pass user input to a shell; use argument-array APIs and strict validation.',
                cwe: fam.cwe,
                poc: `Set ${pointLabel(req, point)} to ${tpl(DELAY)} → response is delayed ~${DELAY}s; ${tpl(0)} is not.`,
                confidence: 0.85,
              });
              done = true;
              break;
            }
          }
        }
      }
    }
  },
};

async function timed(http, req) {
  const res = await send(http, req);
  if (!res || res.ms == null) return null;
  return res.ms;
}
