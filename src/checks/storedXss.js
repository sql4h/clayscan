import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

export default {
  id: 'stored-xss',
  name: 'Stored / blind XSS',
  phase: 'active',
  intrusive: 'high',
  async run({ site, findings, http, target, opts, context }) {
    if (!context) return;
    const base = 'CLYX' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const cap = opts.maxActiveTargets ?? 40;

    const injected = [];
    let n = 0;
    for (const req of corpus) {
      for (const point of insertionPoints(req)) {
        if (n >= cap) break;
        const nonce = `${base}${n}`;
        const payload = `"><img src=x onerror="window.__CLY_XSS__='${nonce}'">clay${nonce}`;
        await send(http, mutate(req, point, payload));
        injected.push({ req, point, nonce });
        n++;
      }
      if (n >= cap) break;
    }
    if (!injected.length) return;

    const nonces = new Map(injected.map((i) => [i.nonce, i]));
    const visit = uniq([target, ...site.pages.map((p) => p.url)]).slice(0, opts.maxStoredVisits ?? 20);

    const page = await context.newPage();
    page.setDefaultTimeout(opts.pageTimeout ?? 15000);
    try {
      for (const url of visit) {
        if (!nonces.size) break;
        try {
          await page.goto(url, { waitUntil: 'domcontentloaded' });
          await page.waitForTimeout(500);
        } catch { continue; }

        const fired = await page.evaluate(() => {
          const v = window.__CLY_XSS__;
          try { delete window.__CLY_XSS__; } catch {  }
          return v || null;
        }).catch(() => null);

        if (fired && nonces.has(fired)) {
          const inj = nonces.get(fired);
          nonces.delete(fired);
          findings.add({
            id: 'stored-xss',
            title: `Stored / blind XSS via ${pointLabel(inj.req, inj.point)}`,
            severity: 'high',
            url: inj.req.url,
            evidence: `A payload injected into ${pointLabel(inj.req, inj.point)} of ${inj.req.method} ${inj.req.url} executed later when loading ${url}.`,
            impact:
              'Attacker-controlled script is stored and runs in other users\' browsers — session theft, account takeover, and worming across users.',
            remediation:
              'Contextually output-encode all stored data on render, sanitize HTML with a vetted library, and apply a strict CSP.',
            cwe: 'CWE-79',
            poc: `Inject the payload via ${pointLabel(inj.req, inj.point)}, then load ${url}.`,
            references: ['https://owasp.org/www-community/attacks/xss/'],
            confidence: 0.95,
          });
        }

        const html = await page.content().catch(() => '');
        for (const [nonce, inj] of [...nonces]) {
          if (html.includes(`clay${nonce}`) && html.includes('onerror')) {
            nonces.delete(nonce);
            findings.add({
              id: 'stored-xss-unescaped',
              title: `Stored unescaped input via ${pointLabel(inj.req, inj.point)}`,
              severity: 'medium',
              url: inj.req.url,
              evidence: `Markup injected into ${pointLabel(inj.req, inj.point)} was stored and returned without encoding on ${url} (script did not execute, possibly CSP-mitigated).`,
              impact: 'Stored, unencoded HTML is a strong stored-XSS indicator; another payload or context may achieve execution.',
              remediation: 'Output-encode stored data on render and enforce a strict CSP.',
              cwe: 'CWE-79',
              confidence: 0.6,
            });
          }
        }
      }
    } finally {
      await page.close().catch(() => {});
    }
  },
};

function uniq(arr) {
  return [...new Set(arr)];
}
