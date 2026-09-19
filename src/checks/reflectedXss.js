import { withParam, paramNames } from '../utils/url.js';

export default {
  id: 'reflected-xss',
  name: 'Reflected Cross-Site Scripting (XSS)',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, context, target, opts }) {
    const marker = 'CLY' + Math.random().toString(36).slice(2, 9).toUpperCase();
    const targets = collectParamUrls(site, target).slice(0, opts.maxActiveTargets ?? 40);

    const probePage = await context.newPage();
    try {
      for (const { url, param } of targets) {
        const reflectUrl = withParam(url, param, `cly"${marker}<x>`);
        const res = await http.request(reflectUrl);
        if (!res.ok || !res.body.includes(marker)) continue;

        const reflectedRaw = res.body.includes(`<x>`) && res.body.includes(marker);

        const execUrl = withParam(
          url,
          param,
          `"><script>window.__CLAYSCAN_XSS__='${marker}'</script>`
        );
        let executed = false;
        try {
          await probePage.goto(execUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
          executed = (await probePage.evaluate(() => window.__CLAYSCAN_XSS__)) === marker;
          await probePage.evaluate(() => { try { delete window.__CLAYSCAN_XSS__; } catch {} });
        } catch {  }

        if (executed) {
          findings.add({
            id: 'reflected-xss',
            title: `Reflected XSS in parameter "${param}"`,
            severity: 'high',
            url,
            evidence: `Injected script via ?${param}= executed in the browser (marker ${marker} set).`,
            impact:
              'An attacker who crafts a link can run arbitrary JavaScript in a victim\'s session: steal cookies/tokens, perform actions as the user, or deface the page.',
            remediation:
              'Context-aware output encoding on all reflected values; adopt a strict CSP; validate input. Never build HTML by string concatenation of user input.',
            cwe: 'CWE-79',
            poc: `${execUrl}\n(loads a benign <script> that sets window.__CLAYSCAN_XSS__)`,
            references: ['https://owasp.org/www-community/attacks/xss/'],
            confidence: 0.95,
          });
        } else if (reflectedRaw) {
          findings.add({
            id: 'reflected-input-unencoded',
            title: `Unencoded reflection of parameter "${param}"`,
            severity: 'medium',
            url,
            evidence: `Marker ${marker} and injected tag characters were reflected without encoding, but script did not execute (possibly CSP-mitigated).`,
            impact:
              'Reflected, unencoded input is a strong XSS indicator; a different payload or context may achieve execution.',
            remediation: 'HTML-encode all reflected output and verify CSP coverage.',
            cwe: 'CWE-79',
            poc: reflectUrl,
            confidence: 0.6,
          });
        }
      }
    } finally {
      await probePage.close().catch(() => {});
    }
  },
};

function collectParamUrls(site, target) {
  const out = [];
  const seen = new Set();
  const urls = new Set([target, ...site.pages.map((p) => p.url), ...site.endpoints]);
  for (const u of urls) {
    for (const param of paramNames(u)) {
      const key = `${u.split('?')[0]}|${param}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ url: u, param });
    }
  }
  return out;
}
