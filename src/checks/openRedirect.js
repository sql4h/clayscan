import { withParam, paramNames } from '../utils/url.js';

const REDIRECT_PARAMS = /^(?:next|url|redirect|redirect_uri|return|returnUrl|returnTo|dest|destination|continue|goto|target|r|u)$/i;
const CANARY = 'https://clayscan-openredirect.example/';

export default {
  id: 'open-redirect',
  name: 'Open redirect',
  phase: 'active',
  intrusive: 'low',
  async run({ site, findings, http, target }) {
    const candidates = [];
    const urls = new Set([target, ...site.pages.map((p) => p.url), ...site.endpoints]);
    for (const u of urls) {
      for (const param of paramNames(u)) {
        if (REDIRECT_PARAMS.test(param)) candidates.push({ url: u, param });
      }
    }

    const seen = new Set();
    for (const { url, param } of candidates) {
      const key = `${url.split('?')[0]}|${param}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const testUrl = withParam(url, param, CANARY);
      const res = await http.request(testUrl, { redirect: 'manual' });
      if (!res.ok) continue;
      const loc = res.headers.location || '';
      if ((res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307) &&
          loc.startsWith(CANARY)) {
        findings.add({
          id: 'open-redirect',
          title: `Open redirect via parameter "${param}"`,
          severity: 'medium',
          url,
          evidence: `${res.status} redirect with Location: ${loc}`,
          impact:
            'Attackers craft links on your trusted domain that bounce victims to phishing or malware sites, and can abuse OAuth redirect flows to steal tokens.',
          remediation:
            'Redirect only to a server-side allowlist of paths/origins; never redirect to a raw user-supplied URL.',
          cwe: 'CWE-601',
          poc: `${testUrl}\n→ Location: ${loc}`,
          references: ['https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards'],
          confidence: 0.9,
        });
      }
    }
  },
};
