import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const PRIVATE_HINT = /user|account|order|basket|cart|invoice|message|address|card|payment|wallet|profile|ticket|document|file|record|customer|member|subscription|transaction|report/i;
const ID_NAME = /^(?:id|.*_id|.*id|guid|uuid|uid|pid|no|num|number|key)$/i;
const ID_VALUE = /^\d{1,9}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ERRORISH = /not\s*found|no such|does not exist|unauthor|forbidden|invalid|denied|error|null/i;

export default {
  id: 'idor',
  name: 'IDOR / broken object-level authorization',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method === 'GET' || r.method === 'POST');
    const cap = opts.maxActiveTargets ?? 40;
    const seen = new Set();
    let tested = 0;

    for (const req of corpus) {
      const targets = idTargets(req);
      for (const t of targets) {
        if (tested >= cap) return;
        const key = `${req.method} ${req.url.split('?')[0]} ${t.label}`;
        if (seen.has(key)) continue;
        seen.add(key);
        tested++;

        const baseline = await send(http, t.make(t.value));
        if (!baseline.ok || baseline.status !== 200) continue;
        if (isErrorish(baseline)) continue;
        if ((baseline.body || '').length < 15) continue;

        const authed = isAuthed(req);
        const priv = PRIVATE_HINT.test(req.url) || PRIVATE_HINT.test(t.label) || looksPersonal(baseline.body);
        if (!priv) continue;

        for (const other of neighbors(t.value)) {
          const alt = await send(http, t.make(other));
          if (!alt.ok || alt.status !== 200) continue;
          if (isErrorish(alt)) continue;
          if ((alt.body || '') === (baseline.body || '')) continue;
          if (!sameShape(baseline.body, alt.body)) continue;
          if (!lenComparable(baseline.body, alt.body)) continue;

          findings.add({
            id: 'idor',
            title: `Possible IDOR in ${t.label} (${req.method} ${new URL(req.url).pathname})`,
            severity: authed ? 'high' : 'medium',
            url: req.url,
            evidence: `Changing ${t.label} from ${t.value} to ${other} returned a different but same-shaped ${baseline.status} record${authed ? ' (request was authenticated)' : ''} — objects appear accessible by ID without authorization.`,
            impact:
              'Broken object-level authorization lets a user read or modify other users\' objects by changing an identifier (account data, orders, messages).',
            remediation:
              'Enforce per-object authorization on every request: check that the authenticated user owns or may access the requested object ID, server-side.',
            cwe: 'CWE-639',
            poc: `Compare ${req.method} with ${t.label}=${t.value} vs ${t.label}=${other}; both return distinct valid records.`,
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
            confidence: authed ? 0.6 : 0.45,
          });
          break;
        }
      }
    }
  },
};

function idTargets(req) {
  const out = [];
  try {
    const u = new URL(req.url);
    const segs = u.pathname.split('/');
    for (let i = 0; i < segs.length; i++) {
      if (/^\d{1,9}$/.test(segs[i])) {
        const idx = i;
        out.push({
          label: `path segment "${segs[i]}"`,
          value: segs[i],
          make: (v) => {
            const nu = new URL(req.url);
            const parts = nu.pathname.split('/');
            parts[idx] = String(v);
            nu.pathname = parts.join('/');
            return { method: req.method, url: nu.toString(), headers: req.headers, body: req.body, contentType: req.contentType };
          },
        });
      }
    }
  } catch {  }

  for (const point of insertionPoints(req)) {
    const name = point.name || (point.path ? point.path[point.path.length - 1] : '');
    const value = currentValue(req, point);
    if (name && ID_NAME.test(name) && value && ID_VALUE.test(String(value))) {
      out.push({
        label: pointLabel(req, point),
        value: String(value),
        make: (v) => mutate(req, point, v),
      });
    }
  }
  return out;
}

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

function neighbors(value) {
  if (/^\d+$/.test(value)) {
    const v = parseInt(value, 10);
    return [...new Set([v + 1, v - 1, v + 2])].filter((x) => x > 0 && x !== v).map(String);
  }
  return [];
}

function looksPersonal(body) {
  const b = (body || '').slice(0, 5000);
  return /"(?:email|e-mail|ssn|password|passwd|token|balance|phone|mobile|address|dob|birth|salary|credit|iban|card|firstname|lastname|username)"\s*:/i.test(b) ||
    /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(b) ||
    /\b\d{3}-\d{2}-\d{4}\b/.test(b);
}

function isAuthed(req) {
  const h = req.headers || {};
  return !!(h.authorization || h.Authorization || h.cookie || h.Cookie || h['x-auth-token']);
}

function isErrorish(res) {
  const b = (res.body || '').slice(0, 400);
  if (/^\s*(\[\s*\]|\{\s*\}|null)\s*$/.test(res.body || '')) return true;
  return ERRORISH.test(b);
}

function sameShape(a, b) {
  const ka = keysOf(a);
  const kb = keysOf(b);
  if (!ka || !kb) return true;
  if (!ka.length || !kb.length) return false;
  const setA = new Set(ka);
  const inter = kb.filter((k) => setA.has(k)).length;
  const jac = inter / new Set([...ka, ...kb]).size;
  return jac >= 0.6;
}

function keysOf(body) {
  try {
    const o = JSON.parse(body);
    if (Array.isArray(o)) return o.length && typeof o[0] === 'object' ? Object.keys(o[0]) : ['__array__'];
    if (o && typeof o === 'object') return Object.keys(o);
  } catch {  }
  return null;
}

function lenComparable(a, b) {
  const la = (a || '').length;
  const lb = (b || '').length;
  if (!la || !lb) return false;
  const r = la / lb;
  return r >= 0.2 && r <= 5;
}
