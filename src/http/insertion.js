import { withParam, sameScope } from '../utils/url.js';

export function buildCorpus(site, target, opts = {}) {
  const corpus = [];
  const seen = new Set();
  const scope = { includeSubdomains: opts.includeSubdomains ?? false };
  const add = (req) => {
    if (!req || !req.url) return;
    if (!sameScope(target, req.url, scope)) return;
    const key = `${req.method} ${req.url.split('?')[0]} ${sig(req)}`;
    if (seen.has(key)) return;
    seen.add(key);
    corpus.push(req);
  };

  for (const r of site.requests || []) {
    add({
      method: r.method || 'GET',
      url: r.url,
      headers: r.headers || {},
      body: r.postData || '',
      contentType: (r.headers && (r.headers['content-type'] || r.headers['Content-Type'])) || '',
    });
  }

  const urls = new Set([target, ...(site.pages || []).map((p) => p.url), ...(site.endpoints || [])]);
  for (const u of urls) {
    if (typeof u === 'string' && u.includes('?')) {
      add({ method: 'GET', url: u, headers: {}, body: '', contentType: '' });
    }
  }

  corpus.sort((a, b) => score(b) - score(a));
  return corpus;
}

function score(req) {
  let s = 0;
  if (req.method && req.method !== 'GET') s += 3;
  if (/login|signin|auth|token|user|account|admin|search|query|register|password|reset/i.test(req.url)) s += 2;
  if (req.body) s += 1;
  return s;
}

function sig(req) {
  try {
    const params = [...new URL(req.url).searchParams.keys()].sort().join(',');
    let bodyKeys = '';
    const b = parseBody(req);
    if (b && b.kind === 'json') bodyKeys = jsonPaths(b.data).map((p) => p.join('.')).join(',');
    else if (b && b.kind === 'form') bodyKeys = [...b.data.keys()].sort().join(',');
    return params + '|' + bodyKeys;
  } catch {
    return req.body ? req.body.slice(0, 40) : '';
  }
}

export function insertionPoints(req) {
  const points = [];
  try {
    for (const name of new URL(req.url).searchParams.keys()) {
      points.push({ kind: 'query', name });
    }
  } catch {  }

  const b = parseBody(req);
  if (b && b.kind === 'json') {
    for (const path of jsonPaths(b.data)) points.push({ kind: 'json', path });
  } else if (b && b.kind === 'form') {
    for (const name of b.data.keys()) points.push({ kind: 'form', name });
  }
  return points;
}

export function mutate(req, point, value, { raw = false } = {}) {
  const clone = { method: req.method, url: req.url, headers: { ...req.headers }, body: req.body, contentType: req.contentType };
  if (point.kind === 'query') {
    clone.url = withParam(req.url, point.name, String(value));
    return clone;
  }
  if (point.kind === 'form') {
    const params = new URLSearchParams(req.body || '');
    params.set(point.name, String(value));
    clone.body = params.toString();
    return clone;
  }
  if (point.kind === 'json') {
    const data = safeJson(req.body);
    if (data == null) return clone;
    setPath(data, point.path, raw ? value : String(value));
    clone.body = JSON.stringify(data);
    return clone;
  }
  return clone;
}

export async function send(http, req) {
  const headers = { ...req.headers };
  for (const h of ['content-length', 'Content-Length', 'host', 'Host', 'connection', 'Connection', 'accept-encoding', 'Accept-Encoding']) {
    delete headers[h];
  }
  if (req.body && !headers['content-type'] && !headers['Content-Type']) {
    headers['content-type'] = req.contentType || 'application/json';
  }
  return http.request(req.url, {
    method: req.method || 'GET',
    headers,
    body: req.body || undefined,
    redirect: 'manual',
  });
}

export function pointLabel(req, point) {
  if (point.kind === 'query') return `query "${point.name}"`;
  if (point.kind === 'form') return `form field "${point.name}"`;
  if (point.kind === 'json') return `JSON field "${point.path.join('.')}"`;
  return 'parameter';
}

function parseBody(req) {
  if (!req.body) return null;
  const ct = (req.contentType || '').toLowerCase();
  if (ct.includes('json') || /^\s*[{[]/.test(req.body)) {
    const data = safeJson(req.body);
    if (data && typeof data === 'object') return { kind: 'json', data };
  }
  if (ct.includes('x-www-form-urlencoded') || (/=/.test(req.body) && !/[{}]/.test(req.body))) {
    return { kind: 'form', data: new URLSearchParams(req.body) };
  }
  return null;
}

function safeJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function jsonPaths(obj, prefix = [], out = []) {
  if (out.length > 60) return out;
  if (obj && typeof obj === 'object') {
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (v && typeof v === 'object') jsonPaths(v, [...prefix, k], out);
      else out.push([...prefix, k]);
    }
  }
  return out;
}

function setPath(obj, path, value) {
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]];
  cur[path[path.length - 1]] = value;
}
