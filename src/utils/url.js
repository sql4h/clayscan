export function normalize(raw) {
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
  const parsed = new URL(u);
  parsed.hash = '';
  return parsed;
}

function apex(host) {
  return host.replace(/^www\./i, '');
}

export function sameScope(target, candidate, { includeSubdomains }) {
  try {
    const t = new URL(target);
    const c = new URL(candidate);
    if (c.protocol !== 'http:' && c.protocol !== 'https:') return false;
    const th = apex(t.hostname);
    const ch = apex(c.hostname);
    if (includeSubdomains) {
      return ch === th || ch.endsWith('.' + th);
    }
    return ch === th;
  } catch {
    return false;
  }
}

export function keyOf(u) {
  try {
    const p = new URL(u);
    const params = [...p.searchParams.keys()].sort().join(',');
    return `${p.origin}${p.pathname}?${params}`;
  } catch {
    return u;
  }
}

export function withParam(rawUrl, name, value) {
  const u = new URL(rawUrl);
  u.searchParams.set(name, value);
  return u.toString();
}

export function paramNames(rawUrl) {
  try {
    return [...new URL(rawUrl).searchParams.keys()];
  } catch {
    return [];
  }
}
