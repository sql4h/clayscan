import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { log } from './logger.js';
import { request } from './utils/http.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_WORDLIST = path.join(__dirname, '..', 'data', 'common-paths.txt');

export async function discoverPaths(target, opts) {
  const origin = new URL(target).origin;
  const words = await loadWordlist(opts.wordlist);
  if (!words.length) return { hits: [], notes: [] };

  log.step(`Content discovery: probing ${words.length} common paths (${opts.discoverConcurrency ?? 24} at a time)...`);

  const baseline = await calibrate(origin, opts);

  const hits = [];
  const notes = [];
  let idx = 0;
  const concurrency = opts.discoverConcurrency ?? 24;

  async function worker() {
    while (idx < words.length) {
      const word = words[idx++];
      const url = `${origin}/${word}`;
      const res = await request(url, { redirect: 'manual', userAgent: opts.userAgent, timeout: 8000 });
      if (!res.ok) continue;
      if (isInteresting(res, baseline)) {
        hits.push({ url, status: res.status, length: (res.body || '').length, location: res.headers?.location });
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));

  hits.sort((a, b) => a.status - b.status || a.url.localeCompare(b.url));
  if (hits.length) notes.push(`content discovery found ${hits.length} path(s) via wordlist`);
  log.ok(`Content discovery: ${hits.length} interesting path(s).`);
  return { hits, notes };
}

async function loadWordlist(custom) {
  const file = custom && custom !== 'common' ? custom : DEFAULT_WORDLIST;
  try {
    const raw = await readFile(file, 'utf8');
    return raw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch (err) {
    log.warn(`Could not read wordlist ${file}: ${err.message}`);
    return [];
  }
}

async function calibrate(origin, opts) {
  const probes = [`clayscan-404-${Date.now()}`, `nope-${Math.random().toString(36).slice(2)}-zzz`];
  const results = [];
  for (const p of probes) {
    const res = await request(`${origin}/${p}`, { redirect: 'manual', userAgent: opts.userAgent, timeout: 8000 });
    if (res.ok) results.push({ status: res.status, length: (res.body || '').length });
  }
  return {
    notFoundStatus: results[0]?.status ?? 404,

    notFoundLength: results.length ? Math.round(results.reduce((s, r) => s + r.length, 0) / results.length) : 0,
    softNotFound: results.length >= 2 && results[0].status === 200 && results[1].status === 200,
  };
}

function isInteresting(res, baseline) {
  const len = (res.body || '').length;

  if ([301, 302, 303, 307, 308].includes(res.status)) return true;

  if (res.status === 401 || res.status === 403) return true;
  if (res.status >= 500) return true;
  if (res.status === 200) {
    if (baseline.softNotFound) {
      return Math.abs(len - baseline.notFoundLength) > Math.max(200, baseline.notFoundLength * 0.25);
    }

    return res.status !== baseline.notFoundStatus;
  }
  return false;
}
