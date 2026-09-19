import { chromium } from 'playwright';
import { log } from './logger.js';
import { sameScope, keyOf } from './utils/url.js';
import { request } from './utils/http.js';
import { discoverPaths } from './discovery.js';
import { applyAuth, performLogin, submitFormsOnPage } from './interact.js';

const ASSET_EXT = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|json|xml|txt|pdf|mp4|webm|zip)(?:$|\?)/i;

const JUNK_ROUTE = /(?:^\/_|\/node_modules\/|\/ROOT\/|\/dist\/|\/compiled\/|\/webpack|\/chunks?\/|\/static\/|\/\.|(?:^|\/)(?:a|b|c|i|j|x|y|z)(?:\/|$))/i;

export async function crawl(target, opts) {
  const browser = await chromium.launch({
    headless: opts.headless,
    channel: opts.channel || undefined,
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent: opts.userAgent,
  });

  const site = {
    pages: [],
    forms: [],
    endpoints: new Set(),
    cookies: [],
    responses: [],
    jsUrls: new Set(),
    jsFiles: [],
    discovery: [],
    requests: [],
    apiBodies: [],
  };

  const seenReq = new Set();
  context.on('request', (req) => {
    try {
      const url = req.url();
      if (!sameScope(target, url, opts)) return;
      const method = req.method();
      const rt = req.resourceType();
      if (!['xhr', 'fetch', 'document', 'other'].includes(rt) && method === 'GET') return;
      const postData = req.postData() || '';
      const key = `${method} ${url.split('#')[0]} ${postData.slice(0, 80)}`;
      if (seenReq.has(key)) return;
      seenReq.add(key);
      if (site.requests.length < (opts.maxRequests ?? 400)) {
        site.requests.push({
          method,
          url,
          headers: req.headers(),
          postData,
          resourceType: rt,
        });
      }
    } catch {  }
  });

  context.on('response', async (res) => {
    try {
      const url = res.url();
      if (!sameScope(target, url, opts)) return;
      const headers = res.headers();
      const ctype = (headers['content-type'] || '').split(';')[0];
      site.responses.push({
        url,
        status: res.status(),
        method: res.request().method(),
        headers,
        type: ctype,
      });
      if ((headers['content-type'] || '').includes('javascript')) site.jsUrls.add(url);
      if (/json|xml|text\/plain/.test(ctype) && site.apiBodies.length < (opts.maxApiBodies ?? 300)) {
        const body = await res.text().catch(() => '');
        if (body) site.apiBodies.push({ url, status: res.status(), type: ctype, body: body.slice(0, 100000) });
      }
    } catch {  }
  });

  const authHeaders = {};
  if (opts.auth?.header) {
    const i = opts.auth.header.indexOf(':');
    if (i > 0) authHeaders[opts.auth.header.slice(0, i).trim()] = opts.auth.header.slice(i + 1).trim();
  }
  const http = (u, o) => request(u, { userAgent: opts.userAgent, ...o, headers: { ...authHeaders, ...(o?.headers || {}) } });

  await applyAuth(context, target, opts.auth);
  if (opts.login?.url) await performLogin(context, opts.login);

  const interactBudget = { remaining: opts.interact ? (opts.maxInteractions ?? 25) : 0 };

  const queue = [target];
  const rawSeeds = opts.seeds || [];
  const useWordlist = opts.discover || rawSeeds.includes('common') || rawSeeds.includes('wordlist');
  for (const s of rawSeeds) {
    if (s === 'common' || s === 'wordlist') continue;
    queue.push(s);
  }
  const seeds = await discoverSeeds(target, opts, http);
  for (const s of seeds.urls) queue.push(s);
  if (seeds.notes.length) site.discovery.push(...seeds.notes);

  if (useWordlist) {
    const { hits, notes } = await discoverPaths(target, opts);
    site.discoveredPaths = hits;
    site.discovery.push(...notes);
    for (const h of hits) if (h.status === 200) queue.push(h.url);
  }

  const visited = new Set();
  const fetchedJs = new Set();
  let count = 0;

  const page = await context.newPage();
  page.setDefaultTimeout(opts.pageTimeout ?? 20000);

  while (queue.length && count < opts.maxPages) {
    const url = queue.shift();
    const k = keyOf(url);
    if (visited.has(k)) continue;
    visited.add(k);

    let resp;
    try {
      resp = await page.goto(url, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(opts.settleMs ?? 400);
    } catch (err) {
      log.warn(`skip ${url}: ${err.message.split('\n')[0]}`);
      continue;
    }
    count++;
    const status = resp ? resp.status() : 0;
    log.step(`[${count}/${opts.maxPages}] ${status} ${url}`);

    const extracted = await extractPage(page).catch(() => null);
    if (!extracted) continue;

    site.pages.push({ url, status, ...extracted });
    for (const f of extracted.forms) site.forms.push({ pageUrl: url, ...f });

    if (interactBudget.remaining > 0 && extracted.forms.length) {
      const n = await submitFormsOnPage(context, url, opts, interactBudget);
      if (n) site.discovery.push(`auto-submitted ${n} form(s) on ${url}`);
    }

    for (const link of extracted.links) {
      site.endpoints.add(link);
      enqueue(queue, visited, target, opts, link, count);
    }

    if ((opts.scanJs ?? true) && fetchedJs.size < (opts.maxJs ?? 100)) {
      for (const src of extracted.scripts) {
        if (!sameScope(target, src, opts) || fetchedJs.has(src)) continue;
        fetchedJs.add(src);
        const jres = await http(src, { redirect: 'follow' });
        if (!jres.ok || !jres.body) continue;
        site.jsFiles.push({ url: src, body: jres.body });
        const routes = extractRoutes(jres.body, target, opts);
        for (const r of routes) {
          if (!visited.has(keyOf(r)) && enqueue(queue, visited, target, opts, r, count)) {
            site.discovery.push(`route "${new URL(r).pathname}" discovered in JS ${short(src)}`);
          }
        }
        if (fetchedJs.size >= (opts.maxJs ?? 100)) break;
      }
    }
  }

  for (const r of site.responses) {
    if (r.method === 'GET' && r.url.includes('?') && sameScope(target, r.url, opts)) {
      site.endpoints.add(r.url);
    }
  }

  try { site.cookies = await context.cookies(); } catch {  }

  return {
    site,
    browser,
    context,
    page,
    async close() {
      await context.close().catch(() => {});
      await browser.close().catch(() => {});
    },
  };
}

function enqueue(queue, visited, target, opts, url, count) {
  if (!sameScope(target, url, opts)) return false;
  if (visited.has(keyOf(url))) return false;
  if (queue.length + count > (opts.maxPages ?? 40) * 4) return false;
  if (ASSET_EXT.test(url)) return false;
  queue.push(url);
  return true;
}

async function discoverSeeds(target, opts, http) {
  const origin = new URL(target).origin;
  const urls = new Set();
  const notes = [];

  const robots = await http(origin + '/robots.txt', { redirect: 'follow' });
  if (robots.ok && robots.status === 200 && /(?:dis)?allow:/i.test(robots.body)) {
    let found = 0;
    for (const line of robots.body.split('\n')) {
      const m = line.match(/^\s*(?:Dis)?[Aa]llow:\s*(\S+)/);
      if (m && m[1] && m[1] !== '/') { urls.add(origin + m[1].replace(/\*$/, '')); found++; }
      const sm = line.match(/^\s*Sitemap:\s*(\S+)/i);
      if (sm) urls.add(sm[1]);
    }
    if (found) notes.push(`robots.txt exposed ${found} path(s)`);
  }

  for (const path of ['/sitemap.xml', '/sitemap_index.xml']) {
    const sm = await http(origin + path, { redirect: 'follow' });
    if (sm.ok && sm.status === 200 && /<loc>/i.test(sm.body)) {
      const locs = [...sm.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((x) => x[1]);
      for (const l of locs.slice(0, 200)) if (sameScope(target, l, opts)) urls.add(l);
      if (locs.length) notes.push(`${path} listed ${locs.length} URL(s)`);
    }
  }

  return { urls: [...urls], notes };
}

function extractRoutes(js, target, opts) {
  const origin = new URL(target).origin;
  const out = new Set();
  const re = /["'`](\/[A-Za-z0-9_\-./]{1,80})["'`]/g;
  let m;
  let n = 0;
  while ((m = re.exec(js)) !== null && n < 4000) {
    n++;
    const p = m[1];
    if (p === '/' || p.startsWith('//')) continue;
    if (ASSET_EXT.test(p)) continue;
    if (/[{}<>\\]/.test(p)) continue;
    if (JUNK_ROUTE.test(p)) continue;
    const abs = origin + p;
    if (sameScope(target, abs, opts)) out.add(abs);
    if (out.size > 100) break;
  }
  return [...out];
}

async function extractPage(page) {
  return page.evaluate(() => {
    const abs = (href) => {
      try { return new URL(href, document.baseURI).toString(); } catch { return null; }
    };
    const links = [...document.querySelectorAll('a[href]')]
      .map((a) => abs(a.getAttribute('href')))
      .filter(Boolean);

    const scripts = [...document.querySelectorAll('script[src]')]
      .map((s) => abs(s.getAttribute('src')))
      .filter(Boolean);

    const forms = [...document.querySelectorAll('form')].map((form) => ({
      action: abs(form.getAttribute('action') || location.href),
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      inputs: [...form.querySelectorAll('input,textarea,select')].map((el) => ({
        name: el.getAttribute('name') || '',
        type: el.getAttribute('type') || el.tagName.toLowerCase(),
        value: el.getAttribute('value') || '',
      })),
      hasCsrfToken: [...form.querySelectorAll('input')].some((el) =>
        /csrf|token|authenticity|nonce|_token/i.test(el.getAttribute('name') || '')
      ),
    }));

    const comments = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let n;
    while ((n = walker.nextNode())) comments.push(n.nodeValue.trim());

    return {
      title: document.title || '',
      html: document.documentElement.outerHTML.slice(0, 800000),
      links,
      scripts,
      forms,
      comments: comments.filter(Boolean).slice(0, 100),
    };
  });
}

function short(u) {
  try { const p = new URL(u); return p.pathname.split('/').pop() || p.pathname; } catch { return u; }
}
