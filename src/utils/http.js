export async function request(url, opts = {}) {
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout ?? 15000);
  try {
    const res = await fetch(url, {
      redirect: opts.redirect ?? 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': opts.userAgent ?? 'ClayScan/0.1 (+authorized-security-testing)',
        ...(opts.headers || {}),
      },
      method: opts.method ?? 'GET',
      body: opts.body,
    });
    const bodyText = opts.readBody === false ? '' : await safeText(res);
    return {
      ok: true,
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: bodyText,
      url: res.url || url,
      ms: Date.now() - started,
    };
  } catch (err) {
    return { ok: false, error: String(err), url, ms: Date.now() - started };
  } finally {
    clearTimeout(timeout);
  }
}

async function safeText(res) {
  try {
    const buf = await res.arrayBuffer();

    return Buffer.from(buf.slice(0, 2 * 1024 * 1024)).toString('utf8');
  } catch {
    return '';
  }
}
