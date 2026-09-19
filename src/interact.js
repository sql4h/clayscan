import { log } from './logger.js';

const DESTRUCTIVE = /delete|remove|destroy|deactivate|logout|sign[\s-]?out|close[\s-]?account|unsubscribe|cancel[\s-]?(?:account|subscription)|wipe|reset[\s-]?all|purge/i;

export async function applyAuth(context, target, auth) {
  if (!auth) return;
  if (auth.header) {
    const idx = auth.header.indexOf(':');
    if (idx > 0) {
      const name = auth.header.slice(0, idx).trim();
      const value = auth.header.slice(idx + 1).trim();
      await context.setExtraHTTPHeaders({ [name]: value });
      log.ok(`Auth: sending header ${name}`);
    }
  }
  if (auth.cookie) {
    const cookies = auth.cookie.split(';').map((c) => c.trim()).filter(Boolean).map((c) => {
      const i = c.indexOf('=');
      return { name: c.slice(0, i).trim(), value: c.slice(i + 1).trim(), url: target };
    });
    try {
      await context.addCookies(cookies);
      log.ok(`Auth: set ${cookies.length} cookie(s)`);
    } catch (e) {
      log.warn(`Auth cookie failed: ${e.message}`);
    }
  }
}

export async function performLogin(context, login) {
  const page = await context.newPage();
  try {
    log.step(`Auth: logging in at ${login.url}`);
    await page.goto(login.url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(600);
    await dismissOverlays(page);

    const passSel = login.passField || 'input[type=password]';
    await page.waitForSelector(passSel, { timeout: 10000 }).catch(() => {});
    const p = await page.$(passSel);
    if (!p) { log.warn('Auth: no password field found at login URL'); return false; }

    const formHandle = await p.evaluateHandle((el) => el.closest('form')).catch(() => null);
    const formEl = formHandle ? formHandle.asElement() : null;
    const scope = formEl || page;
    const userSel = login.userField ||
      'input[type=email],input[id*=email i],input[name*=email i],input[name*=user i],input[id*=user i],input:not([type=password]):not([type=hidden]):not([type=submit]):not([type=checkbox]):not([type=radio])';
    const u = await scope.$(userSel);
    if (u) await u.fill(login.user || '').catch(() => {});
    await p.fill(login.pass || '').catch(() => {});
    await page.waitForTimeout(200);

    await p.press('Enter').catch(() => {});
    await page.waitForTimeout(400);
    const btn = await page.$('button[type=submit],input[type=submit],#loginButton');
    if (btn) await btn.click({ force: true, timeout: 3000 }).catch(() => {});

    await page.waitForTimeout(1600);

    const cookies = await context.cookies();
    const hasSession = cookies.some((c) => /sess|token|auth|jwt|sid/i.test(c.name) && c.value);
    const token = await page.evaluate(() => {
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (/token|jwt|auth/i.test(k) && localStorage.getItem(k)) return true;
        }
      } catch {  }
      return false;
    }).catch(() => false);

    const ok = hasSession || token;
    log.ok(`Auth: login ${ok ? 'appears successful' : 'submitted (session not confirmed)'}`);
    return ok;
  } catch (e) {
    log.warn(`Auth login error: ${e.message.split('\n')[0]}`);
    return false;
  } finally {
    await page.close().catch(() => {});
  }
}

export async function submitFormsOnPage(context, pageUrl, opts, budget) {
  const page = await context.newPage();
  page.setDefaultTimeout(6000);
  let submitted = 0;
  try {
    await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForTimeout(300);
    await dismissOverlays(page);
    const total = await page.$$eval('form', (fs) => fs.length).catch(() => 0);
    const max = Math.min(total, opts.maxFormsPerPage ?? 4);

    for (let i = 0; i < max; i++) {
      if (budget.remaining <= 0) break;
      if (i > 0) {
        await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
        await page.waitForTimeout(250);
        await dismissOverlays(page);
      }
      const forms = await page.$$('form');
      const form = forms[i];
      if (!form) continue;

      const meta = await form.evaluate((f) => ({
        action: f.getAttribute('action') || '',
        text: (f.innerText || '').slice(0, 300),
      })).catch(() => ({ action: '', text: '' }));
      if (DESTRUCTIVE.test(meta.action + ' ' + meta.text)) continue;

      await fillForm(form).catch(() => {});
      await submitForm(page, form).catch(() => {});
      await page.waitForTimeout(700);
      submitted++;
      budget.remaining--;
    }
  } catch (e) {
    log.debug(`interact ${pageUrl}: ${e.message.split('\n')[0]}`);
  } finally {
    await page.close().catch(() => {});
  }
  return submitted;
}

async function fillForm(form) {
  const els = await form.$$('input,textarea,select');
  for (const el of els) {
    const info = await el.evaluate((e) => ({
      tag: e.tagName.toLowerCase(),
      type: (e.getAttribute('type') || '').toLowerCase(),
      name: (e.getAttribute('name') || e.id || '').toLowerCase(),
    })).catch(() => null);
    if (!info) continue;
    try {
      if (info.tag === 'select') {
        const opt = await el.$('option:not([disabled])');
        if (opt) { const v = await opt.getAttribute('value'); if (v != null) await el.selectOption(v).catch(() => {}); }
      } else if (info.type === 'checkbox' || info.type === 'radio') {
        await el.check({ timeout: 1500 }).catch(() => {});
      } else if (info.type === 'file' || info.type === 'hidden' || info.type === 'submit' || info.type === 'button') {
        continue;
      } else {
        await el.fill(valueFor(info), { timeout: 1500 }).catch(() => {});
      }
    } catch {  }
  }
}

function valueFor(info) {
  const n = info.name;
  if (info.type === 'email' || /email/.test(n)) return 'clayscan@example.com';
  if (info.type === 'password' || /pass|pwd/.test(n)) return 'ClayScan123!';
  if (info.type === 'tel' || /phone|tel|mobile/.test(n)) return '15555550100';
  if (info.type === 'url' || /url|website|link/.test(n)) return 'https://example.com';
  if (info.type === 'number' || /age|qty|quantity|amount|count|zip|postal/.test(n)) return '1';
  if (info.type === 'date') return '2020-01-01';
  if (/first.?name|fname/.test(n)) return 'Clay';
  if (/last.?name|lname|surname/.test(n)) return 'Scan';
  if (/name|user/.test(n)) return 'clayscan';
  return 'clayscan';
}

async function submitForm(page, form) {
  const field = await form.$('input:not([type=hidden]):not([type=submit]):not([type=button]), textarea');
  if (field) await field.press('Enter').catch(() => {});
  await page.waitForTimeout(250);

  await form.evaluate((f) => { try { if (f.requestSubmit) f.requestSubmit(); else f.submit(); } catch {  } }).catch(() => {});

  const btn = await form.$('button[type=submit],input[type=submit],button');
  if (btn) {
    const disabled = await btn.isDisabled().catch(() => false);
    if (!disabled) await btn.click({ force: true, timeout: 3000 }).catch(() => {});
  }
}

async function dismissOverlays(page) {
  const selectors = [
    'button[aria-label="Close Welcome Banner"]',
    'button[aria-label*="close" i]',
    'a.cc-btn.cc-dismiss',
    'button:has-text("Dismiss")',
    'button:has-text("Me want it")',
    'button:has-text("Accept")',
    'button:has-text("Got it")',
    '.close-dialog',
    '[mat-dialog-close]',
  ];
  for (const sel of selectors) {
    const el = await page.$(sel).catch(() => null);
    if (el) await el.click({ force: true, timeout: 1500 }).catch(() => {});
  }
  await page.keyboard.press('Escape').catch(() => {});
  await page.waitForTimeout(150);
}
