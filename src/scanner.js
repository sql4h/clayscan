import { log } from './logger.js';
import { normalize } from './utils/url.js';
import { FindingsCollector } from './findings.js';
import { crawl } from './crawler.js';
import { passiveChecks, activeChecks } from './checks/index.js';
import { approveActive } from './approval.js';
import { analyze } from './ai/agent.js';
import { request } from './utils/http.js';
import { printConsole, writeReports, summaryLine } from './report/reporter.js';

export async function runScan(scope, opts) {
  const target = normalize(scope.target).toString();
  const findings = new FindingsCollector();
  const http = { request: (u, o) => request(u, { userAgent: opts.userAgent, ...o }) };

  log.banner('\n  ██████  ClayScan  ██████\n');
  log.step(`Target: ${target}`);
  log.step(`Launching ${opts.headless ? 'headless' : 'headed'} Chrome${opts.channel ? ` (channel: ${opts.channel})` : ''} ...`);

  const approvedActive = await approveActive(activeChecks, opts);
  const willRunActive = new Set(approvedActive.map((c) => c.id));

  log.step('Crawling target and mapping attack surface ...');
  const crawlResult = await crawl(target, opts);
  const { site } = crawlResult;
  log.ok(`Crawl complete: ${site.pages.length} pages, ${site.forms.length} forms, ${site.endpoints.size} endpoints.`);

  const ctx = {
    target,
    site,
    findings,
    http,
    opts,
    context: crawlResult.context,
    page: crawlResult.page,
  };

  let checksRun = 0;
  try {
    log.step('Running passive checks ...');
    for (const check of passiveChecks) {
      await safeRun(check, ctx);
      checksRun++;
    }

    if (approvedActive.length) {
      log.step(`Running ${approvedActive.length} approved active check(s) ...`);
      for (const check of activeChecks) {
        if (!willRunActive.has(check.id)) continue;
        await safeRun(check, ctx);
        checksRun++;
      }
    } else {
      log.warn('No active checks approved — passive-only scan.');
    }
  } finally {
    await crawlResult.close();
  }

  log.step('Generating AI analysis and remediation roadmap ...');
  const ai = await analyze({ scope, findings, site, aiOverrides: opts.ai || {} });

  printConsole(findings, scope);
  const { jsonPath, htmlPath } = await writeReports({
    findings, scope, site, ai, outDir: opts.outDir, checksRun,
  });

  log.ok(`Report (HTML):  ${htmlPath}`);
  log.ok(`Report (JSON):  ${jsonPath}`);
  console.log('  ' + summaryLine(findings.counts()) + '\n');

  return { findings, jsonPath, htmlPath };
}

async function safeRun(check, ctx) {
  const start = Date.now();
  try {
    await check.run(ctx);
    log.ok(`${check.name} ${dim(Date.now() - start)}`);
  } catch (err) {
    log.warn(`${check.name} failed: ${err.message.split('\n')[0]}`);
  }
}

function dim(ms) {
  return `(${ms}ms)`;
}
