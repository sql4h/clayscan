import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import chalk from 'chalk';
import { log, severityTag } from '../logger.js';
import { renderHtml } from './htmlTemplate.js';

export function printConsole(findings, scope) {
  const items = findings.sorted();
  const counts = findings.counts();
  console.log('\n' + chalk.bold('  ClayScan results — ') + chalk.cyan(scope.target));
  console.log('  ' + summaryLine(counts) + '\n');

  if (items.length === 0) {
    log.ok('No findings recorded. (This is not proof of security — coverage is limited by scope and depth.)');
    return;
  }
  for (const f of items) {
    console.log(`${severityTag(f.severity)} ${chalk.bold(f.title)}`);
    console.log(`   ${chalk.gray('url')}      ${f.url}`);
    if (f.cwe) console.log(`   ${chalk.gray('cwe')}      ${f.cwe}`);
    console.log(`   ${chalk.gray('evidence')} ${f.evidence}`);
    console.log(`   ${chalk.gray('impact')}   ${f.impact}`);
    console.log(`   ${chalk.gray('fix')}      ${f.remediation}`);
    console.log('');
  }
}

export function summaryLine(counts) {
  const parts = [
    counts.critical ? chalk.bgRed.white(` ${counts.critical} critical `) : null,
    counts.high ? chalk.red(`${counts.high} high`) : null,
    counts.medium ? chalk.yellow(`${counts.medium} medium`) : null,
    counts.low ? chalk.blue(`${counts.low} low`) : null,
    counts.info ? chalk.gray(`${counts.info} info`) : null,
  ].filter(Boolean);
  return parts.length ? parts.join('  ') : chalk.green('no findings');
}

export async function writeReports({ findings, scope, site, ai, outDir, checksRun, coverage, mode = 'web', slug }) {
  await mkdir(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const name = slug || safeSlug(scope.target);
  const base = path.join(outDir, `clayscan-${name}-${stamp}`);

  const report = {
    tool: 'ClayScan',
    version: '0.1.0',
    mode,
    scope,
    startedAt: scope.at,
    finishedAt: new Date().toISOString(),
    coverage: coverage || {
      pagesCrawled: site.pages.length,
      forms: site.forms.length,
      endpoints: site.endpoints.size,
      checksRun,
    },
    summary: findings.counts(),
    findings: findings.sorted(),
    aiAnalysis: ai,
  };

  const jsonPath = base + '.json';
  const htmlPath = base + '.html';
  await writeFile(jsonPath, JSON.stringify(report, null, 2), 'utf8');
  await writeFile(htmlPath, renderHtml(report), 'utf8');
  return { jsonPath, htmlPath };
}

function safeSlug(s) {
  try { return new URL(s).hostname; } catch {  }
  return String(s).replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'scan';
}
