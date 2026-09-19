import path from 'node:path';
import { log } from './logger.js';
import { scanCode } from './sast/scanner.js';
import { analyze } from './ai/agent.js';
import { printConsole, writeReports, summaryLine } from './report/reporter.js';
import { RULES } from './sast/rules.js';

export async function runCodeScan(targetDir, opts) {
  const root = path.resolve(targetDir);
  log.banner('\n  ██████  ClayScan · code  ██████\n');
  log.step(`Analyzing source tree: ${root}`);

  const { findings, filesScanned } = await scanCode(root, opts);

  const scope = { target: root, operator: opts.operator || 'operator', at: new Date().toISOString() };
  const site = { pages: [], forms: [], endpoints: new Set() };

  log.step('Generating AI analysis and remediation roadmap ...');
  const ai = await analyze({ scope, findings, site, aiOverrides: opts.ai || {} });

  printConsole(findings, scope);

  const { jsonPath, htmlPath } = await writeReports({
    findings,
    scope,
    site,
    ai,
    outDir: opts.outDir,
    mode: 'code',
    slug: path.basename(root),
    coverage: {
      filesScanned,
      rules: RULES.length,
      languages: '8',
    },
  });

  log.ok(`Report (HTML):  ${htmlPath}`);
  log.ok(`Report (JSON):  ${jsonPath}`);
  console.log('  ' + summaryLine(findings.counts()) + '\n');
  return { findings, jsonPath, htmlPath };
}
