#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { setLevel, log } from '../src/logger.js';
import { confirmAuthorization } from '../src/authorization.js';
import { runScan } from '../src/scanner.js';
import { runCodeScan } from '../src/codeScan.js';

const program = new Command();
program
  .name('clayscan')
  .description('ClayScan — authorized-scope, AI-assisted web + code vulnerability scanner');

const aiOpts = (cmd) =>
  cmd
    .option('--ai-provider <name>', 'AI provider: auto|anthropic|openai|openrouter|nim|gemini|groq|together|ollama|custom')
    .option('--ai-model <id>', 'model id for the chosen provider')
    .option('--ai-base-url <url>', 'override the AI endpoint URL (for custom/self-hosted)')
    .option('--ai-key <key>', 'AI API key (otherwise read from provider env var)')
    .option('--out <dir>', 'directory for reports', './clayscan-reports')
    .option('--operator <name>', 'operator name recorded in the report')
    .option('--verbose', 'verbose logging', false)
    .option('--quiet', 'errors only', false);

function ai(o) {
  return { provider: o.aiProvider, model: o.aiModel, baseUrl: o.aiBaseUrl, apiKey: o.aiKey };
}
function levels(o) {
  if (o.verbose) setLevel('debug');
  if (o.quiet) setLevel('error');
}

aiOpts(
  program
    .command('scan', { isDefault: true })
    .description('dynamically scan a live web target (DAST)')
    .argument('<url>', 'target URL to scan (you must be authorized to test it)')
    .option('--headless', 'run Chrome headless (default is headed/visible)', false)
    .option('--channel <name>', 'use an installed browser channel, e.g. "chrome"')
    .option('--max-pages <n>', 'maximum pages to crawl', (v) => parseInt(v, 10), 40)
    .option('--include-subdomains', 'crawl subdomains of the target host', false)
    .option('--seed <urls>', 'comma-separated extra URLs to crawl; use "common" to run the built-in wordlist', (v) => v.split(',').map((s) => s.trim()).filter(Boolean), [])
    .option('--discover', 'run wordlist content discovery (dirbusting) against the origin', false)
    .option('--wordlist <file>', 'path to a custom content-discovery wordlist')
    .option('--max-active-targets <n>', 'cap parameter targets per active check', (v) => parseInt(v, 10), 40)
    .option('--oob-host <host>', 'host/IP the target should call back for SSRF/XXE out-of-band checks (default: auto)')
    .option('--approve-active', 'pre-approve all active tests (non-interactive)', false)
    .option('--no-active', 'passive checks only')
    .option('--interact', 'safely auto-submit forms during the crawl to exercise POST endpoints', false)
    .option('--max-interactions <n>', 'cap total form submissions', (v) => parseInt(v, 10), 25)
    .option('--login-url <url>', 'log in here before crawling (authenticated scan)')
    .option('--login-user <value>', 'username/email for --login-url')
    .option('--login-pass <value>', 'password for --login-url')
    .option('--login-user-field <selector>', 'CSS selector for the username field')
    .option('--login-pass-field <selector>', 'CSS selector for the password field')
    .option('--auth-cookie <cookies>', 'session cookie(s) to send, e.g. "sid=abc; other=1"')
    .option('--auth-header <header>', 'auth header to send, e.g. "Authorization: Bearer xyz"')
    .option('--user-agent <ua>', 'override the User-Agent string')
    .option('--yes', 'skip the interactive authorization prompt (requires --consent)', false)
    .option('--consent <phrase>', 'authorization phrase for non-interactive runs')
).action(async (url, o) => {
  levels(o);
  try {
    const scope = await confirmAuthorization(url, { yes: o.yes, consent: o.consent, operator: o.operator });
    await runScan(scope, {
      headless: o.headless,
      channel: o.channel,
      maxPages: o.maxPages,
      includeSubdomains: o.includeSubdomains,
      seeds: o.seed,
      discover: o.discover,
      wordlist: o.wordlist,
      maxActiveTargets: o.maxActiveTargets,
      oobHost: o.oobHost,
      approveActive: o.approveActive,
      noActive: o.active === false,
      outDir: o.out,
      userAgent: o.userAgent,
      interact: o.interact,
      maxInteractions: o.maxInteractions,
      login: o.loginUrl ? {
        url: o.loginUrl,
        user: o.loginUser,
        pass: o.loginPass,
        userField: o.loginUserField,
        passField: o.loginPassField,
      } : undefined,
      auth: (o.authCookie || o.authHeader) ? { cookie: o.authCookie, header: o.authHeader } : undefined,
      ai: ai(o),
      pageTimeout: 20000,
      settleMs: 400,
    });
  } catch (err) {
    log.error(chalk.red(err.message));
    process.exitCode = 1;
  }
});

aiOpts(
  program
    .command('code')
    .description('statically analyze a local source tree (SAST)')
    .argument('<path>', 'path to the source directory to analyze')
).action(async (dir, o) => {
  levels(o);
  try {
    await runCodeScan(dir, { outDir: o.out, operator: o.operator, ai: ai(o) });
  } catch (err) {
    log.error(chalk.red(err.message));
    process.exitCode = 1;
  }
});

program.parseAsync();
