import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import chalk from 'chalk';
import { normalize } from './utils/url.js';

const CONSENT_PHRASE = 'I am authorized to test this target';

export async function confirmAuthorization(targetUrl, opts) {
  const target = normalize(targetUrl);

  if (opts.yes) {
    if (opts.consent !== CONSENT_PHRASE) {
      throw new Error(
        `Non-interactive runs require --consent "${CONSENT_PHRASE}" to affirm authorization for ${target.host}.`
      );
    }
    return { target: target.toString(), operator: opts.operator || 'unattended', at: new Date().toISOString() };
  }

  console.log(chalk.bold.yellow('\n  Authorization check'));
  console.log('  ClayScan runs active security tests against:');
  console.log('    ' + chalk.cyan(target.toString()));
  console.log(chalk.gray('\n  Only continue if you own this target or hold written permission to test it.'));
  console.log(chalk.gray('  Unauthorized scanning may be a criminal offense.\n'));

  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question(chalk.bold(`  Type exactly: "${CONSENT_PHRASE}"\n  > `));
    if (answer.trim() !== CONSENT_PHRASE) {
      throw new Error('Authorization not confirmed — aborting.');
    }
    const who = (await rl.question('  Your name / handle for the report (optional): ')).trim();
    return { target: target.toString(), operator: who || 'operator', at: new Date().toISOString() };
  } finally {
    rl.close();
  }
}
