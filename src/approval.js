import readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import chalk from 'chalk';

export async function approveActive(activeChecks, opts) {
  if (activeChecks.length === 0) return [];

  if (opts.noActive) return [];
  if (opts.approveActive) return activeChecks;

  console.log(chalk.bold.yellow('\n  Active tests require approval'));
  console.log('  These send additional benign requests to the target:\n');
  for (const c of activeChecks) {
    console.log(`    ${chalk.cyan('•')} ${c.name} ${chalk.gray(`(intrusiveness: ${c.intrusive || 'low'})`)}`);
  }
  console.log(chalk.gray('\n  All payloads are non-destructive: no data is modified, exfiltrated, or brute-forced.'));

  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const ans = (await rl.question('\n  Run active tests? [y]es / [n]o / [s]elect: ')).trim().toLowerCase();
    if (ans === 'y' || ans === 'yes') return activeChecks;
    if (ans === 'n' || ans === 'no' || ans === '') return [];

    const chosen = [];
    for (const c of activeChecks) {
      const a = (await rl.question(`    Run "${c.name}"? [y/N]: `)).trim().toLowerCase();
      if (a === 'y' || a === 'yes') chosen.push(c);
    }
    return chosen;
  } finally {
    rl.close();
  }
}
