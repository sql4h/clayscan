import chalk from 'chalk';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 99 };

let currentLevel = LEVELS.info;

export function setLevel(name) {
  if (LEVELS[name] != null) currentLevel = LEVELS[name];
}

function ts() {
  return chalk.gray(new Date().toISOString().slice(11, 19));
}

export const log = {
  debug(...a) {
    if (currentLevel <= LEVELS.debug) console.log(ts(), chalk.gray('dbg'), ...a);
  },
  info(...a) {
    if (currentLevel <= LEVELS.info) console.log(ts(), chalk.blue('inf'), ...a);
  },
  step(...a) {
    if (currentLevel <= LEVELS.info) console.log(ts(), chalk.cyan('==>'), ...a);
  },
  ok(...a) {
    if (currentLevel <= LEVELS.info) console.log(ts(), chalk.green(' ok'), ...a);
  },
  warn(...a) {
    if (currentLevel <= LEVELS.warn) console.log(ts(), chalk.yellow('wrn'), ...a);
  },
  error(...a) {
    if (currentLevel <= LEVELS.error) console.log(ts(), chalk.red('err'), ...a);
  },
  banner(text) {
    if (currentLevel > LEVELS.info) return;
    console.log(chalk.bold.magenta(text));
  },
};

const SEV_COLOR = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

export function severityTag(sev) {
  const fn = SEV_COLOR[sev] || chalk.white;
  return fn(` ${sev.toUpperCase()} `);
}
