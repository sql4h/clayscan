import { log } from '../logger.js';
import { resolveProvider, callModel } from './providers.js';

const SYSTEM =
  'You are a senior application security engineer writing the summary of an authorized penetration test. ' +
  'Be precise, prioritize by real-world risk, and give concrete, actionable remediation. ' +
  'Never suggest destructive, evasive, or unauthorized techniques. Output GitHub-flavored Markdown.';

export async function analyze({ scope, findings, site, aiOverrides = {} }) {
  const counts = findings.counts();
  const compact = findings.sorted().map((f) => ({
    title: f.title,
    severity: f.severity,
    url: f.url,
    cwe: f.cwe,
    evidence: f.evidence,
  }));

  const provider = resolveProvider(aiOverrides);

  if (provider.shape === 'local') {
    if (provider.missingKey) {
      log.warn(`AI provider "${provider.label}" selected but ${provider.missingKey} is not set — using local analysis.`);
    } else if (provider.error) {
      log.warn(`${provider.error} — using local analysis.`);
    } else {
      log.warn('No AI provider configured — using built-in local analysis. (See README: "AI providers".)');
    }
    return localAnalysis(scope, counts, compact, site);
  }

  log.info(`AI analysis via ${provider.label} (${provider.model}).`);
  try {
    const text = await callModel(provider, {
      system: SYSTEM,
      user: buildPrompt(scope, counts, compact, site),
      maxTokens: 1800,
    });
    if (!text) throw new Error('empty response');
    return { source: provider.name, model: provider.model, markdown: text };
  } catch (err) {
    log.warn(`AI request failed (${err.message}); falling back to local analysis.`);
    return localAnalysis(scope, counts, compact, site);
  }
}

function buildPrompt(scope, counts, compact, site) {
  return [
    `Authorized security assessment of ${scope.target}.`,
    `Pages crawled: ${site.pages.length}. Forms: ${site.forms.length}. Findings by severity: ${JSON.stringify(counts)}.`,
    '',
    'Findings (JSON):',
    '```json',
    JSON.stringify(compact, null, 2).slice(0, 12000),
    '```',
    '',
    'Write:',
    '1. **Executive summary** (3-5 sentences) an engineering manager can act on.',
    '2. **Top risks**, ranked, each with a one-line "why it matters".',
    '3. **Remediation roadmap** grouped into Now / Next / Later.',
    '4. **Suggested follow-up tests** — only safe, non-destructive checks a human should run to confirm or expand coverage.',
  ].join('\n');
}

function localAnalysis(scope, counts, compact, site) {
  const top = compact.slice(0, 6);
  const md = [
    `## AI analysis (local mode)`,
    ``,
    `**Executive summary.** ClayScan crawled ${site.pages.length} page(s) of ${scope.target} and recorded ` +
      `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} informational findings. ` +
      (counts.critical + counts.high > 0
        ? `The critical/high items should be treated as an active incident and remediated before this app is exposed to untrusted users.`
        : `No critical or high issues were confirmed, but the medium/low items still weaken the app's security posture and should be scheduled.`),
    ``,
    `**Top risks.**`,
    ...(top.length
      ? top.map((f) => `- \`${f.severity.toUpperCase()}\` ${f.title} — ${f.url}`)
      : ['- None recorded.']),
    ``,
    `**Remediation roadmap.**`,
    `- **Now:** fix every critical/high finding (secrets, injection, auth-affecting issues).`,
    `- **Next:** add missing security headers and cookie flags; upgrade outdated components.`,
    `- **Later:** tighten CSP, add CSRF tokens everywhere, and wire dependency + DAST scanning into CI.`,
    ``,
    `_Configure any AI provider (Claude, OpenAI, OpenRouter, NVIDIA NIM, Gemini, Groq, Ollama…) to enable full model-powered analysis — see the README._`,
  ].join('\n');
  return { source: 'local', model: null, markdown: md };
}
