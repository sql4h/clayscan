const SEV_COLOR = {
  critical: '#ff4d4f',
  high: '#ff7a45',
  medium: '#faad14',
  low: '#40a9ff',
  info: '#8c8c8c',
};

export function renderHtml(report) {
  const { scope, summary, findings, coverage, aiAnalysis } = report;
  const total = findings.length;
  const isCode = report.mode === 'code';
  const locLabel = isCode ? 'File' : 'URL';
  let hostLabel;
  try { hostLabel = new URL(scope.target).hostname; } catch { hostLabel = String(scope.target); }
  const coverageCards = Object.entries(coverage || {})
    .map(([k, v]) => `<div class="card"><b>${esc(v)}</b><span>${esc(humanize(k))}</span></div>`)
    .join('');

  const badges = Object.entries(summary)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `<span class="badge" style="background:${SEV_COLOR[sev]}">${n} ${sev}</span>`)
    .join(' ') || '<span class="badge" style="background:#52c41a">no findings</span>';

  const rows = findings
    .map(
      (f) => `
      <details class="finding">
        <summary>
          <span class="sev" style="background:${SEV_COLOR[f.severity]}">${esc(f.severity)}</span>
          <span class="ftitle">${esc(f.title)}</span>
          ${f.cwe ? `<span class="cwe">${esc(f.cwe)}</span>` : ''}
        </summary>
        <div class="body">
          <div class="row"><b>${locLabel}</b><code>${esc(f.url)}</code></div>
          <div class="row"><b>Evidence</b><span>${esc(f.evidence)}</span></div>
          <div class="row"><b>Impact</b><span>${esc(f.impact)}</span></div>
          <div class="row"><b>Remediation</b><span>${esc(f.remediation)}</span></div>
          ${f.poc ? `<div class="row"><b>PoC</b><pre>${esc(f.poc)}</pre></div>` : ''}
          ${f.confidence != null ? `<div class="row"><b>Confidence</b><span>${Math.round(f.confidence * 100)}%</span></div>` : ''}
          ${f.references?.length ? `<div class="row"><b>References</b><span>${f.references.map((r) => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join('<br>')}</span></div>` : ''}
        </div>
      </details>`
    )
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClayScan Report — ${esc(hostLabel)}</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9}
  header{padding:28px 32px;border-bottom:1px solid #21262d;background:#161b22}
  h1{margin:0 0 6px;font-size:22px;letter-spacing:.3px}
  h1 .mark{color:#58a6ff}
  .meta{color:#8b949e;font-size:13px}
  .wrap{max-width:960px;margin:0 auto;padding:24px 32px}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;color:#111;font-weight:600;font-size:12px;margin-right:6px}
  .cards{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0 8px}
  .card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 18px;min-width:120px}
  .card b{display:block;font-size:24px}
  .card span{color:#8b949e;font-size:12px}
  .finding{background:#161b22;border:1px solid #21262d;border-radius:8px;margin:10px 0;padding:2px 14px}
  summary{cursor:pointer;display:flex;align-items:center;gap:10px;padding:10px 0}
  summary::-webkit-details-marker{display:none}
  .sev{color:#111;font-weight:700;text-transform:uppercase;font-size:11px;padding:2px 8px;border-radius:5px}
  .ftitle{font-weight:600}
  .cwe{margin-left:auto;color:#8b949e;font-size:12px}
  .body{padding:6px 0 14px}
  .row{display:grid;grid-template-columns:120px 1fr;gap:12px;padding:6px 0;border-top:1px solid #21262d}
  .row b{color:#8b949e;font-weight:600}
  code,pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:2px 6px;font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#79c0ff;white-space:pre-wrap;word-break:break-all}
  pre{padding:10px;display:block}
  a{color:#58a6ff}
  .ai{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px 22px;margin-top:22px}
  .ai h2{margin-top:0}
  .disclaimer{color:#8b949e;font-size:12px;margin-top:28px;border-top:1px solid #21262d;padding-top:16px}
</style></head>
<body>
<header>
  <h1><span class="mark">Clay</span>Scan — Security Report</h1>
  <div class="meta">
    Target: <b>${esc(scope.target)}</b> · Operator: ${esc(scope.operator)} ·
    ${esc(report.startedAt)} → ${esc(report.finishedAt)}
  </div>
</header>
<div class="wrap">
  <div>${badges}</div>
  <div class="cards">
    <div class="card"><b>${total}</b><span>findings</span></div>
    ${coverageCards}
  </div>

  ${aiAnalysis ? `<div class="ai">${mdToHtml(aiAnalysis.markdown)}<p class="meta">— analysis via ${esc(aiAnalysis.source)}${aiAnalysis.model ? ' (' + esc(aiAnalysis.model) + ')' : ''}</p></div>` : ''}

  <h2 style="margin-top:26px">Findings</h2>
  ${rows || '<p class="meta">No findings recorded.</p>'}

  <p class="disclaimer">
    ClayScan performs authorized, non-destructive testing only. Absence of findings is not proof of security —
    results are bounded by the crawl scope, depth, and the checks that were run. Always validate findings manually
    before acting, and only test systems you are authorized to assess.
  </p>
</div>
</body></html>`;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function humanize(k) {
  return String(k).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]/g, ' ').toLowerCase();
}

function mdToHtml(md) {
  const lines = esc(md).split('\n');
  let html = '';
  let inList = false;
  for (let line of lines) {
    line = line.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
    if (/^#{1,3}\s+/.test(line)) {
      if (inList) { html += '</ul>'; inList = false; }
      const level = line.match(/^#+/)[0].length;
      html += `<h${level + 1}>${line.replace(/^#+\s+/, '')}</h${level + 1}>`;
    } else if (/^\s*[-*]\s+/.test(line)) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += `<li>${line.replace(/^\s*[-*]\s+/, '')}</li>`;
    } else if (line.trim() === '') {
      if (inList) { html += '</ul>'; inList = false; }
    } else {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<p>${line}</p>`;
    }
  }
  if (inList) html += '</ul>';
  return html;
}
