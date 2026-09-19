export const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export class FindingsCollector {
  constructor() {
    this.items = [];
    this._seen = new Set();
  }

  add(f) {
    if (!SEVERITY.includes(f.severity)) f.severity = 'info';
    const dedupe = `${f.id}|${f.url}|${f.evidence || ''}`;
    if (this._seen.has(dedupe)) return;
    this._seen.add(dedupe);
    this.items.push({ confidence: 0.8, references: [], ...f, foundAt: new Date().toISOString() });
  }

  sorted() {
    return [...this.items].sort(
      (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title)
    );
  }

  counts() {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const it of this.items) c[it.severity]++;
    return c;
  }
}
