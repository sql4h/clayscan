import { buildCorpus, insertionPoints, mutate, send, pointLabel } from '../http/insertion.js';

const DB_ERRORS = [
  /You have an error in your SQL syntax/i,
  /SQL syntax.*MySQL/i,
  /valid MySQL result/i,
  /check the manual that corresponds to your MySQL/i,
  /mysql_fetch/i,
  /PostgreSQL.*ERROR/i,
  /pg_query\(\)/i,
  /Warning: pg_/i,
  /SQLite\/JDBCDriver/i,
  /SQLite3::/i,
  /sqlite3.OperationalError/i,
  /SQLITE_ERROR/i,
  /SqliteError/i,
  /unrecognized token:/i,
  /near ".*?": syntax error/i,
  /ORA-\d{5}/,
  /Oracle error/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /Unclosed quotation mark after the character string/i,
  /Incorrect syntax near/i,
  /System\.Data\.SqlClient\.SqlException/i,
  /Sequelize\w*Error/i,
  /SequelizeDatabaseError/i,
];

const BYPASS_PAYLOADS = ["' OR 1=1-- -", "' OR '1'='1", "') OR ('1'='1", "\" OR \"1\"=\"1"];
const AUTH_HINTS = /"?(?:token|authentication|access_token|jwt|sessionid|success)"?\s*[:=]/i;

export default {
  id: 'sqli',
  name: 'SQL injection (error-based)',
  phase: 'active',
  intrusive: 'medium',
  async run({ site, findings, http, target, opts }) {
    const corpus = buildCorpus(site, target, opts).filter((r) => r.method !== 'DELETE');
    const cap = opts.maxActiveTargets ?? 60;
    const seen = new Set();
    let tested = 0;

    for (const req of corpus) {
      for (const point of insertionPoints(req)) {
        if (tested >= cap) return;
        const pk = `${req.method} ${req.url.split('?')[0]} ${pointLabel(req, point)}`;
        if (seen.has(pk)) continue;
        seen.add(pk);
        tested++;

        const base = await send(http, mutate(req, point, 'clayscan1'));
        if (!base.ok || matchesError(base.body)) continue;

        const inj = await send(http, mutate(req, point, "clayscan1'"));
        if (!inj.ok) continue;
        const hit = matchesError(inj.body);
        if (hit) {
          findings.add({
            id: 'sqli-error-based',
            title: `SQL injection in ${pointLabel(req, point)}`,
            severity: 'critical',
            url: req.url,
            evidence: `${req.method} ${req.url} — injecting a single quote into ${pointLabel(req, point)} produced a database error: "${hit}"`,
            impact:
              'SQL injection can allow reading or modifying the entire database (credentials, PII), authentication bypass, and in some setups remote code execution.',
            remediation:
              'Use parameterized queries / prepared statements everywhere. Never build SQL from user input. Apply least-privilege DB accounts.',
            cwe: 'CWE-89',
            poc: `Send ${req.method} ${req.url} with ${pointLabel(req, point)} = clayscan1' (a single quote triggers the SQL error; no data was extracted).`,
            references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
            confidence: 0.85,
          });
          continue;
        }

        const bypassed = await tryAuthBypass(http, req, point, base);
        if (bypassed) {
          findings.add({
            id: 'sqli-auth-bypass',
            title: `SQL injection (authentication/logic bypass) in ${pointLabel(req, point)}`,
            severity: 'critical',
            url: req.url,
            evidence: `A boolean SQL payload in ${pointLabel(req, point)} changed the result from ${base.status} to ${bypassed.status} and returned auth/data indicators — the input reaches a SQL WHERE clause.`,
            impact:
              'The parameter is injectable and can be used to bypass authentication or return records that should be inaccessible (e.g. logging in as another user).',
            remediation:
              'Use parameterized queries; never concatenate input into SQL. Enforce auth server-side independent of query results.',
            cwe: 'CWE-89',
            poc: `Send ${req.method} ${req.url} with ${pointLabel(req, point)} = ${bypassed.payload}`,
            references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
            confidence: 0.8,
          });
        }
      }
    }
  },
};

async function tryAuthBypass(http, req, point, base) {
  const baseAuth = AUTH_HINTS.test(base.body || '');
  const baseFail = base.status === 401 || base.status === 403 || base.status >= 500 || base.status === 400;
  if (!baseFail && baseAuth) return null;

  for (const payload of BYPASS_PAYLOADS) {
    const res = await send(http, mutate(req, point, payload));
    if (!res.ok) continue;
    const gainedAuth = AUTH_HINTS.test(res.body || '') && !baseAuth;
    const nowOk = res.status >= 200 && res.status < 300;
    const wasNotOk = base.status < 200 || base.status >= 300;
    if ((nowOk && wasNotOk && (gainedAuth || (res.body || '').length > (base.body || '').length + 200)) || gainedAuth) {
      return { status: res.status, payload };
    }
  }
  return null;
}

function matchesError(body) {
  for (const re of DB_ERRORS) {
    const m = re.exec(body || '');
    if (m) return m[0].slice(0, 120);
  }
  return null;
}
