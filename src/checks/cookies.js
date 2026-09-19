export default {
  id: 'cookies',
  name: 'Cookie security attributes',
  phase: 'passive',
  run({ site, findings, target }) {
    const isHttps = new URL(target).protocol === 'https:';
    for (const c of site.cookies) {
      const where = `${c.domain}${c.path} (cookie: ${c.name})`;
      if (!c.httpOnly && looksSession(c.name)) {
        findings.add({
          id: 'cookie-missing-httponly',
          title: `Session cookie without HttpOnly: ${c.name}`,
          severity: 'medium',
          url: target,
          evidence: `${where} — HttpOnly=false`,
          impact: 'JavaScript (e.g. via XSS) can read the cookie and hijack the session.',
          remediation: 'Set the HttpOnly attribute on all session/auth cookies.',
          cwe: 'CWE-1004',
        });
      }
      if (isHttps && !c.secure) {
        findings.add({
          id: 'cookie-missing-secure',
          title: `Cookie without Secure flag: ${c.name}`,
          severity: 'medium',
          url: target,
          evidence: `${where} — Secure=false on an HTTPS site`,
          impact: 'The cookie can be transmitted over plaintext HTTP and intercepted.',
          remediation: 'Set the Secure attribute so the cookie is only sent over HTTPS.',
          cwe: 'CWE-614',
        });
      }
      if (!c.sameSite || c.sameSite === 'None') {
        findings.add({
          id: 'cookie-weak-samesite',
          title: `Cookie with weak SameSite: ${c.name}`,
          severity: 'low',
          url: target,
          evidence: `${where} — SameSite=${c.sameSite || 'unset'}`,
          impact: 'Cookies sent on cross-site requests enable CSRF and cross-site leakage.',
          remediation: 'Set SameSite=Lax or Strict on cookies unless cross-site use is required.',
          cwe: 'CWE-352',
        });
      }
    }
  },
};

function looksSession(name) {
  return /sess|sid|auth|token|jwt|login|user|account/i.test(name);
}
