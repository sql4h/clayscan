import net from 'node:net';
import tls from 'node:tls';

export default {
  id: 'request-smuggling',
  name: 'HTTP request smuggling (timing)',
  phase: 'active',
  intrusive: 'high',
  async run({ target, findings }) {
    const u = new URL(target);
    const useTls = u.protocol === 'https:';
    const host = u.hostname;
    const port = u.port ? parseInt(u.port, 10) : (useTls ? 443 : 80);
    const path = u.pathname || '/';

    const baseline = await raw({ host, port, useTls, payload: normalReq(host, path), timeoutMs: 5000 });
    if (!baseline.responded || baseline.ms > 3500) return;

    const probes = [
      { type: 'CL.TE', payload: clte(host, path) },
      { type: 'TE.CL', payload: tecl(host, path) },
    ];

    for (const probe of probes) {
      const r1 = await raw({ host, port, useTls, payload: probe.payload, timeoutMs: 7000 });
      if (r1.responded) continue;
      const r2 = await raw({ host, port, useTls, payload: probe.payload, timeoutMs: 7000 });
      if (r2.responded) continue;

      findings.add({
        id: 'request-smuggling',
        title: `Possible ${probe.type} HTTP request smuggling`,
        severity: 'high',
        url: target,
        evidence: `A ${probe.type} timing probe caused the connection to hang (>7s, twice) while a normal request responded in ${baseline.ms}ms — the front-end and back-end disagree on request length.`,
        impact:
          'Request smuggling lets an attacker desynchronize the front-end and back-end, poisoning other users\' requests, bypassing controls, and hijacking sessions.',
        remediation:
          'Use HTTP/2 end to end or ensure the front-end and back-end agree on message length; reject requests with both Content-Length and Transfer-Encoding.',
        cwe: 'CWE-444',
        poc: `Send the ${probe.type} timing payload to ${target}; the response hangs.`,
        references: ['https://portswigger.net/web-security/request-smuggling'],
        confidence: 0.4,
      });
      return;
    }
  },
};

function normalReq(host, path) {
  return `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;
}

function clte(host, path) {
  return `POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX`;
}

function tecl(host, path) {
  return `POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX`;
}

function raw({ host, port, useTls, payload, timeoutMs }) {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;
    const finish = (responded) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch {  }
      resolve({ responded, ms: Date.now() - start });
    };
    const sock = useTls
      ? tls.connect({ host, port, servername: host, rejectUnauthorized: false })
      : net.connect({ host, port });
    sock.setTimeout(timeoutMs);
    sock.on(useTls ? 'secureConnect' : 'connect', () => { try { sock.write(payload); } catch { finish(true); } });
    sock.on('data', () => finish(true));
    sock.on('timeout', () => finish(false));
    sock.on('error', () => finish(true));
    sock.on('end', () => finish(true));
  });
}
