const PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/console', '/graphiql', '/query', '/api/query', '/gql'];
const INTROSPECTION = JSON.stringify({ query: '{__schema{queryType{name} types{name}}}' });

export default {
  id: 'graphql',
  name: 'GraphQL exposure / introspection',
  phase: 'active',
  intrusive: 'low',
  async run({ target, findings, http, site }) {
    const origin = new URL(target).origin;
    const candidates = new Set(PATHS.map((p) => origin + p));
    for (const r of site.responses || []) {
      if (/graphql|\/gql/i.test(r.url)) candidates.add(r.url.split('?')[0]);
    }

    for (const url of candidates) {
      const res = await http.request(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: INTROSPECTION,
        redirect: 'manual',
      });
      if (!res.ok || !res.body) continue;
      if (res.body.includes('__schema') || (res.body.includes('"data"') && res.body.includes('queryType'))) {
        findings.add({
          id: 'graphql-introspection',
          title: 'GraphQL introspection enabled',
          severity: 'medium',
          url,
          evidence: `POST ${url} with an introspection query returned the schema.`,
          impact:
            'Introspection exposes the full API schema (types, fields, mutations), giving an attacker a complete map of the attack surface.',
          remediation:
            'Disable introspection in production, require authentication, and add query depth/complexity limits.',
          cwe: 'CWE-200',
          poc: `curl -s -X POST -H "content-type: application/json" -d '${INTROSPECTION}' "${url}"`,
          confidence: 0.85,
        });
        return;
      }
    }
  },
};
