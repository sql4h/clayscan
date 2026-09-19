# ClayScan

> *"I wait for you to complete the voyage into yourself, for the old wounds to heal."*

ClayScan is a web and source-code vulnerability scanner. You point it at a site you're allowed to test, or at a folder of code, and it tells you what's wrong, why it matters, how to prove it, and how to fix it.

It has two modes:

- `scan` drives a real Chrome browser over a live target, crawls it, discovers hidden endpoints, and runs a set of non-destructive checks for the usual web bugs (XSS, SQL injection, open redirect, CORS, exposed files, and so on).
- `code` reads a source tree and flags dangerous patterns in JavaScript/TypeScript, Python, PHP, Java, Ruby, and Go, with the exact file and line.

Both modes produce the same output: a console summary, a self-contained HTML report, and a JSON file. If you give it an API key it'll also write an executive summary with any model you like; if you don't, it falls back to a summary it builds itself.

A note on scope: ClayScan only does non-destructive testing, it asks you to confirm you're authorized before it touches a live target, and it makes you approve the active checks separately. There's no DoS, no evasion, no mass-targeting, and nothing that tries to exfiltrate data. It finds problems; it doesn't weaponize them.

## Install

```bash
npm install
npm run browser   # downloads Chromium for Playwright
```

Node.js 20 or newer.

## Scanning code

```bash
node bin/clayscan.js code ./path/to/project
```

This one needs no confirmation because it never runs anything or touches the network — it only reads files. It skips the usual noise (`node_modules`, `.git`, build output, minified bundles) and reports each hit with file and line number.

## Scanning a live site

```bash
# Interactive. Asks you to confirm authorization, asks before running active
# checks, and opens a visible browser window.
node bin/clayscan.js https://a-target-you-own.example

# Content discovery with the bundled wordlist (~1,200 paths).
node bin/clayscan.js https://target.example --seed common
node bin/clayscan.js https://target.example --discover --wordlist ./my-list.txt

# Passive only, no active requests.
node bin/clayscan.js https://target.example --no-active

# Unattended (your own lab or CI).
node bin/clayscan.js http://localhost:3000 \
  --yes --consent "I am authorized to test this target" \
  --approve-active --headless --out ./reports
```

### Flags worth knowing

| Flag | What it does |
|------|--------------|
| `--headless` | run Chrome with no window (default shows one) |
| `--channel chrome` | use your installed Chrome instead of the bundled Chromium |
| `--max-pages <n>` | cap how many pages get crawled (default 40) |
| `--include-subdomains` | crawl subdomains of the target as well |
| `--seed <urls>` | extra URLs to crawl, comma-separated; `common` runs the built-in wordlist |
| `--discover` | run wordlist content discovery against the origin |
| `--wordlist <file>` | use your own wordlist instead of the bundled one |
| `--no-active` | passive checks only |
| `--approve-active` | approve the active checks up front (unattended runs) |
| `--interact` | safely auto-submit forms during the crawl to exercise POST endpoints |
| `--login-url <url>` | log in here first, then crawl authenticated |
| `--login-user` / `--login-pass` | credentials for `--login-url` (override field detection with `--login-user-field` / `--login-pass-field`) |
| `--auth-cookie` / `--auth-header` | attach an existing session, e.g. `"sid=abc"` or `"Authorization: Bearer x"` |
| `--out <dir>` | where reports go |

## Choosing an AI model

The summary step talks to two request formats — Anthropic's and the OpenAI chat-completions format — which between them cover most providers. Set the relevant environment variable and it picks that provider automatically:

| Provider | Env var | Default model |
|----------|---------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-5` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o-mini` |
| OpenRouter | `OPENROUTER_API_KEY` | `meta-llama/llama-3.1-70b-instruct` |
| NVIDIA NIM | `NVIDIA_API_KEY` | `meta/llama-3.1-70b-instruct` |
| Google Gemini | `GEMINI_API_KEY` | `gemini-1.5-flash` |
| Groq | `GROQ_API_KEY` | `llama-3.1-70b-versatile` |
| Together | `TOGETHER_API_KEY` | Llama-3.1-70B-Turbo |
| Ollama (local) | none | `llama3.1` |

```bash
# Auto-detected from whichever key is set.
export OPENROUTER_API_KEY=sk-or-...
node bin/clayscan.js https://target.example

# Or pick one explicitly.
node bin/clayscan.js https://target.example --ai-provider gemini --ai-model gemini-1.5-pro

# Local, no key.
node bin/clayscan.js https://target.example --ai-provider ollama --ai-model llama3.1

# Any other OpenAI-compatible endpoint.
node bin/clayscan.js https://target.example \
  --ai-provider custom --ai-base-url http://localhost:8000/v1/chat/completions \
  --ai-model my-model --ai-key optional-key
```

You can also override any provider with `CLAYSCAN_AI_PROVIDER`, `CLAYSCAN_MODEL`, `CLAYSCAN_AI_BASE_URL`, `CLAYSCAN_AI_API_KEY`, and `CLAYSCAN_AI_SHAPE`. With no provider set, it just writes the local summary and the rest of the scan is unaffected.

## Try it safely

There's a small deliberately-broken app and a deliberately-broken code sample in `examples/`, so you can watch both modes work without touching anything real.

```bash
node examples/vulnerable-app.js       # http://localhost:4599
node bin/clayscan.js http://localhost:4599 --yes \
  --consent "I am authorized to test this target" --approve-active --headless

node bin/clayscan.js code examples/vulnerable-code
```

There's also `examples/vuln-range.js`, a small server that is genuinely (not just apparently) vulnerable to command injection and path traversal, for exercising those two active checks:

```bash
node examples/vuln-range.js       # http://localhost:4610
node bin/clayscan.js http://localhost:4610 --yes \
  --consent "I am authorized to test this target" --approve-active --headless
```

## What it looks for

Live site: reflected XSS, stored / blind XSS (confirmed by execution in the browser), error-based and boolean auth-bypass SQL injection, blind (time-based) SQL and command injection, NoSQL injection, OS command injection, SSRF (out-of-band), XXE (file read + blind out-of-band), HTTP request smuggling (CL.TE/TE.CL timing), IDOR / broken object-level authorization, server-side template injection, path traversal / local file inclusion, open redirect, CORS misconfiguration, host header injection, dangerous HTTP methods, GraphQL introspection exposure, exposed files (`.env`, `.git`, backups), hardcoded credentials and client-side auth gates, secret and PII disclosure, sensitive data in API responses (password hashes, keys, bulk emails, card numbers), JWT weaknesses (alg=none, guessable HMAC secrets, missing expiry), missing security headers, weak cookies, clickjacking, missing CSRF tokens, mixed content, outdated JavaScript libraries, and unlinked endpoints via content discovery.

Blind injection uses differential timing (a delay payload vs a zero-delay control) so a naturally slow endpoint doesn't produce a false positive. Stored XSS injects a uniquely-marked payload into each writable point, then re-visits pages in the real browser and reports only the ones whose marker actually executed.

For **SSRF** and **XXE** it runs a local out-of-band collector: it injects a callback URL (or an XML external entity pointing at it) and reports a finding only if the target actually connects back, which is high-confidence. On a localhost target the callback host is auto-detected; for a remote target set `--oob-host <reachable-ip-or-host>` so the target can reach you. XXE is also detected in-band when a `file://` entity is reflected in the response. **Request smuggling** is probed with the standard CL.TE/TE.CL timing method over raw sockets, and only reported when a crafted request reproducibly hangs while a normal one returns fast — it's surfaced conservatively (verify by hand).

It also checks for **IDOR / broken object-level authorization**: when a request carries an object identifier (a numeric path segment or an id-like parameter), it swaps in a neighbouring ID and flags the case where a different but same-shaped record comes back. To avoid false positives on public catalogs, it only reports when the object looks private (an account/order/user-style path or personal data in the response) — not for, say, a public product listing.

With `--interact` the crawler safely fills and submits forms (skipping anything that looks destructive, like delete/logout, and dismissing cookie/welcome overlays first), so the POST requests those forms trigger enter the corpus and get tested. With `--login-url` (or `--auth-cookie`/`--auth-header`) it authenticates first and crawls as a logged-in user, so it reaches endpoints behind the login. Together these let it catch things like login/auth SQL injection on `POST /rest/user/login`, not just bugs on public GET pages.

The injection checks build a request corpus from everything the app actually does — every link, form, and XHR/fetch call observed in the browser (GET query strings, JSON bodies, and form fields) — and test each insertion point. That means a JSON field on a REST endpoint like `POST /rest/user/login` is tested the same way a `?q=` query parameter is, so bugs behind the API get caught, not just the ones in `<a>` links.

The command-injection and path-traversal probes are non-destructive: command injection is confirmed by making the server compute a harmless arithmetic value (so a real result is distinguishable from reflected text), and path traversal is confirmed by matching known signatures of files like `/etc/passwd` or Windows `win.ini`. Both are active checks and only run once you approve them.

Source code: command and code injection (`eval`, `exec`, `shell=True`), SQL injection, path traversal, SSRF, file inclusion, server-side template injection, unsafe deserialization, XSS sinks, weak hashing, insecure randomness, disabled TLS verification, wildcard CORS, debug mode left on, and hardcoded secrets.

## About CTFs and TryHackMe

ClayScan is a scanner, not an auto-exploitation bot. It won't solve a room end to end and hand you the flag — that's a different project, and not one this repo pretends to be. What it will do is the enumeration: it finds the vulnerable classes those rooms are built on and shows you where and how, which is the tedious part. Point it at a legal target you control — the `examples/` here, OWASP Juice Shop, or DVWA — to see it in action.

## Safety and legal

Testing a system you don't own or have written permission to test is illegal in most places (the US CFAA, the UK Computer Misuse Act, and equivalents). ClayScan records your authorization before each live run, but staying in scope is on you. And no scan proves a system is secure — a clean report only means these checks didn't find anything.

## Credits

Written by sql4h, with Claude (Anthropic) and DeepSeek.

## License

MIT. See [LICENSE](LICENSE).
