const JS = /\.(?:js|jsx|ts|tsx|mjs|cjs|vue|svelte)$/i;
const PY = /\.py$/i;
const PHP = /\.php$/i;
const JAVA = /\.java$/i;
const RUBY = /\.rb$/i;
const GO = /\.go$/i;
const ANY = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|php|java|rb|go|json|yml|yaml|env|txt|config|xml|ini|properties|sh)$/i;

export const RULES = [

  {
    id: 'js-eval', title: 'Use of eval() / Function constructor', severity: 'high', cwe: 'CWE-95',
    files: JS, re: /\beval\s*\(|new\s+Function\s*\(/,
    impact: 'Executing dynamically built strings enables code injection if any part is attacker-influenced.',
    remediation: 'Remove eval/Function; parse data with JSON.parse and use explicit logic.', confidence: 0.6,
  },
  {
    id: 'js-cmd-injection', title: 'Command execution with dynamic input', severity: 'critical', cwe: 'CWE-78',
    files: JS, re: /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[`'"][^`'"]*\$\{|\b(?:exec|execSync)\s*\([^)]*\+/,
    impact: 'Concatenating input into a shell command allows OS command injection (full server takeover).',
    remediation: 'Use execFile/spawn with an argument array and never build a shell string from input.', confidence: 0.75,
  },
  {
    id: 'js-sql-injection', title: 'SQL query built by string concatenation/interpolation', severity: 'critical', cwe: 'CWE-89',
    files: JS, re: /(?:query|execute|raw)\s*\(\s*[`'"][^`'"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^`'"]*(?:\$\{|['"]\s*\+)/i,
    impact: 'User input concatenated into SQL enables injection: data theft, auth bypass, sometimes RCE.',
    remediation: 'Use parameterized queries / prepared statements (placeholders), never string building.', confidence: 0.75,
  },
  {
    id: 'js-dom-xss', title: 'Unsafe DOM sink (innerHTML/document.write) with variable', severity: 'high', cwe: 'CWE-79',
    files: JS, re: /\.(?:innerHTML|outerHTML)\s*=\s*(?![`'"])|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(/,
    impact: 'Writing unescaped data into the DOM enables cross-site scripting.',
    remediation: 'Use textContent, or sanitize with a vetted library (DOMPurify) before inserting HTML.', confidence: 0.5,
  },
  {
    id: 'react-dangerous-html', title: 'React dangerouslySetInnerHTML', severity: 'high', cwe: 'CWE-79',
    files: JS, re: /dangerouslySetInnerHTML/,
    impact: 'Injects raw HTML into the React tree; unsanitized values cause XSS.',
    remediation: 'Avoid it, or sanitize the HTML with DOMPurify first.', confidence: 0.5,
  },
  {
    id: 'js-open-redirect', title: 'Redirect to unvalidated input', severity: 'medium', cwe: 'CWE-601',
    files: JS, re: /\.redirect\s*\(\s*(?:req|request|ctx|query|params|body)\b/,
    impact: 'Redirecting to raw user input enables phishing and OAuth token theft (open redirect).',
    remediation: 'Redirect only to a server-side allowlist of paths.', confidence: 0.55,
  },
  {
    id: 'js-path-traversal', title: 'Filesystem access with request-derived path', severity: 'high', cwe: 'CWE-22',
    files: JS, re: /\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|unlink)\s*\([^)]*(?:req\.|request\.|params|query|body)/,
    impact: 'Building a file path from input allows path traversal to read/write arbitrary files.',
    remediation: 'Resolve against a fixed base dir and reject paths that escape it (path.resolve + prefix check).', confidence: 0.6,
  },
  {
    id: 'js-ssrf', title: 'Server-side request to user-controlled URL', severity: 'high', cwe: 'CWE-918',
    files: JS, re: /\b(?:fetch|axios(?:\.get|\.post)?|got|http\.get|https\.get|request)\s*\(\s*(?:req\.|request\.|`[^`]*\$\{(?:req|request|query|params|body))/,
    impact: 'Fetching a user-supplied URL server-side enables SSRF: reach internal services and cloud metadata.',
    remediation: 'Validate the host against an allowlist; block private/link-local ranges and redirects.', confidence: 0.5,
  },

  {
    id: 'weak-hash', title: 'Weak hash algorithm (MD5/SHA1)', severity: 'medium', cwe: 'CWE-327',
    files: /\.(?:js|jsx|ts|tsx|mjs|cjs|py|php|java|rb|go)$/i,
    re: /createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"|\bmd5\s*\(/i,
    impact: 'MD5/SHA-1 are broken for security use (collisions, fast brute force of password hashes).',
    remediation: 'Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.', confidence: 0.7,
  },
  {
    id: 'weak-random', title: 'Insecure randomness for security value', severity: 'medium', cwe: 'CWE-338',
    files: JS, re: /Math\.random\s*\(\s*\)[^;\n]*(?:token|secret|password|key|otp|nonce|session|salt|id)/i,
    impact: 'Math.random is predictable; tokens/secrets derived from it can be guessed.',
    remediation: 'Use crypto.randomBytes / crypto.randomUUID / getRandomValues.', confidence: 0.6,
  },
  {
    id: 'tls-disabled', title: 'TLS certificate verification disabled', severity: 'high', cwe: 'CWE-295',
    files: /\.(?:js|jsx|ts|tsx|mjs|cjs|py|env)$/i,
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/,
    impact: 'Disabling cert validation allows man-in-the-middle interception of "encrypted" traffic.',
    remediation: 'Never disable verification; fix the certificate chain instead.', confidence: 0.85,
  },

  {
    id: 'sast-hardcoded-secret', title: 'Hardcoded secret / credential', severity: 'high', cwe: 'CWE-798',
    files: ANY,
    re: /\b(?:api[_-]?key|apikey|secret|password|passwd|token|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"][^'"\s${]{8,}['"]/i,
    impact: 'Secrets committed to source are exposed to everyone with repo access and leak via history.',
    remediation: 'Move secrets to environment variables / a secrets manager and rotate the exposed value.', confidence: 0.55,
  },
  {
    id: 'sast-aws-key', title: 'AWS access key in source', severity: 'critical', cwe: 'CWE-798',
    files: ANY, re: /AKIA[0-9A-Z]{16}/,
    impact: 'A live AWS key grants direct access to cloud resources.',
    remediation: 'Revoke the key immediately and remove it from history (git filter-repo).', confidence: 0.9,
  },
  {
    id: 'sast-private-key', title: 'Private key committed to source', severity: 'critical', cwe: 'CWE-798',
    files: ANY, re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    impact: 'A committed private key compromises TLS/SSH/signing identities.',
    remediation: 'Rotate the key and purge it from git history.', confidence: 0.95,
  },

  {
    id: 'cors-wildcard', title: "CORS Allow-Origin set to '*'", severity: 'medium', cwe: 'CWE-942',
    files: /\.(?:js|jsx|ts|tsx|mjs|cjs|py|php|java|go)$/i,
    re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]|origin\s*:\s*['"]\*['"]/,
    impact: 'A wildcard origin (especially with credentials) exposes authenticated data cross-site.',
    remediation: 'Echo only an explicit allowlist of trusted origins.', confidence: 0.5,
  },
  {
    id: 'flask-debug', title: 'Flask/Django debug mode enabled', severity: 'high', cwe: 'CWE-489',
    files: PY, re: /debug\s*=\s*True|DEBUG\s*=\s*True/,
    impact: 'Debug mode exposes an interactive console and stack traces — often RCE in production.',
    remediation: 'Disable debug in production; drive it from an environment variable.', confidence: 0.6,
  },

  {
    id: 'py-eval-exec', title: 'Python eval()/exec()', severity: 'high', cwe: 'CWE-95',
    files: PY, re: /\b(?:eval|exec)\s*\(/,
    impact: 'Evaluating dynamic strings enables code injection.',
    remediation: 'Use ast.literal_eval for data, or explicit dispatch logic.', confidence: 0.6,
  },
  {
    id: 'py-cmd-injection', title: 'Python shell command with shell=True / concatenation', severity: 'critical', cwe: 'CWE-78',
    files: PY, re: /os\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True|os\.popen\s*\(/,
    impact: 'shell=True with dynamic input allows OS command injection.',
    remediation: 'Pass an argument list and shell=False; validate inputs.', confidence: 0.6,
  },
  {
    id: 'py-sql', title: 'Python SQL via string formatting', severity: 'critical', cwe: 'CWE-89',
    files: PY, re: /(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*%|['"][^'"]*['"]\s*\.format|['"][^'"]*['"]\s*\+)/,
    impact: 'String-formatted SQL enables injection.',
    remediation: 'Use parameterized queries (execute(sql, params)).', confidence: 0.7,
  },
  {
    id: 'py-deser', title: 'Unsafe deserialization (pickle/yaml.load)', severity: 'high', cwe: 'CWE-502',
    files: PY, re: /pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/,
    impact: 'Deserializing untrusted data can execute arbitrary code.',
    remediation: 'Use yaml.safe_load; avoid pickle for untrusted input.', confidence: 0.65,
  },
  {
    id: 'py-ssti', title: 'Server-side template injection (render_template_string)', severity: 'high', cwe: 'CWE-1336',
    files: PY, re: /render_template_string\s*\([^)]*(?:request|\+|%|format|f['"])/,
    impact: 'Rendering user input as a template enables SSTI → RCE.',
    remediation: 'Render fixed templates with a context dict; never template user input.', confidence: 0.6,
  },

  {
    id: 'php-injection', title: 'PHP dangerous function with user input', severity: 'critical', cwe: 'CWE-78',
    files: PHP, re: /\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/,
    impact: 'User input in a command/eval sink allows RCE.',
    remediation: 'Avoid these sinks; use escapeshellarg and strict validation.', confidence: 0.8,
  },
  {
    id: 'php-sql', title: 'PHP SQL query with superglobal', severity: 'critical', cwe: 'CWE-89',
    files: PHP, re: /(?:mysqli?_query|->query|->exec)\s*\([^)]*\$(?:_GET|_POST|_REQUEST)/,
    impact: 'Superglobals concatenated into SQL enable injection.',
    remediation: 'Use prepared statements (PDO / mysqli with bound params).', confidence: 0.75,
  },
  {
    id: 'php-lfi', title: 'PHP include/require with user input', severity: 'critical', cwe: 'CWE-98',
    files: PHP, re: /\b(?:include|include_once|require|require_once)\s*\(?[^;]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/,
    impact: 'Including a user-controlled path enables local/remote file inclusion → RCE.',
    remediation: 'Map input to a fixed allowlist of files.', confidence: 0.8,
  },
  {
    id: 'php-xss', title: 'PHP echo of superglobal (reflected XSS)', severity: 'high', cwe: 'CWE-79',
    files: PHP, re: /\b(?:echo|print)\b[^;]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/,
    impact: 'Echoing input without encoding causes reflected XSS.',
    remediation: 'Encode output with htmlspecialchars().', confidence: 0.65,
  },
  {
    id: 'php-unserialize', title: 'PHP unserialize() of user input', severity: 'high', cwe: 'CWE-502',
    files: PHP, re: /unserialize\s*\([^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)/,
    impact: 'Object injection can lead to RCE via magic methods.',
    remediation: 'Use json_decode for untrusted data.', confidence: 0.75,
  },

  {
    id: 'java-cmd', title: 'Java Runtime.exec()', severity: 'high', cwe: 'CWE-78',
    files: JAVA, re: /Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(/,
    impact: 'Executing dynamic commands enables OS command injection.',
    remediation: 'Avoid shell execution; pass argument arrays and validate input.', confidence: 0.5,
  },
  {
    id: 'java-sql', title: 'Java SQL via Statement concatenation', severity: 'critical', cwe: 'CWE-89',
    files: JAVA, re: /(?:createStatement\(\)[\s\S]{0,80}?execute(?:Query|Update)?\s*\([^)]*\+)|Statement[^;]*execute[^)]*\+/,
    impact: 'Concatenated SQL enables injection.',
    remediation: 'Use PreparedStatement with bound parameters.', confidence: 0.55,
  },
  {
    id: 'java-deser', title: 'Java native deserialization (ObjectInputStream)', severity: 'high', cwe: 'CWE-502',
    files: JAVA, re: /new\s+ObjectInputStream\s*\(/,
    impact: 'Deserializing untrusted data is a classic RCE vector.',
    remediation: 'Avoid native serialization for untrusted data; use JSON with a schema.', confidence: 0.5,
  },
  {
    id: 'ruby-cmd', title: 'Ruby command execution with interpolation', severity: 'high', cwe: 'CWE-78',
    files: RUBY, re: /(?:system|exec|`[^`]*#\{|%x\{[^}]*#\{)|Open3\.[a-z_]+\s*\([^)]*#\{/,
    impact: 'Interpolating input into a command enables injection.',
    remediation: 'Pass command + args as separate strings; validate input.', confidence: 0.5,
  },
  {
    id: 'go-cmd', title: 'Go exec.Command with dynamic shell', severity: 'high', cwe: 'CWE-78',
    files: GO, re: /exec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"-c"/,
    impact: 'Running "sh -c" with built strings enables command injection.',
    remediation: 'Call the binary directly with explicit args; avoid the shell.', confidence: 0.55,
  },
];
