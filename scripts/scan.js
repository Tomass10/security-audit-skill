#!/usr/bin/env node
/**
 * Security Audit Scanner — Node.js / JavaScript
 * Usage: node scan.js <root_path>
 * Output: JSON to stdout
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

const root = process.argv[2];
if (!root) { console.error('Usage: node scan.js <root_path>'); process.exit(1); }

const findings = [];
let findingId  = 1;

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Risk score: severity × confidence × exploitability weight
// Produces a 0–100 numeric score for prioritization within the same severity band.
const SEVERITY_WEIGHT    = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 };
const CONFIDENCE_WEIGHT  = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const EXPLOIT_WEIGHT     = { remote_unauth: 3, remote_auth: 2, local: 1 };

function calcRiskScore(severity, confidence, exploitability) {
  const s = SEVERITY_WEIGHT[severity]   || 1;
  const c = CONFIDENCE_WEIGHT[confidence] || 2;
  const e = EXPLOIT_WEIGHT[exploitability] || 2;
  return Math.min(100, Math.round((s * c * e / (10 * 3 * 3)) * 100));
}

function addFinding(severity, category, file, line, title, description, snippet, remediation, meta) {
  const confidence    = (meta && meta.confidence)    || 'MEDIUM';
  const exploitability = (meta && meta.exploitability) || 'remote_auth';
  const taintSource   = (meta && meta.taintSource)   || null;
  findings.push({
    id: `SEC-${String(findingId++).padStart(3, '0')}`,
    severity, category,
    file: file || null, line: line || null,
    title, description,
    snippet: snippet || null, remediation,
    cwe:          (meta && meta.cwe)   || null,
    owasp:        (meta && meta.owasp) || null,
    confidence,
    exploitability,
    taint_source: taintSource,
    risk_score:   calcRiskScore(severity, confidence, exploitability),
  });
}

function grepFiles(pattern, extensions, flags) {
  extensions = extensions || ['js', 'ts', 'mjs', 'cjs'];
  flags      = flags      || '-iE';
  const extFilter = extensions.map(e => `--include="*.${e}"`).join(' ');
  const excludeDirs = [
    'node_modules', '.git', '.next', 'dist', 'build', 'coverage',
    '__generated__', 'generated', 'out', '.cache', 'vendor',
  ].map(d => `--exclude-dir="${d}"`).join(' ');
  const cmd = `grep -rn ${flags} "${pattern}" ${extFilter} ${excludeDirs} "${root}" 2>/dev/null || true`;
  try { return execSync(cmd, { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }).trim(); }
  catch { return ''; }
}

function findFiles(namePattern) {
  try {
    return execSync(
      `find "${root}" -name "${namePattern}" ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null`,
      { encoding: 'utf8' }
    ).trim().split('\n').filter(Boolean);
  } catch { return []; }
}

function parseGrepLines(output) {
  return output.split('\n').filter(Boolean).map(line => {
    const m = line.match(/^(.+?):(\d+):(.*)/);
    return m ? { file: m[1], line: parseInt(m[2]), code: m[3].trim() } : null;
  }).filter(Boolean);
}

function fileExists(p) { try { fs.accessSync(p); return true; } catch { return false; } }
function readFile(p)   { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }

function readContext(file, lineNum, before, after) {
  try {
    const lines = readFile(file).split('\n');
    return lines.slice(Math.max(0, lineNum - before - 1),
                       Math.min(lines.length, lineNum + after)).join('\n');
  } catch { return ''; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 1 — Hardcoded Secrets
// ═══════════════════════════════════════════════════════════════════════════════

const secretPatterns = [
  { pattern: 'AKIA[0-9A-Z]{16}',            label: 'AWS Access Key ID' },
  { pattern: 'sk-[a-zA-Z0-9]{32,}',         label: 'OpenAI/Stripe Secret Key' },
  { pattern: 'ghp_[a-zA-Z0-9]{36}',         label: 'GitHub Personal Access Token' },
  { pattern: 'xox[baprs]-[0-9a-zA-Z]{10,}', label: 'Slack Token' },
  { pattern: 'AIza[0-9A-Za-z\\-_]{35}',     label: 'Google API Key' },
  { pattern: '-----BEGIN (RSA|EC|OPENSSH) PRIVATE', label: 'Private Key Block' },
];

parseGrepLines(grepFiles(
  '(password|passwd|api_key|apikey|api_secret|client_secret|auth_token|access_token)\\s*[=:]\\s*[\'"][^\'"]{6,}[\'"]',
  ['js','ts','mjs','json','yaml','yml','env']
)).forEach(({ file, line, code }) => {
  if (/process\.env|os\.environ|<.*>|your[-_]|example|placeholder|changeme|xxxx/i.test(code)) return;
  addFinding(
    /test|spec|mock|fixture/i.test(file) ? 'MEDIUM' : 'CRITICAL',
    'Hardcoded Secret', file, line,
    'Hardcoded credential in source code',
    'A hardcoded secret was found. Committing credentials to source control risks exposure.',
    code,
    'Move to environment variables: process.env.MY_SECRET. Add .env to .gitignore. Rotate immediately.',
    { exploitability: 'remote_unauth' }
  );
});

secretPatterns.forEach(({ pattern, label }) => {
  parseGrepLines(grepFiles(pattern, ['js','ts','json','env','yaml','yml','sh','config'], '-rn -E'))
    .forEach(({ file, line, code }) => {
      addFinding('CRITICAL','Hardcoded Secret',file,line,
        `${label} found in source`,
        `A ${label} was found hardcoded. Rotate this credential immediately.`,
        code, 'Remove from source, store in environment variable, rotate the credential.');
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 2 — SQL / NoSQL Injection
// ═══════════════════════════════════════════════════════════════════════════════

// Classic .query() / .execute() with req input
parseGrepLines(grepFiles('(\\.query|\\.execute)\\s*\\([^)]*req\\.(body|params|query|headers)'))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','SQL Injection',file,line,
      'Possible SQL injection via unsanitized user input',
      'User-controlled input appears directly in a database query without parameterization.',
      code, 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [req.params.id])');
  });

// ORM raw queries — Sequelize / Knex / TypeORM / Prisma
parseGrepLines(grepFiles(
  '(sequelize\\.query|knex\\.raw|typeorm.*\\.query|\\$queryRaw|\\$executeRaw|\\$queryRawUnsafe|\\$executeRawUnsafe)\\s*\\(',
  ['js','ts']
)).forEach(({ file, line, code }) => {
  // Flag any that contain template literals or string concat
  if (/`|\+\s*req\.|req\.\w+\s*\+/.test(code) || /\$queryRawUnsafe|\$executeRawUnsafe/.test(code)) {
    addFinding('CRITICAL','SQL Injection (ORM raw query)',file,line,
      'ORM raw query with possible user input interpolation',
      'Sequelize.query(), knex.raw(), typeorm query(), and Prisma $queryRawUnsafe all execute literal SQL. String-concatenating or template-interpolating user input into these calls is full SQL injection.',
      code,
      'Use parameterized form:\n// Sequelize: sequelize.query("SELECT * FROM t WHERE id = ?", { replacements: [id] })\n// Knex:      knex.raw("SELECT * FROM t WHERE id = ?", [id])\n// Prisma:    prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}` (tagged template = safe)\n// Never use $queryRawUnsafe — replace with $queryRaw tagged template.');
  } else {
    addFinding('MEDIUM','SQL Injection (ORM raw query)',file,line,
      'ORM raw query detected — verify no user input is interpolated',
      'Raw ORM queries bypass the ORM\'s injection protections. Manually confirm no user-controlled value is concatenated or interpolated into this query.',
      code,
      'Audit this query for user input. Use parameterized replacements/bindings rather than string interpolation.');
  }
});

// NoSQL — MongoDB find with req input
parseGrepLines(grepFiles('\\.find(One)?\\s*\\(\\s*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','NoSQL Injection',file,line,
      'Possible NoSQL injection — user input passed to find()',
      'Passing req.body/query directly into MongoDB find() allows operators like {$gt:""} for auth bypass.',
      code, 'Validate and whitelist fields: Model.findOne({ email: String(req.body.email) }). Use express-mongo-sanitize.');
  });

// Mongoose $where / $function — server-side JS execution
parseGrepLines(grepFiles('\\$where|\\$function', ['js','ts']))
  .forEach(({ file, line, code }) => {
    if (/req\./i.test(readContext(file, line, 3, 3))) {
      addFinding('CRITICAL','NoSQL Injection — Server-Side JS',file,line,
        'Mongoose $where / $function with possible user input — RCE risk',
        '$where executes a JavaScript function on the MongoDB server. Passing user input to it is equivalent to eval() with database access.',
        code, 'Never pass user input to $where or $function. Rewrite as a standard query with indexed fields.');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 3 — XSS
// ═══════════════════════════════════════════════════════════════════════════════

// Client-side DOM sinks
parseGrepLines(grepFiles(
  '(innerHTML|outerHTML|document\\.write|dangerouslySetInnerHTML)\\s*[=(]',
  ['js','ts','jsx','tsx','html']
)).forEach(({ file, line, code }) => {
  addFinding('HIGH','XSS',file,line,
    'Potential XSS via unsafe DOM manipulation',
    'Directly writing to innerHTML or using dangerouslySetInnerHTML can allow script injection.',
    code, 'Use textContent instead of innerHTML. Sanitize with DOMPurify if HTML rendering is required.');
});

// Server-side template unescaped output — EJS <%-  Pug !=  Handlebars {{{
parseGrepLines(grepFiles('<%[-]|[!=]{2}|\\{\\{\\{', ['ejs','pug','hbs','njk','html']))
  .forEach(({ file, line, code }) => {
    if (/<%[-]/.test(code) || /[!]=/.test(code) || /\{\{\{/.test(code)) {
      addFinding('HIGH','XSS — Unescaped Template Output',file,line,
        'Unescaped output operator in server-side template',
        'EJS <%-  Pug !=  and Handlebars {{{ render raw HTML without escaping. Any user-controlled value piped through these operators is a stored/reflected XSS.',
        code,
        'Use the escaping operator:\n// EJS:        <%= variable %>  (escapes HTML)\n// Pug:        = variable       (escapes HTML)\n// Handlebars: {{ variable }}   (escapes HTML)\nOnly use unescaped operators for trusted, server-generated HTML.');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 4 — Brute Force / Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

const authRouteHits  = parseGrepLines(grepFiles('(router|app)\\.(post|put)\\s*\\([\'"](/login|/signin|/auth|/token|/password)'));
const rateLimitHits  = parseGrepLines(grepFiles('rate.?limit|rateLimit|rateLimiter|slowDown'));

if (authRouteHits.length > 0 && rateLimitHits.length === 0) {
  addFinding('HIGH','Brute Force Exposure',null,null,
    'No rate limiting detected on authentication endpoints',
    'Auth endpoints exist but no rate-limiting middleware was found. Attackers can make unlimited login attempts.',
    null, 'Add express-rate-limit:\nconst limiter = rateLimit({ windowMs: 15*60*1000, max: 20 });\nrouter.post("/login", limiter, loginHandler);');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 5 — HTTP Security Headers
// ═══════════════════════════════════════════════════════════════════════════════

const helmetHits = parseGrepLines(grepFiles('helmet|Content-Security-Policy|X-Frame-Options|HSTS|Strict-Transport'));
if (helmetHits.length === 0) {
  addFinding('MEDIUM','Missing Security Headers',null,null,
    'No HTTP security headers middleware detected',
    'Security headers (CSP, HSTS, X-Frame-Options, etc.) are absent.',
    null, 'npm install helmet\napp.use(require("helmet")());');
}

// Helmet present but explicitly disabling HSTS
parseGrepLines(grepFiles('hsts\\s*:\\s*false', ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Misconfigured HSTS',file,line,
      'HSTS explicitly disabled in helmet configuration',
      'Disabling HSTS allows browsers to connect over plain HTTP, exposing sessions to network interception.',
      code, 'Remove hsts: false. Set a long maxAge:\nhelmet({ hsts: { maxAge: 31536000, includeSubDomains: true } })');
  });

// CSP unsafe-inline or unsafe-eval in helmet/manual CSP config
parseGrepLines(grepFiles("'unsafe-inline'|'unsafe-eval'", ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Insecure Content Security Policy',file,line,
      "CSP directive contains 'unsafe-inline' or 'unsafe-eval'",
      "'unsafe-inline' allows inline <script> blocks — negating XSS protection. 'unsafe-eval' allows eval()-based attacks. Both are exploitable even with a CSP header present.",
      code, "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts:\nhelmet.contentSecurityPolicy({ directives: { scriptSrc: [\"'self'\", \"'nonce-<random>'\" ] } })");
  });

// X-Powered-By still enabled (no helmet and no explicit disable)
const xpbDisabled = parseGrepLines(grepFiles("disable\\s*\\(\\s*['\"]x-powered-by['\"]")).length > 0;
if (helmetHits.length === 0 && !xpbDisabled) {
  addFinding('LOW','Information Disclosure — X-Powered-By',null,null,
    'X-Powered-By: Express header not suppressed',
    'Advertising the framework version aids fingerprinting and targeted exploit selection.',
    null, 'app.disable("x-powered-by");  // or use helmet(), which disables it automatically');
}

// CORS: credentials:true + wildcard origin (the dangerous combo)
parseGrepLines(grepFiles('credentials\\s*:\\s*true', ['js','ts','mjs']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 6, 5);
    if (/Access-Control-Allow-Origin.*\*|origin\s*:\s*['"`]\*['"`]|allowedOrigins.*\*/i.test(ctx)) {
      addFinding('HIGH','Insecure CORS',file,line,
        'CORS credentials:true combined with wildcard origin',
        'This combination allows any origin to make credentialed cross-site requests, leaking cookies and auth headers.',
        code, "Never combine wildcard with credentials:\ncors({ origin: 'https://yourdomain.com', credentials: true })");
    }
  });

// CORS origin callback always returns true
parseGrepLines(grepFiles('origin\\s*:\\s*\\(.*\\)\\s*=>\\s*(cb\\(null,\\s*true\\)|true)', ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Insecure CORS — Always-Allow Origin',file,line,
      'CORS origin callback unconditionally returns true',
      'A function origin that always calls cb(null, true) is functionally equivalent to origin:"*" but bypasses the wildcard grep — every origin is allowed.',
      code, 'Validate the origin against an explicit allowlist:\nconst allowed = new Set(["https://app.example.com"]);\norigin: (origin, cb) => cb(null, allowed.has(origin))');
  });

// Standalone wildcard CORS
parseGrepLines(grepFiles("Access-Control-Allow-Origin.*\\*"))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Insecure CORS',file,line,
      'Wildcard CORS origin — verify no credentials are combined',
      'Access-Control-Allow-Origin: * allows any site to read responses.',
      code, "res.setHeader('Access-Control-Allow-Origin', 'https://yourdomain.com')");
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 6 — Sensitive Files
// ═══════════════════════════════════════════════════════════════════════════════

findFiles('.env')
  .filter(f => !f.includes('.env.example') && !f.includes('.env.sample'))
  .forEach(f => {
    const content = readFile(f);
    const hasReal = /[A-Z_]+=.{6,}/.test(content) && !/^#/.test(content.split('\n').find(l => l.includes('=')) || '');
    addFinding(hasReal ? 'CRITICAL' : 'HIGH','Sensitive File Exposure',f,null,
      '.env file present in repository',
      '.env files must never be committed to source control.',
      null, 'git rm --cached .env && echo ".env" >> .gitignore');
  });

[...findFiles('*.pem'),...findFiles('*.key'),...findFiles('id_rsa'),...findFiles('id_ed25519')]
  .forEach(f => addFinding('CRITICAL','Sensitive File Exposure',f,null,
    'Private key file found in repository', 'Private key files must never be in source control.',
    null, 'git rm --cached <file>. Add to .gitignore. Rotate the key.'));

// Exposed .git directory in public/static folder
['public','static','dist','build','www'].forEach(dir => {
  const gitDir = path.join(root, dir, '.git');
  if (fileExists(gitDir)) {
    addFinding('CRITICAL','Sensitive File Exposure', path.join(dir,'.git'), null,
      '.git directory inside publicly served folder',
      'If this directory is served by express.static or a web server, the entire source history is downloadable.',
      null, `Remove .git from ${dir}/. Add to .gitignore and rebuild the static output.`);
  }
});

// Source maps in served static directories
['public','static','dist','build','www'].forEach(dir => {
  const mapFiles = findFiles('*.js.map').filter(f => f.includes(`/${dir}/`));
  if (mapFiles.length > 0) {
    addFinding('LOW','Information Disclosure — Source Maps',mapFiles[0],null,
      `Source map files found in served directory (${dir}/)`,
      '.js.map files expose original source code (including comments, variable names, internal structure) to anyone who downloads them.',
      null, 'Delete *.map files from the deployed output, or configure the bundler to omit them in production builds.');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 7 — Path Traversal (Read AND Write)
// ═══════════════════════════════════════════════════════════════════════════════

// Read operations
parseGrepLines(grepFiles('(readFile|readFileSync|sendFile|createReadStream)\\s*\\([^)]*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Path Traversal — Read',file,line,
      'User input in file-read call',
      'Unvalidated user input in file paths allows reading arbitrary files (../../../etc/passwd).',
      code, 'const safePath = path.resolve(UPLOAD_DIR, path.basename(req.params.file));\nif (!safePath.startsWith(UPLOAD_DIR)) return res.status(403).end();');
  });

// Write operations — often overlooked
parseGrepLines(grepFiles(
  '(writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync|unlink|unlinkSync|mkdir|mkdirSync)\\s*\\([^)]*req\\.',
  ['js','ts']
)).forEach(({ file, line, code }) => {
  addFinding('HIGH','Path Traversal — Write',file,line,
    'User input in file-write / file-system mutation call',
    'write/append/rename/unlink with user-controlled paths allows overwriting arbitrary server files, creating webshells, or deleting critical data.',
    code,
    'Validate and resolve the path before any write:\nconst dest = path.resolve(UPLOAD_DIR, path.basename(req.body.filename));\nif (!dest.startsWith(path.resolve(UPLOAD_DIR))) return res.status(400).end();\nfs.writeFile(dest, data);');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 8 — eval / vm / dangerous code execution
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\beval\\s*\\('))
  .forEach(({ file, line, code }) => {
    if (/\/\//i.test(code)) return;
    addFinding('HIGH','Dangerous Code Execution',file,line,
      'eval() usage detected',
      'eval() executes arbitrary code. Any user input reaching it is RCE.',
      code, 'Remove eval(). Use JSON.parse() for data, restructure to avoid dynamic code execution.');
  });

// vm module — commonly misused as "safe eval"
parseGrepLines(grepFiles('vm\\.(run|Script|compile|createContext)', ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Sandbox Escape — vm Module',file,line,
      'Node.js vm module used — sandbox escapes are trivial',
      'vm.runInNewContext / vm.runInThisContext / vm.Script are NOT sandboxes. A single line like `this.constructor.constructor("return process")()` escapes the context and provides full Node.js access. Never use vm as a security boundary.',
      code,
      'Do not rely on vm for isolation. For untrusted code execution use:\n- A separate child_process with restricted permissions\n- A dedicated sandboxing runtime (Deno, isolated-vm, vm2 successor)\n- Firecracker/gVisor for complete isolation');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 9 — Sensitive Data Logging
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  '(console\\.(log|info|warn|error)|logger\\.(info|debug|log))\\s*\\([^)]*\\b(password|token|secret|apikey|auth)'
)).forEach(({ file, line, code }) => {
  addFinding('MEDIUM','Sensitive Data in Logs',file,line,
    'Sensitive data logged to console/logger', 'Passwords/tokens in logs leak to log aggregators and CI output.',
    code, 'Remove sensitive fields from log statements. Use a logger that masks sensitive keys.');
});

// morgan logging in production
parseGrepLines(grepFiles("morgan\\s*\\(\\s*['\"]", ['js','ts']))
  .forEach(({ file, line, code }) => {
    if (/combined|dev|common/i.test(code)) {
      addFinding('LOW','Sensitive Data in Logs — morgan',file,line,
        'morgan request logger may be active in production',
        'morgan("combined") and morgan("dev") log full request URLs, which may contain tokens or passwords in query strings. In production this streams to stdout/log files.',
        code,
        'Guard with NODE_ENV or use a minimal format:\nif (process.env.NODE_ENV !== "production") app.use(morgan("dev"));\n// In production use a structured logger that redacts sensitive fields.');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 10 — Mass Assignment
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\.(create|update|insert)\\s*\\(\\s*req\\.body'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Mass Assignment',file,line,
      'req.body passed directly to database model',
      'Unfiltered req.body lets attackers set privileged fields (isAdmin, role, balance).',
      code, 'Destructure only allowed fields:\nconst { name, email } = req.body;\nUser.create({ name, email });');
  });

// Mongoose strict:false
parseGrepLines(grepFiles('strict\\s*:\\s*false', ['js','ts']))
  .forEach(({ file, line, code }) => {
    // Only flag if near a schema definition
    const ctx = readContext(file, line, 10, 10);
    if (/Schema|model\s*\(/i.test(ctx)) {
      addFinding('HIGH','Mass Assignment — Mongoose strict:false',file,line,
        'Mongoose model defined with strict: false',
        'strict:false causes Mongoose to write every field from req.body to the database, completely bypassing field-level filtering even when you destructure req.body.',
        code, 'Remove strict: false. Use the default strict:true and explicitly define every allowed field in the schema.');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 11 — Command Injection
// ═══════════════════════════════════════════════════════════════════════════════

// Direct req.* in exec call
parseGrepLines(grepFiles('(exec|execSync|execFile|spawn|spawnSync)\\s*\\([^)]*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Command Injection',file,line,
      'User input passed directly to child_process method',
      'Passing user-controlled input to exec/spawn allows arbitrary OS command execution.',
      code, 'Never pass user input to shell commands. Use a whitelist or parameterized alternatives.\nUse spawn with an argument array and shell: false (default).');
  });

// shell: true (broad — catches indirect variable usage)
parseGrepLines(grepFiles('shell\\s*:\\s*true'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Command Injection — shell:true',file,line,
      'shell:true in child_process call — indirect injection risk',
      'shell:true enables shell interpretation. Even with an argument array, a variable derived from user input anywhere in the call chain becomes exploitable. Requires manual data-flow review.',
      code, 'Remove shell:true. Use spawn with an argument array and shell:false.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 12 — Prototype Pollution
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\b(merge|extend|deepmerge|deepClone|_.merge)\\s*\\([^)]*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Prototype Pollution',file,line,
      'Deep merge with user-controlled input',
      'Sending {"__proto__":{"isAdmin":true}} pollutes Object.prototype and bypasses auth checks.',
      code, 'Use Object.assign(Object.create(null), safeFields). Strip __proto__ keys with express-mongo-sanitize.');
  });

parseGrepLines(grepFiles('req\\.(body|query|params)\\[.*\\]\\['))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Prototype Pollution — Dynamic Key',file,line,
      'Nested dynamic bracket access with user-controlled keys',
      'obj[req.body.key][req.body.sub] = value can write to __proto__.',
      code, 'Validate keys are not "__proto__", "constructor", or "prototype" before use.');
  });

parseGrepLines(grepFiles(
  'Object\\.keys\\s*\\(\\s*req\\.(body|query|params)\\s*\\)|for\\s*\\(.*in\\s+req\\.(body|query|params)'
)).forEach(({ file, line, code }) => {
  addFinding('MEDIUM','Prototype Pollution — Unsafe Iteration',file,line,
    'Object.keys() / for...in on req.body exposes polluted keys to downstream logic',
    'Iterating user-supplied objects exposes any injected prototype keys to allowlist checks, schema builders, or assignment logic.',
    code, 'Use an explicit allowlist:\nconst safe = Object.fromEntries(\n  Object.entries(req.body).filter(([k]) => ALLOWED.includes(k))\n);');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 13 — Broken Access Control / IDOR
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('findById\\s*\\(\\s*req\\.(params|body|query)\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Broken Access Control (IDOR)',file,line,
      'Record fetched by user-supplied ID without visible ownership check',
      'findById(req.params.id) without verifying ownership lets any authenticated user access any record.',
      code, 'const doc = await Model.findOne({ _id: req.params.id, userId: req.user.id });\nif (!doc) return res.status(404).end();');
  });

parseGrepLines(grepFiles('findOne\\s*\\(\\s*\\{[^}]*_id\\s*:\\s*req\\.'))
  .forEach(({ file, line, code }) => {
    if (/userId|ownerId|createdBy|req\.user/i.test(code)) return;
    addFinding('MEDIUM','Broken Access Control (IDOR)',file,line,
      'findOne by ID — verify ownership check exists nearby',
      'Querying by _id alone without a userId/ownerId may allow access to other users\' records.',
      code, 'Model.findOne({ _id: id, userId: req.user.id })');
  });

// Unprotected admin / debug routes
parseGrepLines(grepFiles(
  '(router|app)\\.(get|post|put|delete|use)\\s*\\(\\s*[\'"](\\/admin|\\/debug|\\/_debug|\\/graphiql|\\/metrics|\\/healthz|\\/__webpack)',
  ['js','ts']
)).forEach(({ file, line, code }) => {
  const ctx = readContext(file, line, 5, 15);
  if (!/auth|middleware|protect|guard|isAdmin|requireAdmin|checkRole|verifyToken/i.test(ctx)) {
    addFinding('HIGH','Unprotected Admin / Debug Route',file,line,
      'Sensitive route registered without visible auth middleware',
      'Admin, debug, metrics, and GraphiQL routes exposed without authentication give attackers full visibility or control.',
      code,
      'Apply auth middleware before the route handler:\nrouter.use("/admin", requireAuth, requireAdmin);\nIn production: also block /graphiql, /debug, and /metrics at the reverse-proxy level.');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 14 — Weak Cryptography
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles("createHash\\s*\\(\\s*['\"]md5['\"]|createHash\\s*\\(\\s*['\"]sha1['\"]"))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Weak Cryptography',file,line,
      'MD5 or SHA1 used — broken for password hashing',
      'MD5/SHA1 are cryptographically broken. Rainbow table attacks crack them in seconds.',
      code, 'Use bcrypt/argon2 for passwords. Use SHA-256+ for integrity checks.');
  });

parseGrepLines(grepFiles('Math\\.random\\s*\\(\\s*\\)'))
  .forEach(({ file, line, code }) => {
    if (!/token|secret|otp|session|password|reset|code|csrf|nonce/i.test(code)) return;
    addFinding('CRITICAL','Weak Cryptography',file,line,
      'Math.random() used for security-sensitive value',
      'Math.random() is not cryptographically secure. Attackers can predict generated tokens.',
      code, 'const token = require("crypto").randomBytes(32).toString("hex");');
  });

// crypto.createCipher (deprecated — uses MD5 key derivation, no IV)
parseGrepLines(grepFiles('crypto\\.createCipher\\b', ['js','ts']))
  .forEach(({ file, line, code }) => {
    if (/createCipheriv/.test(code)) return; // createCipheriv is fine
    addFinding('HIGH','Weak Cryptography — Deprecated Cipher',file,line,
      'crypto.createCipher() used — deprecated, uses weak MD5 key derivation',
      'createCipher() derives the key using a single MD5 pass with no salt and no IV, making ciphertext highly vulnerable to known-plaintext attacks. It was formally removed in newer Node.js versions.',
      code,
      'Replace with createCipheriv() and a random IV:\nconst iv  = crypto.randomBytes(16);\nconst key = crypto.scryptSync(passphrase, salt, 32);\nconst cipher = crypto.createCipheriv("aes-256-gcm", key, iv);');
  });

// No bcrypt when passwords handled
const pwHandlingHits = parseGrepLines(grepFiles('(password|passwd).*=.*req\\.(body|params)'));
const bcryptHits     = parseGrepLines(grepFiles('bcrypt|argon2|scrypt', ['js','ts','json']));
if (pwHandlingHits.length > 0 && bcryptHits.length === 0) {
  addFinding('CRITICAL','Weak Cryptography',null,null,
    'No bcrypt/argon2 detected — passwords may be stored insecurely',
    'Password handling found but no strong hashing library is used.',
    null, 'npm install bcrypt\nconst hash = await bcrypt.hash(req.body.password, 12);');
}

// Weak bcrypt cost factor
parseGrepLines(grepFiles('bcrypt\\.hash(Sync)?\\s*\\([^,]+,\\s*[1-9]\\s*\\)'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Weak Cryptography',file,line,
      'bcrypt cost factor below 10 — GPU-crackable',
      'Cost factor < 10 completes in microseconds on modern GPUs.',
      code, 'Use at least 12: bcrypt.hash(password, 12)');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 15 — Insecure JWT
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('jwt\\.decode\\s*\\('))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Insecure JWT',file,line,
      'jwt.decode() does NOT verify the signature',
      'jwt.decode() base64-decodes without cryptographic verification. Any forged token is accepted.',
      code, 'Use jwt.verify(token, secret, { algorithms: ["HS256"] })');
  });

parseGrepLines(grepFiles("algorithm[s]?.*['\"]none['\"]"))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Insecure JWT',file,line,
      'JWT "none" algorithm accepted', 'Unsigned tokens mean any payload can be forged.',
      code, 'jwt.verify(token, secret, { algorithms: ["HS256"] })');
  });

parseGrepLines(grepFiles('jwt\\.sign\\s*\\('))
  .forEach(({ file, line, code }) => {
    if (!/expiresIn/i.test(code)) {
      addFinding('MEDIUM','Insecure JWT',file,line,
        'JWT signed without expiresIn', 'Tokens without expiry are valid forever.',
        code, 'jwt.sign(payload, secret, { expiresIn: "15m", algorithms: ["HS256"] })');
    }
    // Weak/short hardcoded secret
    const secretMatch = code.match(/jwt\.sign\s*\([^,]+,\s*['"`]([^'"`]{1,20})['"`]/);
    if (secretMatch) {
      addFinding('CRITICAL','Insecure JWT — Weak Secret',file,line,
        'JWT signed with a short hardcoded secret',
        `The secret "${secretMatch[1]}" is too short/predictable. JWT secrets can be brute-forced offline from any captured token.`,
        code, 'Use a long random secret from env:\nconst secret = process.env.JWT_SECRET; // min 32 random bytes\nVerify it exists at startup and throw if missing.');
    }
  });

// jwt.verify without algorithms whitelist
parseGrepLines(grepFiles('jwt\\.verify\\s*\\(', ['js','ts']))
  .forEach(({ file, line, code }) => {
    if (!/algorithms/i.test(code)) {
      addFinding('MEDIUM','Insecure JWT — Missing Algorithm Whitelist',file,line,
        'jwt.verify() called without algorithms option',
        'Without an explicit algorithms whitelist, some library versions accept the "none" algorithm or RS256 public keys used as HS256 secrets.',
        code, 'Always specify: jwt.verify(token, secret, { algorithms: ["HS256"] })');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 16 — SSRF
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('(axios|fetch|got|request|http\\.get|https\\.get|node-fetch)\\s*\\([^)]*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','SSRF',file,line,
      'HTTP client called with user-controlled URL',
      'Attackers can target internal services (http://169.254.169.254 for cloud metadata).',
      code, 'Validate URL against an allowlist:\nconst allowed = ["https://api.example.com"];\nif (!allowed.some(a => url.startsWith(a))) return res.status(400).end();');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 17 — Uncapped Payloads / DoS
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('express\\.(json|urlencoded)\\s*\\('))
  .forEach(({ file, line, code }) => {
    if (!/limit/i.test(code)) {
      addFinding('MEDIUM','DoS — Uncapped Payload',file,line,
        'express.json() or urlencoded() without size limit',
        'Attackers can send multi-gigabyte payloads to exhaust server memory.',
        code, 'app.use(express.json({ limit: "100kb" }));');
    }
  });

// multer without file count limit
parseGrepLines(grepFiles('multer\\s*\\(', ['js','ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 2, 15);
    if (!/limits/i.test(ctx)) {
      addFinding('MEDIUM','DoS — Uncapped File Upload',file,line,
        'multer configured without limits (fileSize, files)',
        'Without limits an attacker can upload thousands of large files in a single request, exhausting disk and memory.',
        code,
        'const upload = multer({ storage, limits: { fileSize: 5*1024*1024, files: 5 } });');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 18 — ReDoS
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('new RegExp\\s*\\(\\s*req\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','ReDoS',file,line,
      'User-controlled regular expression',
      'User-supplied regex enables catastrophic backtracking, blocking the Node.js event loop.',
      code, 'Never use user input as a regex. Escape if needed:\nconst safe = input.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 19 — Insecure Cookies / Sessions
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('res\\.cookie\\s*\\('))
  .forEach(({ file, line, code }) => {
    const missing = [
      !/httpOnly\s*:\s*true/i.test(code) && 'httpOnly: true',
      !/secure\s*:\s*true/i.test(code)   && 'secure: true',
      !/sameSite/i.test(code)            && 'sameSite: "strict"',
    ].filter(Boolean);
    if (missing.length) {
      addFinding('MEDIUM','Insecure Cookie',file,line,
        `Cookie missing: ${missing.join(', ')}`,
        'Missing flags expose session tokens to XSS theft, HTTP interception, and CSRF.',
        code, `res.cookie("session", token, { httpOnly:true, secure:true, sameSite:"strict", maxAge:3600000 });`);
    }
  });

// express-session configuration issues
parseGrepLines(grepFiles('session\\s*\\(\\s*\\{', ['js','ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 0, 20);
    const issues = [];
    // Weak / hardcoded secret
    const secretM = ctx.match(/secret\s*:\s*['"`]([^'"`]{0,24})['"`]/);
    if (secretM) issues.push(`hardcoded session secret "${secretM[1]}" (min 32 random bytes required)`);
    // MemoryStore in production (default store)
    if (!/store\s*:/i.test(ctx)) issues.push('no persistent session store configured — MemoryStore leaks memory and loses sessions on restart');
    // resave / saveUninitialized
    if (!/resave\s*:\s*false/i.test(ctx)) issues.push('resave not set to false');
    if (!/saveUninitialized\s*:\s*false/i.test(ctx)) issues.push('saveUninitialized not set to false');

    if (issues.length) {
      addFinding('HIGH','Insecure Session Configuration',file,line,
        'express-session misconfiguration: ' + issues.join('; '),
        'A weak session secret allows forging session cookies. MemoryStore is unsuitable for production. Incorrect resave/saveUninitialized settings cause race conditions and unnecessary session creation.',
        code,
        'session({\n  secret: process.env.SESSION_SECRET, // long random string from env\n  resave: false,\n  saveUninitialized: false,\n  store: new RedisStore({ client }),\n  cookie: { httpOnly:true, secure:true, sameSite:"strict" }\n})');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 20 — Leaky Error Handling
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('res\\.(json|send|status)\\s*\\([^)]*err\\.(message|stack)'))
  .forEach(({ file, line, code }) => {
    addFinding('LOW','Leaky Error Handling',file,line,
      'Raw error details returned to client',
      'err.message or err.stack leaks implementation details.',
      code, 'const msg = process.env.NODE_ENV==="production" ? "Internal server error" : err.message;\nres.status(500).json({ error: msg });');
  });

// NODE_ENV not set to production check (look for NODE_ENV=development in .env or missing)
findFiles('.env').forEach(f => {
  const content = readFile(f);
  if (/NODE_ENV\s*=\s*development/i.test(content)) {
    addFinding('MEDIUM','Development Mode in Production Config',f,null,
      'NODE_ENV=development found in .env file',
      'Express and many libraries expose stack traces, enable verbose logging, and disable security features when NODE_ENV is not "production".',
      null, 'Set NODE_ENV=production in your production environment. Never commit .env with development settings.');
  }
  if (!/NODE_ENV/i.test(content)) {
    addFinding('LOW','NODE_ENV Not Configured',f,null,
      'NODE_ENV not set in .env',
      'Without NODE_ENV=production, Express defaults to development mode — enabling stack traces in error responses and disabling caching.',
      null, 'Add NODE_ENV=production to your production .env or deployment environment.');
  }
});

// Unhandled promise rejection handler missing
const hasUnhandledRejection = parseGrepLines(grepFiles("unhandledRejection", ['js','ts'])).length > 0;
const hasAsyncErrorPkg      = parseGrepLines(grepFiles("express-async-errors|express-async-handler", ['js','ts','json'])).length > 0;
if (!hasUnhandledRejection && !hasAsyncErrorPkg) {
  addFinding('MEDIUM','Unhandled Promise Rejections',null,null,
    'No unhandledRejection handler and no express-async-errors detected',
    'In Express 4, async route handlers that throw do not trigger the error middleware — the error silently disappears or crashes the process. Uncaught promise rejections can expose stack traces or leave requests hanging.',
    null,
    '// Option 1: install express-async-errors (patches Express automatically)\nnpm install express-async-errors\nrequire("express-async-errors"); // top of app.js\n\n// Option 2: wrap routes manually\nrouter.get("/", asyncHandler(async (req, res) => { ... }));\n\n// Option 3: global safety net\nprocess.on("unhandledRejection", (reason) => { logger.error(reason); process.exit(1); });');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 21 — XXE
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles("require\\s*\\(\\s*['\"]xml2js|fast-xml-parser|libxmljs|sax['\"]", ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('LOW','XXE',file,line,
      'XML parsing library detected — verify entity expansion is disabled',
      'XML parsers with entity expansion enabled can read local files or cause DoS.',
      code, '// fast-xml-parser: new XMLParser({ processEntities: false })\n// libxmljs: parseXml(str, { noent: false })');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 22 — Open Redirect
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('res\\.redirect\\s*\\(\\s*req\\.(query|body|params)\\.'))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Open Redirect',file,line,
      'User-controlled input in res.redirect()',
      'Unvalidated redirects enable phishing via trusted-looking URLs.',
      code, 'const allowed = ["/dashboard", "/profile"];\nif (!allowed.includes(req.query.url)) return res.redirect("/");\nres.redirect(req.query.url);');
  });

// returnTo / post-login redirect without allowlist validation
parseGrepLines(grepFiles('req\\.session\\.(returnTo|redirectTo|next)', ['js','ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 5, 15);
    if (/redirect\s*\(|res\.redirect/i.test(ctx) && !/startsWith\s*\(['"`]\/|allowlist|whitelist|allowed/i.test(ctx)) {
      addFinding('MEDIUM','Open Redirect — Post-Login returnTo',file,line,
        'Session returnTo / redirectTo used without apparent URL allowlist',
        'OAuth and session auth flows that redirect to req.session.returnTo without validating it is a relative path allow open redirect post-login.',
        code,
        '// Validate returnTo is a safe relative path before redirecting:\nconst to = req.session.returnTo || "/";\ndelete req.session.returnTo;\nif (!to.startsWith("/") || to.startsWith("//")) return res.redirect("/");\nres.redirect(to);');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 23 — Server-Side Template Injection
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  'res\\.render\\s*\\(\\s*req\\.(query|body|params)|res\\.render\\s*\\([^,]+,\\s*req\\.(query|body|params)'
)).forEach(({ file, line, code }) => {
  addFinding('HIGH','Server-Side Template Injection',file,line,
    'User input in template renderer call',
    'User-controlled template name → RCE. User-controlled context → prototype pollution.',
    code, 'Never use user input as a template name. Whitelist template names. Pass only specific safe fields.');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 24 — Timing Attacks
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('if\\s*\\(\\s*(signature|hash|hmac|token)\\s*[=!]=\\s*'))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Timing Attack Exposure',file,line,
      'Standard equality used to compare cryptographic value',
      '=== on signatures allows byte-by-byte timing attacks.',
      code, 'Use crypto.timingSafeEqual():\nconst a=Buffer.from(received), b=Buffer.from(expected);\nif(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.status(401).end();');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 25 — Missing CSRF Protection
// ═══════════════════════════════════════════════════════════════════════════════

const usesCookies = parseGrepLines(grepFiles('res\\.cookie\\s*\\(')).length > 0;
const hasCsrf     = parseGrepLines(grepFiles('csurf|csrf-csrf|double-csrf|doubleCsrf', ['js','ts','json'])).length > 0;
if (usesCookies && !hasCsrf) {
  addFinding('HIGH','Missing CSRF Protection',null,null,
    'Cookie-based sessions detected with no CSRF middleware',
    'Any malicious site can make authenticated requests by tricking the browser into sending cookies.',
    null, 'npm install csrf-csrf\nconst { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET });\napp.use(doubleCsrfProtection);');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 26 — OAuth State Parameter
// ═══════════════════════════════════════════════════════════════════════════════

const oauthHits = parseGrepLines(grepFiles(
  'passport-google-oauth|passport-github|passport-facebook|passport-oauth|passport-twitter|passport-linkedin',
  ['js','ts','json']
));
if (oauthHits.length > 0) {
  const stateHits = parseGrepLines(grepFiles('state\\s*:|callbackURL|state\\s*=', ['js','ts']));
  const stateVerified = parseGrepLines(grepFiles('req\\.query\\.state|state.*verify|verif.*state', ['js','ts'])).length > 0;
  if (!stateVerified) {
    addFinding('HIGH','OAuth — Missing state Parameter Validation',null,null,
      'OAuth/Passport strategy detected but state parameter validation not found',
      'The OAuth state parameter prevents CSRF on the callback endpoint. Without validating it, an attacker can force a victim to link their account to the attacker\'s identity (CSRF on login = account takeover).',
      null,
      '// Passport handles state automatically when state:true is set:\npassport.use(new GoogleStrategy({\n  clientID: process.env.GOOGLE_CLIENT_ID,\n  clientSecret: process.env.GOOGLE_CLIENT_SECRET,\n  callbackURL: process.env.GOOGLE_CALLBACK_URL,\n  state: true,  // ← enables CSRF protection\n}, callback));\n// Also validate state manually on the callback route for custom OAuth flows.');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 27 — WebSocket / SSE Authentication
// ═══════════════════════════════════════════════════════════════════════════════

const wsHits = parseGrepLines(grepFiles("require\\s*\\(\\s*['\"]ws['\"]|require\\s*\\(\\s*['\"]socket\\.io['\"]", ['js','ts','json']));
if (wsHits.length > 0) {
  const wsConnHits  = parseGrepLines(grepFiles("io\\.on\\s*\\(\\s*['\"]connection|wss?\\.on\\s*\\(\\s*['\"]connection", ['js','ts']));
  const wsAuthHits  = parseGrepLines(grepFiles('socket\\.handshake|socket\\.request|verifyClient|authenticate|isAuthenticated', ['js','ts']));
  if (wsConnHits.length > 0 && wsAuthHits.length === 0) {
    addFinding('HIGH','WebSocket — Missing Authentication',null,null,
      'WebSocket/Socket.io connection handler found with no visible authentication',
      'HTTP upgrade happens before Express middleware runs. A socket.io or ws server that does not explicitly validate auth tokens in the handshake or on connection accepts connections from any unauthenticated client.',
      null,
      '// Socket.io: authenticate in middleware before connection\nio.use((socket, next) => {\n  const token = socket.handshake.auth.token;\n  try { socket.user = jwt.verify(token, process.env.JWT_SECRET); next(); }\n  catch { next(new Error("Unauthorized")); }\n});\n\n// ws: use verifyClient in the WebSocket.Server options\nconst wss = new WebSocket.Server({\n  verifyClient: ({ req }, cb) => {\n    const token = parseTokenFromRequest(req);\n    try { req.user = jwt.verify(token, SECRET); cb(true); }\n    catch { cb(false, 401, "Unauthorized"); }\n  }\n});');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 28 — Insecure File Upload
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\.mv\\s*\\(\\s*[^,]*req\\.(files|body)'))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH','Insecure File Upload — Path',file,line,
      'File saved using user-controlled name or path',
      'Using req.files.name directly in .mv() allows path traversal or file overwrite.',
      code, 'Generate a safe UUID filename:\nconst ext = path.extname(req.files.upload.name).toLowerCase();\nif (!allowedExts.includes(ext)) return res.status(400).end();\nreq.files.upload.mv(path.join(UPLOAD_DIR, uuidv4() + ext));');
  });

// MIME-type spoofing
parseGrepLines(grepFiles('multer|diskStorage|memoryStorage', ['js','ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 10, 20);
    if (!/fileFilter|mimetype|mimeType|file\.mimetype/i.test(ctx)) {
      addFinding('MEDIUM','Insecure File Upload — MIME Spoofing',file,line,
        'File upload handler with no MIME-type / fileFilter validation',
        'Without checking file.mimetype an attacker can upload .html disguised as an image, enabling stored XSS.',
        code,
        "fileFilter: (req, file, cb) => {\n  const allowed = ['image/jpeg','image/png','application/pdf'];\n  cb(allowed.includes(file.mimetype) ? null : new Error('Invalid type'), allowed.includes(file.mimetype));\n}\n// Also verify magic bytes with the 'file-type' npm package.");
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 29 — SSJI
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\b(setTimeout|setInterval|Function)\\s*\\(\\s*req\\.(body|query|params)'))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL','Server-Side JavaScript Injection',file,line,
      'User input passed to code-evaluating function',
      'setTimeout/setInterval with a string arg and new Function() are eval() variants — full RCE.',
      code, 'Never pass strings to setTimeout/setInterval. Never use new Function().');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 30 — Insecure Deserialization
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\b(unserialize|deserialize|yaml\\.load)\\s*\\('))
  .forEach(({ file, line, code }) => {
    if (/safeLoad/i.test(code)) return;
    addFinding('HIGH','Insecure Deserialization',file,line,
      'Potentially unsafe deserialization',
      'node-serialize unserialize() and yaml.load() can instantiate arbitrary objects → RCE.',
      code, 'Use JSON.parse(). For YAML use yaml.safeLoad() or FAILSAFE_SCHEMA. Avoid node-serialize.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 31 — Host Header Injection
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('req\\.(headers\\.host|get\\s*\\([\'""]host[\'""]\\))'))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Host Header Injection',file,line,
      'Host header used to construct URLs',
      'The Host header is attacker-controlled. Building password reset links or OAuth callbacks from it leaks tokens to attacker-controlled servers.',
      code, 'Hardcode: const resetLink = `${process.env.BASE_URL}/reset?token=${token}`;');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 32 — Zip Slip
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('[\'"](adm-zip|tar|extract-zip|unzipper|jszip)[\'"]'))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM','Potential Zip Slip',file,line,
      'Archive extraction library detected — verify path sanitization',
      'Crafted archives with ../../ paths overwrite arbitrary server files.',
      code, 'const dest=path.resolve(EXTRACT_DIR,entry.path);\nif(!dest.startsWith(path.resolve(EXTRACT_DIR))) throw new Error("Zip Slip blocked");');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 33 — Dependency Confusion / Supply Chain
// ═══════════════════════════════════════════════════════════════════════════════

const packageJsonPath = path.join(root, 'package.json');
if (fileExists(packageJsonPath)) {
  try {
    const pkg     = JSON.parse(readFile(packageJsonPath));
    const allDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies });
    const scoped  = allDeps.filter(d => d.startsWith('@'));
    const npmrcContent     = readFile(path.join(root, '.npmrc'));
    const hasPrivateReg    = /registry\s*=/.test(npmrcContent) && !/registry\.npmjs\.org/.test(npmrcContent);
    if (scoped.length > 0 && !hasPrivateReg) {
      addFinding('HIGH','Supply Chain / Dependency Confusion',packageJsonPath,null,
        'Scoped packages found with no private registry in .npmrc',
        `Packages (${scoped.slice(0,5).join(', ')}${scoped.length>5?'…':''}) may be internal. Without a private registry, npm resolves them publicly — an attacker can hijack builds.`,
        null, '@your-scope:registry=https://your-registry.example.com in .npmrc\nalways-auth=true');
    }

    // Dangerous lifecycle scripts
    const scripts = pkg.scripts || {};
    ['preinstall','postinstall','prepare','prepack'].forEach(hook => {
      if (scripts[hook]) {
        addFinding('MEDIUM','Supply Chain — Dangerous Lifecycle Script',packageJsonPath,null,
          `package.json defines a ${hook} script that runs on npm install`,
          `"${hook}": "${scripts[hook]}"\nLifecycle scripts execute automatically during npm install. A dependency confusion or compromised transitive dep that runs this script on a CI machine achieves RCE on the build server.`,
          scripts[hook],
          'Review whether this lifecycle script is necessary. If so, audit it carefully and ensure it does not accept environment-derived or network-derived input without validation. Consider using --ignore-scripts in CI: npm ci --ignore-scripts');
      }
    });
  } catch { /* malformed package.json */ }

  // Lockfile check
  const hasLock = fileExists(path.join(root,'package-lock.json')) || fileExists(path.join(root,'yarn.lock')) || fileExists(path.join(root,'pnpm-lock.yaml'));
  if (!hasLock) {
    addFinding('LOW','Missing Lockfile',packageJsonPath,null,
      'No package-lock.json / yarn.lock / pnpm-lock.yaml found',
      'Without a lockfile, npm install resolves the latest semver-compatible version of every dep — a newly published malicious patch version enters the build silently.',
      null, 'Commit your lockfile:\nnpm install  # generates package-lock.json\ngit add package-lock.json');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 34 — HTTP Parameter Pollution
// ═══════════════════════════════════════════════════════════════════════════════

const hasHpp       = parseGrepLines(grepFiles('hpp|http-parameter-pollution', ['js','ts','json'])).length > 0;
const queryUseHits = parseGrepLines(grepFiles('req\\.query\\.', ['js','ts']));
if (!hasHpp && queryUseHits.length > 0) {
  addFinding('MEDIUM','HTTP Parameter Pollution (HPP)',null,null,
    'No HPP middleware — duplicate query params may bypass validation',
    'Express exposes ?id=1&id=2 as an array. String coercion gives "1,2", bypassing numeric validators and WAF rules.',
    null, 'npm install hpp\napp.use(hpp());');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 35 — Subdomain Takeover
// ═══════════════════════════════════════════════════════════════════════════════

const danglingSvc = [
  'azurewebsites\\.net','cloudapp\\.net','trafficmanager\\.net','blob\\.core\\.windows\\.net',
  's3\\.amazonaws\\.com','elasticbeanstalk\\.com','github\\.io','myshopify\\.com',
  'statuspage\\.io','readme\\.io','surge\\.sh','netlify\\.app','fly\\.dev',
  'vercel\\.app','onrender\\.com','pantheonsite\\.io','tumblr\\.com','ghost\\.io',
];
parseGrepLines(grepFiles(
  `(CNAME|cname|target|hostname|endpoint).*\\.(${danglingSvc.join('|')})`,
  ['js','ts','yaml','yml','json','env','sh','config','conf','tf']
)).forEach(({ file, line, code }) => {
  addFinding('MEDIUM','Subdomain Takeover Risk',file,line,
    'Possible dangling cloud CNAME reference',
    'A deprovisioned cloud resource pointed to by this CNAME can be claimed by an attacker to serve content under your subdomain.',
    code, 'Verify the CNAME target still exists and is yours. Delete DNS records for decommissioned services immediately.');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 36 — GraphQL Security
// ═══════════════════════════════════════════════════════════════════════════════

const usesGraphQL = parseGrepLines(grepFiles('graphql|apollo-server|apollo/server|nexus|type-graphql', ['js','ts','json'])).length > 0;
if (usesGraphQL) {
  const introspectionOn  = parseGrepLines(grepFiles('introspection\\s*:\\s*true', ['js','ts'])).length > 0;
  const introspectionOff = parseGrepLines(grepFiles('introspection\\s*:\\s*false', ['js','ts'])).length > 0;
  if (introspectionOn || !introspectionOff) {
    addFinding('HIGH','GraphQL — Introspection Enabled',null,null,
      'GraphQL introspection may be enabled in production',
      'Introspection exposes the entire schema — a complete roadmap for attackers.',
      null, 'introspection: process.env.NODE_ENV !== "production"');
  }
  if (parseGrepLines(grepFiles('depthLimit|queryDepth|complexityLimit|graphql-depth-limit|graphql-query-complexity', ['js','ts','json'])).length === 0) {
    addFinding('HIGH','GraphQL — No Depth/Complexity Limiting',null,null,
      'No GraphQL query depth or complexity limits detected',
      'Deeply nested / aliased queries cause O(n^depth) resolver calls — trivial DoS.',
      null, 'npm install graphql-depth-limit graphql-query-complexity\nvalidationRules: [depthLimit(10), createComplexityRule({ maximumComplexity: 1000 })]');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 37 — Missing Input Validation Layer
// ═══════════════════════════════════════════════════════════════════════════════

const hasValidator = parseGrepLines(grepFiles('express-validator|joi|yup|zod|ajv|celebrate|@hapi/joi', ['js','ts','json'])).length > 0;
const bodyUseHits  = parseGrepLines(grepFiles('req\\.body\\.', ['js','ts']));
if (!hasValidator && bodyUseHits.length > 0) {
  addFinding('MEDIUM','Missing Input Validation Layer',null,null,
    'No schema validation library detected (express-validator, Joi, Zod, AJV)',
    'Reading req.body without schema validation amplifies every injection and type-confusion risk.',
    null, 'npm install zod\nconst schema=z.object({ email:z.string().email() });\nconst result=schema.safeParse(req.body);\nif(!result.success) return res.status(400).json(result.error);');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 38 — express.static Serving Dangerous Paths
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('express\\.static\\s*\\(', ['js','ts']))
  .forEach(({ file, line, code }) => {
    // Flag if path arg is '.', __dirname bare, or process.cwd()
    if (/static\s*\(\s*['"`]\.['"`]|static\s*\(\s*__dirname\s*\)|static\s*\(\s*process\.cwd\s*\(\s*\)/.test(code)) {
      addFinding('HIGH','Dangerous express.static Root',file,line,
        'express.static() serving project root or cwd',
        'Serving ./ or __dirname exposes package.json, .env, source files, and node_modules over HTTP.',
        code, 'Serve only a specific public subdirectory:\napp.use(express.static(path.join(__dirname, "public")));');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 39 — Sensitive Data in URL Parameters
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\?(token|api_?key|apikey|auth|secret|password|passwd)=', ['js','ts','html']))
  .forEach(({ file, line, code }) => {
    addFinding('LOW','Sensitive Data in URL Parameters',file,line,
      'Possible sensitive value in URL query string',
      'Tokens/keys in URLs appear in server logs, browser history, and Referer headers sent to third-party resources.',
      code, 'Pass sensitive values in POST body or Authorization header, never in query strings.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 40 — Missing Subresource Integrity (SRI)
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('<script[^>]+src\\s*=\\s*[\'"]https?://', ['html','ejs','pug','hbs','njk']))
  .forEach(({ file, line, code }) => {
    if (!/integrity\s*=/i.test(code)) {
      addFinding('LOW','Missing Subresource Integrity (SRI)',file,line,
        'External script tag without integrity= attribute',
        'If the CDN is compromised, any script without SRI can be replaced with malicious code that runs in your users\' browsers.',
        code, 'Add integrity and crossorigin:\n<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-<hash>"\n  crossorigin="anonymous"></script>\nGenerate hashes at: https://www.srihash.org/');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 41 — Hardcoded Internal IPs / Network Topology
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  '(10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})',
  ['js','ts','yaml','yml','json','env','sh','conf','config']
)).forEach(({ file, line, code }) => {
  addFinding('LOW','Hardcoded Internal IP Address',file,line,
    'Private IP address range hardcoded in config',
    'Hardcoded internal IPs disclose network topology, aiding SSRF pivot and lateral movement if source code leaks.',
    code, 'Move all internal service addresses to environment variables.');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 42 — Unsafe Numeric Conversion of User Input
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('parseInt\\s*\\(\\s*req\\.|Number\\s*\\(\\s*req\\.', ['js','ts']))
  .forEach(({ file, line, code }) => {
    // parseInt without radix
    if (/parseInt\s*\(\s*req\./.test(code) && !/parseInt\s*\([^,)]+,\s*10\s*\)/.test(code)) {
      addFinding('LOW','Unsafe Numeric Conversion',file,line,
        'parseInt() on user input without radix 10',
        'parseInt without radix can interpret "0x..." as hex and "010" as octal in older engines, producing unexpected values that bypass numeric equality checks.',
        code, 'Always specify radix: parseInt(req.params.id, 10)');
    }
    // Number() producing Infinity / NaN
    if (/Number\s*\(\s*req\./.test(code)) {
      addFinding('LOW','Unsafe Numeric Conversion',file,line,
        'Number() on user input — NaN / Infinity risk',
        'Number("1e308") === Infinity and Number("abc") === NaN. Either can bypass amount checks or comparisons that assume a finite number.',
        code, 'Use parseInt(x,10) with a bounds check or a schema validator (Zod: z.number().int().min(0)).');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 43 — DEBUG Env Variable Left Enabled
// ═══════════════════════════════════════════════════════════════════════════════

findFiles('.env').forEach(f => {
  const content = readFile(f);
  if (/^\s*DEBUG\s*=\s*.+/m.test(content)) {
    addFinding('LOW','DEBUG Variable Enabled',f,null,
      'DEBUG= is set in .env',
      'Many frameworks (Express internals, mongoose, socket.io, passport) output detailed internal state when DEBUG=* is set — leaking query plans, session data, and route internals.',
      null, 'Ensure DEBUG is unset or DEBUG="" in production deployments. Do not commit DEBUG=* to .env files.');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 44 — app.listen binding
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('app\\.listen\\s*\\([^)]*0\\.0\\.0\\.0', ['js','ts']))
  .forEach(({ file, line, code }) => {
    addFinding('LOW','Server Binding to 0.0.0.0',file,line,
      'app.listen() binding to all interfaces (0.0.0.0)',
      'Binding to 0.0.0.0 exposes the raw Node.js server on all network interfaces. Behind a reverse proxy only 127.0.0.1 should be used.',
      code, 'app.listen(PORT, "127.0.0.1", ...);  // only loopback when behind nginx/caddy/etc.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 45 — Dynamic require() / Local File Inclusion
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\brequire\\s*\\([^)]*req\\.', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    // Skip false positives: require at top-level with no req.* (e.g. require('express'))
    if (!/req\.(body|params|query|headers)/i.test(code)) return;
    addFinding('CRITICAL', 'Local File Inclusion / RCE via dynamic require()', file, line,
      'User input passed to require() — arbitrary module load',
      'require(req.params.module) loads any file on the filesystem or any installed package. An attacker can load /proc/self/environ, execute arbitrary installed scripts, or chain with a file-write to achieve RCE.',
      code,
      'Never use user input in require(). Use a hardcoded allowlist:\nconst ALLOWED = { csv: "./exporters/csv", pdf: "./exporters/pdf" };\nconst mod = ALLOWED[req.query.format];\nif (!mod) return res.status(400).end();\nrequire(mod);');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 46 — Server-Side XSS via res.send / res.write string concatenation
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  'res\\.(send|write)\\s*\\(',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  // Flag if the same line contains string concat or template literal with req.*
  if (/req\.(body|params|query|headers)/i.test(code) &&
      (/\+/.test(code) || /`[^`]*\$\{/.test(code))) {
    addFinding('HIGH', 'Server-Side XSS — res.send() with user input', file, line,
      'User input concatenated into res.send() / res.write() response',
      'Building HTML strings by concatenating req.body/params/query produces reflected XSS. Unlike template-engine unescaped operators, this bypasses all template-layer protections entirely.',
      code,
      '// Never concatenate user input into HTML:\n// BAD:  res.send("<h1>Hello " + req.query.name + "</h1>")\n// GOOD: escape first, or use a template engine with auto-escaping:\nconst he = require("he");\nres.send("<h1>Hello " + he.encode(req.query.name) + "</h1>");\n// Or better: use res.render() with an auto-escaping template engine (EJS <%=, Pug =).');
  }
  // Also catch multi-line: res.send() on one line, but a template literal started on this line
  const ctx = readContext(file, line, 0, 4);
  if (/req\.(body|params|query|headers)/i.test(ctx) &&
      /res\.(send|write)\s*\(`/.test(ctx) &&
      !/he\.|escapeHtml|sanitize|encode\(/i.test(ctx)) {
    // avoid double-reporting same line
    if (!/req\.(body|params|query|headers)/i.test(code)) {
      addFinding('MEDIUM', 'Server-Side XSS — res.send() template literal', file, line,
        'res.send() with a template literal — verify user input is escaped',
        'Template literal in res.send() may interpolate user-controlled values without escaping, producing reflected XSS.',
        ctx.split('\n').slice(0, 5).join('\n'),
        'Escape all user values before interpolating into HTML:\nconst he = require("he");\nres.send(`<p>${he.encode(req.query.q)}</p>`);');
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 47 — Mass Assignment via Object.assign(target, req.body)
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('Object\\.assign\\s*\\([^,)]+,\\s*req\\.(body|params|query)', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH', 'Mass Assignment — Object.assign with req.body', file, line,
      'Object.assign() merges all req.body fields into target object',
      'Object.assign(user, req.body) then user.save() writes every attacker-supplied field, including isAdmin, role, balance. Very common in Mongoose update handlers.',
      code,
      'Explicitly pick only the fields you intend to update:\nconst { name, bio } = req.body;\nObject.assign(user, { name, bio });\nawait user.save();');
  });

// Spread operator mass assignment: { ...req.body }  inside create/update
parseGrepLines(grepFiles('\\.\\.\\.req\\.(body|params|query)', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH', 'Mass Assignment — Spread of req.body', file, line,
      'Spread operator on req.body passes all user-supplied fields to model or object',
      '{ ...req.body } inside Model.create(), Model.update(), or Object.assign() is equivalent to passing the whole body — any field including privileged ones is written.',
      code,
      'Destructure only the fields you need:\nconst { title, content } = req.body;\nawait Post.create({ title, content, authorId: req.user.id });');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 48 — SSRF via additional HTTP clients
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  '(superagent|undici|ky\\b|needle|urllib|phin|centra|cross-fetch|isomorphic-fetch|node-fetch)\\s*[\\.\\(]',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  const ctx = readContext(file, line, 3, 3);
  if (/req\.(body|params|query|headers)/i.test(ctx)) {
    addFinding('HIGH', 'SSRF — HTTP client with possible user-controlled URL', file, line,
      `HTTP client (${code.match(/(superagent|undici|ky|needle|urllib|phin|centra|cross-fetch|isomorphic-fetch|node-fetch)/)?.[0] || 'unknown'}) may use user-supplied URL`,
      'User-controlled URLs passed to any HTTP client allow SSRF — reaching internal cloud metadata endpoints, internal APIs, or scanning the internal network.',
      code,
      'Validate the URL against an explicit allowlist before making the request:\nconst { URL } = require("url");\nconst ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);\nconst parsed = new URL(userUrl);\nif (!ALLOWED_HOSTS.has(parsed.hostname)) return res.status(400).end();');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 49 — Sequelize / TypeORM where-clause injection
// ═══════════════════════════════════════════════════════════════════════════════

// sequelize.literal() with user input inside a where clause
parseGrepLines(grepFiles('sequelize\\.literal\\s*\\(', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 3, 3);
    if (/req\.(body|params|query|headers)|`[^`]*\$\{/.test(ctx)) {
      addFinding('CRITICAL', 'SQL Injection — sequelize.literal() with user input', file, line,
        'sequelize.literal() with user input bypasses Sequelize parameterization',
        'sequelize.literal() injects raw SQL directly into the query. Interpolating req.* values here is full SQL injection despite using the ORM.',
        code,
        '// Never interpolate user input into sequelize.literal().\n// Use proper replacements instead:\nModel.findAll({ where: { name: req.body.name } })\n// If raw SQL is unavoidable, use sequelize.query with replacements:\nsequelize.query("SELECT * FROM t WHERE name = ?", { replacements: [req.body.name] })');
    }
  });

// Model.findAll / findOne with req.body/query as the entire where object
parseGrepLines(grepFiles(
  '\\.(findAll|findOne|findAndCountAll|count|update|destroy)\\s*\\(\\s*\\{[^}]*where\\s*:\\s*req\\.',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  addFinding('HIGH', 'ORM Injection — req.* used as where clause', file, line,
    'Entire req.body / req.query passed as Sequelize/TypeORM where clause',
    'Passing req.body directly as a where clause lets attackers inject Sequelize operators ($gt, $like, $or) for auth bypass or data extraction, similar to MongoDB NoSQL injection.',
    code,
    'Explicitly extract and validate individual fields:\nconst { email } = req.body;\nUser.findOne({ where: { email, active: true } });');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 50 — Session Fixation
// ═══════════════════════════════════════════════════════════════════════════════

// Find login/auth success handlers that don't call session.regenerate
const loginSuccessHits = parseGrepLines(grepFiles(
  '(req\\.session\\.user|req\\.session\\.userId|req\\.session\\.authenticated|req\\.session\\.passport)',
  ['js', 'ts']
));
const sessionRegenerateHits = parseGrepLines(grepFiles('session\\.regenerate', ['js', 'ts']));

if (loginSuccessHits.length > 0 && sessionRegenerateHits.length === 0) {
  addFinding('HIGH', 'Session Fixation', null, null,
    'Session data set after login without session.regenerate()',
    'After successful authentication, the session ID must be rotated. Without req.session.regenerate(), an attacker who plants a known session ID (via XSS, network sniffing, or URL injection) before login takes ownership of the newly authenticated session.',
    null,
    'Regenerate the session ID immediately after verifying credentials:\nreq.session.regenerate((err) => {\n  if (err) return next(err);\n  req.session.userId = user.id;\n  req.session.save((err) => {\n    if (err) return next(err);\n    res.redirect("/dashboard");\n  });\n});');
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 51 — child_process.fork() with user input
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('\\bfork\\s*\\([^)]*req\\.', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('CRITICAL', 'Command Injection — child_process.fork() with user input', file, line,
      'User input passed to child_process.fork()',
      'fork() loads and executes an arbitrary Node.js module. With user input as the module path it is equivalent to dynamic require() + execution — full RCE.',
      code,
      'Never use user input as the module path in fork(). Use a hardcoded allowlist of permitted worker scripts.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 52 — AES-ECB mode
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles("createCipheriv\\s*\\(\\s*['\"]aes-[0-9]+-ecb['\"]", ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH', 'Weak Cipher Mode — AES-ECB', file, line,
      'AES in ECB mode — deterministic, leaks plaintext patterns',
      'ECB mode encrypts each 16-byte block independently with the same key. Identical plaintext blocks produce identical ciphertext blocks, leaking structure (the "penguin problem"). An attacker observing multiple ciphertexts can detect repeated values without knowing the key.',
      code,
      'Use AES-GCM (authenticated encryption) instead:\nconst iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv("aes-256-gcm", key, iv);\n// Store iv alongside the ciphertext; verify the auth tag on decryption.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 53 — Cookie flags checked in multi-line context
// (supplements CHECK 19 which only sees the single matched line)
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('res\\.cookie\\s*\\(', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    // Already reported flags missing on single line in CHECK 19.
    // Here: if single-line check found nothing missing, re-examine with context window
    // to catch multi-line cookie option objects.
    const singleLineMissingHttpOnly = !/httpOnly\s*:\s*true/i.test(code);
    const singleLineMissingSecure   = !/secure\s*:\s*true/i.test(code);
    const singleLineMissingSameSite = !/sameSite/i.test(code);

    // Only do context scan when at least one flag looked absent on the single line
    if (singleLineMissingHttpOnly || singleLineMissingSecure || singleLineMissingSameSite) {
      const ctx = readContext(file, line, 0, 8);
      const ctxHttpOnly  = /httpOnly\s*:\s*true/i.test(ctx);
      const ctxSecure    = /secure\s*:\s*true/i.test(ctx);
      const ctxSameSite  = /sameSite/i.test(ctx);

      const stillMissing = [
        !ctxHttpOnly  && 'httpOnly: true',
        !ctxSecure    && 'secure: true',
        !ctxSameSite  && 'sameSite: "strict"',
      ].filter(Boolean);

      // Only add a new finding when context scan reveals genuinely missing flags
      // that the single-line check also missed (avoid double-reporting)
      if (stillMissing.length &&
          stillMissing.length < [singleLineMissingHttpOnly, singleLineMissingSecure, singleLineMissingSameSite].filter(Boolean).length) {
        // Context rescued some flags — update with accurate missing list (info only, lower severity)
        addFinding('LOW', 'Insecure Cookie — multi-line config verification', file, line,
          `Cookie option object spans multiple lines — confirmed missing: ${stillMissing.join(', ')}`,
          'After reading the full option object across lines, these security flags are still absent.',
          ctx,
          `Ensure all three flags are set:\nres.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });`);
      }
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 54 — .gitignore does not protect .env
// ═══════════════════════════════════════════════════════════════════════════════

const gitignorePath    = path.join(root, '.gitignore');
const gitignoreContent = readFile(gitignorePath);
const envFilesPresent  = findFiles('.env').filter(f =>
  !f.includes('.env.example') && !f.includes('.env.sample')
).length > 0;

if (envFilesPresent || fileExists(path.join(root, '.env.example'))) {
  // Project uses .env pattern — verify .gitignore protects it
  if (!gitignoreContent) {
    addFinding('HIGH', 'Missing .gitignore', null, null,
      'No .gitignore file found in repository root',
      'Without .gitignore, any git add . will stage .env files, private keys, node_modules, and build artifacts. A single git push leaks all secrets.',
      null,
      'Create a .gitignore. At minimum include:\n.env\n.env.local\n.env.*.local\nnode_modules/\n*.pem\n*.key');
  } else if (!/(^|\n)\.env/.test(gitignoreContent)) {
    addFinding('HIGH', '.env not in .gitignore', gitignorePath, null,
      '.gitignore exists but does not include .env',
      'The project has an .env file pattern but .gitignore does not list .env. One accidental `git add .` exposes all secrets.',
      null,
      'Add to .gitignore:\n.env\n.env.local\n.env.*.local\n.env.production');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 55 — JSONP callback injection
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('req\\.(query|body)\\.(callback|jsonp|cb)\\b', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 0, 8);
    // Only flag if used in a response
    if (/res\.(send|write|json|end)|jsonp/i.test(ctx)) {
      addFinding('HIGH', 'JSONP Callback Injection', file, line,
        'User-controlled JSONP callback name reflected in response',
        'If the callback parameter is reflected into the response body without strict alphanumeric validation (e.g. `?callback=alert(1)//`), the browser executes it as JavaScript — reflected XSS even when Content-Type is application/json.',
        code,
        '// Validate callback to alphanumeric + underscore only:\nconst cb = req.query.callback;\nif (!/^[a-zA-Z_$][\\w$]*$/.test(cb)) return res.status(400).end();\nres.type("application/javascript");\nres.send(`${cb}(${JSON.stringify(data)});`);\n// Better: switch to CORS instead of JSONP entirely.');
    }
  });

// Also catch express jsonp() usage
parseGrepLines(grepFiles('res\\.jsonp\\s*\\(', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('MEDIUM', 'JSONP endpoint — verify callback validation', file, line,
      'res.jsonp() endpoint detected',
      'Express res.jsonp() automatically wraps the response in the callback parameter. The default callback name validation is permissive. JSONP is a legacy pattern that introduces XSS risk and should be replaced with CORS.',
      code,
      'Replace JSONP endpoints with CORS:\n// Remove res.jsonp() and use:\nres.json(data); // with proper CORS headers\n// Or configure Express callback name validation:\napp.set("jsonp callback name", "cb"); // at least rename from default "callback"');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 56 — Referrer-Policy header missing
// ═══════════════════════════════════════════════════════════════════════════════

const hasReferrerPolicy = parseGrepLines(
  grepFiles('Referrer-Policy|referrerPolicy|referrer.policy', ['js', 'ts'])
).length > 0;

if (!hasReferrerPolicy) {
  // Only flag if there are auth or token-bearing routes (URLs with tokens in them are the risk)
  const hasSensitiveRoutes = parseGrepLines(grepFiles(
    '(reset|verify|confirm|activate|token|invite).*router|router.*(reset|verify|confirm|activate|token|invite)',
    ['js', 'ts']
  )).length > 0;

  if (hasSensitiveRoutes || helmetHits.length === 0) {
    addFinding('LOW', 'Missing Referrer-Policy Header', null, null,
      'Referrer-Policy header not explicitly configured',
      'Without Referrer-Policy, browsers send the full URL (including path and query string) as the Referer header to third-party resources loaded on the same page. Password reset tokens, session IDs, or invite tokens embedded in URLs leak to analytics services, CDNs, and ad networks.',
      null,
      '// With helmet (already sets no-referrer by default — verify it is not overridden):\nhelmet({ referrerPolicy: { policy: "strict-origin-when-cross-origin" } })\n// Without helmet:\nres.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 57 — Hardcoded database connection string URLs (secrets in URL form)
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  '(mongodb[+srv]?|postgres|postgresql|mysql|redis|amqp|amqps|elasticsearch)://[^@\\s\'"`]+:[^@\\s\'"`]+@',
  ['js', 'ts', 'yaml', 'yml', 'json', 'env', 'sh', 'config']
)).forEach(({ file, line, code }) => {
  if (/process\.env|<|your[-_]|example|placeholder|localhost:[0-9]/i.test(code)) return;
  addFinding('CRITICAL', 'Hardcoded Database Credentials in Connection String', file, line,
    'Database/service connection URL with embedded credentials',
    'Connection strings of the form protocol://user:password@host embed credentials in source code. These are not caught by key=value secret patterns but are equally dangerous — rotating them requires a code change and redeploy.',
    code,
    'Use environment variables for the full connection string:\n// BAD:  mongoose.connect("mongodb://admin:s3cr3t@db.example.com/app")\n// GOOD: mongoose.connect(process.env.MONGODB_URI)\n// In .env: MONGODB_URI=mongodb://admin:s3cr3t@db.example.com/app (not committed)');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 58 — Overly permissive package.json version ranges
// ═══════════════════════════════════════════════════════════════════════════════

if (fileExists(packageJsonPath)) {
  try {
    const pkg = JSON.parse(readFile(packageJsonPath));
    const dangerousRanges = [];
    ['dependencies', 'devDependencies'].forEach(section => {
      Object.entries(pkg[section] || {}).forEach(([name, version]) => {
        if (/^\*$|^latest$|^x$|^>=\s*0/.test(version)) {
          dangerousRanges.push(`${name}: "${version}"`);
        }
      });
    });
    if (dangerousRanges.length > 0) {
      addFinding('LOW', 'Overly Permissive Dependency Version Ranges', packageJsonPath, null,
        `${dangerousRanges.length} dependencies use *, latest, or >= 0 version ranges`,
        `Ranges like * or latest accept any published version including a future malicious release. Affected packages: ${dangerousRanges.slice(0, 5).join(', ')}${dangerousRanges.length > 5 ? ` (+${dangerousRanges.length - 5} more)` : ''}.`,
        dangerousRanges.slice(0, 5).join('\n'),
        'Pin to exact versions or narrow semver ranges:\n// BAD:  "lodash": "*"\n// GOOD: "lodash": "4.17.21"\n// Run: npm shrinkwrap  or commit package-lock.json (already checked separately)');
    }
  } catch { /* malformed package.json */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 59 — GraphQL field-level authorization
// ═══════════════════════════════════════════════════════════════════════════════

if (usesGraphQL) {
  const hasFieldAuth = parseGrepLines(grepFiles(
    'graphql-shield|graphql-authz|fieldMiddleware|applyMiddleware.*shield|createRateLimitRule|allow\\.|deny\\.',
    ['js', 'ts', 'json']
  )).length > 0;

  if (!hasFieldAuth) {
    addFinding('MEDIUM', 'GraphQL — No Field-Level Authorization', null, null,
      'GraphQL app with no field-level authorization library detected',
      'Schema-wide auth middleware only validates that a user is logged in. Without field-level authorization (graphql-shield, graphql-authz), any authenticated user can query fields intended only for admins or other users — leaking personal data, internal metrics, or privileged operations.',
      null,
      'npm install graphql-shield\n\nimport { shield, rule, and } from "graphql-shield";\nconst isAuthenticated = rule()((parent, args, ctx) => ctx.user !== null);\nconst isAdmin         = rule()((parent, args, ctx) => ctx.user?.role === "admin");\n\nconst permissions = shield({\n  Query: { users: and(isAuthenticated, isAdmin) },\n  User:  { email: isAuthenticated },\n});\n\n// Apply via makeExecutableSchema or ApolloServer plugins');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 60 — Password reset token: no expiry enforcement
// ═══════════════════════════════════════════════════════════════════════════════

const resetTokenQueryHits = parseGrepLines(grepFiles(
  '(resetToken|reset_token|passwordResetToken|forgotPasswordToken)\\s*:\\s*req\\.',
  ['js', 'ts']
));
if (resetTokenQueryHits.length > 0) {
  resetTokenQueryHits.forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 5, 10);
    if (!/expiresAt|expiry|expiredAt|resetExpires|tokenExpiry|Date\.now\(\)|> new Date/i.test(ctx)) {
      addFinding('HIGH', 'Password Reset Token — No Expiry Check', file, line,
        'Password reset token queried without apparent expiry validation',
        'A reset token without an expiry check is valid forever. An attacker who obtains a token (from logs, email interception, or DB breach) can reset any account at any time, even years later.',
        code,
        '// Always include an expiry condition in the reset token lookup:\nconst user = await User.findOne({\n  resetToken: req.body.token,\n  resetTokenExpiry: { $gt: Date.now() },  // token valid for e.g. 1 hour\n});\nif (!user) return res.status(400).json({ error: "Invalid or expired token" });\n// Immediately invalidate after use:\nuser.resetToken = undefined;\nuser.resetTokenExpiry = undefined;\nawait user.save();');
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 61 — console.error(err) leaking stack traces to stdout in production
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('console\\.error\\s*\\(\\s*err\\b|console\\.log\\s*\\(\\s*err\\b', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    if (/NODE_ENV|process\.env/i.test(readContext(file, line, 3, 3))) return; // guarded
    addFinding('LOW', 'Stack Trace Leakage via console.error(err)', file, line,
      'console.error(err) logs full stack trace unconditionally',
      'In production, full stack traces written to stdout/stderr reach log aggregators, Datadog, CloudWatch, etc. These often surface in developer dashboards that have broader access than expected, and can leak file paths, library versions, and business logic.',
      code,
      '// Log the full error internally but never send it to the client:\nif (process.env.NODE_ENV !== "production") console.error(err);\nelse logger.error({ message: err.message, code: err.code }); // structured, no stack\n// Use a structured logger (pino, winston) with log levels in production.');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 62 — trust proxy misconfiguration
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles("set\\s*\\(['\"]trust\\s*proxy['\"]", ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    if (/true\b|,\s*true/.test(code)) {
      addFinding('MEDIUM', 'Insecure trust proxy Setting', file, line,
        'app.set("trust proxy", true) — spoofable req.ip, broken rate limiting',
        'trust proxy:true blindly trusts all X-Forwarded-For headers. An attacker can spoof any IP, bypassing IP-based rate limiting, geo-blocking, and access controls that rely on req.ip.',
        code,
        'Set only the number of proxies actually in front of the app:\napp.set("trust proxy", 1);  // one reverse proxy (nginx, Cloudflare)\n// Or subnet: app.set("trust proxy", "10.0.0.0/8");');
    }
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 63 — CORS dynamic origin reflection
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  'req\\.(headers\\.origin|get\\s*\\([\'"]origin[\'"]\\))',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  const ctx = readContext(file, line, 2, 6);
  if (/Access-Control-Allow-Origin|setHeader.*origin|cors.*origin/i.test(ctx)) {
    addFinding('HIGH', 'CORS — Dynamic Origin Reflection', file, line,
      'Request Origin header reflected directly into Access-Control-Allow-Origin',
      'Echoing req.headers.origin back as the CORS allowed origin is functionally equivalent to origin:"*" but also permits credentialed requests — any site can make authenticated cross-origin requests.',
      code,
      'Use an explicit allowlist:\nconst ALLOWED = new Set(["https://app.example.com"]);\nconst origin = req.headers.origin;\nif (ALLOWED.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin);\n// Never: res.setHeader("Access-Control-Allow-Origin", req.headers.origin)');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 64 — State-changing GET endpoints
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles(
  "(router|app)\\.get\\s*\\(['\"][^'\"]*\\/(delete|remove|destroy|drop|reset|disable|ban|block|approve|reject|activate|deactivate|confirm|cancel|purge)",
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  addFinding('MEDIUM', 'State-Changing GET Endpoint', file, line,
    'GET route performs a destructive or state-mutating action',
    'GET requests are cached, prefetched, and logged by proxies. State-changing GETs are vulnerable to CSRF even with SameSite=Strict cookies since browsers issue GETs freely during navigation.',
    code,
    '// Use POST/PUT/DELETE for state-mutating operations:\n// BAD:  router.get("/users/:id/delete", deleteUser)\n// GOOD: router.delete("/users/:id", csrfProtect, deleteUser)');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 65 — SSRF: http.request / https.request + webhook/image-proxy patterns
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('(http|https)\\.request\\s*\\([^)]*req\\.', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding('HIGH', 'SSRF — http.request() with user-controlled input', file, line,
      'Node.js built-in http.request() called with user-controlled input',
      'http.request() makes arbitrary outbound connections. User-supplied URLs or options reach internal services and cloud metadata endpoints.',
      code,
      'Validate and allowlist before any outbound request:\nconst u = new URL(req.body.url);\nconst ALLOWED = new Set(["api.example.com"]);\nif (!ALLOWED.has(u.hostname)) return res.status(400).end();');
  });

parseGrepLines(grepFiles(
  '(webhook|proxy|imageProxy|image_proxy|fetchUrl|proxyRequest|forwardRequest).*req\\.(body|query|params)',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  const ctx = readContext(file, line, 0, 10);
  if (/(axios|fetch|got|request|http|https|superagent|undici)/i.test(ctx)) {
    addFinding('HIGH', 'SSRF — Webhook / Image-Proxy with User-Controlled URL', file, line,
      'Webhook forwarding or image-proxy endpoint with user-controlled URL',
      'Webhook and image-proxy endpoints are the most commonly exploited SSRF targets — they exist precisely to make outbound HTTP requests, so any user-controlled URL component reaches internal services.',
      code,
      'Validate every URL:\n// Parse → check hostname in allowlist → reject private IPs (10.x, 172.16.x, 192.168.x, 127.x)\n// Libraries: ssrf-filter, ssrf-req-filter');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 66 — eval() with JSON / string concatenation (deserialization variant)
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles("eval\\s*\\(\\s*['\"]\\s*\\(|eval\\s*\\(.*[+].*json|eval\\s*\\(.*JSON", ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    if (/\/\//i.test(code)) return;
    addFinding('CRITICAL', 'Unsafe Deserialization via eval()', file, line,
      "eval('(' + json + ')') — arbitrary code execution from JSON input",
      "This pattern executes any JavaScript inside the string, not just JSON. An attacker who controls the input achieves RCE.",
      code,
      '// Replace with JSON.parse():\nconst data = JSON.parse(userInput); // throws SyntaxError, never executes code');
  });

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 67 — Advanced file upload: SVG, double-extension, image-processing RCE
// ═══════════════════════════════════════════════════════════════════════════════

// 67a: SVG in allowed upload types
parseGrepLines(grepFiles(
  '(allowedExts|allowedMimes|allowedTypes|ALLOWED_EXT|ALLOWED_MIME|whitelist).*svg|svg.*(allowedExts|allowedMimes|allowedTypes)',
  ['js', 'ts']
)).forEach(({ file, line, code }) => {
  addFinding('HIGH', 'Insecure File Upload — SVG Allowed', file, line,
    'SVG permitted in upload allowlist — stored XSS risk',
    'SVG is XML that can contain <script> tags. When served as image/svg+xml and opened directly, it executes JavaScript in your site origin — stored XSS without any HTML injection.',
    code,
    '// Remove SVG from allowed types, or sanitize server-side with DOMPurify:\n// import createDOMPurify from "dompurify"; const { JSDOM } = require("jsdom");\n// const window = new JSDOM("").window; const DOMPurify = createDOMPurify(window);\n// const clean = DOMPurify.sanitize(svgContent);\n// Always serve SVG with Content-Disposition: attachment to prevent browser rendering.');
});

// 67b: Double-extension bypass — splitting on "." instead of path.extname
parseGrepLines(grepFiles("\\.split\\s*\\(['\"]\\.['\"]\\)", ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    const ctx = readContext(file, line, 0, 5);
    if (/(originalname|filename|upload|file)/i.test(ctx) && !/\.pop\(\)|slice\s*\(-1\)|path\.extname/.test(ctx)) {
      addFinding('MEDIUM', 'Insecure File Upload — Double-Extension Bypass', file, line,
        'File extension extracted by splitting on "." — double-extension bypass possible',
        'Splitting "malware.php.jpg" on "." and taking [1] yields "php", not "jpg". Use path.extname() which always returns the last extension.',
        code,
        '// Use path.extname() — always returns the last extension:\nconst ext = path.extname(file.originalname).toLowerCase();\n// "malware.php.jpg" → ".jpg"  ✓');
    }
  });

// 67c: ImageMagick / GraphicsMagick — known RCE surface
parseGrepLines(grepFiles(
  "(imagemagick|gm\\b|graphicsmagick|imagickal|node-imagemagick)",
  ['js', 'ts', 'json']
)).forEach(({ file, line, code }) => {
  addFinding('HIGH', 'Image Processing — ImageMagick / gm RCE Surface', file, line,
    'ImageMagick or GraphicsMagick detected — verify policy.xml and input validation',
    'ImageMagick has a history of critical RCE vulnerabilities (ImageTragick CVE-2016-3714 and many successors). Processing attacker-uploaded images without a hardened policy.xml allows RCE, SSRF, and file reads via crafted SVG/MVG/MSL payloads.',
    code,
    '// Harden /etc/ImageMagick-*/policy.xml:\n// <policy domain="coder" rights="none" pattern="MVG" />\n// <policy domain="coder" rights="none" pattern="MSL" />\n// <policy domain="coder" rights="none" pattern="EPHEMERAL" />\n// Validate file magic bytes before processing. Consider sharp (libvips) as a safer alternative.');
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 68 — Cloud / infrastructure secret leakage
// ═══════════════════════════════════════════════════════════════════════════════

// 68a: Dockerfile / docker-compose — secrets in ENV/ARG
const dockerFiles = [
  ...findFiles('Dockerfile'), ...findFiles('Dockerfile.*'),
  ...findFiles('docker-compose.yml'), ...findFiles('docker-compose.yaml'),
  ...findFiles('compose.yml'), ...findFiles('compose.yaml'),
];
dockerFiles.forEach(f => {
  const lines = readFile(f).split('\n');
  lines.forEach((ln, idx) => {
    if (/^\s*(ENV|ARG)\s+\w*(password|secret|key|token|api_key|apikey|auth|credential)\w*\s*=\s*.+/i.test(ln) &&
        !/process\.env|<.*>|your[-_]|example|changeme|placeholder|\$\{/i.test(ln)) {
      addFinding('CRITICAL', 'Hardcoded Secret in Dockerfile', f, idx + 1,
        'Plaintext credential in Docker ENV or ARG instruction',
        'Secrets in ENV/ARG are baked into every image layer and visible via `docker history` to anyone with registry access.',
        ln.trim(),
        '// Use runtime env injection or Docker build secrets:\n// docker build --secret id=mysecret,src=./secret.txt .\n// RUN --mount=type=secret,id=mysecret ...\n// Never bake secrets into image layers.');
    }
  });
  // docker-compose hardcoded DB passwords
  const content = readFile(f);
  if (/docker-compose|compose\.ya?ml/.test(f)) {
    const m = content.match(/^\s+(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*:\s*(?![${\s]).+/m);
    if (m) {
      addFinding('HIGH', 'Hardcoded DB Password in docker-compose', f, null,
        'Plaintext database password in docker-compose environment block',
        'Hard-coded DB passwords in docker-compose are committed to version control.',
        m[0].trim(),
        '// Use .env file (in .gitignore):\n// environment:\n//   POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}');
    }
  }
});

// 68b: GitHub Actions — secret echoed to log / pull_request_target danger
const workflowFiles = [
  ...findFiles('*.yml').filter(f => f.includes('.github')),
  ...findFiles('*.yaml').filter(f => f.includes('.github')),
];
workflowFiles.forEach(f => {
  const content = readFile(f);
  const lines   = content.split('\n');
  lines.forEach((ln, idx) => {
    if (/echo.*\$\{\{\s*secrets\./i.test(ln)) {
      addFinding('HIGH', 'GitHub Actions — Secret Echoed to Build Log', f, idx + 1,
        'secrets.* value echoed in run: step — visible in CI logs',
        "GitHub's secret masking is bypassed by base64-encoding or char-splitting. Direct echo of a secret in run: is an accidental disclosure risk.",
        ln.trim(),
        '// Pass as env var and never echo:\n// env:\n//   API_KEY: ${{ secrets.API_KEY }}\n// run: ./deploy.sh  # reads $API_KEY internally without logging');
    }
    if (/pull_request_target/i.test(ln) &&
        content.includes('actions/checkout') &&
        content.includes('github.event.pull_request')) {
      addFinding('CRITICAL', 'GitHub Actions — pull_request_target + PR Code Checkout', f, idx + 1,
        'pull_request_target with checkout of PR branch — secrets exfiltration risk',
        "pull_request_target runs with write permissions and secrets. Checking out a contributor's PR code and running it allows any external contributor to exfiltrate all repository secrets.",
        ln.trim(),
        '// Never checkout PR head code in pull_request_target.\n// Use pull_request (no secrets) for untrusted code.\n// See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/');
    }
  });
});

// 68c: Terraform hardcoded secrets
findFiles('*.tf').concat(findFiles('*.tfvars')).forEach(f => {
  const content = readFile(f);
  const m = content.match(/(?:password|secret|api_key|token)\s*=\s*"(?!var\.|local\.|data\.|module\.)[^"]{6,}"/gi);
  if (m) {
    addFinding('CRITICAL', 'Hardcoded Secret in Terraform', f, null,
      'Plaintext secret in Terraform config or tfvars file',
      'Terraform secrets in .tf/.tfvars live in version control and in the state file (often S3/GCS). Both are common breach vectors.',
      m[0],
      '// Use variables sourced from environment or Vault:\n// variable "db_password" { sensitive = true }\n// export TF_VAR_db_password="$(vault kv get -field=password secret/db)"');
  }
});

// 68d: Kubernetes Secret manifests committed to git
findFiles('*.yaml').concat(findFiles('*.yml')).forEach(f => {
  const content = readFile(f);
  if (/kind:\s*Secret/i.test(content) && /data:/i.test(content) &&
      !/external-secrets|sealed-secret|vault\.hashicorp\.com|secretKeyRef/i.test(content)) {
    addFinding('HIGH', 'Hardcoded Secret in Kubernetes Manifest', f, null,
      'Kubernetes Secret resource with inline base64 data committed to source',
      'Kubernetes Secrets are only base64-encoded, not encrypted. Committing them to git exposes plaintext to everyone with repo access.',
      'kind: Secret with data:',
      '// Use External Secrets Operator, Sealed Secrets, or SOPS instead.\n// Enable etcd encryption at rest in your cluster.');
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 69 — Next.js framework-specific security
// ═══════════════════════════════════════════════════════════════════════════════

const isNextJs = fileExists(path.join(root, 'next.config.js'))  ||
                 fileExists(path.join(root, 'next.config.ts'))   ||
                 fileExists(path.join(root, 'next.config.mjs'));

if (isNextJs) {
  // 69a: NEXT_PUBLIC_ with secret-like name — baked into browser bundle
  findFiles('.env*').forEach(f => {
    readFile(f).split('\n').forEach((ln, idx) => {
      if (/NEXT_PUBLIC_\w*(secret|key|token|password|api_key|apikey|auth|private)/i.test(ln) &&
          !/=\s*$|NEXT_PUBLIC_\w+=\s*$/.test(ln)) {
        addFinding('CRITICAL', 'Next.js — Secret Exposed via NEXT_PUBLIC_ Prefix', f, idx + 1,
          'Secret-like variable with NEXT_PUBLIC_ is baked into the browser bundle',
          'Any NEXT_PUBLIC_* variable is inlined into client-side JS — visible to all users in DevTools. Never use this prefix for secrets.',
          ln.trim(),
          '// Remove NEXT_PUBLIC_ prefix from secrets:\n// BAD:  NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...\n// GOOD: STRIPE_SECRET_KEY=sk_live_...  (server-side only)');
      }
    });
  });

  // 69b: Next.js API routes without auth
  const apiRoutes = [
    ...findFiles('*.ts').filter(f => /pages[\\/]api[\\/]|app[\\/]api[\\/]/.test(f)),
    ...findFiles('*.js').filter(f => /pages[\\/]api[\\/]|app[\\/]api[\\/]/.test(f)),
    ...findFiles('*.tsx').filter(f => /pages[\\/]api[\\/]|app[\\/]api[\\/]/.test(f)),
  ];
  apiRoutes.forEach(f => {
    const content = readFile(f);
    if (!/getSession|getServerSession|auth\(\)|withAuth|verifyToken|jwt\.verify|requireAuth|isAuthenticated|Authorization/i.test(content)) {
      addFinding('MEDIUM', 'Next.js — API Route Without Visible Auth', f, null,
        'Next.js API route with no authentication check',
        'Next.js API routes are public HTTP endpoints. Without auth, any unauthenticated request reaches the handler.',
        path.relative(root, f),
        '// Add at the top of every protected route:\nconst session = await getServerSession(req, res, authOptions);\nif (!session) return res.status(401).json({ error: "Unauthorized" });');
    }
  });

  // 69c: Server Actions without auth (Next.js 13+ app dir)
  [
    ...findFiles('*.ts'), ...findFiles('*.tsx'),
    ...findFiles('*.js'), ...findFiles('*.jsx'),
  ].filter(f => f.includes('/app/')).forEach(f => {
    const content = readFile(f);
    if (/"use server"/i.test(content) &&
        !/getServerSession|auth\(\)|verifyToken|requireAuth|isAuthenticated|Authorization/i.test(content)) {
      addFinding('MEDIUM', 'Next.js — Server Action Without Auth', f, null,
        '"use server" directive found without authentication guard',
        'Server Actions are exposed as POST endpoints. Without auth, attackers invoke them directly by crafting POST requests.',
        path.relative(root, f),
        '// Authenticate at the top of every server action:\nconst session = await getServerSession(authOptions);\nif (!session) throw new Error("Unauthorized");');
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 70 — High-entropy string detection (unknown secret formats)
// ═══════════════════════════════════════════════════════════════════════════════

(function entropyCheck() {
  function shannonEntropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((s, n) => s + (n/len) * Math.log2(n/len), 0);
  }

  const re = /['"`]([A-Za-z0-9+/=_\-]{32,})['"`]/g;

  let files = [];
  try {
    files = execSync(
      `find "${root}" -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.env" \\)` +
      ' ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/.next/*"' +
      ' ! -path "*/dist/*" ! -path "*/build/*" ! -path "*/coverage/*" 2>/dev/null',
      { encoding: 'utf8', maxBuffer: 5 * 1024 * 1024 }
    ).trim().split('\n').filter(Boolean);
  } catch { return; }

  files.forEach(f => {
    readFile(f).split('\n').forEach((ln, idx) => {
      if (/process\.env|require\s*\(|import |\/\//i.test(ln)) return;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(ln)) !== null) {
        if (shannonEntropy(m[1]) > 4.5) {
          addFinding('LOW', 'High-Entropy String — Possible Hardcoded Secret', f, idx + 1,
            `High-entropy literal (entropy ${shannonEntropy(m[1]).toFixed(2)}) — possible secret`,
            'Shannon entropy above 4.5 is consistent with randomly generated tokens, keys, or secrets not caught by service-specific patterns.',
            ln.trim().slice(0, 120),
            'If this is a secret: move to process.env.\nIf intentional (public cert, test vector): add a comment to suppress.');
          break;
        }
      }
    });
  });
})();


// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 73 — AI / LLM API cost protection
// Detects routes that call paid AI APIs (OpenAI, Anthropic, Google Gemini, etc.)
// without rate limiting, token budget caps, prompt size limits, or auth guards —
// allowing attackers to exhaust your API quota and generate large bills.
// ═══════════════════════════════════════════════════════════════════════════════

(function llmCostProtectionCheck() {
  // 73a: Detect use of any paid LLM SDK / client
  const llmPatterns = [
    'openai', 'anthropic', '@anthropic-ai', 'claude',
    'google-generativeai', '@google/generative-ai', 'gemini',
    'cohere-ai', 'cohere',
    '@aws-sdk.*bedrock', 'bedrock',
    'mistralai', 'mistral',
    'replicate',
    'huggingface',
    'groq',
    'together',
    'ai\\.sdk', 'vercel.*ai', '@ai-sdk',
    'langchain', '@langchain',
  ];
  const llmDetectPattern = llmPatterns.join('|');

  const llmImportHits = parseGrepLines(
    grepFiles(llmDetectPattern, ['js', 'ts', 'json'], '-rn -iE')
  );

  // Only run sub-checks if an LLM SDK is actually in use
  if (llmImportHits.length === 0) return;

  // Collect the files that contain LLM API calls (completions, chat, generate, invoke)
  const llmCallHits = parseGrepLines(grepFiles(
    '(\\.chat\\.completions\\.create|\\.messages\\.create|\\.complete|\\.generateContent|\\.generate|\\.invoke|\\.stream|\\.converse)',
    ['js', 'ts'], '-rn -E'
  ));

  if (llmCallHits.length === 0) return; // SDK imported but no actual call site found

  // 73b: No rate limiting anywhere in the project
  const rateLimitHits = parseGrepLines(grepFiles(
    'rate.?limit|rateLimit|rateLimiter|slowDown|express-rate-limit|rate-limiter-flexible|bottleneck|p-throttle|p-limit',
    ['js', 'ts', 'json']
  ));
  if (rateLimitHits.length === 0) {
    addFinding('CRITICAL', 'AI/LLM API — No Rate Limiting',
      llmCallHits[0].file, llmCallHits[0].line,
      'LLM API calls with no rate limiting — attackers can exhaust your quota',
      'The app calls a paid AI API (OpenAI, Anthropic, Gemini, etc.) but no rate-limiting middleware was found. ' +
      'An attacker can flood your endpoint with requests, burning through your token quota and generating large bills ' +
      'within minutes. This is sometimes called "prompt flooding" or "LLM billing abuse".',
      llmCallHits[0].code,
      '// express-rate-limit (per IP, per user, or global):\nconst { rateLimit } = require("express-rate-limit");\nconst aiLimiter = rateLimit({\n  windowMs: 60 * 1000,  // 1 minute\n  max: 10,              // max 10 AI requests per IP per minute\n  message: { error: "Too many requests" },\n  keyGenerator: (req) => req.user?.id || req.ip, // per-user is stronger than per-IP\n});\nrouter.post("/ai/chat", aiLimiter, chatHandler);\n\n// Also consider: rate-limiter-flexible for Redis-backed distributed limiting',
      { confidence: 'HIGH', exploitability: 'remote_unauth', owasp: 'A05:2021', cwe: 'CWE-770' }
    );
  }

  // 73c: No max_tokens / maxOutputTokens cap found near LLM call sites
  const tokenCapHits = parseGrepLines(grepFiles(
    'max_tokens|maxTokens|maxOutputTokens|max_completion_tokens',
    ['js', 'ts']
  ));
  if (tokenCapHits.length === 0) {
    addFinding('HIGH', 'AI/LLM API — No Output Token Cap (max_tokens)',
      llmCallHits[0].file, llmCallHits[0].line,
      'LLM calls found with no max_tokens / maxOutputTokens limit',
      'Without a token cap the model can return extremely long responses (up to its context window). ' +
      'Attackers can craft prompts that force maximum-length outputs — multiplying cost per request by 10–100×. ' +
      'A single request to GPT-4o without a cap can cost ~$0.30+; at scale this becomes significant.',
      llmCallHits[0].code,
      '// Always set an output token budget appropriate to your use case:\nconst response = await openai.chat.completions.create({\n  model: "gpt-4o",\n  messages,\n  max_tokens: 512,  // ← cap to what your UI actually needs\n});\n\n// For Anthropic:\nconst msg = await anthropic.messages.create({\n  model: "claude-sonnet-4-5",\n  max_tokens: 512,\n  messages,\n});',
      { confidence: 'HIGH', exploitability: 'remote_auth', owasp: 'A05:2021', cwe: 'CWE-770' }
    );
  }

  // 73d: No prompt / input size validation before passing user content to LLM
  const promptSizeHits = parseGrepLines(grepFiles(
    '(\\.length\\s*[<>]|slice\\s*\\(0|substring\\s*\\(0|truncate|maxLength|max.?length|trim)',
    ['js', 'ts']
  ));
  // Check specifically near LLM call sites — look for user input flowing to messages/prompt without length check
  const userInputInPromptHits = parseGrepLines(grepFiles(
    '(req\\.body|req\\.query|req\\.params).*content|messages.*req\\.|prompt.*req\\.',
    ['js', 'ts'], '-rn -iE'
  ));
  if (userInputInPromptHits.length > 0 && promptSizeHits.length === 0) {
    addFinding('HIGH', 'AI/LLM API — No Input Prompt Size Limit',
      userInputInPromptHits[0].file, userInputInPromptHits[0].line,
      'User-controlled input passed to LLM prompt without length validation',
      'User input appears to flow directly into the LLM prompt with no size cap. ' +
      'Sending a 100,000-token input to GPT-4o costs ~$1 per request in input tokens alone. ' +
      'Attackers can paste entire books or generated noise to maximize input costs.',
      userInputInPromptHits[0].code,
      '// Validate and truncate user input before including in prompts:\nconst MAX_PROMPT_CHARS = 2000; // ~500 tokens\nconst userMessage = String(req.body.message).slice(0, MAX_PROMPT_CHARS);\n\n// Or use a token counter for precision:\n// npm install gpt-tokenizer\nimport { encode } from "gpt-tokenizer";\nconst tokens = encode(userMessage);\nif (tokens.length > 500) return res.status(400).json({ error: "Message too long" });',
      { confidence: 'MEDIUM', exploitability: 'remote_auth', owasp: 'A05:2021', cwe: 'CWE-770' }
    );
  }

  // 73e: LLM endpoint has no authentication — completely open to the public
  const llmRouteFiles = [...new Set(llmCallHits.map(h => h.file))];
  llmRouteFiles.forEach(f => {
    const content = readFile(f);
    const hasAuth = /requireAuth|isAuthenticated|verifyToken|getServerSession|jwt\.verify|passport\.|@UseGuards|authMiddleware|bearerAuth|Authorization/i.test(content);
    if (!hasAuth) {
      addFinding('CRITICAL', 'AI/LLM API — Endpoint Accessible Without Authentication',
        f, null,
        'LLM API call in file with no visible authentication check',
        'This file makes paid LLM API calls but contains no authentication guard. ' +
        'Any anonymous user (or bot) can invoke it freely, with all charges going to your account. ' +
        'Even a low-traffic public endpoint can be scraped to zero budget overnight.',
        path.relative(root, f),
        '// Protect every route that proxies an AI API:\nrouter.post("/ai/chat", requireAuth, aiLimiter, async (req, res) => {\n  const userId = req.user.id;\n  // optionally: enforce per-user monthly token budget in DB\n  const usage = await db.getMonthlyUsage(userId);\n  if (usage.tokens > USER_MONTHLY_LIMIT) return res.status(429).json({ error: "Budget exceeded" });\n  // ... make LLM call\n});',
        { confidence: 'MEDIUM', exploitability: 'remote_unauth', owasp: 'A01:2021', cwe: 'CWE-306' }
      );
    }
  });

  // 73f: No per-user token budget / usage tracking
  const budgetTrackingHits = parseGrepLines(grepFiles(
    'usage\\.total_tokens|usage\\.input_tokens|usage\\.output_tokens|prompt_tokens|completion_tokens|token.*budget|monthly.*limit|usage.*limit|credit|quota',
    ['js', 'ts'], '-rn -iE'
  ));
  if (budgetTrackingHits.length === 0) {
    addFinding('MEDIUM', 'AI/LLM API — No Per-User Token Budget Tracking',
      null, null,
      'No token usage tracking or per-user budget enforcement detected',
      'The app makes LLM API calls but does not appear to track token consumption per user. ' +
      'Without usage tracking you cannot enforce fair-use limits, detect abuse early, or alert on cost spikes. ' +
      'Most providers return usage counts in every API response — log them.',
      null,
      '// Log and accumulate token usage per user after every LLM call:\nconst response = await openai.chat.completions.create({ ... });\nconst { prompt_tokens, completion_tokens, total_tokens } = response.usage;\nawait db.incrementUserTokenUsage(req.user.id, total_tokens);\n\n// Check budget before calling:\nconst usage = await db.getMonthlyTokenUsage(req.user.id);\nconst MONTHLY_LIMIT = 100_000; // tokens\nif (usage + estimatedTokens > MONTHLY_LIMIT)\n  return res.status(402).json({ error: "Monthly token budget exceeded" });',
      { confidence: 'LOW', exploitability: 'remote_auth', owasp: 'A05:2021', cwe: 'CWE-770' }
    );
  }
})();

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 71 — NestJS framework-specific security
// ═══════════════════════════════════════════════════════════════════════════════

const usesNestJS = parseGrepLines(grepFiles('@nestjs', ['ts','js','json'])).length > 0;
if (usesNestJS) {
  // 71a: Missing @UseGuards on controllers / resolvers
  const guardHits      = parseGrepLines(grepFiles('@UseGuards\\s*\\(', ['ts']));
  const controllerHits = parseGrepLines(grepFiles('@(Controller|Resolver)\\s*\\(', ['ts']));
  if (controllerHits.length > 0 && guardHits.length === 0) {
    addFinding('HIGH', 'NestJS — Missing Auth Guards', null, null,
      'NestJS controllers or resolvers found with no @UseGuards() decorators',
      'Without @UseGuards(JwtAuthGuard) or equivalent, all routes are publicly accessible. A global guard in main.ts would also satisfy this check.',
      null,
      '// Option 1: apply globally in main.ts\napp.useGlobalGuards(new JwtAuthGuard());\n\n// Option 2: per-controller\n@Controller("users")\n@UseGuards(JwtAuthGuard)\nexport class UsersController {}',
      { confidence: 'MEDIUM', owasp: 'A01:2021', cwe: 'CWE-306' });
  }

  // 71b: Global ValidationPipe absent
  const validationPipeHits = parseGrepLines(grepFiles('ValidationPipe|useGlobalPipes', ['ts']));
  if (validationPipeHits.length === 0) {
    addFinding('HIGH', 'NestJS — Missing Global ValidationPipe', null, null,
      'No ValidationPipe detected — request bodies accepted without DTO validation',
      'Without a global ValidationPipe, NestJS accepts any request body shape. class-validator decorators on DTOs are silently ignored, enabling mass assignment and type coercion attacks.',
      null,
      '// main.ts\napp.useGlobalPipes(new ValidationPipe({\n  whitelist: true,\n  forbidNonWhitelisted: true,\n  transform: true,\n}));',
      { confidence: 'MEDIUM', owasp: 'A03:2021', cwe: 'CWE-20' });
  }

  // 71c: DTO classes without class-validator decorators
  parseGrepLines(grepFiles('export\\s+class\\s+\\w+Dto', ['ts'])).forEach(({ file, line, code }) => {
    const content = readFile(file);
    if (!/@(IsString|IsNumber|IsEmail|IsBoolean|IsArray|IsOptional|IsNotEmpty|MinLength|MaxLength|IsEnum|IsInt|IsDate)/.test(content)) {
      addFinding('MEDIUM', 'NestJS — DTO Without class-validator Decorators', file, line,
        'DTO class found without class-validator annotations',
        'An undecorated DTO provides no runtime type enforcement — even with ValidationPipe, all inputs pass unchecked.',
        code,
        '// Annotate every field:\nimport { IsString, IsEmail, MinLength } from "class-validator";\nexport class CreateUserDto {\n  @IsString() @MinLength(2) name: string;\n  @IsEmail() email: string;\n}',
        { confidence: 'LOW', owasp: 'A03:2021', cwe: 'CWE-20' });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 72 — Fastify framework-specific security
// ═══════════════════════════════════════════════════════════════════════════════

const usesFastify = parseGrepLines(grepFiles('fastify\\s*\\(|require\\(.{0,5}fastify', ['js','ts'])).length > 0;
if (usesFastify) {
  // 72a: Routes without JSON schema validation
  const schemaHits       = parseGrepLines(grepFiles('schema\\s*:\\s*\\{', ['js','ts']));
  const fastifyRouteHits = parseGrepLines(grepFiles('fastify\\.(get|post|put|patch|delete)\\s*\\(', ['js','ts']));
  if (fastifyRouteHits.length > 0 && schemaHits.length === 0) {
    addFinding('HIGH', 'Fastify — Routes Without JSON Schema Validation', null, null,
      'Fastify routes registered with no schema validation',
      'Routes without a schema accept arbitrary input and may leak internal fields in responses when serialization is unguarded.',
      null,
      '// Attach a schema to every route:\nfastify.post("/users", {\n  schema: {\n    body: { type: "object", required: ["email"], properties: { email: { type: "string", format: "email" } }, additionalProperties: false },\n    response: { 200: { type: "object", properties: { id: { type: "string" } } } },\n  },\n}, handler);',
      { confidence: 'MEDIUM', owasp: 'A03:2021', cwe: 'CWE-20' });
  }

  // 72b: Potentially unsafe serializer usage
  parseGrepLines(grepFiles('require\\(.{0,5}serialize-javascript|fast-json-stringify\\s*\\(\\s*\\{', ['js','ts']))
    .forEach(({ file, line, code }) => {
      addFinding('MEDIUM', 'Fastify — Unsafe Serializer Risk', file, line,
        'Serializer library detected — verify schema prevents data leakage',
        'fast-json-stringify skips fields not in the schema but a loose or missing schema may expose internal fields (passwords, tokens) in responses.',
        code,
        '// Ensure response schema explicitly whitelists returned fields only.',
        { confidence: 'LOW', owasp: 'A04:2021', cwe: 'CWE-200' });
    });

  // 72c: No authentication hook or plugin
  const hookHits       = parseGrepLines(grepFiles('addHook\\s*\\(.{0,20}(onRequest|preHandler)', ['js','ts']));
  const fastifyAuthPkg = parseGrepLines(grepFiles('fastify-auth|fastify-jwt|@fastify\\/auth|@fastify\\/jwt', ['js','ts','json']));
  if (fastifyRouteHits.length > 0 && hookHits.length === 0 && fastifyAuthPkg.length === 0) {
    addFinding('HIGH', 'Fastify — No Authentication Hook Detected', null, null,
      'No onRequest/preHandler auth hook or fastify-auth plugin found',
      'Fastify has no built-in auth middleware. Without a hook or @fastify/auth plugin all routes are publicly accessible.',
      null,
      '// Global auth hook:\nfastify.addHook("onRequest", async (request, reply) => {\n  try { await request.jwtVerify(); }\n  catch { reply.code(401).send({ error: "Unauthorized" }); }\n});',
      { confidence: 'MEDIUM', owasp: 'A01:2021', cwe: 'CWE-306' });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// npm audit (saved to temp file — avoids pipe truncation)
// ═══════════════════════════════════════════════════════════════════════════════

if (fileExists(packageJsonPath)) {
  let auditTmp;
  try {
    auditTmp = path.join(os.tmpdir(), `npm-audit-${Date.now()}.json`);
    execSync(`cd "${root}" && npm audit --json > "${auditTmp}" 2>/dev/null`, { encoding:'utf8', timeout:30000 });
    const audit  = JSON.parse(readFile(auditTmp));
    const vulns  = audit.vulnerabilities || {};
    Object.values(vulns).forEach(v => {
      if (['critical','high'].includes(v.severity)) {
        addFinding(v.severity.toUpperCase(),'Vulnerable Dependency',`package.json (${v.name})`,null,
          `${v.name}: ${v.severity} vulnerability`,
          v.title || 'Known vulnerability in dependency.',
          null, `npm install ${v.name}@latest  or  npm audit fix`);
      }
    });
  } catch { /* npm audit unavailable */ }
  finally { if (auditTmp) { try { fs.unlinkSync(auditTmp); } catch {} } }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Output
// ═══════════════════════════════════════════════════════════════════════════════

const summary = {
  total:      findings.length,
  critical:   findings.filter(f => f.severity === 'CRITICAL').length,
  high:       findings.filter(f => f.severity === 'HIGH').length,
  medium:     findings.filter(f => f.severity === 'MEDIUM').length,
  low:        findings.filter(f => f.severity === 'LOW').length,
  confidence: {
    high:   findings.filter(f => f.confidence === 'HIGH').length,
    medium: findings.filter(f => f.confidence === 'MEDIUM').length,
    low:    findings.filter(f => f.confidence === 'LOW').length,
  },
  risk_scores: {
    max:    findings.length ? Math.max(...findings.map(f => f.risk_score)) : 0,
    top5:   [...findings].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5)
              .map(f => ({ id: f.id, title: f.title, risk_score: f.risk_score, severity: f.severity })),
  },
  taint_sources: findings.reduce((acc, f) => {
    if (f.taint_source) acc[f.taint_source] = (acc[f.taint_source] || 0) + 1;
    return acc;
  }, {}),
  by_owasp: findings.reduce((acc, f) => {
    if (f.owasp) acc[f.owasp] = (acc[f.owasp] || 0) + 1;
    return acc;
  }, {}),
  frameworks_detected: {
    nestjs:  usesNestJS  || false,
    fastify: usesFastify || false,
    graphql: (typeof usesGraphQL !== 'undefined' && usesGraphQL) || false,
  },
};

console.log(JSON.stringify({ summary, findings }, null, 2));
