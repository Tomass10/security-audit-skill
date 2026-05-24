# Node.js Security Audit — Claude Skill

A Claude skill that performs comprehensive security audits of Node.js / JavaScript web applications. Point it at a codebase and it produces a prioritized, actionable report with file paths, line numbers, vulnerable code snippets, and concrete fixes.

---

## What it does

The skill runs a 2,100-line static analysis script (`scripts/scan.js`) across your codebase, then Claude layers manual review, context, and remediation advice on top. No external tools or API keys required — just Node.js.

**83 checks across 5 severity levels:**

| Severity | Meaning | Example |
|----------|---------|---------|
| 🔴 Critical | RCE, auth bypass, exposed secrets, billing abuse | Hardcoded API key, SQL injection, open LLM endpoint |
| 🟠 High | Exploitable without significant skill | Missing auth guard, insecure JWT, SSRF |
| 🟡 Medium | Exploitable with effort or in combination | Missing CSRF, weak cookies, open redirect |
| 🔵 Low | Hardening / hygiene issues | X-Powered-By exposed, missing lockfile |
| ℹ️ Info | Informational findings | High-entropy string, debug flag |

Each finding includes: `id · severity · category · file · line · snippet · remediation · CWE · OWASP · confidence · risk_score`

---

## Installation

### Option 1 — One command (recommended)

```bash
npx skills add https://github.com/Tomass10/security-audit-skill --skill security-audit-skill
```

This installs the skill into your agent's config directory and works with Claude Code and 40+ other agents. It will ask which agent to install for — pick **Claude Code**.

To install non-interactively:

```bash
npx skills add Tomass10/security-audit-skill --agent claude-code --yes
```

To install globally (available in all projects, not just the current one):

```bash
npx skills add Tomass10/security-audit-skill --agent claude-code --global --yes
```

### Option 2 — Manual install

```bash
git clone https://github.com/Tomass10/security-audit-skill.git ~/.claude/skills/security-audit-skill
```

### Option 3 — Run the scanner without Claude

The scanner works standalone with no dependencies:

```bash
git clone https://github.com/Tomass10/security-audit-skill.git
node security-audit-skill/scripts/scan.js /path/to/your/app
```

Pipe to `jq` for readable output:

```bash
# Summary only
node scripts/scan.js /path/to/your/app | jq '.summary'

# Critical findings only
node scripts/scan.js /path/to/your/app | jq '.findings[] | select(.severity == "CRITICAL")'

# Top 5 by risk score
node scripts/scan.js /path/to/your/app | jq '.summary.risk_scores.top5'
```

---

## Checks by category

<details>
<summary><strong>🔴 Injection & RCE (Checks 1–12, 29, 30, 66)</strong></summary>

- Hardcoded secrets (AWS keys, OpenAI/Stripe keys, GitHub tokens, Google API keys, private key blocks)
- SQL injection — string concatenation & template literals in queries
- NoSQL injection — `req.body` passed directly to `.find()` / `.findOne()`
- ORM raw query injection — `sequelize.query`, `knex.raw`, `prisma.$queryRawUnsafe`
- Mongoose `$where` / `$function` server-side JS execution
- Command injection — `exec`, `execSync`, `spawn`, `fork` with user input
- `eval()` / `new Function()` / `vm.runInNewContext()` with user input
- Server-side JavaScript injection (SSJI) — user input in `setTimeout`, `setInterval`
- Prototype pollution — deep merge / clone with `req.body`
- Dynamic `require()` / Local File Inclusion
- Insecure deserialization — `unserialize()`, `yaml.load()` on user data
- `eval()` with JSON concatenation (deserialization RCE variant)
</details>

<details>
<summary><strong>🟠 Auth & Access Control (Checks 13, 19, 25–27, 50, 60, 62)</strong></summary>

- Broken access control / IDOR — `findById(req.params.id)` without ownership check
- Insecure session config — weak secret, `MemoryStore`, missing flags
- Missing CSRF protection — cookie auth with no `csrf-csrf` / `doubleCsrf`
- OAuth state parameter absent — Passport strategies without `state: true`
- WebSocket / SSE authentication bypass
- Session fixation — no `req.session.regenerate()` after login
- Password reset token with no expiry enforcement
- `trust proxy: true` misconfiguration (spoofable `req.ip`, broken rate limiting)
</details>

<details>
<summary><strong>🟠 Injection — Other (Checks 16, 22, 23, 31, 34, 45, 46, 48, 49, 55, 65)</strong></summary>

- SSRF — `axios`, `fetch`, `got`, `request`, `http.request`, `https.request` with user URL
- SSRF — additional clients (`superagent`, `undici`, `ky`, `needle`)
- SSRF — webhook / image-proxy patterns
- Path traversal — read (`readFile`, `sendFile`, `createReadStream`)
- Path traversal — write (`writeFile`, `appendFile`, `rename`, `unlink`)
- Open redirect — `res.redirect(req.query.url)` and `returnTo` patterns
- Server-side template injection (SSTI)
- Host header injection — `req.headers.host` used to build URLs
- HTTP parameter pollution
- JSONP callback injection
- Sequelize / TypeORM where-clause injection
</details>

<details>
<summary><strong>🟠 XSS (Checks 3, 14, 15, 46)</strong></summary>

- DOM XSS — `innerHTML`, `outerHTML`, `document.write`
- React `dangerouslySetInnerHTML`
- Template engine unescaped output — EJS `<%-`, Pug `!=`, Handlebars `{{{`
- Server-side XSS — `res.send('<p>' + req.query.x)`
- Multi-line template literal in `res.send()` with user input
</details>

<details>
<summary><strong>🟠 Cryptography & JWT (Checks 14, 15, 52)</strong></summary>

- MD5 / SHA1 for passwords
- `Math.random()` for tokens — not cryptographically secure
- Bcrypt cost factor below 10
- `crypto.createCipher` (deprecated, MD5 key derivation, no IV)
- AES-ECB mode — deterministic, leaks plaintext patterns
- JWT: `jwt.decode()` instead of `jwt.verify()`
- JWT: `none` algorithm accepted
- JWT: no `algorithms` whitelist
- JWT: weak or hardcoded secret
</details>

<details>
<summary><strong>🟠 File Uploads (Checks 28, 67)</strong></summary>

- Multer path traversal — `.mv()` with user-controlled filename
- No MIME type / fileFilter validation
- SVG in upload allowlist (executes JS in browser)
- Double-extension bypass — `.split(".")` instead of `path.extname()`
- ImageMagick / `gm` RCE surface
- Zip Slip — archive extraction without path bounds check
</details>

<details>
<summary><strong>🟡 Configuration & Headers (Checks 4–5, 17–18, 51–54, 56–58, 61, 63–64)</strong></summary>

- No rate limiting on auth endpoints
- Missing HTTP security headers (`helmet`)
- CSP `unsafe-inline` / `unsafe-eval`
- CORS wildcard, credentialed wildcard, dynamic origin reflection
- Uncapped request body payload (DoS)
- Uncapped file upload (DoS)
- ReDoS — `new RegExp(userInput)`
- Insecure cookies — missing `httpOnly`, `secure`, `sameSite` (single-line and multi-line scan)
- Missing input validation layer (no Zod / Joi / express-validator)
- Sensitive data in logs — passwords / tokens in `console.log`
- Overly permissive `package.json` version ranges (`*`, `latest`)
- `console.error(err)` leaking stack traces
- CORS dynamic origin reflection
- State-changing GET endpoints (CSRF-vulnerable)
</details>

<details>
<summary><strong>🔴 Secrets & Infrastructure (Check 68)</strong></summary>

- Hardcoded secrets in Dockerfile (`ENV`/`ARG`)
- Hardcoded DB password in `docker-compose.yml`
- Hardcoded secret in Terraform `.tf` / `.tfvars`
- Kubernetes Secret manifest committed to git
- GitHub Actions: `pull_request_target` + PR code checkout
- GitHub Actions: `secrets.*` echoed to build log
</details>

<details>
<summary><strong>🔴 Framework-Specific — Next.js (Check 69)</strong></summary>

- `NEXT_PUBLIC_` prefix on secret-named variables (baked into browser bundle)
- API routes without session / auth check
- Server Actions (`"use server"`) without authentication
</details>

<details>
<summary><strong>🟠 Framework-Specific — NestJS (Check 71)</strong></summary>

- Controllers / resolvers with no `@UseGuards()` and no global guard
- Missing global `ValidationPipe` in `main.ts`
- DTO classes without `class-validator` decorators
</details>

<details>
<summary><strong>🟠 Framework-Specific — Fastify (Check 72)</strong></summary>

- Routes without a JSON schema definition
- No `onRequest` / `preHandler` auth hook and no `@fastify/auth` plugin
- Unsafe serializer usage
</details>

<details>
<summary><strong>🟠 GraphQL (Checks 36, 59)</strong></summary>

- Introspection enabled in production
- No query depth / complexity limits
- No field-level authorization (`graphql-shield` or equivalent)
</details>

<details>
<summary><strong>🔴🟠🟡 AI / LLM API Cost Protection (Check 73)</strong></summary>

- No rate limiting on endpoints that call paid LLM APIs (OpenAI, Anthropic, Gemini, Bedrock, Cohere, Mistral, Replicate, Groq, Vercel AI SDK, LangChain)
- LLM endpoint accessible without authentication — anonymous billing abuse
- No `max_tokens` / `maxOutputTokens` cap — unbounded response cost
- User input flows to prompt without length validation
- No per-user token budget tracking or quota enforcement
</details>

<details>
<summary><strong>Supply Chain & Dependencies (Check 33, 58, 80–81)</strong></summary>

- Dependency confusion — scoped packages without private registry in `.npmrc`
- Lifecycle scripts (`preinstall`, `postinstall`, `prepare`) in `package.json`
- `npm audit` — known CVEs in dependency tree (High + Critical only)
- Overly permissive version ranges
- Missing lockfile
</details>

---

## Output format

The scanner produces JSON:

```json
{
  "summary": {
    "total": 12,
    "critical": 2,
    "high": 4,
    "medium": 4,
    "low": 2,
    "confidence": { "high": 5, "medium": 6, "low": 1 },
    "risk_scores": {
      "max": 100,
      "top5": [
        { "id": "SEC-001", "title": "Hardcoded OpenAI Key", "risk_score": 100, "severity": "CRITICAL" }
      ]
    },
    "taint_sources": { "req.body": 3, "req.query": 2 },
    "frameworks_detected": { "nestjs": false, "fastify": false, "graphql": true },
    "by_owasp": { "A03:2021": 4, "A01:2021": 2 }
  },
  "findings": [
    {
      "id": "SEC-001",
      "severity": "CRITICAL",
      "category": "Hardcoded Secret",
      "file": "config/db.js",
      "line": 3,
      "title": "Hardcoded credential in source code",
      "description": "...",
      "snippet": "const apiKey = \"sk-proj-abc123...\"",
      "remediation": "Move to process.env.OPENAI_API_KEY. Add .env to .gitignore. Rotate immediately.",
      "cwe": null,
      "owasp": null,
      "confidence": "HIGH",
      "exploitability": "remote_unauth",
      "taint_source": null,
      "risk_score": 100
    }
  ]
}
```

Claude then uses this JSON to produce the final formatted report.

---

## Repo structure

```
security-audit-skill/
│
├── SKILL.md                    # Claude skill definition — instructions, check catalogue,
│                               # severity model, manual review steps
│
├── scripts/
│   └── scan.js                 # Standalone Node.js scanner (~2,100 lines, no dependencies)
│                               # Usage: node scan.js <root_path>
│                               # Output: JSON { summary, findings }
│
└── references/
    ├── patterns.md             # grep commands and code signatures for every check category
    ├── report-template.md      # Markdown template Claude uses to format the final report
    └── manual-checks.md        # Fallback one-liners if scan.js is unavailable
```

---

## Supported frameworks

The scanner detects which frameworks are in use and activates targeted checks:

| Framework | Detection | Dedicated Checks |
|-----------|-----------|-----------------|
| Express | Always active (baseline) | Headers, CORS, sessions, rate limiting, trust proxy |
| Next.js | `next.config.*` present | `NEXT_PUBLIC_` leaks, API route auth, Server Actions |
| NestJS | `@nestjs` imports | Guards, ValidationPipe, DTO decorators |
| Fastify | `fastify(` call | Schema validation, auth hooks, serializer safety |
| GraphQL | `apollo-server` / `graphql` imports | Introspection, depth limits, field auth |
| AI / LLM | OpenAI / Anthropic / Gemini / etc. SDK imports | Rate limiting, token caps, input size, budget tracking |

---

## Limitations

- **No cross-file taint tracking.** The scanner uses pattern matching, not a full AST data-flow engine. A vulnerability where user input is assigned to an intermediate variable before reaching a sink may not be caught. Complement with [Semgrep](https://semgrep.dev) (`semgrep --config p/nodejs`) for data-flow analysis.
- **No dynamic / runtime analysis.** Use [OWASP ZAP](https://www.zaproxy.org/) or Burp Suite to exercise auth flows, session handling, and injection at runtime.
- **False positives possible.** Results from test files, mocks, and example code are filtered where possible but may still appear. Review `LOW` confidence findings manually.

### Recommended complement tools

| Tool | Purpose |
|------|---------|
| `semgrep --config p/nodejs` | AST-based taint tracking — catches multi-variable data flows |
| `gitleaks detect` | High-entropy secret detection across full git history |
| `trivy fs .` | CVE scanning of dependencies + Dockerfile misconfigurations |
| `npm audit` | Known CVEs in dependency tree (also run by scan.js automatically) |
| OWASP ZAP / Burp Suite | Dynamic testing — runtime auth, session, and injection |

---

## License

MIT