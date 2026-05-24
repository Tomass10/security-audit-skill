---
name: security-audit
description: >
  Perform a comprehensive security audit of a Node.js / JavaScript web application's
  source code. Use this skill whenever the user asks to: audit security, check for
  vulnerabilities, scan for hardcoded secrets, check for SQL injection, review
  security posture, find security issues, check if their app is secure, run a
  security check, look for exposed API keys or passwords, or any variation of
  "is my code secure?". Trigger even for casual phrasing like "check my repo for
  security stuff" or "make sure I didn't leave any passwords in my code". Produces
  a structured, prioritized security report with specific file/line references and
  remediation advice.
---

# Security Audit Skill — Node.js / JavaScript

You are performing a thorough security audit of a Node.js web application.
Your job is to systematically scan the codebase and produce a clear, actionable
report. Be precise: cite file paths and line numbers. Prioritize findings by severity.

---

## Step 1 — Locate the codebase

If the user hasn't specified a path, ask. Common locations:
- Current working directory
- An uploaded zip (extract first with `unzip`)
- A path like `/mnt/user-data/uploads/myapp/`

```bash
find <root> -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.env*" \
  -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.sh" \
  -o -name "*.ejs" -o -name "*.pug" -o -name "*.hbs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" | head -120
```

---

## Step 2 — Run the automated scan script

```bash
node /home/claude/security-audit/scripts/scan.js <root_path>
```

This outputs a JSON object with `summary` and `findings`. Parse it and proceed to Step 3.

If the script fails, fall back to the manual checks in `references/manual-checks.md`.

---

## Step 3 — Deep-dive manual review

After the automated scan, manually inspect:

1. **Auth & session logic** — JWT handling, session config, OAuth state param
2. **Database queries** — string concatenation with user input, ORM raw queries
3. **File upload handlers** — MIME validation, SVG, path bounds, file count limits
4. **WebSocket / SSE handlers** — auth verification before connection accepted
5. **Third-party dependencies** — npm audit, lifecycle scripts, version ranges
6. **Environment config** — NODE_ENV, DEBUG, NEXT_PUBLIC_ misuse, secrets in .env
7. **GraphQL** — introspection flag, depth/complexity validators, field-level auth
8. **Template files (.ejs, .pug, .hbs)** — unescaped output operators
9. **Infrastructure files** — Dockerfile, docker-compose, .github/workflows, .tf, k8s YAML
10. **trust proxy** — verify app.set("trust proxy", ...) matches actual proxy topology
11. **NestJS** — global ValidationPipe present, all controllers have @UseGuards, DTOs have class-validator decorators
12. **Fastify** — every route has a JSON schema, auth hook or @fastify/auth plugin present, serializers don't expose internal fields

```bash
# npm audit — full output saved to avoid truncation
AUDIT_TMP=$(mktemp /tmp/npm-audit-XXXXXX.json)
cd <root> && npm audit --json > "$AUDIT_TMP" 2>/dev/null && cat "$AUDIT_TMP"
rm -f "$AUDIT_TMP"

# npm doctor — checks registry, git, node/npm versions, and permissions
npm doctor

# Dependency tree for manual supply-chain review
npm ls --depth=3 2>/dev/null | head -100
```

### Recommended external tools (complement this scan)
| Tool | Purpose |
|------|---------|
| `semgrep --config p/nodejs` | AST-based taint analysis, catches data-flow issues grep misses |
| `gitleaks detect` | High-entropy secret detection across full git history |
| `trivy fs .` | CVE scanning of dependencies + misconfigurations |
| `eslint-plugin-security` | Inline linting for common security anti-patterns |
| `npm audit --audit-level=moderate` | Known CVEs in dependency tree |
| OWASP ZAP / Burp Suite | Dynamic testing — exercises runtime auth, session, and injection |

---

## Step 4 — Produce the report

Structure your report exactly like the template in `references/report-template.md`.

- **Severity**: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · ℹ️ Info
- Always include: severity, file path, line number, description, remediation
- Group by category, end with Executive Summary + top 3 action items
- Pair every problem with a concrete fix

---

## Scanning Categories (83 checks)

### 🔴 Critical
| # | Category | What to look for |
|---|----------|-----------------:|
| 1 | Hardcoded secrets | Passwords, API keys, tokens, private keys in source |
| 2 | SQL / NoSQL injection | Unsanitized user input in queries |
| 3 | ORM raw query injection | Sequelize.query, knex.raw, Prisma $queryRawUnsafe, sequelize.literal() with user input |
| 4 | Mongoose $where / $function | Server-side JS execution via user-controlled MongoDB operators |
| 5 | Command injection | User input in exec, spawn, execSync, fork() |
| 6 | vm module sandbox escape | vm.runInNewContext / vm.Script used as security boundary |
| 7 | Prototype pollution | Deep merge/clone with user-controlled input (__proto__) |
| 8 | Weak cryptography | MD5/SHA1 for passwords, Math.random() for tokens, no bcrypt |
| 9 | Insecure JWT | none algorithm, jwt.decode(), weak/hardcoded secret |
| 10 | SSJI | User input in setTimeout, setInterval, new Function() |
| 11 | Sensitive file exposure | .env committed, private keys in repo, .git in public dir |
| 12 | Dynamic require() / LFI | require(req.params.x) — arbitrary module load = RCE |
| 13 | Hardcoded DB connection strings | mongodb://user:pass@host embedded in source |

### 🟠 High
| # | Category | What to look for |
|---|----------|-----------------:|
| 14 | XSS — DOM sinks | innerHTML, dangerouslySetInnerHTML |
| 15 | XSS — Template unescaped output | EJS <%-, Pug !=, Handlebars {{{ with user data |
| 16 | XSS — res.send() concatenation | res.send('<p>' + req.query.x + '</p>') |
| 17 | Path traversal — Read | User input in readFile, sendFile, createReadStream |
| 18 | Path traversal — Write | User input in writeFile, appendFile, rename, unlink, mkdir |
| 19 | Brute force exposure | No rate limiting on auth endpoints |
| 20 | Broken access control (IDOR) | findById(req.params.id) without ownership check |
| 21 | Unprotected admin/debug routes | /admin, /debug, /metrics, /graphiql without auth middleware |
| 22 | SSRF — primary clients | axios, fetch, got, request, http.get with user-controlled URL |
| 23 | SSRF — additional clients | superagent, undici, ky, needle, urllib, phin with user URL |
| 24 | Mass assignment — model methods | req.body to DB model directly; Mongoose strict:false |
| 25 | Mass assignment — Object.assign / spread | Object.assign(user, req.body) or { ...req.body } in model |
| 26 | Missing CSRF protection | Cookie sessions with no csrf-csrf / doubleCsrf |
| 27 | OAuth state param absence | Passport OAuth strategy without state validation |
| 28 | WebSocket / SSE auth bypass | ws/socket.io connection handler with no auth check |
| 29 | Session fixation | Login without req.session.regenerate() |
| 30 | Insecure session config | Weak secret, MemoryStore, resave:true, saveUninitialized:true |
| 31 | CSP unsafe-inline / unsafe-eval | Helmet present but CSP is deliberately weakened |
| 32 | Insecure CORS — credentials+wildcard | credentials:true + origin:* combination |
| 33 | CORS always-allow origin | Origin callback unconditionally returns true |
| 34 | Insecure JWT — no algorithms whitelist | jwt.verify() without algorithms option |
| 35 | Insecure file upload — path | .mv() with user-controlled filename |
| 36 | Insecure deserialization | unserialize(), yaml.load() on user data |
| 37 | Supply chain — dependency confusion | Scoped packages without private registry in .npmrc |
| 38 | ReDoS | new RegExp(userInput) |
| 39 | Weak bcrypt cost factor | Cost factor < 10 |
| 40 | crypto.createCipher (deprecated) | Weak MD5 key derivation, no IV |
| 41 | AES-ECB mode | Deterministic cipher mode leaks plaintext patterns |
| 42 | express.static serving project root | Exposes .env, package.json, source over HTTP |
| 43 | GraphQL introspection enabled | Schema exposed in production |
| 44 | GraphQL no depth/complexity limits | DoS via deeply nested queries |
| 45 | SSTI | User input as template name or raw context in res.render() |
| 46 | JSONP callback injection | req.query.callback reflected without validation |
| 47 | Password reset token — no expiry | Reset token queried without expiry/date check |
| 48 | .env not in .gitignore | Project uses .env but .gitignore does not protect it |
| 49 | ORM where-clause injection | req.body used as Sequelize/TypeORM where object |

### 🟡 Medium
| # | Category | What to look for |
|---|----------|-----------------:|
| 50 | Insecure CORS — wildcard | Access-Control-Allow-Origin: * standalone |
| 51 | Missing HTTP security headers | No helmet, no manual CSP/HSTS/X-Frame |
| 52 | Insecure cookies | Missing httpOnly, secure, sameSite flags (single-line + multi-line scan) |
| 53 | Insecure file upload — MIME spoofing | No fileFilter/mimetype check in multer |
| 54 | DoS — uncapped body payload | express.json() / urlencoded() without limit |
| 55 | DoS — uncapped file upload | multer without fileSize/files limits |
| 56 | HTTP Parameter Pollution | No hpp middleware, req.query used throughout |
| 57 | Missing input validation layer | No Zod/Joi/express-validator, req.body used |
| 58 | Sensitive data in logs | Passwords/tokens in console.log / morgan in production |
| 59 | Open redirect — direct | res.redirect(req.query.url) |
| 60 | Open redirect — returnTo | req.session.returnTo redirected without allowlist |
| 61 | Host header injection | req.headers.host used to build URLs |
| 62 | Zip Slip | Archive extraction without path bounds check |
| 63 | Subdomain takeover risk | Dangling CNAME to deprovisioned cloud service |
| 64 | Timing attack exposure | === on HMAC/token comparison |
| 65 | Unhandled promise rejections | No unhandledRejection handler, no express-async-errors |
| 66 | Supply chain — lifecycle scripts | preinstall/postinstall/prepare scripts in package.json |
| 67 | NODE_ENV=development in config | Debug mode enabled in production .env |
| 68 | Prototype pollution — iteration | Object.keys() / for...in on req.body |
| 69 | Prototype pollution — dynamic key | req.body[key][sub] nested bracket access |
| 70 | JSONP res.jsonp() endpoint | Legacy JSONP pattern — verify callback validation |
| 71 | GraphQL — no field-level authorization | No graphql-shield or equivalent per-field auth |
| 72 | XSS — res.send() template literal | Multi-line template literal in res.send() with user input |

### 🔵 Low / Info
| # | Category | What to look for |
|---|----------|-----------------:|
| 73 | Leaky error handling | err.message / err.stack returned to client |
| 74 | console.error(err) in production | Full stack trace unconditionally written to stdout |
| 75 | XXE | XML parsing library without entity expansion disabled |
| 76 | X-Powered-By not suppressed | Express version fingerprinting |
| 77 | HSTS explicitly disabled | helmet({ hsts: false }) |
| 78 | Source maps in production | *.js.map files in served directories |
| 79 | Sensitive data in URL params | ?token=, ?apiKey= in routes or fetch calls |
| 80 | Missing lockfile | No package-lock.json / yarn.lock |
| 81 | Overly permissive version ranges | *, latest, >= 0 in package.json dependencies |
| 82 | Missing SRI on CDN scripts | <script src="https://cdn..."> without integrity= |
| 83 | Hardcoded internal IPs | 10.x / 172.16.x / 192.168.x in config files |
| 84 | Unsafe parseInt / Number | parseInt without radix 10, Number() on user input |
| 85 | DEBUG variable enabled | DEBUG=* in .env |
| 86 | NODE_ENV not configured | NODE_ENV absent from .env |
| 87 | Server binding to 0.0.0.0 | app.listen(..., "0.0.0.0") behind a reverse proxy |
| 88 | morgan logging in production | morgan("combined") / morgan("dev") always active |
| 89 | Missing Referrer-Policy | Sensitive token routes without Referrer-Policy header |
| 90 | Cookie flags — multi-line config | Second-pass context scan confirming missing flags |

### 🔴 Critical (infrastructure & cloud)
| # | Category | What to look for |
|---|----------|-----------------:|
| 91 | Hardcoded secret in Dockerfile | ENV/ARG with password/key/token values |
| 92 | GitHub Actions pull_request_target + PR checkout | Secrets exfiltration from CI |
| 93 | Hardcoded secret in Terraform | Plaintext values in .tf / .tfvars |
| 94 | Next.js NEXT_PUBLIC_ secret exposure | Secret-named vars baked into browser bundle |

### 🟠 High (infrastructure & cloud)
| # | Category | What to look for |
|---|----------|-----------------:|
| 95 | Hardcoded DB password in docker-compose | POSTGRES_PASSWORD etc. plaintext |
| 96 | Kubernetes Secret manifest committed | kind:Secret with inline base64 data |
| 97 | CORS — dynamic origin reflection | req.headers.origin echoed into Allow-Origin |
| 98 | SSRF — http.request() with user input | Node.js built-in request with user URL |
| 99 | SSRF — webhook / image-proxy pattern | Forwarding endpoints with user-controlled URL |
| 100 | eval() with JSON concatenation | eval('(' + json + ')') deserialization RCE |
| 101 | SVG in upload allowlist | SVG executes JS when opened in browser |
| 102 | ImageMagick / gm RCE surface | Known critical CVE history, policy.xml required |
| 103 | GitHub Actions — secret echoed to log | secrets.* in run: echo command |
| 104 | Session fixation after login | No session.regenerate() after auth |
| 105 | Next.js API route without auth | pages/api or app/api route with no session check |

### 🟡 Medium (infrastructure & framework)
| # | Category | What to look for |
|---|----------|-----------------:|
| 106 | trust proxy: true | Spoofable req.ip, broken rate limiting |
| 107 | State-changing GET endpoint | GET /delete, GET /reset — CSRF-vulnerable |
| 108 | Double-extension bypass | .split(".") instead of path.extname() on filenames |
| 109 | Next.js Server Action without auth | "use server" file without session check |
| 110 | GraphQL — no field-level authorization | No graphql-shield or equivalent |

### 🟠 High (NestJS-specific)
| # | Category | What to look for |
|---|----------|-----------------:|
| 111 | NestJS — Missing @UseGuards | Controllers/resolvers with no auth guard and no global guard in main.ts |
| 112 | NestJS — Missing Global ValidationPipe | No `useGlobalPipes(new ValidationPipe(...))` in main.ts |

### 🟠 High (Fastify-specific)
| # | Category | What to look for |
|---|----------|-----------------:|
| 113 | Fastify — Routes Without JSON Schema | Routes registered without a `schema:` body/response definition |
| 114 | Fastify — No Auth Hook | No `addHook("onRequest")`/`preHandler` and no `@fastify/auth` plugin |

### 🟡 Medium (NestJS / Fastify)
| # | Category | What to look for |
|---|----------|-----------------:|
| 115 | NestJS — DTO Without class-validator | DTO class with no `@IsString` / `@IsEmail` / etc. annotations |
| 116 | Fastify — Unsafe Serializer | `fast-json-stringify` or `serialize-javascript` without a strict response schema |

### 🔴 Critical (AI / LLM cost protection)
| # | Category | What to look for |
|---|----------|-----------------:|
| 118 | AI/LLM — No Rate Limiting | LLM SDK in use but no `express-rate-limit` / `rate-limiter-flexible` anywhere |
| 119 | AI/LLM — Unauthenticated Endpoint | File making LLM API calls with no auth guard — open to anonymous abuse |

### 🟠 High (AI / LLM cost protection)
| # | Category | What to look for |
|---|----------|-----------------:|
| 120 | AI/LLM — No Output Token Cap | LLM calls with no `max_tokens` / `maxOutputTokens` — unbounded response cost |
| 121 | AI/LLM — No Input Size Limit | User input flows to prompt with no `.length` check or truncation |

### 🟡 Medium (AI / LLM cost protection)
| # | Category | What to look for |
|---|----------|-----------------:|
| 122 | AI/LLM — No Per-User Budget Tracking | No `usage.total_tokens` logging or monthly quota enforcement per user |

### 🔵 Low (heuristic)
| # | Category | What to look for |
|---|----------|-----------------:|
| 123 | High-entropy string literal | Shannon entropy > 4.5 on 32+ char strings |

> **Output fields per finding:** `id`, `severity`, `category`, `file`, `line`, `title`, `description`, `snippet`, `remediation`, `cwe`, `owasp`, `confidence`, `exploitability`, `taint_source`, `risk_score`
> The summary block also includes confidence breakdown, OWASP category counts, **top-5 findings by risk score**, **taint source breakdown**, and **detected frameworks**.

> **Risk score formula:** `(severity_weight × confidence_weight × exploitability_weight) / max` — normalized 0–100. Use to prioritize within the same severity band.

> **Taint source** labels which `req.*` source (`req.body`, `req.query`, `req.params`, etc.) flows into the sink when detectable by pattern matching.

> **Scanner limit:** Pattern matching cannot track data across intermediate variables. Always complement with manual review of critical auth/DB/file flows, and dynamic tools (OWASP ZAP, Semgrep `p/nodejs`) for production apps.

Read `references/patterns.md` for grep commands and code signatures for each category.
