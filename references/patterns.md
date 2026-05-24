# Security Patterns Reference — Node.js

Patterns to search for in each audit category. Use `grep -rn` or the scan script.

---

## 1. Hardcoded Secrets

### High-signal regex patterns
```
# Generic secret assignment
(password|passwd|pwd|secret|api_key|apikey|api_token|auth_token|access_token|private_key|client_secret)\s*[:=]\s*['"][^'"]{6,}['"]

# Common service keys (high precision)
AKIA[0-9A-Z]{16}                          # AWS Access Key ID
sk-[a-zA-Z0-9]{32,}                       # OpenAI / Stripe secret key
ghp_[a-zA-Z0-9]{36}                       # GitHub personal access token
xox[baprs]-[0-9a-zA-Z]{10,}              # Slack token
AIza[0-9A-Za-z\-_]{35}                    # Google API key
-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE   # Private keys
```

### False-positive filters (skip these)
- `process.env.` prefixed values → safe
- `os.environ` prefixed values → safe
- Placeholder strings like `your-api-key-here`, `<API_KEY>`, `TODO`
- Test/mock values clearly labeled as such

### grep command
```bash
grep -rn -iE "(password|api_key|secret|token|private_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]" \
  --include="*.js" --include="*.ts" --include="*.json" --include="*.env" \
  --exclude-dir=node_modules --exclude-dir=.git <root>
```

---

## 2. SQL / NoSQL Injection

### Patterns — SQL
```javascript
// Dangerous: string concatenation in queries
db.query("SELECT * FROM users WHERE id = " + req.params.id)
db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`)

// Dangerous: template literals with user input
const sql = `DELETE FROM sessions WHERE token = '${token}'`
```

### Patterns — NoSQL (MongoDB)
```javascript
// Dangerous: direct use of req.body/params in find()
User.find({ email: req.body.email })        // could be {$gt: ''} injection
Model.findOne(req.query)                     // entire query object from user
```

### What to look for
- `.query(` or `.execute(` with `+` or template literals containing `req.`
- `.find(req.` / `.findOne(req.` / `.where(req.`
- Raw SQL strings built from user inputs without parameterization

### grep command
```bash
grep -rn -E "(\.query|\.execute)\s*\([^)]*req\.(body|params|query)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "\.find(One)?\s*\(\s*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 3. XSS (Cross-Site Scripting)

### Dangerous patterns
```javascript
element.innerHTML = userInput           // DOM XSS
document.write(req.query.search)        // Reflected XSS
res.send('<h1>' + req.params.name)      // Server-side XSS
dangerouslySetInnerHTML={{ __html: x }} // React - dangerous
```

### grep command
```bash
grep -rn -E "(innerHTML|outerHTML|document\.write|\.html\()\s*[=\(]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx" \
  --exclude-dir=node_modules <root>
```

---

## 4. Brute Force Exposure

### What to look for
- Login/auth endpoints WITHOUT rate limiting middleware
- Absence of `express-rate-limit`, `rate-limiter-flexible`, or similar
- No account lockout logic

### grep command
```bash
# Find auth routes
grep -rn -E "(\/login|\/signin|\/auth|\/token)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Check if rate limiting is imported anywhere
grep -rn "rate.limit\|rateLimit\|rateLimiter" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

If auth routes exist but rate limiting is not imported → flag as High.

---

## 5. Insecure HTTP Headers

### What to look for
- Absence of `helmet` or equivalent header middleware
- `Access-Control-Allow-Origin: *` with credentials
- Missing `Content-Security-Policy`

### grep command
```bash
grep -rn "helmet\|csp\|Content-Security-Policy\|HSTS\|X-Frame" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn "Access-Control-Allow-Origin" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 6. Sensitive File Exposure

### Files that should NOT be committed
```
.env
.env.local / .env.production / .env.staging
*.pem / *.key / *.p12 / *.pfx
id_rsa / id_ed25519
config/secrets.* 
database.yml with credentials
```

### grep command
```bash
# Check if .env exists in repo (not just .env.example)
find <root> -name ".env" ! -name ".env.example" ! -path "*/node_modules/*"

# Find private key files
find <root> \( -name "*.pem" -o -name "*.key" -o -name "id_rsa" \) \
  ! -path "*/node_modules/*"

# Check .gitignore covers secrets
cat <root>/.gitignore 2>/dev/null | grep -E "\.env|\.key|\.pem"
```

---

## 7. Path Traversal

### Dangerous patterns
```javascript
fs.readFile(req.params.file)                        // direct user input
path.join(__dirname, req.query.filename)            // not validated
res.sendFile(req.body.path)                         // user-controlled path
```

### grep command
```bash
grep -rn -E "(readFile|readFileSync|sendFile|createReadStream)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 8. CSRF

### What to look for
- POST/PUT/DELETE routes without CSRF protection
- Absence of `csurf`, `csrf-csrf`, or SameSite cookie attributes
- APIs that use cookie-based auth without CSRF tokens

### grep command
```bash
grep -rn "csurf\|csrf\|SameSite" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 9. Dangerous Eval / Deserialization

### Patterns
```javascript
eval(userInput)
new Function(req.body.code)()
vm.runInNewContext(req.query.script)
JSON.parse(req.body)           // OK on its own, but watch for __proto__ pollution
```

### grep command
```bash
grep -rn -E "\beval\s*\(" --include="*.js" --include="*.ts" \
  --exclude-dir=node_modules <root>

grep -rn "new Function\(" --include="*.js" --include="*.ts" \
  --exclude-dir=node_modules <root>
```

---

## 10. Sensitive Data in Logs

### Patterns
```javascript
console.log("password:", req.body.password)
logger.info({ user, token })
console.log(req.headers.authorization)
```

### grep command
```bash
grep -rn -iE "(console\.(log|info|warn|error)|logger\.(info|debug))\s*\([^)]*\b(password|token|secret|key|auth)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 11. Mass Assignment

### Patterns
```javascript
// Dangerous: spreading entire req.body into DB model
User.create(req.body)
Object.assign(user, req.body)
await Model.update(req.body, { where: { id } })
```

### grep command
```bash
grep -rn -E "\.(create|update|insert)\s*\(\s*req\.body" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn "Object\.assign\s*\([^,]+,\s*req\.body" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 12. Command Injection 🔴

### Dangerous patterns
```javascript
exec("ls " + req.body.folder)                    // classic injection
execSync(`convert ${req.params.filename}`)       // template literal
spawn("sh", ["-c", req.query.cmd])              // shell: true is the danger
child_process.exec(userInput)
```

### What to look for
- Any `exec`, `execSync`, `spawn`, `spawnSync`, `execFile` call where an argument
  contains `req.body`, `req.params`, `req.query`, or any user-derived variable
- `shell: true` option in `spawn`/`spawnSync` (enables shell injection even with arrays)

### grep command
```bash
grep -rn -E "(exec|execSync|execFile|spawn|spawnSync)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Also catch indirect: variable assigned from req.* then passed to exec
grep -rn -E "\bshell\s*:\s*true" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 13. Prototype Pollution 🔴

### Dangerous patterns
```javascript
_.merge(target, req.body)                        // lodash merge with user input
Object.assign({}, req.body)                      // shallow — less dangerous
deepmerge(obj, req.body)                         // deep merge libraries
JSON.parse(req.body).__proto__                   // manual prototype access
```

### What to look for
- Deep merge / extend / clone functions receiving user-controlled input
- Any object key access pattern like `obj[key][value]` where key/value come from req
- Libraries: `lodash.merge`, `deepmerge`, `jquery.extend`, `hoek.merge`

### grep command
```bash
grep -rn -E "\b(merge|extend|deepmerge|deepClone)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "req\.(body|query|params)\[.*\]\[" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Check if express body parser has prototype pollution protection
grep -rn "express-mongo-sanitize\|hpp\|@hapi/hoek" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

---

## 14. Broken Access Control / IDOR 🔴

### Dangerous patterns
```javascript
// No ownership check — any authenticated user can access any record
User.findById(req.params.id)
Order.findOne({ _id: req.params.id })            // missing: userId: req.user.id
Post.update({ id: req.body.id }, data)           // no owner verification
```

### What to look for
- `findById(req.params.id)` without a subsequent ownership check
- `findOne({ _id: ... })` missing a `userId`/`ownerId` field in the query
- Admin-only routes missing role/permission middleware
- Routes that accept an ID parameter and return data without verifying the requestor owns it

### grep command
```bash
grep -rn -E "findById\s*\(\s*req\.(params|body|query)\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "findOne\s*\(\s*\{[^}]*_id\s*:\s*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

Manual review: for each hit, check whether `req.user.id` or equivalent appears
in the same query or in a follow-up ownership assertion.

---

## 15. Weak Cryptography / Hashing 🔴

### Dangerous patterns
```javascript
crypto.createHash('md5').update(password)        // MD5 for passwords
crypto.createHash('sha1').update(password)       // SHA1 for passwords
Math.random()                                    // not cryptographically secure
Math.floor(Math.random() * 1000000)              // insecure token generation
```

### What to look for
- MD5 / SHA1 used on password or sensitive data
- `Math.random()` used for token, OTP, reset link, session ID generation
- Missing `bcrypt`, `argon2`, or `scrypt` for password hashing

### grep command
```bash
grep -rn -E "createHash\s*\(\s*['\"]md5['\"]|createHash\s*\(\s*['\"]sha1['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "Math\.random\s*\(\s*\)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Check if bcrypt/argon2 is used
grep -rn "bcrypt\|argon2\|scrypt" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

If password-handling code exists without bcrypt/argon2 → flag as Critical.

---

## 16. Insecure JWT Implementation 🔴

### Dangerous patterns
```javascript
jwt.verify(token, secret, { algorithms: ['none'] })   // accepts unsigned tokens
jwt.decode(token)                                      // no verification at all!
jwt.sign(payload, 'secret')                            // weak/hardcoded secret
jwt.verify(token, secret)                              // missing expiresIn check
```

### What to look for
- `algorithms: ['none']` or `algorithm: 'none'` in verify options
- `jwt.decode()` used instead of `jwt.verify()` for auth decisions
- Hardcoded JWT secrets (short strings, dictionary words)
- `jwt.sign()` without `expiresIn`
- Missing `issuer`/`audience` validation

### grep command
```bash
grep -rn -E "jwt\.(decode|verify|sign)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "algorithms.*none|algorithm.*none" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# jwt.decode without a nearby jwt.verify is suspicious
grep -rn "jwt\.decode" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 17. SSRF — Server-Side Request Forgery 🟠

### Dangerous patterns
```javascript
axios.get(req.body.url)                          // user controls destination
fetch(req.query.endpoint)                        // internal network reachable
http.get(req.params.url, callback)
request(req.body.webhookUrl)
```

### What to look for
- HTTP client calls (`axios`, `fetch`, `got`, `node-fetch`, `request`, `http.get`)
  where the URL is derived from user input without validation
- Missing allowlist of permitted domains/schemes

### grep command
```bash
grep -rn -E "(axios|fetch|got|request|http\.get|https\.get)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 18. DoS via Uncapped Payloads 🟠

### What to look for
- `express.json()` or `express.urlencoded()` without a `limit` option
- `multer` or file upload handlers without size restrictions
- No global payload size cap middleware

### grep command
```bash
grep -rn -E "express\.(json|urlencoded)\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

Check each hit: if no `limit:` key is present in the options object → flag as Medium.

```bash
# Also check for multer limits
grep -rn "multer\|fileSize\|limits" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 19. ReDoS — Regex Denial of Service 🟠

### Dangerous patterns
```javascript
// Catastrophic backtracking patterns applied to user input
/^(a+)+$/.test(req.body.input)
/(x+x+)+y/.test(userInput)
new RegExp(req.query.pattern)                    // user-controlled regex!
```

### What to look for
- `new RegExp(userInput)` — user controlling the regex itself (Critical)
- Nested quantifiers in custom regex: `(a+)+`, `(a|a)+`, `(.*)*`
- Complex alternation with overlapping groups applied to unbounded input

### grep command
```bash
grep -rn -E "new RegExp\s*\(\s*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Find potentially catastrophic patterns (manual review needed)
grep -rn -E "/(\(.+\+\).+\+|\(.+\|\))" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 20. Insecure Cookie / Session Management 🟠

### Dangerous patterns
```javascript
res.cookie('session', token)                     // no flags set
res.cookie('auth', jwt, { httpOnly: false })     // JS-accessible
app.use(session({ cookie: {} }))                 // no Secure/SameSite
```

### What to look for
- Cookies set without `httpOnly: true` → XSS can steal them
- Cookies set without `secure: true` → sent over HTTP
- Cookies without `sameSite: 'strict'` or `'lax'` → CSRF risk
- Session middleware without `resave: false, saveUninitialized: false`

### grep command
```bash
grep -rn -E "res\.cookie\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "app\.use\s*\(\s*session\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

For each hit, check whether `httpOnly`, `secure`, and `sameSite` are all set.

---

## 21. Leaky Error Handling 🟡

### Dangerous patterns
```javascript
res.status(500).json({ error: err.message })     // stack info to client
res.send(err.stack)                              // full stack trace
next(err)                                        // unfiltered error forwarding
console.error(err); res.json({ err })
```

### What to look for
- `err.message`, `err.stack`, or the raw `err` object sent in responses
- No `NODE_ENV === 'production'` guard around detailed error output
- Missing global error handler that sanitizes before responding

### grep command
```bash
grep -rn -E "res\.(json|send|status)\s*\([^)]*err\.(message|stack)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 22. XXE — XML External Entity 🟡

### What to look for
- XML parsing libraries: `xml2js`, `fast-xml-parser`, `libxmljs`, `sax`, `expat`
- Entity expansion not disabled in parser options
- User-supplied XML being parsed

### grep command
```bash
grep -rn -E "require\s*\(\s*['\"]xml2js|fast-xml-parser|libxmljs|sax['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "parseString|parseXml|xml\.parse" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

If XML parsing found: verify `processEntities: false` (fast-xml-parser) or
`resolve_externals: false` (libxmljs) is set.

---

## 23. Open Redirect 🟠

### Dangerous patterns
```javascript
res.redirect(req.query.url)              // attacker controls destination
res.redirect(req.body.returnTo)
res.redirect(req.params.next)
```

### What to look for
- `res.redirect()` called with any `req.query`, `req.body`, or `req.params` value
- No allowlist validation of destination URLs
- Relative-path bypass tricks: `//evil.com`, `/\evil.com`

### grep command
```bash
grep -rn -E "res\.redirect\s*\(\s*req\.(query|body|params)\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 24. Server-Side Template Injection (SSTI) 🟠

### Dangerous patterns
```javascript
res.render(req.query.page, data)         // user controls template name → RCE
res.render('view', req.query)            // raw user object as template context
res.render('view', req.body)             // Pug/EJS prototype pollution via context
```

### What to look for
- `res.render()` where the first argument (template name) comes from user input
- `res.render()` where the second argument (context) is `req.body` or `req.query` unfiltered
- Template engines in use: Pug, EJS, Handlebars, Nunjucks, Mustache

### grep command
```bash
grep -rn -E "res\.render\s*\(\s*req\.(query|body|params)|res\.render\s*\([^,]+,\s*req\.(query|body|params)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 25. Timing Attack Exposure 🟡

### Dangerous patterns
```javascript
if (signature === expected)              // early-exit leaks timing info
if (token !== storedToken)
if (hmac == req.headers['x-signature'])
```

### What to look for
- `===` or `!==` used to compare HMAC signatures, webhook secrets, API tokens, or hashes
- Absence of `crypto.timingSafeEqual()` in auth/verification code

### grep command
```bash
grep -rn -E "if\s*\(\s*(signature|hash|hmac|token)\s*[=!]=\s*" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 26. Weak Bcrypt Configuration 🟠

### Dangerous patterns
```javascript
bcrypt.hash(password, 4)                 // < 10 rounds — GPU-crackable
bcrypt.hashSync(password, 1)
```

### What to look for
- `bcrypt.hash()` or `bcrypt.hashSync()` with a cost factor of 1–9
- Recommended minimum: 12 (balances security and latency)

### grep command
```bash
grep -rn -E "bcrypt\.hash(Sync)?\s*\([^,]+,\s*[1-9]\s*\)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 27. Missing CSRF Protection 🟠

### What to look for
- `res.cookie()` used for session management (detected elsewhere)
- No `csurf`, `csrf-csrf`, `double-csrf`, or equivalent middleware anywhere
- No `SameSite: strict` applied globally as a substitute

### grep command
```bash
grep -rn "csurf\|csrf-csrf\|double-csrf\|doubleCsrf" \
  --include="*.js" --include="*.ts" --include="package.json" \
  --exclude-dir=node_modules <root>
```

If `res.cookie()` is used AND no CSRF middleware is found → flag as High.

---

## 28. Insecure File Upload 🟠

### Dangerous patterns
```javascript
req.files.upload.mv('./uploads/' + req.files.upload.name)   // user-controlled name
req.files.photo.mv(uploadDir + req.body.filename)           // path traversal risk
```

### What to look for
- `.mv()` (express-fileupload) called with a path derived from `req.files` or `req.body`
- No UUID-based renaming of uploaded files
- No file extension/MIME-type allowlist validation

### grep command
```bash
grep -rn -E "\.mv\s*\(\s*[^,]*req\.(files|body)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "filename\s*:\s*function.*req" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 29. Server-Side JavaScript Injection (SSJI) 🔴

### Dangerous patterns
```javascript
setTimeout(req.body.code, 1000)          // string arg → evaluated as code
setInterval(req.query.fn, 500)
new Function(req.params.handler)()
```

### What to look for
- `setTimeout` or `setInterval` where the **first** argument comes from user input (string form = RCE)
- `new Function(userInput)` — identical to `eval()`
- Note: `setTimeout(() => fn(), req.body.delay)` is safe — the delay arg is not evaluated as code

### grep command
```bash
grep -rn -E "\b(setTimeout|setInterval|Function)\s*\(\s*req\.(body|query|params)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 30. Insecure Deserialization 🟠

### Dangerous patterns
```javascript
unserialize(req.body.data)               // node-serialize → IIFE RCE
yaml.load(req.body.config)               // js-yaml v3 → arbitrary object instantiation
deserialize(userInput)
```

### What to look for
- `node-serialize` / `unserialize()` with user data
- `yaml.load()` (unsafe) instead of `yaml.safeLoad()` (js-yaml v3) or `FAILSAFE_SCHEMA` (v4)
- Any generic `deserialize()` call receiving external input

### grep command
```bash
grep -rn -E "\b(unserialize|deserialize|yaml\.load)\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

Skip hits containing `safeLoad` — those are safe.

---

## 31. Host Header Injection 🟡

### Dangerous patterns
```javascript
const resetUrl = `https://${req.headers.host}/reset?token=${token}`
const base = req.get('host')
sendEmail({ link: `http://${req.headers.host}/verify` })
```

### What to look for
- `req.headers.host` or `req.get('host')` used in string concatenation or template literals
- Especially dangerous in password reset emails, OAuth callbacks, email verification links

### grep command
```bash
grep -rn -E "req\.(headers\.host|get\s*\(['\"]host['\"]\))" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

---

## 32. Zip Slip 🟡

### Dangerous patterns
```javascript
zip.extractAllTo('./uploads/')           // adm-zip without path validation
tar.extract({ cwd: dest })              // tar without entry path check
await extract(zipPath, { dir: dest })   // extract-zip without validation
```

### What to look for
- `adm-zip`, `tar`, `extract-zip`, `unzipper`, `jszip` used to extract user-uploaded archives
- No `path.resolve()` + bounds check before writing each entry

### grep command
```bash
grep -rn -E "['\"](adm-zip|tar|extract-zip|unzipper|jszip)['\"]" \
  --include="*.js" --include="*.ts" --include="package.json" \
  --exclude-dir=node_modules <root>
```

For each hit, check whether entry paths are validated:
```javascript
// Required guard
const dest = path.resolve(EXTRACT_DIR, entry.path);
if (!dest.startsWith(path.resolve(EXTRACT_DIR) + path.sep)) {
  throw new Error('Zip Slip blocked');
}
```

---

## ⚠️ Inherent Limits of Static Scanning

This scanner is regex-based. Be aware of two structural limitations:

**Data flow blindness** — Intermediate variables are not tracked:
```javascript
const data = req.body;         // assignment
db.query(data);                // scanner misses this — no 'req.' on this line
```
Always manually review data flows for critical paths (auth, DB queries, file ops).

**False positives** — Context matters:
```javascript
setTimeout(myFunc, req.body.delay)   // safe — delay is a number, not code
```
The scanner flags the pattern; you must confirm the first arg is not a string from user input.

For production security, complement this scan with:
- **Dynamic analysis**: OWASP ZAP, Burp Suite
- **Dedicated SAST tools**: Semgrep with `p/nodejs` ruleset, Snyk Code
- **Penetration testing** for critical applications

---

## 33. Dependency Confusion / Supply Chain Attack 🟠

### What to look for
- Scoped packages (e.g. `@company/utils`) in `package.json` with **no** private registry configured in `.npmrc`
- Absence of `@scope:registry=https://...` in `.npmrc` for internal packages
- Internal package names that are not claimed/stubbed on the public npm registry

### Why it matters
If `@acme/auth` resolves from the public registry instead of your private one, an attacker who publishes a package with that name at a higher version can silently inject malicious code into CI/CD builds.

### grep / check commands
```bash
# Find scoped packages
cat package.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(k for k in {**d.get('dependencies',{}),**d.get('devDependencies',{})} if k.startswith('@')))"

# Check .npmrc for private registry
cat .npmrc 2>/dev/null | grep registry
```

If scoped packages exist and `.npmrc` has no non-npmjs.org registry → flag as High.

### Remediation
```ini
# .npmrc — lock all @acme packages to your private registry
@acme:registry=https://your-registry.example.com
always-auth=true
```
Also: stub every internal package name on the public npm registry (even as a 0.0.1 placeholder) to block squatting.

---

## 34. HTTP Parameter Pollution (HPP) 🟡

### What to look for
- Routes that read `req.query.*` without HPP middleware
- Absence of `hpp` package in `package.json` or middleware setup

### Dangerous pattern
```
GET /api/users?role=user&role=admin
// Express: req.query.role → ['user', 'admin']
// req.query.role.toString() → 'user,admin' (bypasses equality checks)
```

### grep command
```bash
# Check if hpp is installed
grep -r "hpp\|http-parameter-pollution" --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>

# Check extent of req.query usage
grep -rn "req\.query\." --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

If `req.query` is used and `hpp` is absent → flag as Medium.

### Remediation
```bash
npm install hpp
```
```javascript
app.use(hpp());
// Allow specific params to be arrays:
app.use(hpp({ whitelist: ['tags', 'filters'] }));
```

---

## 35. Subdomain Takeover Risk 🟡

### What to look for
- CNAME records or config references pointing at cloud hostnames for services that may have been deprovisioned:
  - `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`
  - `*.s3.amazonaws.com`, `*.elasticbeanstalk.com`
  - `*.github.io`, `*.netlify.app`, `*.vercel.app`, `*.fly.dev`
  - `*.myshopify.com`, `*.statuspage.io`, `*.surge.sh`

### grep command
```bash
grep -rn -iE "(CNAME|target|hostname|endpoint).*(azurewebsites\.net|s3\.amazonaws\.com|github\.io|netlify\.app|vercel\.app|elasticbeanstalk\.com|surge\.sh|fly\.dev)" \
  --include="*.yaml" --include="*.yml" --include="*.json" --include="*.conf" \
  --include="*.tf" --include="*.sh" --exclude-dir=node_modules <root>
```

### Remediation
```bash
# For each suspicious CNAME target, verify it resolves to a live, owned resource:
dig CNAME sub.yourdomain.com
curl -I https://<cname-target>  # should return your content, not 404/unclaimed page
```
Delete DNS entries immediately when decommissioning cloud services.

---

## 36. GraphQL Security Issues 🟠

### What to look for
- `introspection: true` in Apollo Server config (or no explicit `introspection: false`)
- Absence of `graphql-depth-limit` or `graphql-query-complexity` in validation rules
- GraphQL endpoint accessible without authentication

### Dangerous patterns
```javascript
// Introspection enabled in production (default is true)
new ApolloServer({ schema });  // no introspection: false

// No depth/complexity limits
new ApolloServer({ schema, validationRules: [] });

// Deeply nested DoS query:
// { user { friends { friends { friends { friends { name } } } } } }
```

### grep command
```bash
# Detect GraphQL usage
grep -rn "graphql\|apollo-server\|apollo/server\|nexus\|type-graphql" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>

# Check introspection setting
grep -rn "introspection" --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Check depth/complexity limits
grep -rn "depthLimit\|depth.limit\|complexityLimit\|graphql-depth-limit\|graphql-query-complexity" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

### Remediation
```bash
npm install graphql-depth-limit graphql-query-complexity
```
```javascript
import depthLimit from 'graphql-depth-limit';
import { createComplexityRule } from 'graphql-query-complexity';

new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== 'production',
  validationRules: [
    depthLimit(10),
    createComplexityRule({ maximumComplexity: 1000 }),
  ],
});
```

---

## 37. Unsafe Object.keys() / for...in on req.body 🟡

### What to look for
- `Object.keys(req.body)` or `for (const key in req.body)` patterns
- These expose prototype-polluted keys to downstream logic

### Dangerous pattern
```javascript
// An attacker sends: { "__proto__": { "isAdmin": true } }
// After pollution, Object.keys(req.body) may surface injected keys
for (const key in req.body) {
  model[key] = req.body[key];  // writes polluted prototype keys into model
}
```

### grep command
```bash
grep -rn -E "Object\.keys\s*\(\s*req\.(body|query|params)\s*\)|for\s*\(.*in\s+req\.(body|query|params)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Use an explicit allowlist instead of iterating user keys:
const ALLOWED = ['name', 'email', 'bio'];
const safe = Object.fromEntries(
  ALLOWED.filter(k => Object.hasOwn(req.body, k)).map(k => [k, req.body[k]])
);
// Or use express-mongo-sanitize to strip __proto__ keys at the middleware layer:
app.use(require('express-mongo-sanitize')());
```

---

## 38. CORS: credentials:true + Wildcard Origin 🟠

### What to look for
- `credentials: true` in CORS config alongside `origin: '*'` or `Access-Control-Allow-Origin: *`
- This combination is the actually dangerous CORS misconfiguration; a plain wildcard without credentials is far less impactful

### Dangerous pattern
```javascript
// CRITICAL — allows any site to make authenticated cross-origin requests
app.use(cors({ origin: '*', credentials: true }));

// Also dangerous when set as raw headers:
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

### grep command
```bash
# Find credentials: true
grep -rn -E "credentials\s*:\s*true" --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Then check the surrounding ~15 lines for a wildcard origin
grep -rn -E "origin\s*:\s*['\"\`]\*['\"\`]|Access-Control-Allow-Origin.*\*" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Never combine wildcard with credentials — always use an explicit origin list:
const allowed = ['https://app.yourdomain.com', 'https://admin.yourdomain.com'];
app.use(cors({
  origin: (origin, cb) => cb(null, allowed.includes(origin)),
  credentials: true,
}));
```

---

## 39. File Upload: MIME-Type / Content-Type Spoofing 🟠

### What to look for
- `multer` storage configuration without a `fileFilter` function
- `fileFilter` that doesn't check `file.mimetype` against an allowlist
- No magic-byte verification (relying solely on the MIME header, which is user-controlled)

### Dangerous pattern
```javascript
// No fileFilter — accepts any file type
const upload = multer({ dest: 'uploads/' });

// fileFilter checking only extension (not MIME) — still bypassable
fileFilter: (req, file, cb) => cb(null, file.originalname.endsWith('.jpg'))
```

### grep command
```bash
# Find multer usage
grep -rn -E "multer|diskStorage|memoryStorage" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Check if fileFilter / mimetype validation is present
grep -rn -E "fileFilter|mimetype|mimeType|file\.mimetype" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB cap
});

// Additionally verify magic bytes after upload (MIME header is user-controlled):
// npm install file-type
const { fileTypeFromBuffer } = await import('file-type');
const type = await fileTypeFromBuffer(fs.readFileSync(uploadedPath));
if (!['image/jpeg', 'image/png'].includes(type?.mime)) {
  fs.unlinkSync(uploadedPath);
  return res.status(400).json({ error: 'Invalid file content' });
}
```

---

## 40. Missing Input Validation Layer 🟡

### What to look for
- Application reads `req.body.*` but imports no schema validation library
- Absence of: `express-validator`, `joi`, `@hapi/joi`, `yup`, `zod`, `ajv`, `celebrate`

### Why it matters
Without a validation layer, type coercion bugs, injection vectors, and mass-assignment risks are hard to audit systematically. A missing validation library amplifies the impact of every other input-handling finding.

### grep command
```bash
# Check for validation libraries
grep -rn "express-validator\|joi\|yup\|zod\|ajv\|celebrate\|@hapi/joi" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>

# Check extent of req.body usage
grep -rn "req\.body\." --include="*.js" --include="*.ts" --exclude-dir=node_modules <root> | wc -l
```

If `req.body` is used in many places and no validation library is found → flag as Medium.

### Remediation
```bash
npm install zod
```
```javascript
import { z } from 'zod';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  age: z.number().int().min(0).max(120),
});

router.post('/register', (req, res, next) => {
  const result = registerSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json(result.error);
  next();
}, registerHandler);
```

---

## 41. vm Module Sandbox Escape 🔴

### What to look for
- `vm.runInNewContext()`, `vm.runInThisContext()`, `vm.Script`, `vm.compileFunction()` used to execute untrusted code

### Why it matters
The Node.js `vm` module is NOT a security sandbox. A single one-liner escapes it:
```javascript
vm.runInNewContext('this.constructor.constructor("return process")()')
```
This gives full access to the Node.js `process` object — RCE.

### grep command
```bash
grep -rn -E "vm\.(run|Script|compile|createContext)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
Never use `vm` as a security boundary. Use `isolated-vm`, Deno, or a container.

---

## 42. Insecure express-session Configuration 🟠

### What to look for
- Hardcoded or short `secret` value
- No `store` configured (defaults to MemoryStore — memory leak, no persistence)
- `resave: true` (unnecessary re-saves cause race conditions)
- `saveUninitialized: true` (creates sessions for unauthenticated users)

### Dangerous pattern
```javascript
app.use(session({ secret: 'keyboard cat' })) // hardcoded, no store, wrong flags
```

### grep command
```bash
grep -rn -E "session\s*\(\s*\{" --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# then read the surrounding ~20 lines for secret, store, resave, saveUninitialized
```

### Remediation
```javascript
session({
  secret: process.env.SESSION_SECRET,  // long random string, from env
  resave: false,
  saveUninitialized: false,
  store: new RedisStore({ client }),
  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
})
```

---

## 43. Mongoose $where / $function Injection 🔴

### What to look for
- `$where` with any user-controlled value — executes JavaScript on the MongoDB server
- `$function` (MongoDB 4.4+) with user input — same risk

### Dangerous pattern
```javascript
Model.find({ $where: `this.role === '${req.body.role}'` }) // JS injection
```

### grep command
```bash
grep -rn -E "\\\$where|\\\$function" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# then check surrounding lines for req.* input
```

### Remediation
Rewrite as a standard indexed query. Never pass user input to `$where` or `$function`.

---

## 44. ORM Raw Query Injection — Sequelize / Knex / TypeORM / Prisma 🔴

### Dangerous patterns
```javascript
sequelize.query(`SELECT * FROM users WHERE id = ${req.params.id}`)   // injection
knex.raw(`SELECT * FROM orders WHERE user = '${req.body.user}'`)
prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`)           // always unsafe
typeorm.query("SELECT * FROM t WHERE id = " + req.params.id)
```

### grep command
```bash
grep -rn -E "(sequelize\.query|knex\.raw|typeorm.*\.query|\\\$queryRaw|\\\$executeRaw|\\\$queryRawUnsafe|\\\$executeRawUnsafe)\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

For each hit check whether user input is interpolated via template literals or `+`.

### Remediation
```javascript
// Sequelize
sequelize.query('SELECT * FROM users WHERE id = ?', { replacements: [req.params.id] })
// Knex
knex.raw('SELECT * FROM orders WHERE user = ?', [req.body.user])
// Prisma (tagged template = parameterized)
prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`
// TypeORM
repo.query('SELECT * FROM t WHERE id = $1', [req.params.id])
```
Never use `$queryRawUnsafe` or `$executeRawUnsafe`.

---

## 45. Path Traversal — Write Operations 🟠

### What to look for
- `fs.writeFile`, `fs.writeFileSync`, `fs.appendFile`, `fs.appendFileSync` with user-controlled path
- `fs.rename`, `fs.unlink`, `fs.mkdir` with user input — can delete or overwrite arbitrary files

### Dangerous pattern
```javascript
fs.writeFile(req.body.path, data)      // writes anywhere on the filesystem
fs.unlink('./uploads/' + req.params.filename)  // deletes arbitrary files with ../
```

### grep command
```bash
grep -rn -E "(writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync|unlink|unlinkSync|mkdir|mkdirSync)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const dest = path.resolve(UPLOAD_DIR, path.basename(req.body.filename));
if (!dest.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) return res.status(400).end();
fs.writeFile(dest, data);
```

---

## 46. CSP unsafe-inline / unsafe-eval 🟠

### What to look for
- `'unsafe-inline'` or `'unsafe-eval'` in any CSP `script-src` directive
- Present even when helmet is used — helmet allows custom CSP configs that re-introduce these

### grep command
```bash
grep -rn -E "'unsafe-inline'|'unsafe-eval'" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
Replace with nonces or hashes:
```javascript
helmet.contentSecurityPolicy({
  directives: {
    scriptSrc: ["'self'", "'nonce-<per-request-random>'"],
  }
})
```

---

## 47. OAuth State Parameter Validation 🟠

### What to look for
- Passport OAuth strategies (`passport-google-oauth`, `passport-github`, etc.) without `state: true`
- Custom OAuth callback routes that don't verify `req.query.state` against a stored value

### grep command
```bash
grep -rn -E "passport-google-oauth|passport-github|passport-facebook|passport-oauth|passport-twitter" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>

grep -rn -E "state\s*:|req\.query\.state" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:  process.env.GOOGLE_CALLBACK_URL,
  state: true,   // ← CSRF protection on callback
}, verifyCallback));
```

---

## 48. WebSocket / Socket.io Authentication 🟠

### What to look for
- `io.on('connection', ...)` or `wss.on('connection', ...)` handlers
- No `io.use()` middleware or `verifyClient` option validating tokens before the handler runs

### grep command
```bash
grep -rn -E "io\.on\s*\(\s*['\"]connection|wss?\.on\s*\(\s*['\"]connection" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "socket\.handshake|verifyClient|socket\.request\.user" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Socket.io
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try { socket.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { next(new Error('Unauthorized')); }
});

// ws
const wss = new WebSocket.Server({
  verifyClient: ({ req }, cb) => {
    try { req.user = jwt.verify(parseToken(req), SECRET); cb(true); }
    catch { cb(false, 401, 'Unauthorized'); }
  }
});
```

---

## 49. Unprotected Admin / Debug Routes 🟠

### What to look for
- Routes for `/admin`, `/debug`, `/_debug`, `/graphiql`, `/metrics`, `/healthz`, `/__webpack_hmr`
- No auth middleware applied before the handler in the surrounding ~15 lines

### grep command
```bash
grep -rn -E "(router|app)\.(get|post|put|delete|use)\s*\(\s*['\"](\\/admin|\\/debug|\\/_debug|\\/graphiql|\\/metrics|\\/healthz|\\/__webpack)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
router.use('/admin', requireAuth, requireRole('admin'));
router.use('/metrics', requireInternalNetwork);
// In production, block /graphiql and /debug at the reverse-proxy level.
```

---

## 50. express.static Serving Project Root 🟠

### What to look for
- `express.static('.')`, `express.static(__dirname)`, `express.static(process.cwd())`
- These serve the entire project tree including .env, package.json, and source files over HTTP

### grep command
```bash
grep -rn -E "express\.static\s*\(\s*['\"\`]\.[\'\"\`]|express\.static\s*\(\s*__dirname\s*\)|express\.static\s*\(\s*process\.cwd" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Always specify an explicit subdirectory:
app.use(express.static(path.join(__dirname, 'public')));
```

---

## 51. crypto.createCipher — Deprecated Weak KDF 🟠

### What to look for
- `crypto.createCipher()` (without `iv`) — uses MD5 key derivation, no salt, no IV
- Removed in Node.js 22+, formally deprecated since Node.js 10

### grep command
```bash
grep -rn -E "crypto\.createCipher\b" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Exclude hits that are actually createCipheriv
```

### Remediation
```javascript
const iv     = crypto.randomBytes(16);
const salt   = crypto.randomBytes(32);
const key    = crypto.scryptSync(passphrase, salt, 32);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

---

## 52. Sensitive Data in URL Parameters 🔵

### What to look for
- `?token=`, `?api_key=`, `?apikey=`, `?auth=`, `?secret=`, `?password=` in route definitions or fetch calls
- These appear in server access logs, browser history, Referer headers, and analytics

### grep command
```bash
grep -rn -E "\?(token|api_?key|apikey|auth|secret|password|passwd)=" \
  --include="*.js" --include="*.ts" --include="*.html" --exclude-dir=node_modules <root>
```

### Remediation
Pass sensitive values in the POST body or `Authorization` header.
```javascript
// Bad:  GET /api/data?token=abc123
// Good: GET /api/data with Authorization: Bearer abc123
```

---

## 53. Missing Subresource Integrity (SRI) 🔵

### What to look for
- `<script src="https://...">` or `<link href="https://...">` tags without `integrity=` attribute
- Affects HTML, EJS, Pug, Handlebars template files

### grep command
```bash
grep -rn -E "<script[^>]+src\s*=\s*['\"]https?://" \
  --include="*.html" --include="*.ejs" --include="*.pug" --include="*.hbs" \
  --exclude-dir=node_modules <root>
# Filter hits that already have integrity=
```

### Remediation
```html
<script
  src="https://cdn.example.com/lib.min.js"
  integrity="sha384-<hash-from-srihash.org>"
  crossorigin="anonymous">
</script>
```
Generate hashes at https://www.srihash.org/

---

## 54. Source Maps Exposed in Production 🔵

### What to look for
- `*.js.map` files in `public/`, `dist/`, `build/`, `www/` directories
- These reconstruct the original source tree for anyone who downloads them

### grep command
```bash
find <root>/public <root>/dist <root>/build <root>/www -name "*.js.map" 2>/dev/null
```

### Remediation
Configure your bundler to suppress source maps in production:
```javascript
// webpack:  devtool: false  (production config)
// vite:     build: { sourcemap: false }
// esbuild:  sourcemap: false
```
Or serve source maps only to authenticated developers via a separate internal URL.

---

## 55. JWT Secret Strength 🔴

### What to look for
- `jwt.sign(payload, 'short_literal')` — hardcoded secret under ~32 chars
- `jwt.verify()` without `algorithms` option — can accept unintended algorithms
- `jwt.sign()` without `expiresIn`

### grep command
```bash
# Find short/hardcoded secrets in jwt.sign
grep -rn -E "jwt\.sign\s*\([^,]+,\s*['\"\`][^'\"\`]{1,20}['\"\`]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

# Find jwt.verify without algorithms
grep -rn -E "jwt\.verify\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Then check each for absence of 'algorithms' option
```

### Remediation
```javascript
// Signing
jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });
// Verification — always specify algorithm
jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
// Startup guard
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)
  throw new Error('JWT_SECRET must be at least 32 characters');
```

---

## 56. Unhandled Promise Rejections 🟡

### What to look for
- No `process.on('unhandledRejection', ...)` anywhere in the app
- No `express-async-errors` or `express-async-handler` package
- Async route handlers without try/catch (Express 4 does not catch async throws)

### grep command
```bash
grep -rn "unhandledRejection" --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
grep -rn "express-async-errors\|express-async-handler" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Simplest fix: top of app.js
require('express-async-errors');

// Or global safety net:
process.on('unhandledRejection', (reason, promise) => {
  logger.error({ reason }, 'Unhandled promise rejection');
  process.exit(1);
});
```

---

## 57. morgan Logging in Production 🔵

### What to look for
- `app.use(morgan('combined'))` or `app.use(morgan('dev'))` without a `NODE_ENV` guard
- Custom morgan format logging `:req[authorization]` or `:body`

### grep command
```bash
grep -rn -E "morgan\s*\(\s*['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', { stream: logger.stream })); // structured logger, no body logging
}
```

---

## 58. Missing Lockfile 🔵

### What to look for
- Absence of `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml` in the repository root

### check command
```bash
ls package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null || echo "No lockfile found"
```

### Remediation
```bash
npm install   # generates package-lock.json
git add package-lock.json
git commit -m "chore: add lockfile"
```
In CI: always use `npm ci` (not `npm install`) to enforce the lockfile.

---

## 59. Hardcoded Internal IP Addresses 🔵

### What to look for
- RFC 1918 private ranges in source/config: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Disclose internal network topology if source code leaks

### grep command
```bash
grep -rn -E "(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})" \
  --include="*.js" --include="*.ts" --include="*.yaml" --include="*.env" \
  --exclude-dir=node_modules <root>
```

### Remediation
Move all internal service addresses to environment variables.

---

## 60. Post-Login returnTo Open Redirect 🟡

### What to look for
- `req.session.returnTo` (or `redirectTo`, `next`) used in a `res.redirect()` call
- No check that the value starts with `/` and does not start with `//`

### grep command
```bash
grep -rn -E "req\.session\.(returnTo|redirectTo|next)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Check surrounding lines for res.redirect and allowlist validation
```

### Remediation
```javascript
const to = req.session.returnTo || '/';
delete req.session.returnTo;
// Must be a relative path — reject protocol-relative (//evil.com) and absolute URLs
if (!to.startsWith('/') || to.startsWith('//')) return res.redirect('/');
res.redirect(to);
```

---

## ⚠️ Inherent Limits of Static Scanning

**Data flow blindness** — Intermediate variables are not tracked:
```javascript
const data = req.body;    // assignment
db.query(data);           // scanner misses this — no 'req.' on this line
```
Always manually review data flows for critical paths (auth, DB queries, file ops).

**False positives** — Context matters:
```javascript
setTimeout(myFunc, req.body.delay)  // safe — delay is a number, not code string
```
The scanner flags the pattern; confirm the first arg is not a string from user input.

For production security, complement with:
- **Dynamic analysis**: OWASP ZAP, Burp Suite
- **SAST tools**: Semgrep `p/nodejs`, Snyk Code
- **Penetration testing** for critical applications

---

## 61. Dynamic require() / Local File Inclusion 🔴

### What to look for
- `require(req.params.x)`, `require('./' + req.body.path)`, `require(req.query.module)`
- Loads arbitrary files or installed packages — full RCE

### grep command
```bash
grep -rn -E "\brequire\s*\([^)]*req\.(body|params|query|headers)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const ALLOWED = { csv: './exporters/csv', pdf: './exporters/pdf' };
const mod = ALLOWED[req.query.format];
if (!mod) return res.status(400).end();
require(mod);
```

---

## 62. Server-Side XSS via res.send() String Concatenation 🟠

### Dangerous patterns
```javascript
res.send('<h1>Hello ' + req.query.name + '</h1>')   // reflected XSS
res.write(`<div>${req.body.input}</div>`)            // template literal XSS
```

### grep command
```bash
# Lines where res.send/write and req.* appear with + or template literal
grep -rn -E "res\.(send|write)\s*\(" --include="*.js" --include="*.ts" \
  --exclude-dir=node_modules <root> | grep -E "req\.(body|params|query|headers)" | grep -E "\+|`"
```

### Remediation
```javascript
const he = require('he');
res.send('<h1>Hello ' + he.encode(req.query.name) + '</h1>');
// Or use a template engine with auto-escaping (EJS <%=, Pug =)
```

---

## 63. Mass Assignment via Object.assign / Spread Operator 🟠

### Dangerous patterns
```javascript
Object.assign(user, req.body)     // merges all attacker-supplied fields
await User.update({ ...req.body }) // spread passes all fields
```

### grep commands
```bash
grep -rn -E "Object\.assign\s*\([^,)]+,\s*req\.(body|params|query)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "\.\.\.req\.(body|params|query)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const { name, bio } = req.body;   // only allowed fields
Object.assign(user, { name, bio });
await user.save();
```

---

## 64. SSRF — Additional HTTP Clients 🟠

### What to look for
- `superagent`, `undici`, `ky`, `needle`, `urllib`, `phin`, `centra`, `cross-fetch`, `isomorphic-fetch`
- Any of these making requests with URLs derived from req.*

### grep command
```bash
grep -rn -E "(superagent|undici|ky\b|needle|urllib|phin|centra|cross-fetch|isomorphic-fetch)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Then check surrounding lines for req.* usage
```

### Remediation
```javascript
const { URL } = require('url');
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);
const parsed = new URL(req.body.url);
if (!ALLOWED_HOSTS.has(parsed.hostname)) return res.status(400).end();
```

---

## 65. Sequelize/TypeORM where-clause / sequelize.literal() Injection 🔴/🟠

### Dangerous patterns
```javascript
sequelize.literal(`name = '${req.body.name}'`)     // SQL injection
Model.findAll({ where: req.body })                  // operator injection
Model.findAll({ where: { name: req.body } })        // whole body as where
```

### grep commands
```bash
# sequelize.literal with user input
grep -rn -E "sequelize\.literal\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Check surrounding lines for req.*

# where clause using req.* directly
grep -rn -E "\.(findAll|findOne|findAndCountAll|count|update|destroy)\s*\(\s*\{[^}]*where\s*:\s*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// sequelize.literal: use replacements instead
sequelize.query('SELECT * FROM t WHERE name = ?', { replacements: [req.body.name] });
// findAll: always pass specific validated fields
Model.findAll({ where: { name: String(req.body.name), active: true } });
```

---

## 66. Session Fixation 🟠

### What to look for
- `req.session.user`, `req.session.userId`, `req.session.authenticated` being set
- Absence of `req.session.regenerate()` anywhere in the codebase

### grep commands
```bash
grep -rn -E "(req\.session\.user|req\.session\.userId|req\.session\.authenticated|req\.session\.passport)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn "session\.regenerate" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

If session fields are set without a matching `regenerate()` call → flag as High.

### Remediation
```javascript
req.session.regenerate((err) => {
  if (err) return next(err);
  req.session.userId = user.id;
  req.session.save((err) => {
    if (err) return next(err);
    res.redirect('/dashboard');
  });
});
```

---

## 67. AES-ECB Mode 🟠

### What to look for
- `createCipheriv('aes-128-ecb', ...)` or `createCipheriv('aes-256-ecb', ...)`
- ECB produces identical ciphertext for identical plaintext blocks

### grep command
```bash
grep -rn -E "createCipheriv\s*\(\s*['\"]aes-[0-9]+-ecb['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Use GCM (authenticated encryption):
const iv     = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
// Store iv with the ciphertext; verify authTag on decryption
```

---

## 68. JSONP Callback Injection 🟠

### Dangerous patterns
```javascript
const cb = req.query.callback;
res.send(`${cb}(${JSON.stringify(data)})`);     // XSS if cb = "alert(1)//"
res.jsonp(data);                                 // express built-in — permissive default
```

### grep commands
```bash
grep -rn -E "req\.(query|body)\.(callback|jsonp|cb)\b" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "res\.jsonp\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const cb = req.query.callback;
if (!/^[a-zA-Z_$][\w$]*$/.test(cb)) return res.status(400).end();
res.type('application/javascript');
res.send(`${cb}(${JSON.stringify(data)});`);
// Preferred: replace JSONP with CORS entirely
```

---

## 69. .env Not Protected by .gitignore 🟠

### What to look for
- `.gitignore` present but does not contain `.env`
- Or `.gitignore` entirely absent while project uses `.env` files

### check command
```bash
cat .gitignore 2>/dev/null | grep "\.env" || echo ".env not in .gitignore"
ls .gitignore 2>/dev/null || echo "No .gitignore"
```

### Remediation
```
# Add to .gitignore:
.env
.env.local
.env.*.local
.env.production
```

---

## 70. Hardcoded Database Connection String URLs 🔴

### What to look for
- `mongodb://user:pass@host/db`, `postgres://user:pass@host/db`, `redis://:pass@host`, `mysql://user:pass@host/db`
- Credentials embedded in the URL instead of environment variables

### grep command
```bash
grep -rn -E "(mongodb[+srv]?|postgres|postgresql|mysql|redis|amqp)://[^@\s'\"` + "`" + `]+:[^@\s'\"` + "`" + `]+@" \
  --include="*.js" --include="*.ts" --include="*.yaml" --include="*.json" \
  --include="*.env" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// BAD:
mongoose.connect('mongodb://admin:s3cr3t@db.example.com/app');
// GOOD:
mongoose.connect(process.env.MONGODB_URI);
```

---

## 71. Overly Permissive package.json Version Ranges 🔵

### What to look for
- `"*"`, `"latest"`, `"x"`, `">= 0"` as version specifiers in dependencies or devDependencies
- These accept any future version including potentially malicious ones

### check command
```bash
cat package.json | python3 -c "
import sys, json
pkg = json.load(sys.stdin)
for s in ['dependencies', 'devDependencies']:
    for k, v in pkg.get(s, {}).items():
        if v in ('*', 'latest', 'x') or v.startswith('>=0'):
            print(f'{s}: {k}: {v}')
"
```

### Remediation
Pin to exact or narrow ranges:
```json
{ "lodash": "4.17.21" }
```

---

## 72. GraphQL Field-Level Authorization 🟡

### What to look for
- GraphQL app without `graphql-shield`, `graphql-authz`, or equivalent
- Schema-level middleware only (auth at the HTTP layer) but no per-field/per-type rules

### grep command
```bash
grep -rn -E "graphql-shield|graphql-authz|fieldMiddleware|applyMiddleware.*shield" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
import { shield, rule, and } from 'graphql-shield';
const isAuthenticated = rule()((parent, args, ctx) => ctx.user !== null);
const isAdmin         = rule()((parent, args, ctx) => ctx.user?.role === 'admin');
const permissions = shield({
  Query:  { users: and(isAuthenticated, isAdmin) },
  User:   { email: isAuthenticated },
});
```

---

## 73. Password Reset Token — No Expiry 🟠

### What to look for
- Query using `resetToken: req.body.token` without a date/expiry check alongside
- Token stored in DB but no `resetTokenExpiry > Date.now()` condition

### grep command
```bash
grep -rn -E "(resetToken|reset_token|passwordResetToken):\s*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Check surrounding ~15 lines for expiry condition
```

### Remediation
```javascript
const user = await User.findOne({
  resetToken: req.body.token,
  resetTokenExpiry: { $gt: Date.now() },   // 1-hour window
});
if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
user.resetToken = undefined;
user.resetTokenExpiry = undefined;
await user.save();
```

---

## 74. console.error(err) Stack Trace in Production 🔵

### What to look for
- `console.error(err)` or `console.log(err)` without a `NODE_ENV` guard
- In production these go to stdout → log aggregators → potential disclosure

### grep command
```bash
grep -rn -E "console\.(error|log)\s*\(\s*err\b" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Flag lines where no NODE_ENV guard exists in the surrounding 3 lines
```

### Remediation
```javascript
if (process.env.NODE_ENV !== 'production') {
  console.error(err);
} else {
  logger.error({ message: err.message, code: err.code }); // no stack
}
```

---

## 75. Missing Referrer-Policy Header 🔵

### What to look for
- No `Referrer-Policy` header set manually or via helmet config
- Especially important when password reset, verification, or invite tokens appear in URLs

### grep command
```bash
grep -rn -E "Referrer-Policy|referrerPolicy|referrer.policy" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// With helmet (sets no-referrer by default — verify not overridden):
helmet({ referrerPolicy: { policy: 'strict-origin-when-cross-origin' } })
// Without helmet:
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
```

---

## 76. trust proxy Misconfiguration 🟡

### What to look for
- `app.set("trust proxy", true)` or `app.set('trust proxy', 1)` where the value is `true`
- Makes `req.ip` fully user-spoofable; breaks IP-based rate limiting and geo-checks

### grep command
```bash
grep -rn -E "set\s*\(['\"]trust\s*proxy['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
// Set to the exact number of proxies in front of Node:
app.set("trust proxy", 1);               // nginx in front
app.set("trust proxy", "10.0.0.0/8");   // specific subnet
// Never use: app.set("trust proxy", true)
```

---

## 77. CORS Dynamic Origin Reflection 🟠

### Dangerous pattern
```javascript
res.setHeader("Access-Control-Allow-Origin", req.headers.origin); // reflects any origin
app.use(cors({ origin: (o, cb) => cb(null, o) }));                // same
```

### grep command
```bash
grep -rn -E "req\.(headers\.origin|get\s*\(['\"]origin['\"]\))" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
# Then check surrounding lines for Access-Control-Allow-Origin usage
```

### Remediation
```javascript
const ALLOWED = new Set(["https://app.example.com"]);
const origin  = req.headers.origin;
if (ALLOWED.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
```

---

## 78. State-Changing GET Endpoints 🟡

### Dangerous pattern
```javascript
router.get("/users/:id/delete", deleteUser)  // CSRF-vulnerable
router.get("/admin/reset-password", reset)
```

### grep command
```bash
grep -rn -E "(router|app)\.get\s*\(['\"][^'\"]*\/(delete|remove|destroy|reset|disable|ban|block)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
Use `router.delete()` / `router.post()` for all state mutations. Apply CSRF protection.

---

## 79. SSRF — http.request() and Webhook/Image-Proxy Patterns 🟠

### Dangerous patterns
```javascript
http.request({ host: req.body.host, path: req.body.path })  // SSRF
app.get("/proxy", (req) => axios.get(req.query.url))        // image proxy SSRF
app.post("/webhook", (req) => fetch(req.body.callbackUrl))  // webhook SSRF
```

### grep commands
```bash
grep -rn -E "(http|https)\.request\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>

grep -rn -E "(webhook|proxy|imageProxy|fetchUrl|proxyRequest).*req\.(body|query|params)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
Validate every URL: parse, check hostname allowlist, reject RFC-1918 ranges and non-HTTPS.
Libraries: `ssrf-filter`, `ssrf-req-filter`.

---

## 80. eval() with JSON Concatenation 🔴

### Dangerous pattern
```javascript
eval('(' + req.body.data + ')')    // executes arbitrary JS, not just JSON
eval("(" + JSON.stringify(x) + ")") // slightly safer but still risky
```

### grep command
```bash
grep -rn -E "eval\s*\(\s*['\"\(]|eval\s*\(.*\+.*json" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
```javascript
const data = JSON.parse(userInput); // safe — throws SyntaxError, never executes code
```

---

## 81. SVG Upload Allowed 🟠

### Why dangerous
SVG is XML that can contain `<script>` tags. Serving `image/svg+xml` in a browser executes JavaScript in your site's origin — stored XSS without HTML injection.

### grep command
```bash
grep -rn -iE "(allowedExts|allowedMimes|allowedTypes).*svg" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Remediation
- Remove SVG from allowed types, or sanitize with server-side DOMPurify before storing.
- If serving SVGs: always add `Content-Disposition: attachment` to prevent browser rendering.

---

## 82. ImageMagick / gm RCE Surface 🟠

### Why dangerous
ImageMagick has critical historical CVEs (ImageTragick, CVE-2016-3714+). Processing attacker-uploaded images without a hardened `policy.xml` allows RCE, SSRF, and file reads.

### grep command
```bash
grep -rn -iE "(imagemagick|node-imagemagick|imagickal|graphicsmagick|[^a-z]gm\b)" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules <root>
```

### Remediation
- Restrict coders in `/etc/ImageMagick-*/policy.xml` (MVG, MSL, EPHEMERAL, etc.)
- Validate file magic bytes before passing to ImageMagick
- Consider `sharp` (libvips) as a safer alternative for common operations

---

## 83. Dockerfile / docker-compose Secrets 🔴

### Dangerous patterns
```dockerfile
ENV DB_PASSWORD=supersecret123        # baked into image layer
ARG API_KEY=production-key-here
```
```yaml
# docker-compose.yml
environment:
  POSTGRES_PASSWORD: mysecretpassword  # in git history
```

### grep command
```bash
grep -rn -iE "^\s*(ENV|ARG)\s+\w*(password|secret|key|token)\w*\s*=\s*.+" Dockerfile* docker-compose*
```

### Remediation
```dockerfile
# Use build-time secrets (never stored in layers):
RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret
# Build: docker build --secret id=mysecret,src=./secret.txt .
# At runtime: use env vars injected by orchestrator, never baked in
```

---

## 84. GitHub Actions Security 🔴/🟠

### Dangerous patterns
```yaml
- run: echo ${{ secrets.API_KEY }}         # leaks to log

on: pull_request_target                    # + checkout of PR code = RCE
  steps:
    - uses: actions/checkout@v3
      with:
        ref: ${{ github.event.pull_request.head.sha }}
```

### grep commands
```bash
grep -rn -iE "echo.*\$\{\{\s*secrets\." .github/workflows/
grep -rn "pull_request_target" .github/workflows/
```

### Remediation
- Never `echo ${{ secrets.X }}`. Pass to env and use in scripts without logging.
- Separate `pull_request_target` (privileged) from PR code checkout. See [GitHub Security Lab](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

---

## 85. Terraform / Kubernetes Plaintext Secrets 🔴

### Dangerous patterns
```hcl
# terraform
resource "aws_db_instance" "db" {
  password = "mysecretpassword"   # in git + state file
}
```
```yaml
# kubernetes
kind: Secret
data:
  password: bXlzZWNyZXQ=          # base64, not encrypted; in git
```

### grep commands
```bash
grep -rn -iE "password\s*=\s*\"[^\"]{6,}\"" *.tf *.tfvars
grep -rn "kind: Secret" **/*.yaml **/*.yml
```

### Remediation
- Terraform: use `sensitive = true` variables + environment injection or Vault provider
- Kubernetes: use External Secrets Operator, Sealed Secrets, or SOPS
- Enable etcd encryption at rest in cluster config

---

## 86. Next.js Security Checks 🔴/🟡

### NEXT_PUBLIC_ secret exposure
```bash
# Scan .env* files for secret-named NEXT_PUBLIC_ vars
grep -rn -iE "NEXT_PUBLIC_\w*(secret|key|token|password|api_key|auth|private)" .env*
```
Any `NEXT_PUBLIC_*` value is inlined into the browser bundle — never use for secrets.

### API routes without auth
```bash
# Find API route files lacking auth patterns
find pages/api app/api -name "*.ts" -o -name "*.js" | while read f; do
  grep -qiE "getSession|getServerSession|auth\(\)|jwt\.verify|requireAuth" "$f" || echo "No auth: $f"
done
```

### Server Actions without auth
```bash
grep -rn '"use server"' app/ --include="*.ts" --include="*.tsx" | while IFS=: read file line rest; do
  grep -qiE "getServerSession|auth\(\)|verifyToken" "$file" || echo "No auth in server action: $file"
done
```

---

## 87. High-Entropy String Detection 🔵

### What it detects
String literals with Shannon entropy > 4.5 that are 32+ characters long — consistent with randomly generated tokens, API keys, or secrets not matching service-specific patterns (AWS AKIA, GitHub ghp_, etc.).

### Manual verification
For each flagged string:
1. Is it in a comment or documentation? → safe
2. Is it a known public value (public certificate, test vector)? → safe, add comment
3. Does it look like a random token or key? → move to `process.env`

### Entropy formula
Shannon entropy H = -Σ p(c) × log₂(p(c)) where p(c) = frequency of character c.
- English text: ~4.0 bits/char
- Random Base64: ~6.0 bits/char
- Threshold 4.5: catches most secrets while limiting false positives


---

## AI / LLM API Cost Protection

### What to look for
- Any import of a paid LLM SDK without rate limiting, token caps, auth guards, or usage tracking

### Detect LLM SDK usage
```bash
grep -rn -iE "(openai|anthropic|@anthropic-ai|@google/generative-ai|cohere|bedrock|mistralai|replicate|groq|@ai-sdk|langchain)" \
  --include="*.js" --include="*.ts" --include="*.json" --exclude-dir=node_modules <root>
```

### Detect LLM call sites
```bash
grep -rn -E "(\.chat\.completions\.create|\.messages\.create|\.complete|\.generateContent|\.generate|\.invoke|\.stream)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Check for rate limiting
```bash
grep -rn -iE "(rate.?limit|rateLimit|rateLimiter|slowDown|bottleneck|p-throttle)" \
  --include="*.js" --include="*.ts" --include="*.json" --exclude-dir=node_modules <root>
```

### Check for token caps
```bash
grep -rn -E "(max_tokens|maxTokens|maxOutputTokens|max_completion_tokens)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Check for input size validation
```bash
grep -rn -iE "(req\.(body|query|params).*content|messages.*req\.|prompt.*req\.)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Check for usage tracking / budget enforcement
```bash
grep -rn -iE "(usage\.(total_tokens|input_tokens|output_tokens)|prompt_tokens|completion_tokens|token.*budget|monthly.*limit)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules <root>
```

### Safe example — protected AI endpoint
```javascript
const { rateLimit } = require("express-rate-limit");

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.user?.id || req.ip,
});

router.post("/ai/chat", requireAuth, aiLimiter, async (req, res) => {
  const userMessage = String(req.body.message).slice(0, 2000); // input cap

  const usage = await db.getMonthlyTokenUsage(req.user.id);
  if (usage > 100_000) return res.status(402).json({ error: "Budget exceeded" });

  const response = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: userMessage }],
    max_tokens: 512,  // output cap
  });

  await db.incrementUserTokenUsage(req.user.id, response.usage.total_tokens);
  res.json({ reply: response.choices[0].message.content });
});
```

### CWE / OWASP
- CWE-770: Allocation of Resources Without Limits or Throttling
- OWASP A05:2021 — Security Misconfiguration
- OWASP LLM Top 10: LLM04 — Model Denial of Service
