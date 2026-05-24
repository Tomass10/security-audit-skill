# Manual Checks Fallback

Use this if `scan.js` fails. Run these grep commands manually.

## Quick one-liner audit
```bash
ROOT="<your_path>"

echo "=== HARDCODED SECRETS ===" && \
grep -rn -iE "(password|api_key|secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT" | grep -v "process\.env"

echo "=== SQL INJECTION ===" && \
grep -rn -E "(\.query|\.execute)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== XSS ===" && \
grep -rn -E "innerHTML\s*=" \
  --include="*.js" --include="*.ts" --include="*.jsx" --exclude-dir=node_modules "$ROOT"

echo "=== EVAL ===" && \
grep -rn -E "\beval\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== PATH TRAVERSAL ===" && \
grep -rn -E "(readFile|sendFile)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== .ENV FILES ===" && \
find "$ROOT" -name ".env" ! -name ".env.example" ! -path "*/node_modules/*"

echo "=== MASS ASSIGNMENT ===" && \
grep -rn -E "\.(create|update)\s*\(\s*req\.body" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== RATE LIMITING ===" && \
grep -rn "rateLimit\|rate-limit\|slowDown" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== HELMET/HEADERS ===" && \
grep -rn "helmet" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"
```

## Extended quick checks (new categories)

```bash
ROOT="<your_path>"

echo "=== VM MODULE (sandbox escape) ===" && \
grep -rn -E "vm\.(run|Script|compile|createContext)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== ORM RAW QUERIES ===" && \
grep -rn -E "(sequelize\.query|knex\.raw|\\\$queryRaw|\\\$queryRawUnsafe|typeorm.*\.query)\s*\(" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== WRITE PATH TRAVERSAL ===" && \
grep -rn -E "(writeFile|appendFile|rename|unlink|mkdir)\s*\([^)]*req\." \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== EXPRESS-SESSION CONFIG ===" && \
grep -rn -E "session\s*\(\s*\{" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== WEBSOCKET AUTH ===" && \
grep -rn -E "io\.on\s*\(\s*['\"]connection|wss?\.on\s*\(\s*['\"]connection" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== OAUTH STATE ===" && \
grep -rn -E "passport-(google|github|facebook|oauth)" \
  --include="*.js" --include="*.ts" --include="package.json" --exclude-dir=node_modules "$ROOT"

echo "=== UNESCAPED TEMPLATE OUTPUT ===" && \
grep -rn -E "<%[-]|[!]=" \
  --include="*.ejs" --include="*.pug" --include="*.hbs" --include="*.njk" "$ROOT"

echo "=== CSP UNSAFE ===" && \
grep -rn -E "'unsafe-inline'|'unsafe-eval'" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== ADMIN ROUTES ===" && \
grep -rn -E '(router|app)\.(get|post|put|delete|use)\s*\(\s*["'"'"'](\\/admin|\\/debug|\\/metrics|\\/graphiql)' \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== MONGOOSE STRICT:FALSE ===" && \
grep -rn -E "strict\s*:\s*false" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== EXPRESS.STATIC ROOT ===" && \
grep -rn -E "express\.static\s*\(\s*['\"]\.['\"]]|express\.static\s*\(\s*__dirname\s*\)" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT"

echo "=== SOURCE MAPS IN PRODUCTION ===" && \
find "$ROOT/public" "$ROOT/dist" "$ROOT/build" -name "*.js.map" 2>/dev/null

echo "=== SENSITIVE URL PARAMS ===" && \
grep -rn -E "\?(token|api_?key|auth|secret|password)=" \
  --include="*.js" --include="*.ts" --include="*.html" --exclude-dir=node_modules "$ROOT"

echo "=== MISSING SRI ON CDN SCRIPTS ===" && \
grep -rn -E "<script[^>]+src\s*=\s*['\"]https?://" \
  --include="*.html" --include="*.ejs" --include="*.pug" "$ROOT" | grep -v integrity

echo "=== LOCKFILE PRESENT ===" && \
ls "$ROOT/package-lock.json" "$ROOT/yarn.lock" "$ROOT/pnpm-lock.yaml" 2>/dev/null || echo "NO LOCKFILE"

echo "=== DEBUG ENV ===" && \
grep -rn "DEBUG\s*=" "$ROOT"/.env* 2>/dev/null

echo "=== DEPRECATED crypto.createCipher ===" && \
grep -rn -E "crypto\.createCipher\b" \
  --include="*.js" --include="*.ts" --exclude-dir=node_modules "$ROOT" | grep -v createCipheriv
```
