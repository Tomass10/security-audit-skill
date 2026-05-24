# Contributing

## Adding a new check

### 1. Add the check to `scripts/scan.js`

Copy the block comment format used by existing checks:

```javascript
// ═══════════════════════════════════════════════════════════════════════════════
// CHECK N — Short descriptive name
// ═══════════════════════════════════════════════════════════════════════════════

parseGrepLines(grepFiles('your-pattern-here', ['js', 'ts']))
  .forEach(({ file, line, code }) => {
    addFinding(
      'HIGH',                          // CRITICAL / HIGH / MEDIUM / LOW
      'Category Name',                 // shown in report grouping
      file, line,
      'Short title',
      'Full description of why this is dangerous.',
      code,                            // the matched snippet
      'Concrete remediation with code example.',
      {
        confidence: 'HIGH',            // HIGH / MEDIUM / LOW
        exploitability: 'remote_auth', // remote_unauth / remote_auth / local
        owasp: 'A03:2021',
        cwe: 'CWE-89',
      }
    );
  });
```

**Severity guide:**
- `CRITICAL` — RCE, auth bypass, exposed secret, billing abuse
- `HIGH` — directly exploitable by an attacker with standard skill
- `MEDIUM` — exploitable with effort, or dangerous in combination
- `LOW` — hardening / hygiene, not directly exploitable

**Confidence guide:**
- `HIGH` — the pattern is unambiguously dangerous (e.g. `eval(req.body.x)`)
- `MEDIUM` — likely dangerous but context could change it
- `LOW` — requires manual verification to confirm

### 2. Add patterns to `references/patterns.md`

Document the grep commands and code signatures so humans can run the check manually. Include:
- What to look for (dangerous pattern examples)
- The grep command
- A safe / fixed example
- CWE and OWASP mapping

### 3. Add the entry to `SKILL.md`

Add a row to the appropriate check table under `## Scanning Categories`.

### 4. Open a PR

Include in the PR description:
- What vulnerability the check detects
- A minimal vulnerable code example
- Why existing checks don't already catch it
- Any known false positive scenarios and how they're filtered

## Running locally

```bash
# Test the scanner against a target directory
node scripts/scan.js /path/to/test/app | jq .

# Check only critical findings
node scripts/scan.js /path/to/test/app | jq '.findings[] | select(.severity == "CRITICAL")'

# Summary only
node scripts/scan.js /path/to/test/app | jq '.summary'
```

## False positive policy

Checks that produce high false positive rates on realistic codebases are not merged. When submitting a check, describe what filtering is in place (e.g. skipping test files, skipping `process.env` prefixed values).
