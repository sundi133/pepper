# Advanced SAST Report: Pepper

Generated: 2026-05-01
Target: `/home/sam/pepper`
Scope: application source, API routes, worker code, configuration, dependency audit, lint/test signal.
Excluded: generated/copy folders such as `.next`, `dist`, `extracted`, and `node_modules`.

## Executive Summary

The application has multiple exploitable server-side issues. The highest-risk finding is authenticated remote command execution in the scan worker through Git clone command interpolation. Several authenticated API routes also perform resource access by ID without tenant authorization, which turns normal user access into cross-tenant read/write/delete capabilities. Webhook endpoints can enqueue scans without strong authentication in common misconfiguration states, making the worker RCE reachable without a normal login if chained with the Git clone issue.

Automated checks:

| Check | Result |
| --- | --- |
| `npm test` | Passed: 6/6 tests |
| `npm run lint` | Failed: 12 errors, 13 warnings |
| `npm audit --omit=dev --json` | 21 production advisories: 1 critical, 9 high, 9 moderate, 2 low |
| `semgrep --version` | Not available in this environment |

Risk summary:

| Severity | Count | Key Themes |
| --- | ---: | --- |
| Critical | 1 | Worker command injection / RCE |
| High | 7 | IDOR, RBAC bypass, webhook auth bypass, SSRF, upload extraction risk, insecure defaults, vulnerable dependencies |
| Medium | 4 | CSV formula injection, plaintext secret storage, login brute force risk, lint/security hardening gaps |

## Findings

### SAST-01: OS Command Injection in Git Scan Worker

Severity: Critical
Confidence: High
CWE: CWE-78
Affected files:

- `src/app/api/scans/route.ts`
- `src/worker/scan-processor.ts`

Evidence:

- `repoUrl` and `branch` are accepted as optional strings in `createScanSchema` without URL/ref allowlists.
- The worker executes `git clone` through `execSync` with a template string containing those attacker-controlled values.

Vulnerable flow:

1. Authenticated user calls `POST /api/scans` with `repoUrl` and `branch`.
2. API stores the values in `sourceRef` and BullMQ job data.
3. Worker runs:

```ts
execSync(
  `git clone --depth 1 --branch ${branch} ${repoUrl} ${workDir}/repo`,
  { timeout: 120000 },
);
```

Impact:

An attacker can execute arbitrary shell commands inside the worker container. This can expose source code, environment variables, database/Redis/MinIO credentials, scan artifacts, and internal network services.

Safe proof of concept:

```bash
curl -i -X POST "$BASE_URL/api/scans" \
  -H "Content-Type: application/json" \
  -H "Cookie: next-auth.session-token=$TOKEN" \
  --data '{
    "projectId":"PROJECT_ID",
    "scanType":"SAST_ONLY",
    "repoUrl":"https://github.com/octocat/Hello-World.git",
    "branch":"main; id > /tmp/pepper-rce-poc #"
  }'
```

Recommended fix:

- Replace `execSync` shell strings with `execFileSync` or `spawn` argument arrays.
- Validate Git URLs with a scheme allowlist, ideally `https:` and controlled `ssh:`.
- Validate refs with a strict pattern such as `^[A-Za-z0-9._/-]{1,128}$`, reject values starting with `-`, and reject `..`.
- Add regression tests for metacharacters in `branch` and `repoUrl`.

### SAST-02: Broken Access Control / IDOR Across Tenant Resources

Severity: High
Confidence: High
CWE: CWE-639, CWE-862, CWE-863
Affected files:

- `src/lib/auth-guard.ts`
- `src/app/api/scans/[scanId]/route.ts`
- `src/app/api/scans/[scanId]/findings/route.ts`
- `src/app/api/scans/[scanId]/artifacts/[type]/route.ts`
- `src/app/api/findings/[findingId]/route.ts`
- `src/app/api/scans/[scanId]/findings/export/route.ts`
- `src/app/api/scans/route.ts`
- `src/app/api/settings/build-gates/route.ts`

Evidence:

- `requireAuth()` only checks that a user is logged in.
- Several routes query by `scanId`, `findingId`, or `projectId` and return or mutate data without checking the resource's `organizationId` against the user's memberships.
- `GET /api/scans/[scanId]` includes `project.organizationId` in the query but never calls `requireRole`.
- `GET /api/scans/[scanId]/findings` lists findings by `scanId` directly.
- `GET/PATCH /api/findings/[findingId]` reads or updates a finding by ID directly.

Impact:

A user from one organization can read scan results, download SARIF/SBOM/log artifacts, update finding statuses, or tamper with build gates for another organization if they know or can obtain IDs.

Safe proof of concept:

```bash
curl -i "$BASE_URL/api/scans/VICTIM_SCAN_ID/findings" \
  -H "Cookie: next-auth.session-token=$ATTACKER_TOKEN"

curl -i -X PATCH "$BASE_URL/api/findings/VICTIM_FINDING_ID" \
  -H "Content-Type: application/json" \
  -H "Cookie: next-auth.session-token=$ATTACKER_TOKEN" \
  --data '{"status":"FALSE_POSITIVE","statusNote":"tampered"}'
```

Recommended fix:

- Create shared authorization helpers that load the resource's project and organization.
- Require membership for reads and stronger roles for writes/deletes.
- Filter list queries by `project.organizationId` and not only by user-provided IDs.
- Return `404` or `403` consistently to avoid resource enumeration.

### SAST-03: Missing RBAC on Administrative APIs

Severity: High
Confidence: High
CWE: CWE-862
Affected files:

- `src/app/api/users/route.ts`
- `src/app/api/settings/llm/route.ts`
- `src/app/api/settings/build-gates/route.ts`
- `src/app/api/settings/policies/route.ts`

Evidence:

- `POST /api/users` allows any authenticated member of the default org to create or update organization membership and choose roles up to `ADMIN`.
- `PUT /api/settings/llm` allows any authenticated user to change LLM provider/base URL/API key settings for the default org.
- `PUT /api/settings/build-gates` accepts a `projectId` and upserts the build gate without role checks or tenant checks.

Impact:

Low-privilege users can invite admins, weaken build gate policies, redirect LLM scanning to an attacker-controlled endpoint, or disable security scanning features.

Recommended fix:

- Use `requireRole(orgId, "ADMIN")` for user management and organization settings.
- Use `requireRole(project.organizationId, "SECURITY")` or stronger for build gate/policy changes.
- Derive organization IDs from the target resource, not from the user's first membership.

### SAST-04: Weak or Missing Webhook Authentication

Severity: High
Confidence: High
CWE: CWE-347, CWE-306
Affected files:

- `src/app/api/webhooks/github/route.ts`
- `src/app/api/webhooks/gitlab/route.ts`

Evidence:

- GitHub verification runs only when both `GITHUB_WEBHOOK_SECRET` and a signature are present. If the secret exists but the request omits the signature, the request is accepted.
- GitLab rejects invalid tokens only when `GITLAB_WEBHOOK_SECRET` is configured. If unset, all webhook requests are trusted.
- Both routes enqueue scan jobs with `repoUrl` and `branch` from request payloads.

Impact:

Unauthenticated attackers can trigger scan jobs in misconfigured deployments. Chained with SAST-01, this can become unauthenticated worker command execution.

Recommended fix:

- Fail closed when webhook secrets are absent in production.
- For GitHub, reject when `GITHUB_WEBHOOK_SECRET` is set and `x-hub-signature-256` is missing.
- Use `crypto.timingSafeEqual` after length checks for HMAC comparison.
- Validate event type, delivery ID replay, repository identity, and branch/ref values.

### SAST-05: SSRF and Source Exfiltration via Configurable LLM/OSV Endpoints

Severity: High
Confidence: Medium-High
CWE: CWE-918
Affected files:

- `src/app/api/settings/llm/route.ts`
- `src/app/api/scans/route.ts`
- scanner code using `orgSettings.llmBaseUrl` and `orgSettings.osvApiUrl`

Evidence:

- Authenticated users can set `llmBaseUrl` and `osvApiUrl` to any syntactically valid URL.
- The scan job includes LLM API key/config and sends scan content to the configured provider.

Impact:

An attacker with settings access can redirect requests to internal services, cloud metadata endpoints, or attacker infrastructure. This can leak source snippets, vulnerability findings, API keys, and dependency inventory.

Recommended fix:

- Restrict configurable endpoints to an admin role.
- Add egress allowlists for supported providers.
- Block private, link-local, loopback, and metadata IP ranges after DNS resolution.
- Store provider keys encrypted and never include them in long-lived job payloads.

### SAST-06: Unrestricted Upload and Unsafe Archive Extraction

Severity: High
Confidence: Medium-High
CWE: CWE-22, CWE-400
Affected files:

- `src/app/api/scans/route.ts`
- `src/worker/scan-processor.ts`

Evidence:

- Uploaded source archives are read fully into memory with `file.arrayBuffer()` and stored without size limits.
- Worker extracts archives using shell commands: `unzip` and `tar`.
- No explicit defense is visible for archive bombs, large file counts, symlink tricks, or path traversal entries.

Impact:

Attackers can cause API/worker memory, disk, or CPU exhaustion. Malicious archives may write unexpected paths or create symlinks/hardlinks if the extraction tooling allows it.

Recommended fix:

- Enforce request and archive size limits before buffering.
- Use safe archive libraries or pre-scan archive manifests.
- Reject absolute paths, `..`, symlinks/hardlinks, device files, excessive entry counts, and excessive decompressed size.
- Extract into a locked-down temporary directory with quotas and timeouts.

### SAST-07: Insecure Default Credentials and Runtime Secrets

Severity: High
Confidence: High
CWE: CWE-798
Affected files:

- `docker-compose.yml`
- `prisma/seed.ts`
- `.env.example`

Evidence:

- Docker Compose defaults include weak database, MinIO, NextAuth, and admin credentials such as development fallback values.
- Seed logic creates an admin with default email/password when `ADMIN_EMAIL` and `ADMIN_PASSWORD` are unset.
- A real `.env` file exists in the local project directory. Values were not printed in this report.

Impact:

If deployed with defaults, an attacker can authenticate as admin or access backing services. Weak `NEXTAUTH_SECRET` may also undermine session security.

Recommended fix:

- Fail startup in production when required secrets are missing or set to known defaults.
- Generate unique secrets during local bootstrap.
- Remove default admin password behavior outside development.
- Ensure `.env` is not committed or included in release artifacts.

### SAST-08: CSV Formula Injection in Findings Export

Severity: Medium
Confidence: High
CWE: CWE-1236
Affected file:

- `src/app/api/scans/[scanId]/findings/export/route.ts`

Evidence:

- CSV fields are escaped for commas/quotes/newlines but values beginning with `=`, `+`, `-`, `@`, tab, or carriage return are not neutralized.
- Scanner findings include attacker-controlled repository content such as titles, descriptions, snippets, file paths, and proof-of-concept text.

Impact:

When analysts open exported CSV in spreadsheet software, malicious formulas can execute spreadsheet actions, trigger external requests, or phish users.

Recommended fix:

- Prefix formula-leading values with a single quote before CSV escaping.
- Apply this to all string fields in CSV exports.
- Add regression tests for `=HYPERLINK(...)`, `+cmd`, `-1+2`, `@SUM(...)`, tab, and carriage-return prefixes.

### SAST-09: Sensitive Secrets Stored in Plaintext and Job Payloads

Severity: Medium
Confidence: High
CWE: CWE-312, CWE-522
Affected files:

- `src/app/api/scans/route.ts`
- `src/app/api/settings/llm/route.ts`
- `src/worker/scan-processor.ts`

Evidence:

- `llmApiKey` and SVN credentials are stored in database settings or BullMQ job data.
- SVN password is passed to CLI arguments, which can be exposed through process inspection on some systems.

Impact:

Database, Redis, logs, or process-list access can reveal provider API keys and repository credentials.

Recommended fix:

- Encrypt sensitive fields at rest with a managed key.
- Avoid putting long-lived secrets in queue payloads; pass secret references and fetch just-in-time.
- Prefer credential helpers or temporary tokens over command-line password arguments.
- Redact secrets in logs and error messages.

### SAST-10: Missing Login Rate Limiting

Severity: Medium
Confidence: Medium
CWE: CWE-307
Affected file:

- `src/lib/auth.ts`

Evidence:

- Credentials login performs a direct lookup and `bcrypt.compare` with no visible rate limiting, lockout, IP throttling, or failed-attempt tracking.

Impact:

Credential stuffing and brute force attacks are practical, especially when combined with known default admin credentials.

Recommended fix:

- Add IP and account-based rate limiting.
- Add progressive delays or temporary lockouts.
- Alert on repeated failures and default admin login attempts.

### SAST-11: Vulnerable Production Dependencies

Severity: High
Confidence: High
Source: `npm audit --omit=dev --json`

Audit summary:

- Total production advisories: 21
- Critical: 1
- High: 9
- Moderate: 9
- Low: 2

Notable advisories:

- `fast-xml-parser`: critical entity/DOCTYPE handling issues and DoS advisories.
- `next`: high/moderate Next.js advisories; audit suggests `next@16.2.4`.
- `prisma` / `@prisma/config` / `@prisma/dev`: high advisories through transitive packages.
- `@hono/node-server` / `hono`: static path and routing bypass issues through Prisma tooling chain.
- `lodash`: code injection/prototype pollution advisories.
- `bullmq` / `uuid`: moderate advisory chain.
- `nodemailer`: SMTP command injection advisories; no fix available in audit output for the current dependency path.

Recommended fix:

- Upgrade direct dependencies where patched versions exist, starting with `next`, `prisma`, and `bullmq`.
- Re-run `npm audit --omit=dev` after each lockfile update.
- For advisories without fixes, document exploitability and isolate the dependency behind input validation or operational controls.

### SAST-12: Lint Failures Hide Security-Relevant Defects

Severity: Medium
Confidence: High
Source: `npm run lint`

Evidence:

- 12 lint errors and 13 warnings.
- Notable failures include conditional React hook usage, `no-explicit-any` in seed code, unescaped entity in UI, and forbidden `require()` import in PDF parsing code.

Impact:

Lint failure means CI cannot reliably gate code quality. Hook-order bugs can cause runtime state confusion, and unchecked `any` usage weakens type guarantees in seed/bootstrap code.

Recommended fix:

- Fix existing lint errors and enforce lint in CI.
- Avoid blanket disabling of security-adjacent rules.
- Add route authorization tests so lint/type checks are supplemented by behavioral controls.

## Positive Observations

- Passwords use `bcrypt.hash(..., 12)` and `bcrypt.compare`.
- Several schemas use `zod` validation for basic input shape.
- Some destructive actions, such as scan deletion, already call `requireRole`; this pattern should be extended consistently.
- Tests for `security-report` currently pass.

## Prioritized Remediation Plan

1. Fix worker command execution immediately: use argument-array process execution and strict SCM input validation.
2. Add resource-level authorization helpers and retrofit all scan, finding, artifact, project, build gate, policy, and export routes.
3. Make webhook verification fail closed and validate branch/repo inputs before queueing scans.
4. Restrict LLM/OSV endpoint configuration to admins and enforce outbound allowlists.
5. Add upload size limits and safe archive extraction.
6. Remove production defaults for admin/password/service secrets.
7. Fix CSV formula injection.
8. Encrypt or reference sensitive secrets instead of storing them in plaintext job payloads.
9. Add login rate limiting.
10. Upgrade vulnerable dependencies and restore lint as a passing CI gate.

## Verification Notes

Commands run:

```bash
npm test
npm run lint
npm_config_cache="/home/sam/pepper/.npm-cache" npm audit --omit=dev --json
semgrep --version
```

Results:

- `npm test`: passed.
- `npm run lint`: failed with existing issues.
- `npm audit`: completed with 21 production advisories.
- `semgrep`: unavailable (`command not found`).

