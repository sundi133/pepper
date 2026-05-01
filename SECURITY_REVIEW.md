# Pepper Source Code Security Review

Review target: `/home/sam/pepper-main.zip`, extracted to `extracted/pepper-main`.

## Executive Summary

| ID | Vulnerability | Severity | Primary Impact |
| --- | --- | --- | --- |
| VULN-01 | OS Command Injection in Git scan worker | Critical | Authenticated worker RCE |
| VULN-02 | Broken Access Control / IDOR across tenant resources | High | Cross-tenant read/write/delete of projects, scans, findings, artifacts |
| VULN-03 | Missing RBAC on admin APIs | High | Viewer/developer can invite admins and change security controls |
| VULN-04 | SSRF and source-code exfiltration via configurable LLM/OSV endpoints | High | Internal network access, API key and source disclosure |
| VULN-05 | Weak or missing webhook authentication | High | Unauthenticated scan creation, DoS, RCE chain with VULN-01 |
| VULN-06 | Unrestricted upload and unsafe archive extraction | High | API/worker disk, memory, and CPU DoS; archive traversal risk |
| VULN-07 | Insecure default admin credentials and secrets | High | Full admin takeover on misconfigured deployments |
| VULN-08 | CSV Formula Injection in findings export | Medium | Spreadsheet command execution/phishing on analyst workstation |
| VULN-09 | Sensitive secrets stored in plaintext/job payloads | Medium | LLM, SMTP, and SVN credential disclosure after DB/Redis access |
| VULN-10 | Missing login rate limiting | Medium | Credential stuffing and brute force, especially against default admin |

---

## VULN-01: OS Command Injection in Git Scan Worker

**Severity: Critical.** A logged-in user can enqueue a Git scan with attacker-controlled `repoUrl` or `branch`. The worker passes those values into `child_process.execSync()` through a shell, allowing arbitrary command execution inside the worker container. Combined with VULN-02 or VULN-05, this can become cross-tenant or unauthenticated RCE.

### Affected Source Code

| File | Function | Lines | What happens |
| --- | --- | --- | --- |
| `src/app/api/scans/route.ts` | `POST` | 17, 34-58 | `repoUrl` is accepted as any string and parsed from JSON/form data. No URL scheme allowlist, no branch validation. |
| `src/app/api/scans/route.ts` | `POST` | 105-137 | Untrusted `repoUrl`/`branch` are stored in `sourceRef` and queue job data. |
| `src/worker/scan-processor.ts` | `processScanJob` | 58-65 | `execSync(\`git clone --depth 1 --branch ${branch} ${repoUrl} ${workDir}/repo\`)` interpolates untrusted values into a shell command. |

Unsafe logic:

```ts
// src/worker/scan-processor.ts:62-64
execSync(
  `git clone --depth 1 --branch ${branch} ${repoUrl} ${workDir}/repo`,
  { timeout: 120000 },
);
```

### Root Cause

The code uses shell string interpolation for a command that includes user-controllable input. `repoUrl` in scan creation is not even validated as a URL, and `branch` accepts shell metacharacters.

### Attack Scenario

An attacker with any valid account submits a scan with `branch` set to `main; id > /tmp/pepper-rce-poc #`. The worker executes the injected `id` command. From there, an attacker can read mounted application files, environment variables, Redis/Postgres/MinIO credentials, source artifacts, and attempt lateral movement inside the Docker network.

### Steps to Reproduce

1. Authenticate as any user and capture the session cookie.
2. Find or create a project ID.
3. Send:

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

### Safe Proof of Concept

Expected observable behavior on the worker container:

```bash
cat /tmp/pepper-rce-poc
# uid=... gid=...
```

### Impact

Worst case: remote code execution in the scan worker, theft of secrets and scanned source code, tampering with scan findings/build gates, persistence through Redis jobs or images, and movement to Postgres/Redis/MinIO services.

### How to Fix

Use `execFileSync` or `spawn` with an argument array. Validate Git URLs and branch names before queueing.

```ts
// src/app/api/scans/route.ts
const safeGitUrl = z
  .string()
  .url()
  .refine((u) => ["https:", "ssh:"].includes(new URL(u).protocol), {
    message: "Only https and ssh Git URLs are allowed",
  });

const safeGitRef = z
  .string()
  .regex(/^[A-Za-z0-9._\/-]{1,128}$/, "Invalid Git ref")
  .refine((v) => !v.includes("..") && !v.startsWith("-"));

const createScanSchema = z.object({
  projectId: z.string(),
  repoUrl: safeGitUrl.optional(),
  branch: safeGitRef.optional(),
  // existing fields...
});
```

```ts
// src/worker/scan-processor.ts
const { execFileSync } = await import("child_process");
const repoUrl = job.data.repoUrl || sourceRef;
const branch = job.data.branch || "main";

execFileSync(
  "git",
  ["clone", "--depth", "1", "--branch", branch, "--", repoUrl, path.join(workDir, "repo")],
  { timeout: 120000, stdio: "pipe" },
);
```

### Security Test Cases

```ts
it("rejects branch command injection", async () => {
  await expectCreateScan({ branch: "main; touch /tmp/pwned" }).rejects.toHaveStatus(400);
});

it("rejects non-url repoUrl", async () => {
  await expectCreateScan({ repoUrl: "https://x.git; id" }).rejects.toHaveStatus(400);
});

it("invokes git without a shell", () => {
  expect(execFileSync).toHaveBeenCalledWith(
    "git",
    expect.arrayContaining(["clone", "--", "https://github.com/org/repo.git"]),
    expect.any(Object),
  );
});
```

### Regression Prevention

Add a SAST rule banning `exec`, `execSync`, and `spawn(..., { shell: true })` with template strings. Require URL/ref validators for all SCM input. Run worker containers as non-root with read-only root filesystem and no broad network egress.

### Final Developer Summary

Replace shell-based Git clone with `execFileSync("git", args)`, validate `repoUrl` and `branch`, and add a test that the injection payload is rejected.

---

## VULN-02: Broken Access Control / IDOR Across Tenant Resources

**Severity: High.** Many routes verify only that the requester is authenticated, then read or mutate resources by attacker-supplied IDs without checking that the resource belongs to one of the user's organizations. This exposes scan findings, source metadata, SARIF/SBOM artifacts, project settings, and destructive actions across tenants.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/lib/auth-guard.ts` | `requireAuth` | 12-20 | Checks login only. No org or role authorization. |
| `src/app/api/projects/[projectId]/route.ts` | `GET/PATCH/DELETE` | 15-16, 69-71, 98 | Direct project lookup/update/delete by `projectId`. |
| `src/app/api/projects/[projectId]/schedule/route.ts` | `GET/PUT/DELETE` | 26-28, 48-58, 85 | Schedule access by `projectId` only. |
| `src/app/api/scans/route.ts` | `POST` | 61-65 | Comment says access is verified, but only existence is checked. |
| `src/app/api/scans/[scanId]/route.ts` | `GET` | 14-21 | Returns scan by `scanId` without org membership check. |
| `src/app/api/scans/[scanId]/findings/route.ts` | `GET` | 22-45 | Lists findings by `scanId` without scan ownership check. |
| `src/app/api/scans/[scanId]/artifacts/[type]/route.ts` | `GET` | 29-43 | Downloads artifact by `scanId`/type without authorization. |
| `src/app/api/scans/[scanId]/cancel/route.ts` | `POST` | 15-42 | Cancels any queued/running scan by ID. |
| `src/app/api/findings/[findingId]/route.ts` | `GET/PATCH` | 30-40, 64-72 | Reads/updates any finding by ID. |
| `src/app/api/findings/bulk/route.ts` | `PATCH` | 26-34 | Updates any list of finding IDs. |
| `src/app/api/settings/build-gates/route.ts` | `PUT` | 23-40 | Updates any project's build gate by `projectId`. |

### Root Cause

Multi-tenancy exists in the schema, but resource-specific authorization is not enforced in most route handlers. `requireRole()` exists but is not used on these endpoints.

### Attack Scenario

A user from Organization A enumerates or obtains a `scanId` for Organization B and calls `/api/scans/{scanId}/artifacts/sarif`. The response can include file paths, vulnerable code snippets, dependency inventory, and scan metadata. The same user can mark critical findings as `FALSE_POSITIVE`, cancel scans, delete projects, or start RCE scans against another tenant's project.

### Steps to Reproduce

```bash
curl -i "$BASE_URL/api/scans/VICTIM_SCAN_ID/findings" \
  -H "Cookie: next-auth.session-token=$ATTACKER_TOKEN"

curl -i -X PATCH "$BASE_URL/api/findings/VICTIM_FINDING_ID" \
  -H "Content-Type: application/json" \
  -H "Cookie: next-auth.session-token=$ATTACKER_TOKEN" \
  --data '{"status":"FALSE_POSITIVE","statusNote":"tampered"}'
```

### Safe Proof of Concept

Expected behavior before fix: HTTP 200 with another tenant's findings, or 200 with the updated finding. Expected behavior after fix: HTTP 403.

### Impact

Cross-tenant confidentiality breach, integrity loss for vulnerability triage/build gates, denial of service by scan cancellation/deletion, and RCE chain through unauthorized scan creation.

### How to Fix

Authorize through the resource's organization in every route. Do not trust client-supplied org IDs. Fetch the resource with its project/org relation, then call `requireRole()`.

```ts
// src/lib/auth-guard.ts
export async function requireResourceRole(
  organizationId: string,
  minRole: Role,
) {
  return requireRole(organizationId, minRole);
}
```

```ts
// Example: src/app/api/scans/[scanId]/findings/route.ts
const scan = await prisma.scan.findUnique({
  where: { id: scanId },
  select: { project: { select: { organizationId: true } } },
});
if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });

const authz = await requireRole(scan.project.organizationId, "VIEWER");
if ("error" in authz) return authz.error;

const findings = await prisma.finding.findMany({ where: { scanId } });
```

For direct mutations, scope the write:

```ts
await prisma.project.update({
  where: { id: projectId, organizationId: authz.membership.organizationId },
  data,
});
```

If Prisma unique filters do not allow that shape, use `updateMany` plus `count === 1`, or fetch then authorize.

### Security Test Cases

```ts
it("blocks cross-tenant scan findings", async () => {
  const res = await requestAs(orgAViewer).get(`/api/scans/${orgBScan.id}/findings`);
  expect(res.status).toBe(403);
});

it("allows same-tenant viewer to read findings", async () => {
  const res = await requestAs(orgBViewer).get(`/api/scans/${orgBScan.id}/findings`);
  expect(res.status).toBe(200);
});

it("blocks cross-tenant finding status update", async () => {
  const res = await requestAs(orgADeveloper)
    .patch(`/api/findings/${orgBFinding.id}`)
    .send({ status: "RESOLVED" });
  expect(res.status).toBe(403);
});
```

### Regression Prevention

Add an API authorization matrix test for every route. Add a lint/SAST rule that flags `prisma.*.findUnique/update/delete` in route handlers unless followed by `requireRole` or a scoped organization predicate.

### Final Developer Summary

Every project, scan, finding, artifact, schedule, and build-gate route must authorize against the resource's real `organizationId` before returning or mutating data.

---

## VULN-03: Missing RBAC on Admin APIs

**Severity: High.** Any authenticated member, including `VIEWER`, can perform organization-admin actions: invite users as `ADMIN`, modify LLM/security settings, edit policies, and weaken build gates.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/app/api/users/route.ts` | `POST` | 43-85 | Uses `requireAuth()` only, then creates/upserts org membership with attacker-chosen role. |
| `src/app/api/settings/llm/route.ts` | `PUT` | 54-79 | Any member can update LLM/OSV config and API key. |
| `src/app/api/settings/policies/route.ts` | `POST` | 31-50 | Any member can add security policies. |
| `src/app/api/settings/policies/[policyId]/route.ts` | `PATCH/DELETE` | 15-33, 48-58 | Any member can alter/delete policies by ID. |
| `src/app/api/settings/build-gates/route.ts` | `PUT` | 15-42 | Any member can change build gate thresholds. |

### Root Cause

The app defines role hierarchy in `src/lib/constants.ts:36-41` and `requireRole()` in `src/lib/auth-guard.ts:22-43`, but admin endpoints do not use it.

### Attack Scenario

A viewer posts to `/api/users` with `"role":"ADMIN"` and their own email, becoming an admin. They can then disable LLM scans, set permissive build gates, create policies that hide true findings, or combine with VULN-04 to exfiltrate code to an attacker-controlled LLM endpoint.

### Steps to Reproduce

```bash
curl -i -X POST "$BASE_URL/api/users" \
  -H "Content-Type: application/json" \
  -H "Cookie: next-auth.session-token=$VIEWER_TOKEN" \
  --data '{"email":"attacker@example.com","name":"Attacker","role":"ADMIN","password":"TempPassw0rd!"}'
```

### Safe Proof of Concept

Expected vulnerable response: `201` with a membership role of `ADMIN`. Expected fixed response: `403 Forbidden` for non-admins.

### Impact

Privilege escalation, security control tampering, false compliance posture, and easier exploitation of SSRF/RCE paths.

### How to Fix

Require appropriate roles:

```ts
// src/app/api/users/route.ts POST
const orgId = getDefaultOrgId(auth.session);
const authz = await requireRole(orgId, "ADMIN");
if ("error" in authz) return authz.error;
```

Suggested minimum roles:

| Operation | Minimum role |
| --- | --- |
| Invite/remove users, assign roles | `ADMIN` |
| LLM provider/API key/OSV URL settings | `ADMIN` |
| Build gate thresholds | `SECURITY` |
| Security policy create/update/delete | `SECURITY` |
| Finding status updates | `DEVELOPER` or `SECURITY`, depending on workflow |

Also prevent privilege self-escalation and last-admin removal.

### Security Test Cases

```ts
it("viewer cannot invite admin", async () => {
  const res = await requestAs(viewer).post("/api/users").send({ email, role: "ADMIN" });
  expect(res.status).toBe(403);
});

it("admin can invite developer", async () => {
  const res = await requestAs(admin).post("/api/users").send({ email, role: "DEVELOPER" });
  expect(res.status).toBe(201);
});
```

### Regression Prevention

Maintain a role-to-route matrix in tests. Log all role changes and security setting changes with actor, org, target, old value, and new value.

### Final Developer Summary

Replace `requireAuth()` with `requireRole()` on admin/security endpoints and test each role explicitly.

---

## VULN-04: SSRF and Source-Code Exfiltration via Configurable LLM/OSV Endpoints

**Severity: High.** The application lets users configure arbitrary URLs for LLM and OSV services. Those URLs are later called by the server/worker with source code, findings, dependency data, and possibly API keys.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/app/api/settings/llm/route.ts` | `PUT` | 43-51, 70-77 | Accepts any URL for `llmBaseUrl` and `osvApiUrl`; no host allowlist or private-IP block. |
| `src/lib/llm-gateway.ts` | `createOpenAIClient` | 39-57 | Uses configured `baseURL`; OpenAI client sends API key to that URL. |
| `src/lib/llm-gateway.ts` | `analyzeWithLlm` | 137-148 | Sends source chunks/findings to the configured LLM endpoint. |
| `src/scanners/sca/osv-client.ts` | `queryOsvBatch` | 43-47 | `fetch(`${apiUrl}/v1/querybatch`)` calls configured OSV URL. |
| `src/app/api/scans/route.ts` | `POST` | 138-147 | Queues org LLM/OSV config into worker jobs. |

### Root Cause

URL validation checks syntax only, not trust boundaries. The app also lacks RBAC on who may change these settings.

### Attack Scenario

A low-privilege user sets `llmBaseUrl` to `http://attacker.example/v1` and `llmApiKey` to an existing key or lure value. When a scan runs, the worker sends code chunks and finding details to the attacker endpoint. A private URL such as `http://169.254.169.254` or `http://postgres:5432` can be used for SSRF probing in cloud or Docker networks.

### Steps to Reproduce

```bash
curl -i -X PUT "$BASE_URL/api/settings/llm" \
  -H "Content-Type: application/json" \
  -H "Cookie: next-auth.session-token=$TOKEN" \
  --data '{
    "llmProvider":"openai",
    "llmBaseUrl":"http://127.0.0.1:8000/v1",
    "llmModel":"poc",
    "llmApiKey":"poc-secret",
    "enableLlmSast":true
  }'
```

Run a local listener, start a scan, and observe `POST /v1/chat/completions` containing source snippets and an `Authorization: Bearer poc-secret` header.

### Safe Proof of Concept

Expected vulnerable behavior: the listener receives LLM requests from the worker. Expected fixed behavior: settings update is rejected unless the host is explicitly allowed.

### Impact

Source code, detected secrets, dependency inventory, vulnerability findings, and LLM API keys can be exfiltrated. SSRF can probe internal services and cloud metadata endpoints.

### How to Fix

Restrict outbound service targets to trusted providers and block private/link-local/loopback ranges. Apply RBAC before settings changes.

```ts
import dns from "dns/promises";
import net from "net";

const ALLOWED_LLM_HOSTS = new Set([
  "api.openai.com",
  "openrouter.ai",
  "localhost", // only if explicitly enabled for on-prem Ollama
]);

async function assertAllowedServiceUrl(raw: string) {
  const url = new URL(raw);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid protocol");
  if (!ALLOWED_LLM_HOSTS.has(url.hostname)) throw new Error("Host is not allowed");

  const records = await dns.lookup(url.hostname, { all: true });
  for (const r of records) {
    if (isPrivateAddress(r.address)) throw new Error("Private network targets are blocked");
  }
}
```

Prefer separate fixed configs per provider over user-entered base URLs. If custom internal LLM endpoints are required, make them admin-only and deploy egress policies at the container/network layer.

### Security Test Cases

```ts
it("rejects metadata endpoint as llmBaseUrl", async () => {
  const res = await requestAs(admin)
    .put("/api/settings/llm")
    .send({ llmBaseUrl: "http://169.254.169.254/v1" });
  expect(res.status).toBe(400);
});

it("rejects viewer updating LLM settings", async () => {
  const res = await requestAs(viewer).put("/api/settings/llm").send({ llmModel: "x" });
  expect(res.status).toBe(403);
});
```

### Regression Prevention

Add egress allowlists for API and worker containers. Log and alert on settings changes to service URLs. Add SAST rules for server-side `fetch` or SDK clients using user-configurable URLs.

### Final Developer Summary

Make LLM/OSV endpoint changes admin-only, restrict hosts, block private networks, and prevent source code from being sent to arbitrary URLs.

---

## VULN-05: Weak or Missing Webhook Authentication

**Severity: High.** GitHub and GitLab webhook endpoints can accept unauthenticated requests when secrets are not configured. The GitHub route also accepts a request with no signature even when a secret exists, because it verifies only when both secret and signature are present.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/app/api/webhooks/github/route.ts` | `POST` | 7-21 | Signature verification is skipped if `x-hub-signature-256` is missing. No timing-safe compare. |
| `src/app/api/webhooks/github/route.ts` | `POST` | 23-42 | Parses attacker JSON and matches project using `contains`. |
| `src/app/api/webhooks/github/route.ts` | `POST` | 51-95 | Creates scan and queues Git clone from webhook payload. |
| `src/app/api/webhooks/gitlab/route.ts` | `POST` | 6-13 | If `GITLAB_WEBHOOK_SECRET` is unset, all requests are accepted. |
| `src/app/api/webhooks/gitlab/route.ts` | `POST` | 25-81 | Creates scan and queues Git clone from webhook payload. |

### Root Cause

Webhook authentication is optional, and missing signatures are not treated as failures. Project matching relies on untrusted payload strings.

### Attack Scenario

An internet attacker posts a fake GitHub webhook with `repository.full_name` containing a victim project's repo substring and a malicious `pull_request.head.ref`. The app queues a scan. With VULN-01, the branch value becomes command injection.

### Steps to Reproduce

```bash
curl -i -X POST "$BASE_URL/api/webhooks/github" \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  --data '{
    "action":"opened",
    "repository":{
      "full_name":"ORG/REPO",
      "clone_url":"https://github.com/octocat/Hello-World.git"
    },
    "pull_request":{
      "head":{"ref":"main; id > /tmp/webhook-rce #","sha":"abc"},
      "base":{"sha":"def"},
      "number":1
    }
  }'
```

### Safe Proof of Concept

Expected vulnerable response: `200` with `{ "scanId": "...", "status": "QUEUED" }` without any signature. Expected fixed response: `401`.

### Impact

Unauthenticated scan spam, compute-cost DoS, project scan pollution, and unauthenticated RCE chain through the Git clone injection.

### How to Fix

Require webhook secrets in production and reject missing/invalid signatures.

```ts
const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
if (!webhookSecret) {
  return NextResponse.json({ error: "Webhook secret not configured" }, { status: 503 });
}
if (!signature?.startsWith("sha256=")) {
  return NextResponse.json({ error: "Missing signature" }, { status: 401 });
}

const expected = Buffer.from(
  `sha256=${crypto.createHmac("sha256", webhookSecret).update(body).digest("hex")}`,
);
const actual = Buffer.from(signature);
if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
  return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
}
```

Bind webhook delivery to a specific project or stored provider installation/repo ID instead of `contains`.

### Security Test Cases

```ts
it("rejects github webhook without signature when secret configured", async () => {
  const res = await request.post("/api/webhooks/github").set("X-GitHub-Event", "pull_request").send(payload);
  expect(res.status).toBe(401);
});

it("rejects fake repo full_name that only contains the victim name", async () => {
  const res = await signedGithubWebhook({ repository: { full_name: "attacker/victim-repo-copy" } });
  expect(res.status).toBe(404);
});
```

### Regression Prevention

Add webhook auth tests for missing, malformed, bad, and valid signatures. Alert on webhook-triggered scan volume spikes.

### Final Developer Summary

Webhook endpoints must fail closed: no secret or no signature means no scan.

---

## VULN-06: Unrestricted Upload and Unsafe Archive Extraction

**Severity: High.** The scan upload path reads the entire file into memory, accepts archives based on filename extension, stores them, and extracts them without size, entry count, path, or compression-ratio limits.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/app/api/scans/route.ts` | `POST` | 44-55 | Reads uploaded file fully into memory with `file.arrayBuffer()`. |
| `src/app/api/scans/route.ts` | `POST` | 96-104 | Chooses extension from filename, no MIME/content/size validation. |
| `src/worker/scan-processor.ts` | `processScanJob` | 50-57 | Downloads and writes archive to disk, then extracts. |
| `src/worker/scan-processor.ts` | `extractArchive` | 530-541 | Uses `unzip`/`tar` directly with no pre-scan of entries or extraction limits. |

### Root Cause

The upload handler lacks maximum request/file size and archive validation. The worker trusts archive tools to handle dangerous entries and decompression bombs.

### Attack Scenario

An authenticated user uploads a small zip bomb that expands to many GB or millions of files. The API may exhaust memory while reading the file, and the worker may exhaust disk/inodes/CPU while extracting, preventing other tenants from scanning.

### Steps to Reproduce

1. Create a benign compressed bomb in a test environment.
2. Upload it as a scan source:

```bash
curl -i -X POST "$BASE_URL/api/scans" \
  -H "Cookie: next-auth.session-token=$TOKEN" \
  -F 'data={"projectId":"PROJECT_ID","scanType":"SAST_ONLY"};type=application/json' \
  -F "file=@bomb.zip;type=application/zip"
```

### Safe Proof of Concept

Expected vulnerable behavior: request accepts the archive and worker disk/memory usage spikes. Expected fixed behavior: request returns `413 Payload Too Large` or `400 Invalid archive`.

### Impact

Denial of service for API and worker, queue backlog, scan failure, and possible overwrite/traversal behavior depending on tar/unzip implementation and crafted entries.

### How to Fix

Set body/file limits, validate magic bytes, inspect archive entries before extraction, and extract with a safe library that enforces normalized paths.

```ts
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
if (file.size > MAX_UPLOAD_BYTES) {
  return NextResponse.json({ error: "File too large" }, { status: 413 });
}

const allowedTypes = new Set(["application/zip", "application/gzip", "application/x-tar"]);
if (!allowedTypes.has(file.type)) {
  return NextResponse.json({ error: "Unsupported archive type" }, { status: 400 });
}
```

Before writing each extracted entry:

```ts
const target = path.resolve(destDir, entryName);
const root = path.resolve(destDir) + path.sep;
if (!target.startsWith(root)) throw new Error("Archive path traversal blocked");
```

Run extraction in a sandbox with disk quota, file count limit, max expanded bytes, and timeout.

### Security Test Cases

```ts
it("rejects upload larger than max size", async () => {
  const res = await uploadArchive({ size: MAX_UPLOAD_BYTES + 1 });
  expect(res.status).toBe(413);
});

it("rejects archive entry with parent traversal", async () => {
  await expect(extractArchiveWithEntry("../outside.txt")).rejects.toThrow(/traversal/);
});

it("rejects archive with too many entries", async () => {
  await expect(extractArchiveWithEntries(100001)).rejects.toThrow(/too many/);
});
```

### Regression Prevention

Add request size limits at reverse proxy and app layers. Use worker cgroups/quotas. Add upload abuse alerts and scan queue backpressure.

### Final Developer Summary

Do not read unlimited uploads into memory or blindly extract archives. Enforce file size, MIME/magic, entry count, path normalization, expanded-size quotas, and worker sandboxing.

---

## VULN-07: Insecure Default Admin Credentials and Secrets

**Severity: High.** The app ships known fallback admin credentials and known fallback `NEXTAUTH_SECRET` values. The Dockerfile runs the seed script on startup, and the seed script resets the admin password to the configured value or the public default.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `.env.example` | config | 16, 58-59 | Public example contains `NEXTAUTH_SECRET="change-me..."` and default admin password. |
| `docker-compose.yml` | config | 67-70 | Defaults `NEXTAUTH_SECRET` and `ADMIN_PASSWORD` to known values. |
| `Dockerfile` | `CMD` | 38-39 | Runs seed script every startup. |
| `prisma/seed.ts` | `main` | 49-57 | Falls back to `admin@pepper.local` / `pepper-admin-changeme` and updates password hash. |

### Root Cause

Production startup does not fail closed when required secrets are missing. Known defaults are accepted as real credentials.

### Attack Scenario

An operator deploys without overriding `ADMIN_PASSWORD` or `NEXTAUTH_SECRET`. An attacker logs in as `admin@pepper.local` with `pepper-admin-changeme`. A known auth secret can also undermine the integrity/confidentiality of NextAuth JWT cookies.

### Steps to Reproduce

1. Start the default compose deployment.
2. Browse to `/login`.
3. Login with:

```text
admin@pepper.local
pepper-admin-changeme
```

### Safe Proof of Concept

Expected vulnerable behavior: admin login succeeds. Expected fixed behavior: application refuses to start until a strong unique secret and admin password are provided, or generates a one-time setup flow.

### Impact

Full application takeover, tenant data exposure, security control tampering, and potential session forgery if `NEXTAUTH_SECRET` is known.

### How to Fix

Fail startup in production when required secrets are missing or set to known defaults.

```ts
function requireStrongEnv(name: string, forbidden: string[]) {
  const value = process.env[name];
  if (!value || forbidden.includes(value) || value.length < 32) {
    throw new Error(`${name} must be set to a unique strong value`);
  }
  return value;
}

const password = requireStrongEnv("ADMIN_PASSWORD", ["pepper-admin-changeme"]);
requireStrongEnv("NEXTAUTH_SECRET", ["dev-secret-change-me", "change-me-to-a-random-secret"]);
```

Do not reset admin password on every startup. Seed only during first-run setup, or require an explicit `SEED_ADMIN=true`.

### Security Test Cases

```ts
it("fails seed when default admin password is used in production", async () => {
  process.env.NODE_ENV = "production";
  process.env.ADMIN_PASSWORD = "pepper-admin-changeme";
  await expect(seed()).rejects.toThrow(/ADMIN_PASSWORD/);
});
```

### Regression Prevention

Add secret scanning for default values. Add deployment preflight checks and release checklist items that block known defaults.

### Final Developer Summary

Known defaults must never authenticate users or sign sessions. Make setup explicit and fail closed.

---

## VULN-08: CSV Formula Injection in Findings Export

**Severity: Medium.** Finding fields are attacker-controlled because they originate from scanned repositories and LLM output. CSV export writes those values without neutralizing spreadsheet formulas.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/app/api/scans/[scanId]/findings/export/route.ts` | `GET` | 59-76 | Writes title/description/file/snippet to CSV. |
| `src/app/api/scans/[scanId]/findings/export/route.ts` | `csvEscape` | 86-91 | Escapes delimiters only; does not neutralize `=`, `+`, `-`, `@`, tab, CR. |

### Root Cause

CSV escaping is not the same as spreadsheet formula prevention.

### Attack Scenario

An attacker commits code that causes a finding title/snippet beginning with `=HYPERLINK("https://attacker.example","Click")`. When an analyst exports findings and opens the CSV, the spreadsheet evaluates the formula.

### Steps to Reproduce

Insert or mock a finding with:

```text
title = =HYPERLINK("https://example.test","Click")
```

Then:

```bash
curl -o findings.csv "$BASE_URL/api/scans/SCAN_ID/findings/export?format=csv" \
  -H "Cookie: next-auth.session-token=$TOKEN"
```

### Safe Proof of Concept

Expected vulnerable CSV cell:

```csv
=HYPERLINK("https://example.test","Click")
```

Expected fixed CSV cell:

```csv
'=HYPERLINK("https://example.test","Click")
```

### Impact

Phishing, local command abuse in legacy spreadsheet configurations, or data exfiltration from analyst workstations.

### How to Fix

Prefix dangerous leading characters before CSV quoting.

```ts
function csvEscape(value: string): string {
  const normalized = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const safe = /^[=+\-@\t\n\r]/.test(normalized) ? `'${normalized}` : normalized;
  if (/[",\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}
```

### Security Test Cases

```ts
for (const prefix of ["=", "+", "-", "@", "\t", "\r"]) {
  it(`neutralizes CSV formula prefix ${JSON.stringify(prefix)}`, () => {
    expect(csvEscape(`${prefix}cmd`)).toMatch(/^'?/);
    expect(csvEscape(`${prefix}cmd`).startsWith("'")).toBe(true);
  });
}
```

### Regression Prevention

Centralize CSV generation in a utility and ban ad hoc CSV building in route handlers.

### Final Developer Summary

CSV export must neutralize spreadsheet formula prefixes, not only quote commas.

---

## VULN-09: Sensitive Secrets Stored in Plaintext and Queue Payloads

**Severity: Medium.** LLM API keys, SMTP passwords, and SVN passwords are stored or transported as plaintext in the database and Redis queue.

### Affected Source Code

| File | Lines | Unsafe logic |
| --- | --- | --- |
| `prisma/schema.prisma` | 305, 315 | `llmApiKey` and `smtpPassword` are plaintext `Text` fields. |
| `src/app/api/scans/route.ts` | 132-146 | `svnPassword` and `llmApiKey` are included in BullMQ job data. |
| `src/lib/queue.ts` | 38-52 | Queue schema includes `svnPassword` and `llmApiKey`. |
| `src/worker/scheduler.ts` | 101-109 | LLM API key is queued for scheduled scans. |

### Root Cause

Secrets are treated as ordinary application data instead of being encrypted, referenced, or fetched just-in-time.

### Attack Scenario

Anyone with read access to Postgres or Redis, logs, queue dashboards, snapshots, or failed job payloads can recover provider API keys and source repository credentials.

### Steps to Reproduce

Create an SVN scan with a password or configure an LLM API key, then inspect the BullMQ job payload in Redis or the `OrgSettings` row.

### Safe Proof of Concept

Expected vulnerable behavior: plaintext secret appears in DB/Redis. Expected fixed behavior: DB stores ciphertext and queue payload contains only a reference.

### Impact

Credential theft, unauthorized LLM billing/use, SMTP abuse, and repository access compromise.

### How to Fix

Encrypt secrets at rest with envelope encryption and avoid placing them in queue payloads.

```ts
// Queue only references org/project/scan IDs.
const jobData = {
  scanId: scan.id,
  projectId: project.id,
  orgId: project.organizationId,
};

// Worker fetches and decrypts just-in-time.
const settings = await prisma.orgSettings.findUnique({ where: { organizationId: job.data.orgId } });
const llmApiKey = decrypt(settings.llmApiKeyCiphertext);
```

Use a KMS or locally managed `PEPPER_ENCRYPTION_KEY`, rotate keys, and redact secrets from logs/errors.

### Security Test Cases

```ts
it("does not include llmApiKey in queued job data", async () => {
  const job = await enqueueScan();
  expect(JSON.stringify(job.data)).not.toContain("sk-");
});

it("stores LLM key encrypted", async () => {
  const row = await prisma.orgSettings.findUnique({ where: { organizationId } });
  expect(row.llmApiKey).not.toBe("plaintext-secret");
});
```

### Regression Prevention

Add secret-field naming checks in CI, Redis payload redaction tests, and backup encryption requirements.

### Final Developer Summary

Do not persist or queue raw credentials. Store encrypted secrets and pass references to workers.

---

## VULN-10: Missing Login Rate Limiting

**Severity: Medium.** The credentials provider accepts unlimited password attempts. This is especially risky because the project also ships default admin credentials.

### Affected Source Code

| File | Function | Lines | Unsafe logic |
| --- | --- | --- | --- |
| `src/lib/auth.ts` | Credentials `authorize` | 19-30 | Direct password verification with no rate limit, lockout, or audit signal. |
| `src/app/(auth)/login/page.tsx` | `handleSubmit` | 30-34 | Client submits directly to NextAuth without additional throttling. |

### Root Cause

No per-IP, per-account, or global throttling is applied to credential login attempts.

### Attack Scenario

An attacker performs credential stuffing against `admin@pepper.local` or real user emails. Without throttling, only bcrypt cost limits the attack.

### Steps to Reproduce

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/auth/callback/credentials" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "email=admin@pepper.local&password=wrong-$i"
done
```

### Safe Proof of Concept

Expected vulnerable behavior: repeated attempts are processed. Expected fixed behavior: attempts after threshold return `429 Too Many Requests`.

### Impact

Account compromise through password guessing or credential stuffing, especially with default or weak passwords.

### How to Fix

Add server-side throttling in the credentials `authorize` path, backed by Redis.

```ts
async function assertLoginAllowed(email: string, ip: string) {
  const key = `login:${ip}:${email.toLowerCase()}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, 15 * 60);
  if (count > 10) throw new Error("Too many login attempts");
}
```

Record failed attempts, add alerting for stuffing patterns, and require MFA for admins.

### Security Test Cases

```ts
it("rate limits repeated failed logins", async () => {
  for (let i = 0; i < 10; i++) await login("admin@pepper.local", "wrong");
  const res = await login("admin@pepper.local", "wrong-again");
  expect(res.status).toBe(429);
});
```

### Regression Prevention

Add DAST checks for login throttling, WAF/rate-limit rules, account lockout monitoring, and audit logs for failed login bursts.

### Final Developer Summary

Throttle credential login attempts by IP and account, alert on bursts, and require MFA for admin users.

---

## Global Remediation Priorities

1. Fix VULN-01 immediately by removing shell interpolation from Git clone.
2. Add resource-level authorization and RBAC tests before expanding API features.
3. Lock down webhook authentication and LLM/OSV egress.
4. Add upload limits and safe extraction before accepting untrusted archives.
5. Remove known defaults and fail deployment preflight when secrets are missing.

## Suggested CI/CD Gates

| Gate | Rule |
| --- | --- |
| SAST | Block `exec`/`execSync` with template strings or string concatenation. |
| Authorization tests | Every API route has same-tenant allow and cross-tenant deny tests. |
| Secret scanning | Fail on `pepper-admin-changeme`, `dev-secret-change-me`, `minioadmin`, and provider key patterns. |
| Dependency scanning | Run `npm audit` or equivalent in CI and image builds. |
| DAST | Exercise login throttling, webhook signature rejection, IDOR checks, and upload limits. |
| Runtime | Worker runs non-root with network egress allowlist, memory/disk quotas, and read-only root filesystem where practical. |

