# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Commands

```bash
# Setup & Development
npm install                          # Install dependencies
npm run dev                          # Start web server (localhost:3000)
npm run worker                       # Start scan worker (separate terminal)
npm run db:setup                     # Initialize DB: migrate + push + seed

# Database
npm run db:migrate                   # Create new migration
npm run db:deploy                    # Apply migrations to prod
npm run db:push                      # Sync schema to DB (dev)
npm run db:generate                  # Regenerate Prisma client

# Testing & Quality
npm test                             # Run tests (vitest)
npm run lint                         # Lint code (eslint)

# Building & Deployment
npm run build                        # Build Next.js (outputs .next/)
npm start                            # Run production server
docker compose up -d                 # Start infra (postgres, redis, minio)
docker compose down                  # Stop infra
npm run docker:build                 # Build Docker images
```

## Architecture Overview

**Pepper** is an AI-powered SAST platform with five major components:

### 1. Web Dashboard (Next.js)
- **Location:** `src/app/(dashboard)/` — authenticated pages (projects, scans, settings, integrations)
- **API Routes:** `src/app/api/` — REST endpoints for scans, findings, webhooks, VCS integrations
- **Auth:** NextAuth.js (OAuth + email/password); multi-tenant via organization slug
- **Database:** Prisma ORM + PostgreSQL; schema in `prisma/schema.prisma`
- **UI:** React + Shadcn (Radix) + Tailwind

### 2. Scanner Framework
- **Location:** `src/scanners/` — modular scanner implementations
- **Execution:** Workers run scanners in parallel via BullMQ (Redis queue)
- **Scanners:**
  - **SAST:** Pattern-based (Semgrep) + LLM-assisted (Ollama/OpenAI/Anthropic)
  - **SCA (Dependency):** Package manifest parsing + OSV.dev vulnerability lookup
  - **Secrets:** Regex patterns + LLM confidence scoring
  - **IaC:** Terraform/CloudFormation/Dockerfile validation
  - **Container:** Trivy integration for image scanning
  - **Zero-Day:** Advanced AI-driven vulnerability detection
  - **DAST:** Dapper integration (HTTP API / CLI)

### 3. Dependency Scanning (SCA)
- **Location:** `src/scanners/sca/`
- **Parsers:** `src/scanners/sca/parsers/` — language-specific manifest parsers
  - Currently supports: JS (package.json), Python (requirements.txt, pyproject.toml), Java (pom.xml), Go (go.mod), Rust (Cargo.toml), PHP (composer.json), Ruby (Gemfile), .NET (csproj), Dart, Swift, Elixir
  - **Missing (priority):** `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `gradle.lockfile`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `Dockerfile` dependency extraction
- **Vulnerability Source:** `osv-client.ts` queries OSV.dev API
- **SBOM:** `sbom-generator.ts` — CycloneDX 1.5 + SPDX 2.3 output
- **Deduplication:** `triage.ts` — groups related findings

### 4. VCS Integration & Webhooks
- **Location:** `src/lib/*-(github|bitbucket|azure-devops|gitlab)*`
- **OAuth Connections:** Store encrypted tokens in DB; refresh on use
- **PR Feedback:**
  - Inline comments on diffs (file + line)
  - Summary/status checks
  - Auto-fix PRs (agent-driven)
- **Webhook Scanning:** GitHub/Bitbucket/Azure → Incremental scans on PR/push
- **Query Source Links:** Generate links to code lines in GitHub/Bitbucket UI

### 5. Worker & Async Jobs
- **Location:** `src/worker/` — standalone process (not Next.js)
- **Queue:** BullMQ + Redis (bullmq config in code, Redis URL from env)
- **Job Types:** Scans, notifications, compliance report generation, scheduled scans
- **LLM Gateway:** `src/lib/llm-gateway.ts` — abstraction over Ollama/OpenAI/Anthropic with retries + rate limiting
- **Artifact Storage:** MinIO (S3-compatible) for scan results, SBOMs, reports

## Key Files & Their Purpose

### Scanner Framework
- `src/scanners/framework.test.ts` — Base scanner interface & test utilities
- `src/scanners/index.ts` — Scanner orchestration & selection
- `src/scanners/types.ts` — Unified finding format (scanner-agnostic)

### Finding Deduplication & Report Output
- `src/lib/finding-report.ts` — Converts scanner results → customer-ready findings
  - Groups by component/version/sink
  - Applies suppression rules
  - Calculates risk score & exploitability
- `src/lib/suppression-rules.ts` — Per-org suppression (auto-generated from false-positive marking)
- `src/lib/severity-calibration.ts` — CVSS → context-aware risk adjustments
- `src/lib/risk-score.ts` — Composite risk calculation (CVSS + reachability + exploit maturity)

### VCS & PR Integration
- `src/lib/github-pr-inline-format.ts` — Formats findings for GitHub PR comments
- `src/lib/github-open-fix-pr.ts` — Agent-driven remediation PR generation
- `src/lib/open-fix-pr-flow.ts` — Orchestrates auto-fix across all VCS providers
- Equivalent files for Bitbucket, Azure DevOps, GitLab

### Reports
- `src/lib/finding-report.ts` — JSON export of findings
- `src/lib/pdf-report.ts` — PDF report generation (pdfkit)
- `src/lib/compliance/` — Compliance framework mappings (SOC2, PCI-DSS, etc.)

### LLM Integration
- `src/lib/llm-gateway.ts` — Provider abstraction (Ollama, OpenAI, Anthropic, OpenRouter, Azure, vLLM)
  - Retry logic, rate limiting, token counting
  - Context injection (repo code, finding evidence)
- `src/lib/llm-repo-context.ts` — Extracts context window for LLM (affected code, dependencies)

### Settings & Configuration
- `src/app/api/settings/llm/` — LLM provider config (model, API key, toggles per scan type)
- `src/app/(dashboard)/settings/` — UI for all org-level settings (integrations, policies, webhooks, signing, suppressions)

### Database & ORM
- `prisma/schema.prisma` — Full data model (Organizations, Projects, Scans, Findings, Suppressions, etc.)
- `prisma/migrations/` — Timestamped migration files (auto-applied on startup)

## Execution Flow

### 1. Scan Initiation
1. User creates scan in UI or via API (`POST /api/scans`)
2. Validates source (repo URL, file upload, or SVN checkout)
3. Queues scan job → BullMQ (Redis)
4. Worker picks up job, downloads/extracts source
5. Dispatches to scanner modules in parallel (SAST, SCA, Secrets, etc.)

### 2. Dependency Scanning (SCA)
1. Worker locates manifests: `src/scanners/sca/index.ts`
2. Reads each manifest (package.json, requirements.txt, pom.xml, etc.)
3. Parser extracts dependencies + versions
4. OSV client queries `api.osv.dev` for vulnerabilities
5. Groups findings, applies suppressions
6. Returns unified finding array

### 3. PR Feedback (on webhook)
1. Webhook received → matched to project
2. Scan queued (incremental if PR, full if push to main)
3. After scan, findings → inline comments + status check
4. If user clicks "fix", agent → generates PR with patches

### 4. Report Generation
1. User downloads PDF/CSV/HTML or views in UI
2. `finding-report.ts` deduplicates & formats
3. Each finding includes evidence, links, remediation, exploitability context

## Data Model

### Core Tables
- **Organization** — tenants; slug is URL identifier
- **Project** — repositories; linked to VCS connections (GitHub ID, Bitbucket UUID, etc.)
- **Scan** — one run; tracks status, progress, timestamps, linked to project
- **Finding** — individual vulnerability; linked to scan, includes scanner, severity, file path, evidence
- **SuppressionRule** — org/project-level rules; auto-generated when users mark false positives
- **OrgSettings** — LLM provider config, SMTP, DAST endpoint, signing certs, webhook secrets (encrypted)
- **SecurityPolicy** — custom rules (natural language) that LLM enforces
- **IntegrationConfig** — Slack, Jira, SIEM webhooks
- **Notification** — scan-complete alerts per user

### Key Constraints
- `Scan.projectId` (unique) — one active scan per project (queues upcoming)
- `Finding.scanId` + unique hash — deduplicates within scan
- `SuppressionRule` scoped by org + optional projectId + reason field

## Workflow: Adding a New Dependency Parser

1. Create `src/scanners/sca/parsers/lockfile-name.ts`
   - Export `parseManifest(content: string): Dependency[]` (name + version)
   - Test with fixture in `parsers/__fixtures__/`
2. Register in `src/scanners/sca/index.ts` manifest matcher
3. Add to PR feedback & report generation to surface locked versions
4. Test with real manifests (exact version resolution, transitive deps)

## Environment Variables

### Web Server & Auth
- `NEXTAUTH_URL` — callback base (e.g., `http://localhost:3000`)
- `NEXTAUTH_SECRET` — session encryption key (generate: `openssl rand -base64 32`)
- `DATABASE_URL` — Postgres: `postgresql://user:password@host:5432/pepper`
- `REDIS_URL` — Redis: `redis://localhost:6379`
- `MINIO_URL`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` — S3-compatible artifact storage

### LLM Integration
- `OLLAMA_HOST` — Local LLM server (default: `http://host.docker.internal:11434`)
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` — if using cloud providers
- `LLM_PROVIDER` — `ollama`, `openai`, `anthropic`, `openrouter`, `azure`, `vllm` (configurable per org in UI)

### VCS Integrations
- `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` — GitHub OAuth app
- `TOKEN_ENCRYPTION_KEY` — encrypts stored VCS tokens (defaults to NEXTAUTH_SECRET)
- `GITHUB_WEBHOOK_SECRET`, `BITBUCKET_WEBHOOK_SECRET`, `AZURE_DEVOPS_WEBHOOK_SECRET` — webhook HMAC keys

### Email & Notifications
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`

### Scheduler & Workers
- `WORKER_CONCURRENCY` — parallel scans per worker (default: 2)
- `MAX_LLM_CONCURRENCY` — parallel LLM calls per scan (default: 1, increase on GPU)
- `WORKER_REPLICAS` — number of worker containers (Docker only)

### Advanced
- `DASTER_ENDPOINT` — Dapper DAST service URL
- `DAPPER_WORKSPACE_DIR` — local Dapper orchestration directory
- `HCAPTCHA_SECRET` — hCaptcha verification (if enabled)

## Testing

- **Unit tests:** `*.test.ts` co-located with source
- **Run:** `npm test` (watch mode: `npm test -- --watch`)
- **Coverage:** Reporters in `vitest.config.ts`
- **Integration tests:** Spin up Docker services, run against live DB (see `docker compose` in package.json)

Tests for parsers, risk scoring, suppression matching, and PR formatting are critical before deployment.

## Common Tasks

### Add a new SCA parser
1. Create `src/scanners/sca/parsers/manifest-type.ts`
2. Test with `npm test src/scanners/sca/parsers/manifest-type.test.ts`
3. Add pattern match in `src/scanners/sca/index.ts`

### Update severity calibration
- Edit `src/lib/severity-calibration.ts`
- Adjust CVSS → risk mappings, reachability weights, exploit maturity bonuses
- Rebuild & test report output

### Add a suppression type
- Create suppression rule in `src/lib/suppression-rules.ts`
- Update `SuppressionRule` Prisma model if needed (new field)
- Add UI in `src/app/(dashboard)/settings/suppressions/`

### Debug a finding
- Check `Finding` record in DB (scanner, fingerprint, evidence)
- Trace through `finding-report.ts` deduplication & severity logic
- Run `npm test` on affected modules
- Check LLM context in `llm-repo-context.ts` if LLM-assisted scanner

### Deploy to production
- Build: `npm run build` (validates TypeScript, generates Prisma client)
- Tag Docker images: `docker tag pepper:latest myregistry/pepper:v1.0.0`
- Push: `docker push myregistry/pepper:v1.0.0`
- Migrations run automatically on container startup

## Immediate Priorities (from SAST Roadmap)

1. **Lockfile Parsing:** Implement exact-version resolution for:
   - `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (JS)
   - `poetry.lock`, `Pipfile.lock` (Python)
   - `gradle.lockfile` (Java)
   - `go.sum` (Go)
   - `Cargo.lock` (Rust)
   - `composer.lock`, `Gemfile.lock` (PHP/Ruby)

2. **Deduplication:** Consolidate CVE-only findings under one finding in `finding-report.ts`

3. **Exploitability & Reachability:** Add states (Not exploitable → Verified) to Finding model; integrate into `risk-score.ts`

4. **Dockerfile Dependency Extraction:** Parse `FROM`, `RUN pip install`, etc. in `src/scanners/sca/parsers/dockerfile.ts`

5. **Custom Sanitizer Support:** Store org-specific sanitizer functions; integrate into SAST false-positive reduction

6. **AI Agent Security:** Add scanning for MCP configs, agent manifests, system prompts in `src/scanners/zero-day/` or new `src/scanners/agent-security/`

## Notes

- **No DAST work yet:** Focus is SAST, SCA, Secrets, IaC, Zero-Day maturity only
- **Quality over quantity:** Prioritize accurate, actionable findings over finding count
- **Opt-in LLM:** All LLM analysis is toggleable per org + per scan type
- **Customer-centric reports:** Every finding must answer "Can this be exploited?" and "What do I fix?"
