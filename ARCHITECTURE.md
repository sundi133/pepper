# Pepper SAST — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PEPPER SAST PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │   Next.js    │    │   Worker     │    │   Scheduler              │  │
│  │   Web App    │    │   Process    │    │   (inside worker)        │  │
│  │   (API +UI)  │    │   (BullMQ)   │    │   checks every 60s      │  │
│  │   Port 3000  │    │              │    │   for due scan schedules │  │
│  └──────┬───────┘    └──────┬───────┘    └──────────┬───────────────┘  │
│         │                   │                       │                   │
│         │    ┌──────────────┴───────────────────────┘                   │
│         │    │                                                          │
│  ┌──────┴────┴──────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐  │
│  │   PostgreSQL     │  │   Redis    │  │   MinIO    │  │  Ollama   │  │
│  │   (Data Store)   │  │   (Queue)  │  │   (Object  │  │  (LLM)   │  │
│  │   Port 5432      │  │  Port 6379 │  │   Storage) │  │ Port 11434│  │
│  └──────────────────┘  └────────────┘  │  Port 9000 │  └───────────┘  │
│                                        └────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Web Application (Next.js)

```
src/app/
├── (auth)/
│   └── login/page.tsx              # Login page (NextAuth)
├── (dashboard)/
│   ├── layout.tsx                  # Sidebar + topbar layout
│   ├── dashboard/page.tsx          # Dashboard with charts (recharts)
│   ├── projects/
│   │   ├── page.tsx                # Project list
│   │   ├── new/page.tsx            # Create project form
│   │   └── [projectId]/page.tsx    # Project detail
│   ├── scans/
│   │   ├── page.tsx                # All scans list (with scan ID column)
│   │   └── [scanId]/page.tsx       # Scan detail + findings table
│   └── settings/
│       ├── llm/page.tsx            # LLM provider config (Ollama/OpenAI/OpenRouter)
│       ├── build-gates/page.tsx    # Build gate thresholds
│       ├── team/page.tsx           # Team/RBAC management
│       └── integrations/page.tsx   # Webhook URLs (GitHub/GitLab)
└── api/
    ├── auth/[...nextauth]/         # NextAuth (credentials + OAuth)
    ├── dashboard/stats/            # Dashboard chart data
    ├── projects/
    │   ├── route.ts                # CRUD projects
    │   └── [projectId]/
    │       ├── route.ts            # Project detail/update/delete
    │       └── schedule/route.ts   # Scan schedule CRUD
    ├── scans/
    │   ├── route.ts                # Create scan (upload/git/svn), list scans
    │   └── [scanId]/
    │       ├── route.ts            # Scan detail
    │       ├── cancel/route.ts     # Cancel running scan
    │       ├── findings/
    │       │   ├── route.ts        # List findings (filter by severity/scanner/status)
    │       │   └── export/route.ts # Export CSV/JSON
    │       └── artifacts/[type]/   # Download SARIF/SBOM
    ├── findings/
    │   ├── [findingId]/route.ts    # GET/PATCH single finding status
    │   └── bulk/route.ts           # Bulk status update (up to 500)
    ├── settings/
    │   ├── llm/route.ts            # LLM config GET/PUT
    │   └── build-gates/route.ts    # Build gate config
    ├── users/route.ts              # Team management
    ├── webhooks/
    │   ├── github/route.ts         # GitHub PR webhook
    │   └── gitlab/route.ts         # GitLab MR webhook
    └── health/route.ts             # Health check
```

### 2. Scanner Engine

```
src/scanners/
├── index.ts                    # Scanner orchestrator (getScanners, runScanners)
│                               # Runs all scanners in parallel via Promise.allSettled
│                               # FindingDeduplicator prevents duplicates
├── types.ts                    # Core types: ScanContext, RawFinding, ScannerPlugin
│
├── sast/                       # ──── SAST (Static Application Security Testing) ────
│   ├── index.ts                # Exports: sastPatternScanner, sastLlmScanner
│   ├── pattern-rules.ts        # Rule registry (combines all language rules)
│   ├── rules/
│   │   ├── javascript.ts       # JS/TS regex patterns (SQLi, XSS, eval, etc.)
│   │   ├── python.ts           # Python patterns (pickle, exec, SQL, etc.)
│   │   ├── go.ts               # Go patterns (sql.Query, exec.Command, etc.)
│   │   ├── java.ts             # Java patterns (Runtime.exec, JDBC, etc.)
│   │   ├── php.ts              # PHP patterns (shell_exec, mysql_query, etc.)
│   │   └── generic.ts          # Cross-language patterns (hardcoded secrets, etc.)
│   ├── llm-analyzer.ts         # LLM-based SAST (chunked analysis with progress)
│   └── chunker.ts              # File chunking for LLM context windows
│
├── sca/                        # ──── SCA (Software Composition Analysis) ────
│   ├── index.ts                # Dependency parser + OSV batch scanner
│   ├── osv-client.ts           # OSV.dev batch API client
│   ├── malicious-pkg.ts        # Supply chain scanner (3-phase):
│   │                           #   Phase 1: OSV batch for MAL-* advisories
│   │                           #   Phase 2: Registry metadata (npm/PyPI/Maven/Go/Cargo/RubyGems)
│   │                           #   Phase 3: LLM typosquat + install script analysis
│   ├── sbom-generator.ts       # CycloneDX SBOM output
│   └── parsers/                # Dependency manifest parsers (12 ecosystems):
│       ├── package-json.ts     # npm: package.json, package-lock.json
│       ├── requirements-txt.ts # PyPI: requirements.txt, Pipfile.lock
│       ├── pyproject-toml.ts   # PyPI: pyproject.toml (PEP 621 + Poetry)
│       ├── go-mod.ts           # Go: go.mod
│       ├── cargo-toml.ts       # Rust: Cargo.toml
│       ├── pom-xml.ts          # Maven: pom.xml, build.gradle
│       ├── gemfile-lock.ts     # RubyGems: Gemfile.lock
│       ├── composer-json.ts    # Packagist: composer.json, composer.lock
│       ├── csproj.ts           # NuGet: *.csproj, packages.config
│       ├── pubspec-yaml.ts     # Pub: pubspec.yaml (Dart/Flutter)
│       ├── mix-lock.ts         # Hex: mix.lock (Elixir)
│       └── swift-package.ts    # SwiftPM: Package.resolved
│
├── secrets/                    # ──── Secrets Detection ────
│   ├── index.ts                # Pattern + LLM secret scanners
│   ├── patterns.ts             # Regex patterns (AWS keys, GCP, GitHub tokens, etc.)
│   ├── entropy.ts              # Shannon entropy calculator
│   ├── llm-classifier.ts       # LLM-based false positive reduction
│   └── masker.ts               # Credential masking for display
│
├── iac/                        # ──── IaC Security ────
│   └── index.ts                # LLM-based IaC scanner
│                               # Covers: Dockerfile, Terraform, Kubernetes,
│                               # Helm, GitHub Actions, GitLab CI, CloudFormation
│
├── zero-day/                   # ──── Zero-Day / Business Logic ────
│   ├── index.ts                # LLM scanner for novel vulnerabilities
│   ├── prompts.ts              # Specialized prompt: IDOR, business logic, race conditions,
│   │                           # trust boundaries, auth flaws, parameter tampering, etc.
│   └── file-prioritizer.ts     # Selects high-value files (auth, payment, API, admin)
│
├── sarif-builder.ts            # SARIF 2.1.0 output generator
└── diff-parser.ts              # Git diff parser (for incremental scans)
```

### 3. Worker Process

```
src/worker/
├── index.ts                    # BullMQ worker + scheduler startup
│                               # Concurrency: WORKER_CONCURRENCY env var
│                               # Lock duration: 5 min (for slow LLM inference)
├── scan-processor.ts           # Main scan job processor:
│                               #   1. Download/extract source (ZIP/Git/SVN)
│                               #   2. Enumerate files
│                               #   3. Run all scanners (parallel)
│                               #   4. Insert findings to DB (streaming)
│                               #   5. Generate SARIF + SBOM artifacts
│                               #   6. Evaluate build gate
│                               #   7. Send email notification
│                               #   8. Cleanup temp files
└── scheduler.ts                # Cron-like scheduler:
                                #   Checks every 60s for due ScanSchedule records
                                #   Creates Scan + enqueues BullMQ job
                                #   Computes next run time
```

### 4. Shared Libraries

```
src/lib/
├── auth.ts                     # NextAuth config (credentials + GitHub/GitLab OAuth)
├── auth-guard.ts               # requireAuth(), requireRole(), getDefaultOrgId()
├── prisma.ts                   # Prisma client singleton
├── redis.ts                    # Redis connection (ioredis)
├── queue.ts                    # BullMQ scan queue + ScanJobData interface
├── minio.ts                    # MinIO S3 client (upload/download/presign)
├── llm-gateway.ts              # Unified LLM client:
│                               #   Ollama (native SDK, 15min timeout)
│                               #   OpenAI (standard API)
│                               #   OpenRouter (custom headers, no response_format)
│                               #   Azure, vLLM, custom endpoints
├── email.ts                    # Nodemailer email service (SMTP)
│                               # HTML email template for scan completion
├── schedule-utils.ts           # computeNextRun() for scan scheduling
├── constants.ts                # Scanner labels, file extensions, IaC detection,
│                               # chunk sizes, skip directories
├── logger.ts                   # Pino logger
└── utils.ts                    # Tailwind cn() helper
```

## Data Flow

### Scan Lifecycle

```
User/Webhook/Scheduler
        │
        ▼
  ┌─────────────┐    ┌───────────┐    ┌──────────────┐
  │ POST /api/   │───▶│  MinIO    │    │  PostgreSQL  │
  │ scans        │    │ (upload)  │    │ (Scan record │
  │              │───▶│           │    │  QUEUED)     │
  └──────┬───────┘    └───────────┘    └──────────────┘
         │
         ▼
  ┌──────────────┐
  │ Redis/BullMQ │
  │ (job queue)  │
  └──────┬───────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │                   WORKER PROCESS                      │
  │                                                       │
  │  1. Extract source ──────────────────────────────┐    │
  │     (ZIP / git clone / svn export)               │    │
  │                                                   │    │
  │  2. Enumerate files ─────────────────────────────┤    │
  │                                                   │    │
  │  3. Run scanners (parallel) ─────────────────────┤    │
  │     ┌─────────────────┐  ┌──────────────────┐   │    │
  │     │ SAST Pattern    │  │ SAST LLM         │   │    │
  │     │ (regex rules)   │  │ (Ollama/OpenAI)  │   │    │
  │     └─────────────────┘  └──────────────────┘   │    │
  │     ┌─────────────────┐  ┌──────────────────┐   │    │
  │     │ SCA             │  │ Supply Chain     │   │    │
  │     │ (OSV batch API) │  │ (OSV+Registry    │   │    │
  │     │                 │  │  +LLM typosquat) │   │    │
  │     └─────────────────┘  └──────────────────┘   │    │
  │     ┌─────────────────┐  ┌──────────────────┐   │    │
  │     │ Secrets         │  │ IaC Security     │   │    │
  │     │ (pattern + LLM) │  │ (LLM analysis)   │   │    │
  │     └─────────────────┘  └──────────────────┘   │    │
  │     ┌─────────────────┐                          │    │
  │     │ Zero-Day / IDOR │                          │    │
  │     │ (LLM, priority  │                          │    │
  │     │  files only)    │                          │    │
  │     └─────────────────┘                          │    │
  │                                                   │    │
  │  4. Stream findings to DB ◄──────────────────────┘    │
  │     (onBatchFindings + onScannerComplete)              │
  │                                                       │
  │  5. Generate SARIF + SBOM ──▶ MinIO                   │
  │  6. Evaluate build gate                               │
  │  7. Send email notification (SMTP)                    │
  └───────────────────────────────────────────────────────┘
```

### Scanner Selection by Scan Type

```
FULL scan:
  ├── SAST Pattern    (regex, all languages)
  ├── SAST LLM        (AI, if LLM enabled)
  ├── SCA              (OSV batch)
  ├── Supply Chain     (malicious pkg detection)
  ├── Secrets          (pattern or LLM)
  ├── IaC Security     (LLM, if IaC files present)
  └── Zero-Day / IDOR  (LLM, priority files only)

SAST_ONLY:
  ├── SAST Pattern
  ├── SAST LLM
  └── IaC Security

SCA_ONLY:
  ├── SCA
  └── Supply Chain

SECRETS_ONLY:
  └── Secrets (pattern or LLM)
```

## Database Schema (Key Models)

```
Organization ──┬── OrgMember (role: ADMIN|SECURITY|DEVELOPER|VIEWER)
               │     └── notification prefs (emailOnScanComplete, etc.)
               ├── OrgSettings (LLM config, SMTP config, OSV URL)
               ├── Project ──┬── Scan ──┬── Finding (status: OPEN|IN_PROGRESS|
               │             │          │            FALSE_POSITIVE|ACCEPTED_RISK|
               │             │          │            RESOLVED)
               │             │          └── ScanArtifact (SARIF, SBOM)
               │             ├── BuildGate (max thresholds per severity)
               │             └── ScanSchedule (DAILY|WEEKLY|BIWEEKLY|MONTHLY)
               └── ApiKey (for CI/CD integration)

AuditLog (organization-wide action history)
```

## LLM Provider Architecture

```
                    ┌──────────────────────┐
                    │   llm-gateway.ts     │
                    │   createLlmClient()  │
                    │   analyzeWithLlm()   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐ ┌──────▼───────┐ ┌──────▼────────┐
     │   Ollama      │ │   OpenAI     │ │  OpenRouter   │
     │   (native     │ │   (standard  │ │  (custom      │
     │    SDK)       │ │    API)      │ │   headers,    │
     │   15min       │ │   response_  │ │   no json     │
     │   timeout     │ │   format:    │ │   format,     │
     │   for CPU     │ │   json       │ │   prompt-     │
     │   inference   │ │              │ │   enforced)   │
     └──────────────┘ └──────────────┘ └──────────────┘
                                              │
                                    Also supports:
                                    Azure, vLLM, custom
```

## Supply Chain Scanner (3-Phase Pipeline)

```
Dependencies parsed from 12 ecosystems
              │
              ▼
┌─────────────────────────────────────────┐
│ PHASE 1: OSV Batch API                  │
│ ─ Single batch call (up to 1000 deps)   │
│ ─ Filters for MAL-* malware advisories  │
│ ─ Free, fast, authoritative             │
│ ─ All ecosystems supported              │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ PHASE 2: Registry Metadata              │
│ ─ npm: age, install scripts, repo       │
│ ─ PyPI: age, repository                 │
│ ─ Maven: age                            │
│ ─ Go: age                               │
│ ─ crates.io: age, repository            │
│ ─ RubyGems: age, repository             │
│ Flags: <7 days old, no source repo      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ PHASE 3: LLM Deep Analysis             │
│ ─ Typosquatting detection (batches)     │
│ ─ Install script behavioral analysis    │
│ ─ Works for all ecosystems              │
│ ─ Only runs if LLM is enabled           │
└─────────────────────────────────────────┘
```

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Docker Compose Stack                     │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │
│  │ pepper-api │  │ pepper-    │  │ postgres:16-alpine │ │
│  │ (Next.js)  │  │ worker     │  │ (database)         │ │
│  │ :3000      │  │ (BullMQ +  │  │ :5432              │ │
│  │            │  │  scheduler)│  │                    │ │
│  └────────────┘  └────────────┘  └────────────────────┘ │
│                                                          │
│  ┌────────────┐  ┌─────────────────────────────────────┐ │
│  │ redis:7    │  │ minio (S3-compatible object store)  │ │
│  │ (job queue)│  │ SARIF reports, SBOMs, source uploads│ │
│  │ :6379      │  │ :9000 (API) :9001 (console)        │ │
│  └────────────┘  └─────────────────────────────────────┘ │
│                                                          │
│  ┌──────────────────────────────────────────────────────┐ │
│  │ Ollama (runs on host, accessed via Docker network)   │ │
│  │ :11434 — qwen2.5-coder:7b (default model)           │ │
│  └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Source Input Methods

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│ ZIP/TAR     │  │ Git Clone   │  │ SVN Export  │  │ Webhook      │
│ Upload      │  │ (branch)    │  │ (revision)  │  │ (GitHub/     │
│             │  │             │  │             │  │  GitLab PR)  │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘
       │                │                │                │
       └────────────────┴────────────────┴────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   scan-processor.ts   │
                    │   Extract to /tmp     │
                    │   Enumerate files     │
                    │   Run scanners        │
                    └──────────────────────┘
```

## Finding Lifecycle

```
  Scanner detects issue
         │
         ▼
  ┌──────────────┐
  │    OPEN      │ ◄── Default status for all new findings
  └──────┬───────┘
         │
    ┌────┼─────────────┬──────────────┐
    │    │             │              │
    ▼    ▼             ▼              ▼
┌──────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐
│ IN   │ │ FALSE    │ │ ACCEPTED   │ │ RESOLVED │
│ PROG │ │ POSITIVE │ │ RISK       │ │          │
└──────┘ └──────────┘ └────────────┘ └──────────┘

Status update via:
  - Single: PATCH /api/findings/{id}
  - Bulk:   PATCH /api/findings/bulk (up to 500 at once)
```

## Technology Stack

| Layer             | Technology                                           |
| ----------------- | ---------------------------------------------------- |
| Frontend          | Next.js 15, React, Tailwind CSS, shadcn/ui, recharts |
| Backend API       | Next.js API Routes, NextAuth                         |
| Worker            | BullMQ, Node.js                                      |
| Database          | PostgreSQL 16, Prisma ORM                            |
| Queue             | Redis 7                                              |
| Object Storage    | MinIO (S3-compatible)                                |
| LLM               | Ollama / OpenAI / OpenRouter (configurable)          |
| Email             | Nodemailer (SMTP)                                    |
| Auth              | NextAuth (credentials + OAuth)                       |
| CI/CD Integration | GitHub/GitLab webhooks, SARIF export                 |
| Container         | Docker, Docker Compose                               |
