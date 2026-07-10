# Local / On-Prem Setup (no Supabase)

## TL;DR — there is no Supabase dependency

Pepper does **not** use the Supabase SDK, Supabase Auth, Supabase Storage, or any
Supabase-specific SQL (no RLS, no `auth.` schema, no connection pooler
requirement). The only thing Supabase ever provided was a **hosted PostgreSQL
database**, reached through a standard connection string.

Everything Pepper needs is plain, self-hostable open-source infrastructure:

| Concern            | Component        | How it's used                                   | Supabase? |
| ------------------ | ---------------- | ----------------------------------------------- | --------- |
| Database           | PostgreSQL 16    | Prisma + `@prisma/adapter-pg` (`pg.Pool`)       | No — any Postgres |
| Auth               | NextAuth         | `CredentialsProvider` (bcrypt) + `PrismaAdapter`| No — users live in Postgres |
| Job queue          | Redis 7          | BullMQ (scan jobs)                              | No |
| Object storage     | MinIO (S3 API)   | scan uploads, SBOMs, reports                    | No — never was Supabase Storage |
| LLM (AI scanning)  | Ollama / OpenRouter / OpenAI / Anthropic | configurable per-org           | No |
| Email (optional)   | SMTP             | notifications / invites                         | No |

**To "move off Supabase" you only change one thing:** point `DATABASE_URL` at a
Postgres you control. That's it. Redis, MinIO, auth, and storage were already
self-hosted.

---

## What a customer changes to go on-prem

1. **`DATABASE_URL`** → their own Postgres (Docker, RDS, bare-metal, whatever).
   Must be reachable from both the `sast-api` and `sast-worker` processes.
2. **`REDIS_URL`, `MINIO_*`** → already point at the bundled containers in
   `docker-compose.yml`; no change needed unless they bring their own.
3. **`NEXTAUTH_SECRET`** → a fresh random secret (`openssl rand -base64 32`).
4. **`NEXTAUTH_URL`** → the URL users hit (e.g. `https://pepper.acme.internal`).
5. **`ADMIN_EMAIL` / `ADMIN_PASSWORD`** → seeded first admin login.
6. **LLM** (optional) → set `LLM_PROVIDER`/`LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`,
   or run Ollama locally (`OLLAMA_HOST`). AI scanning is off if none configured.
7. Remove the `DIRECT_URL` env var if it was ever set for a Supabase pooler — it
   is optional and falls back to `DATABASE_URL` (`prisma.config.ts`).

No code changes are required.

---

## Option A — Full stack in Docker (recommended for customer on-prem)

The turnkey path: one command builds the image and runs Postgres + Redis +
MinIO + the API + the worker. The API container auto-runs `prisma migrate
deploy`, `prisma db push`, and the seed on boot
(`scripts/docker-entrypoint-api.sh`) — no manual DB steps.

### A1 — Hardened (use this for a real customer deployment) ✅ validated

Use **`docker-compose.onprem.yml`**. Compared with the dev compose it:

- publishes **only** the app on port 3000 — Postgres/Redis/MinIO have no host
  ports and are reachable only on the internal network (artifacts are proxied
  through the API, so MinIO never needs to be browser-reachable);
- sets `restart: unless-stopped` on every service;
- has **no insecure default secrets** — required vars must be present in `.env`
  or `docker compose` fails immediately with a clear message.

```bash
cp .env.example .env
# Set at minimum (compose refuses to start otherwise):
#   POSTGRES_PASSWORD, NEXTAUTH_SECRET, NEXTAUTH_URL,
#   ADMIN_EMAIL, ADMIN_PASSWORD, MINIO_ROOT_USER, MINIO_ROOT_PASSWORD
#   (NEXTAUTH_SECRET: openssl rand -base64 32)
docker compose -f docker-compose.onprem.yml up -d --build
```

All other config (`LLM_*`, `SMTP_*`, `GITHUB_*`, `OLLAMA_HOST`,
`WORKER_CONCURRENCY`, …) is passed through from `.env` automatically — no
compose edits needed. To reach the MinIO admin console, uncomment the `ports:`
block under the `minio` service.

Tear down (keep data): `docker compose -f docker-compose.onprem.yml down`
Tear down (wipe data):  `docker compose -f docker-compose.onprem.yml down -v`

### A2 — Quick eval (dev-flavoured)

`docker-compose.yml` is the same stack but with host ports exposed and
dev-default secrets — handy for a throwaway local eval, **not** for a customer
box.

```bash
cp .env.example .env
docker compose up -d --build   # app :3000, postgres :5432, minio console :9001
```

> **Port note:** this file binds host port **5432**. If another Postgres already
> occupies 5432, change the published port (`ports: ["5433:5432"]`) — the
> internal container-to-container URL is unaffected.

---

## Option B — Infra in Docker, app on host (fast dev / testing) ✅ verified

Best for local iteration with hot reload. Only Postgres/Redis/MinIO run in
Docker (via `docker-compose.infra.yml`); you run the app and worker on the host.
Host ports are chosen to avoid clashing with an existing Postgres on 5432 —
**Postgres is published on 5544**.

```bash
# 1. Start backing services (Postgres:5544, Redis:6379, MinIO:9000/9001)
docker compose -f docker-compose.infra.yml up -d

# 2. Create .env (see the ready block below)

# 3. Install deps + generate Prisma client
npm install
npm run db:generate

# 4. Create schema + seed the first admin.
#    IMPORTANT: use db:setup, NOT just `migrate deploy`. The tracked migrations
#    have drift vs schema.prisma; db:setup runs migrate deploy -> db push -> seed
#    so the live schema fully matches the schema file. (`migrate deploy` alone
#    leaves the DB missing columns and the seed fails on orgSettings.upsert.)
npm run db:setup

# 5. Run the app (terminal 1) and the worker (terminal 2)
npm run dev            # http://localhost:3000
npm run worker
```

### Ready-to-use `.env` for Option B

```dotenv
DATABASE_URL="postgresql://pepper:pepper_dev@localhost:5544/pepper"
REDIS_URL="redis://localhost:6379"
MINIO_ENDPOINT="localhost"
MINIO_PORT="9000"
MINIO_ACCESS_KEY="minioadmin"
MINIO_SECRET_KEY="minioadmin"
MINIO_USE_SSL="false"
MINIO_BUCKET="pepper-artifacts"
NEXTAUTH_SECRET="dev-secret-change-me"
NEXTAUTH_URL="http://localhost:3000"
ADMIN_EMAIL="admin@pepper.local"
ADMIN_PASSWORD="pepper-admin-changeme"
WORKER_CONCURRENCY="2"
MAX_LLM_CONCURRENCY="2"

# Optional — AI scanning. Leave unset to run without AI.
# Local, fully offline:
# OLLAMA_HOST="http://localhost:11434"
# Or a cloud gateway:
# LLM_PROVIDER="openrouter"
# LLM_BASE_URL="https://openrouter.ai/api/v1"
# LLM_MODEL="google/gemini-2.5-flash"
# LLM_API_KEY="sk-..."
```

Tear down: `docker compose -f docker-compose.infra.yml down`  (add `-v` to wipe data).

---

## Verify it's working

```bash
curl http://localhost:3000/api/health
# -> {"status":"healthy", ...}   (this pings Postgres via Prisma)
```

Then open <http://localhost:3000/login> and sign in with `ADMIN_EMAIL` /
`ADMIN_PASSWORD`. A "Sample Project" and 20 sample security policies are seeded.

## Migrating existing data off Supabase

Because the schema is identical, a standard Postgres dump/restore moves data
with no transformation:

```bash
pg_dump "$SUPABASE_DATABASE_URL" --no-owner --no-privileges -Fc -f pepper.dump
pg_restore --no-owner --no-privileges -d "$LOCAL_DATABASE_URL" pepper.dump
```

Object storage (MinIO) and the Redis queue are runtime state, not Supabase, so
nothing there needs migrating.
```
