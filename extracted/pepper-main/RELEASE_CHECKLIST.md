# Pepper Release Checklist

Internal release checklist for preparing a client-ready Pepper deployment without sharing source code.

## Goal

Produce:

- versioned API and worker images
- a client deployment bundle zip
- a short set of handoff values for the client

Do not send the repository to clients.

## Inputs

Before starting, confirm:

- target Git commit is correct
- Docker Desktop / Docker daemon is running
- registry path is decided
- release version is decided
- client OpenRouter model is decided
- client OpenRouter API key is available

Example:

```bash
VERSION=1.2.0
REGISTRY=registry.example.com/security
MODEL=google/gemini-2.5-flash
```

## 1. Update Local Checkout

```bash
git pull --ff-only origin main
```

If schema changed, be aware that local testing may still require:

```bash
docker compose run --rm --entrypoint sh sast-api -c "npx prisma db push && npx tsx prisma/seed.ts"
```

## 2. Verify App Builds Locally

```bash
docker compose up -d --build
```

Check:

- API starts successfully
- worker starts successfully
- `http://localhost:3000/api/health` returns healthy

If startup fails on missing Prisma tables, run the `db push` step above and restart the API.

## 3. Smoke Test Core Paths

Minimum checks:

- login works with seeded admin account
- create or view a project
- trigger one scan
- confirm worker picks up the job
- confirm scan finishes

If the release includes UI changes, also spot-check the affected pages.

## 4. Build And Push Release Images

Use the release script:

```bash
VERSION=1.2.0 REGISTRY=registry.example.com/security bash scripts/release-dist.sh
```

Expected outputs:

- `registry.example.com/security/pepper:<version>`
- `registry.example.com/security/pepper-worker:<version>`
- `release/pepper-<version>.zip`

## 5. Validate The Generated Bundle

Open the generated zip contents and confirm these files exist:

- `.env.example`
- `docker-compose.yml`
- `setup.sh`
- `INSTALL.md`

Confirm `.env.example` includes:

- `LLM_PROVIDER="openrouter"`
- `LLM_BASE_URL="https://openrouter.ai/api/v1"`
- `LLM_MODEL="google/gemini-2.5-flash"` or chosen model
- `PEPPER_API_IMAGE`
- `PEPPER_WORKER_IMAGE`
- `PEPPER_VERSION`

## 6. Prepare Client Handoff Values

Provide the client only:

- deployment bundle zip
- registry hostname
- registry username/password or pull token
- client-specific OpenRouter API key
- chosen OpenRouter model
- deployment URL guidance

Do not provide:

- source repository
- internal Git history
- non-client API keys
- internal registry credentials shared across customers unless intentionally designed that way

## 7. Recommended Client Handoff Message

Send the client:

1. the deployment zip
2. these required `.env` values:

```dotenv
PEPPER_API_IMAGE="registry.example.com/security/pepper"
PEPPER_WORKER_IMAGE="registry.example.com/security/pepper-worker"
PEPPER_VERSION="1.2.0"
LLM_PROVIDER="openrouter"
LLM_BASE_URL="https://openrouter.ai/api/v1"
LLM_MODEL="google/gemini-2.5-flash"
LLM_API_KEY="<client_key>"
```

3. registry login details if using a private registry
4. installation instruction:

```bash
chmod +x setup.sh
./setup.sh
```

## 8. Post-Release Validation

After the client installs:

- verify they can log in
- verify a sample scan runs
- verify OpenRouter-backed LLM scans complete
- verify outbound access to target repositories works

## 9. Rollback Plan

If the release is bad:

- retag or repoint the client to the previous known-good image version
- update `.env`:

```dotenv
PEPPER_VERSION="<previous_version>"
```

- restart:

```bash
docker compose pull
docker compose up -d
```

## 10. Known Current Caveat

Pepper currently does not ship Prisma migrations in the usual way. Schema-changing releases may require:

```bash
npx prisma db push
```

Track this as technical debt until proper migrations are added.
