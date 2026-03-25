# Pepper SAST - Customer Installation Guide

## What You Receive

Your deployment bundle should contain only:

- `docker-compose.yml`
- `.env.example`
- `setup.sh`
- this `INSTALL.md`

Pepper source code is not required for customer deployment.

## Default Deployment Model

Pepper is designed to be delivered as prebuilt container images plus a small deployment bundle.

Recommended defaults:

- private registry images for `pepper` and `pepper-worker`
- OpenRouter as the default LLM provider
- a customer-specific OpenRouter API key

## Prerequisites

- Docker 24+
- Docker Compose v2
- 4 GB RAM minimum
- outbound access to:
  - your image registry
  - `https://openrouter.ai`
  - target Git/SVN repositories to be scanned

## Fastest Setup

```bash
mkdir pepper && cd pepper
# copy setup.sh, docker-compose.yml, .env.example, INSTALL.md here

chmod +x setup.sh
./setup.sh
```

The script will:

1. install Docker if needed
2. create `.env`
3. generate secure secrets and admin password
4. optionally log in to a private registry if credentials are present in `.env`
5. pull images
6. start Pepper

## Required `.env` Values

Set these before first production use:

```dotenv
POSTGRES_PASSWORD="..."
NEXTAUTH_SECRET="..."
ADMIN_EMAIL="admin@yourcompany.com"
ADMIN_PASSWORD="..."
LLM_PROVIDER="openrouter"
LLM_BASE_URL="https://openrouter.ai/api/v1"
LLM_MODEL="google/gemini-2.5-flash"
LLM_API_KEY="..."
```

If you are using a private registry, also set:

```dotenv
PEPPER_API_IMAGE="registry.example.com/pepper"
PEPPER_WORKER_IMAGE="registry.example.com/pepper-worker"
PEPPER_VERSION="1.2.0"
PEPPER_REGISTRY="registry.example.com"
PEPPER_REGISTRY_USERNAME="..."
PEPPER_REGISTRY_PASSWORD="..."
```

## Manual Setup

```bash
cp .env.example .env
# edit .env with your values

docker compose pull
docker compose up -d
```

Then open:

```text
http://localhost:3000
```

Sign in with `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`.

## OpenRouter Defaults

Pepper is bundled to work with OpenRouter first.

Recommended settings:

```dotenv
LLM_PROVIDER="openrouter"
LLM_BASE_URL="https://openrouter.ai/api/v1"
LLM_MODEL="google/gemini-2.5-flash"
LLM_API_KEY="..."
```

Optional metadata:

```dotenv
OPENROUTER_REFERER="https://pepper.yourcompany.com"
OPENROUTER_TITLE="Pepper SAST"
```

## Optional Ollama Mode

If a customer wants a fully local LLM instead of OpenRouter:

```dotenv
LLM_PROVIDER="ollama"
OLLAMA_HOST="http://host.docker.internal:11434"
LLM_MODEL="qwen2.5-coder:7b"
```

That mode requires Ollama on the host and is slower on CPU.

## SVN Scanning

Pepper supports SVN repositories directly. The worker image already includes Subversion.

When creating a scan, provide:

- the full SVN URL
- optional revision
- username/password if the repo is private

## Upgrade Procedure

```bash
docker compose pull
docker compose up -d
```

If your deployment bundle version changes, update `PEPPER_VERSION` in `.env` first.

## Backup

```bash
docker compose exec postgres pg_dump -U pepper pepper > backup.sql
```

Restore:

```bash
docker compose exec -i postgres psql -U pepper pepper < backup.sql
```

## Troubleshooting

If scans stay queued:

```bash
docker compose logs -f pepper-worker
```

If the UI does not come up:

```bash
docker compose logs -f pepper-api
```

If registry pulls fail:

- verify `PEPPER_REGISTRY`, `PEPPER_REGISTRY_USERNAME`, `PEPPER_REGISTRY_PASSWORD`
- run `docker login <registry>` manually

If OpenRouter scans fail:

- verify `LLM_API_KEY`
- verify outbound internet access to `openrouter.ai`
- verify the selected model name is valid for your account
