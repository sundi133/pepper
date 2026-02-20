# Pepper SAST — Installation Guide

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **4 GB RAM** minimum (8 GB recommended if using Ollama for AI scanning)
- **Ollama** (optional) — for AI-powered SAST and secrets scanning

## Quick Start

```bash
# 1. Create a directory
mkdir pepper && cd pepper

# 2. Download these three files into the directory:
#    - docker-compose.yml
#    - .env.example
#    (provided by your account manager)

# 3. Configure
cp .env.example .env
nano .env   # set POSTGRES_PASSWORD, NEXTAUTH_SECRET, ADMIN_PASSWORD

# 4. Start
docker compose up -d

# 5. Open http://localhost:3000
#    Log in with ADMIN_EMAIL / ADMIN_PASSWORD from your .env
```

That's it. Docker pulls the images automatically from Docker Hub:
- `sundi133/pepper` — Web UI + API
- `sundi133/pepper-worker` — Scan worker

## Ollama Setup (AI Scanning)

Pepper uses Ollama for AI-powered vulnerability analysis. Install it on the host machine:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the recommended model
ollama pull qwen2.5-coder:7b

# Verify it's running
curl http://localhost:11434/api/tags
```

Set `OLLAMA_HOST` in your `.env`:
- **macOS / Windows (Docker Desktop):** `http://host.docker.internal:11434` (default)
- **Linux:** `http://172.17.0.1:11434` or your host's IP address

## Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_PASSWORD` | Yes | — | Database password |
| `NEXTAUTH_SECRET` | Yes | — | Session encryption key (`openssl rand -base64 32`) |
| `ADMIN_EMAIL` | Yes | — | Initial admin email |
| `ADMIN_PASSWORD` | Yes | — | Initial admin password |
| `PEPPER_PORT` | No | `3000` | Host port for web UI |
| `OLLAMA_HOST` | No | `host.docker.internal:11434` | Ollama API endpoint |
| `WORKER_CONCURRENCY` | No | `2` | Parallel scan jobs |
| `MAX_LLM_CONCURRENCY` | No | `1` | Parallel LLM requests per scan |
| `WORKER_REPLICAS` | No | `1` | Number of worker containers |

## Upgrading

```bash
# Pull latest images
docker compose pull

# Restart (migrations run automatically on startup)
docker compose up -d
```

## Data & Backups

All data is stored in Docker volumes:
- `pgdata` — PostgreSQL (findings, scan history, users)
- `redisdata` — Redis (job queue)
- `miniodata` — MinIO (SARIF reports, SBOMs)

Backup the database:
```bash
docker compose exec postgres pg_dump -U pepper pepper > backup.sql
```

Restore:
```bash
docker compose exec -i postgres psql -U pepper pepper < backup.sql
```

## Stopping & Uninstalling

```bash
# Stop (keeps data)
docker compose down

# Stop and delete all data
docker compose down -v
```

## Troubleshooting

**Worker shows "could not renew lock":**
Ollama is slow (CPU inference). Set `MAX_LLM_CONCURRENCY=1` in `.env` and restart.

**LLM scanner shows "Headers Timeout Error":**
Ollama can't keep up. Reduce `MAX_LLM_CONCURRENCY` or use a smaller model (`qwen2.5-coder:3b`).

**Scans stuck in QUEUED:**
Check the worker is running: `docker compose logs pepper-worker`

**Port conflict:**
Change `PEPPER_PORT` in `.env` (e.g., `PEPPER_PORT=8080`).

**Cannot connect to Ollama from Docker on Linux:**
Use your host IP instead of `host.docker.internal`:
```bash
OLLAMA_HOST="http://$(hostname -I | awk '{print $1}'):11434"
```
