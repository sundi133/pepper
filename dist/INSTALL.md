# Pepper SAST — Installation Guide

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **4 GB RAM** minimum (8 GB recommended if using Ollama for AI scanning)
- **Ollama** (optional) — for AI-powered SAST and secrets scanning
- **Subversion CLI** (optional) — required only if you plan to scan SVN repositories

## Automated Setup (Recommended)

The setup script installs Docker, Ollama, configures `.env` with secure random passwords, and starts Pepper — all in one command:

```bash
# 1. Download the pepper distribution files into a directory
mkdir pepper && cd pepper
# Place setup.sh, docker-compose.yml, and .env.example here

# 2. Run the setup script
chmod +x setup.sh
./setup.sh
```

The script will:

1. Install Docker (if not already installed)
2. Install Ollama and pull the `qwen2.5-coder:7b` model
3. Generate secure random passwords and create `.env`
4. Pull Docker images and start all services

Options:

```bash
./setup.sh --no-ollama    # Skip Ollama (no AI scanning)
./setup.sh --help         # Show all options

OLLAMA_MODEL=qwen2.5-coder:3b ./setup.sh   # Use a smaller model
```

## Manual Setup

If you prefer to install manually:

```bash
# 1. Create a directory
mkdir pepper && cd pepper

# 2. Download these files into the directory:
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

Docker pulls the images automatically from Docker Hub:

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

### Supported Models

| Model               | Size   | Speed  | Accuracy  | Best For            |
| ------------------- | ------ | ------ | --------- | ------------------- |
| `qwen2.5-coder:7b`  | 4.7 GB | Medium | High      | Recommended default |
| `qwen2.5-coder:3b`  | 2.0 GB | Fast   | Good      | Low-memory machines |
| `qwen2.5-coder:14b` | 9.0 GB | Slow   | Very High | GPU machines        |

### Connecting Ollama to Docker

Set `OLLAMA_HOST` in your `.env`:

- **macOS / Windows (Docker Desktop):** `http://host.docker.internal:11434` (default)
- **Linux:** `http://172.17.0.1:11434` or your host's IP address

To find your host IP on Linux:

```bash
hostname -I | awk '{print $1}'
```

## Configuration Reference

| Variable              | Required | Default                      | Description                                        |
| --------------------- | -------- | ---------------------------- | -------------------------------------------------- |
| `POSTGRES_PASSWORD`   | Yes      | —                            | Database password                                  |
| `NEXTAUTH_SECRET`     | Yes      | —                            | Session encryption key (`openssl rand -base64 32`) |
| `ADMIN_EMAIL`         | Yes      | —                            | Initial admin email                                |
| `ADMIN_PASSWORD`      | Yes      | —                            | Initial admin password                             |
| `PEPPER_PORT`         | No       | `3000`                       | Host port for web UI                               |
| `OLLAMA_HOST`         | No       | `host.docker.internal:11434` | Ollama API endpoint                                |
| `WORKER_CONCURRENCY`  | No       | `2`                          | Parallel scan jobs                                 |
| `MAX_LLM_CONCURRENCY` | No       | `1`                          | Parallel LLM requests per scan                     |
| `WORKER_REPLICAS`     | No       | `1`                          | Number of worker containers                        |
| `LLM_CHUNK_TOKENS`    | No       | `3000`                       | Tokens per LLM chunk (API models)                  |
| `OLLAMA_CHUNK_TOKENS` | No       | `1200`                       | Tokens per LLM chunk (Ollama)                      |
| `LLM_MIN_CONFIDENCE`  | No       | `0.7`                        | Drop findings below this confidence                |

## Upgrading

```bash
# Pull latest images
docker compose pull

# Restart (migrations run automatically on startup)
docker compose up -d
```

Or upgrade to a specific version:

```bash
# Set version in .env
echo 'PEPPER_VERSION=1.3.0' >> .env

docker compose pull
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

## SVN Repository Scanning

Pepper supports scanning code directly from Subversion repositories. The `svn` CLI must be available on the worker. The provided Docker worker image includes it by default — no extra steps are needed for Docker deployments.

For non-Docker / local development setups, install it manually:

```bash
# macOS
brew install subversion

# Ubuntu / Debian
sudo apt-get install -y subversion

# Fedora / RHEL
sudo dnf install -y subversion
```

When creating a scan, select **SVN** as the source and provide:

- **SVN URL** — full URL to the path you want to scan, e.g. `https://svn.example.com/repos/myproject/trunk`
- **Revision** — a revision number (e.g. `42`) or leave blank for `HEAD`
- **Username / Password** — only required for private repositories

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

**Ollama out of memory:**
Use a smaller model: `OLLAMA_MODEL=qwen2.5-coder:3b ollama pull qwen2.5-coder:3b`
Then set the model in Pepper's organization settings.

**SVN scan fails — "SVN CLI not found":**
Install Subversion on the worker machine. For Docker: rebuild the worker image, which installs `subversion` automatically.

**SVN scan fails — "Authorization failed":**
The username or password you provided is incorrect. Check your SVN credentials.

**SVN scan fails — "path not found":**
The URL doesn't point to a valid SVN path. Make sure to include the correct sub-path, e.g. `/trunk` or `/branches/main`.
