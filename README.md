# Pepper SAST

AI-powered Static Application Security Testing platform.

## Customer On-Prem Deployment

### Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **4 GB RAM** minimum (8 GB recommended with AI scanning)
- **Ollama** (optional) for AI-powered vulnerability analysis
- **Subversion CLI** (optional) for scanning SVN repositories

### Quick Start (Automated)

```bash
# 1. Create a directory and place the distribution files
mkdir pepper && cd pepper
# Copy setup.sh, docker-compose.yml, and .env.example into this directory

# 2. Run the setup script
chmod +x setup.sh
./setup.sh
```

The script will:

1. Install Docker (if not present)
2. Install Ollama and pull the `qwen2.5-coder:7b` model
3. Generate secure random passwords and create `.env`
4. Pull Docker images and start all services
5. Print admin credentials to the terminal

Options:

```bash
./setup.sh --no-ollama                          # Skip Ollama (disables AI scanning)
OLLAMA_MODEL=qwen2.5-coder:3b ./setup.sh       # Use a smaller model for low-memory machines
```

### Manual Setup

```bash
# 1. Copy and configure environment
cp .env.example .env
nano .env   # Set POSTGRES_PASSWORD, NEXTAUTH_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD

# 2. Start all services
docker compose up -d

# 3. Open http://localhost:3000 and log in with your admin credentials
```

### Ollama Setup (AI Scanning)

Pepper uses Ollama running on the host machine for AI-powered SAST:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the recommended model
ollama pull qwen2.5-coder:7b

# Verify
curl http://localhost:11434/api/tags
```

Set `OLLAMA_HOST` in `.env`:

- **macOS / Windows (Docker Desktop):** `http://host.docker.internal:11434` (default)
- **Linux:** `http://<host-ip>:11434`

#### Supported Models

| Model               | Size   | Speed  | Accuracy  | Best For              |
| ------------------- | ------ | ------ | --------- | --------------------- |
| `qwen2.5-coder:7b`  | 4.7 GB | Medium | High      | Recommended default   |
| `qwen2.5-coder:3b`  | 2.0 GB | Fast   | Good      | Low-memory machines   |
| `qwen2.5-coder:14b` | 9.0 GB | Slow   | Very High | GPU-equipped machines |

### Configuration Reference

| Variable              | Required | Default                      | Description                     |
| --------------------- | -------- | ---------------------------- | ------------------------------- |
| `POSTGRES_PASSWORD`   | Yes      | —                            | Database password               |
| `NEXTAUTH_SECRET`     | Yes      | —                            | Session encryption key          |
| `ADMIN_EMAIL`         | Yes      | —                            | Initial admin login email       |
| `ADMIN_PASSWORD`      | Yes      | —                            | Initial admin login password    |
| `PEPPER_PORT`         | No       | `3000`                       | Host port for web UI            |
| `OLLAMA_HOST`         | No       | `host.docker.internal:11434` | Ollama API endpoint             |
| `WORKER_CONCURRENCY`  | No       | `2`                          | Parallel scan jobs              |
| `MAX_LLM_CONCURRENCY` | No       | `1`                          | Parallel LLM requests per scan  |
| `WORKER_REPLICAS`     | No       | `1`                          | Number of worker containers     |
| `PEPPER_IMAGE`        | No       | `sundi133/pepper`            | Override for private registries |
| `PEPPER_VERSION`      | No       | `latest`                     | Pin to a specific release       |

### Air-Gapped Deployment

For environments without internet access:

```bash
# On a machine with internet — export images
docker pull sundi133/pepper:latest
docker pull sundi133/pepper-worker:latest
docker save sundi133/pepper sundi133/pepper-worker postgres:16-alpine redis:7-alpine minio/minio:latest -o pepper-images.tar

# Transfer pepper-images.tar + dist/ files to the target machine

# On the target machine — load images and start
docker load -i pepper-images.tar
cp .env.example .env
nano .env
docker compose up -d
```

For Ollama in air-gapped environments, copy the model directory from `~/.ollama/models` on a connected machine.

### Upgrading

```bash
docker compose pull
docker compose up -d
```

Migrations run automatically on startup.

### Backup & Restore

```bash
# Backup
docker compose exec postgres pg_dump -U pepper pepper > backup.sql

# Restore
docker compose exec -i postgres psql -U pepper pepper < backup.sql
```

### Stopping

```bash
docker compose down       # Stop (keeps data)
docker compose down -v    # Stop and delete all data
```

### SVN Repository Scanning

Pepper can scan code from Subversion repositories. The `svn` CLI must be installed on the worker machine (or inside the worker container for Docker deployments).

**macOS:**

```bash
brew install subversion
svn --version   # confirm: 1.x.x
```

**Ubuntu / Debian:**

```bash
sudo apt-get install -y subversion
```

**Fedora / RHEL:**

```bash
sudo dnf install -y subversion
```

**Docker deployments:** The provided `Dockerfile` already installs `subversion` in the worker image. No extra steps needed.

Once installed, create a scan and select **SVN** as the source. Provide the full SVN URL including the path you want to scan (e.g. `https://svn.example.com/repos/myproject/trunk`), an optional revision number (leave blank for `HEAD`), and credentials if the repo is private.

### GitHub repository connection (OAuth)

Connect GitHub from **Repositories** in the sidebar to import repositories without pasting clone URLs or tokens.

1. Create a [GitHub OAuth App](https://github.com/settings/developers) (type: OAuth App).
2. Set **Authorization callback URL** to `{NEXTAUTH_URL}/api/integrations/github/callback` (e.g. `http://localhost:3000/api/integrations/github/callback`).
3. Configure environment variables:

| Variable | Description |
| -------- | ----------- |
| `GITHUB_OAUTH_CLIENT_ID` | OAuth App client ID (or reuse `GITHUB_ID`) |
| `GITHUB_OAUTH_CLIENT_SECRET` | OAuth App client secret (or reuse `GITHUB_SECRET`) |
| `TOKEN_ENCRYPTION_KEY` | Optional; encrypts stored tokens (defaults to `NEXTAUTH_SECRET`) |

Pepper requests `read:user` and `repo` scopes (GitHub requires `repo` for private repository metadata and clone). The access token is stored **encrypted** in the database and is never exposed to the browser. After you import repositories, an initial full scan is queued automatically; private clones use the org token on the worker.

Revoke access from **Settings → Integrations** or the Repositories page.

### Scan Scheduling

Pepper can automatically scan your projects on a recurring schedule. Configure per-project in **Settings > Projects > [Project] > Schedule**.

Supported frequencies: **Daily**, **Weekly**, **Biweekly**, **Monthly**.

Scheduled scans require the project to have a **repository URL** (Git or SVN) — file upload scans cannot be scheduled.

Scans run at **2:00 AM UTC** by default. The scheduler runs inside the worker process and checks for due scans every 60 seconds.

**API:**

```bash
# Set a weekly full scan schedule
curl -X PUT http://localhost:3000/api/projects/<projectId>/schedule \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "frequency": "WEEKLY", "scanType": "FULL"}'

# Check current schedule
curl http://localhost:3000/api/projects/<projectId>/schedule

# Disable schedule
curl -X DELETE http://localhost:3000/api/projects/<projectId>/schedule
```

### Email Notifications

Pepper can send email notifications when scans complete. Each user can configure their notification preferences:

- **On scan complete** — receive a summary email after every scan
- **On gate failure** — only notify when the build gate fails
- **On critical findings** — only notify when critical vulnerabilities are found

**SMTP Configuration:**

Set via environment variables (simplest) or per-org in the database:

| Variable        | Default                     | Description          |
| --------------- | --------------------------- | -------------------- |
| `SMTP_HOST`     | —                           | SMTP server hostname |
| `SMTP_PORT`     | `587`                       | SMTP port            |
| `SMTP_USER`     | —                           | SMTP username        |
| `SMTP_PASSWORD` | —                           | SMTP password        |
| `SMTP_FROM`     | `noreply@pepper-sast.local` | From address         |
| `SMTP_TLS`      | `true`                      | Use TLS              |

For Gmail:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=you@gmail.com
```

For AWS SES:

```
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=AKIA...
SMTP_PASSWORD=...
SMTP_FROM=security@yourdomain.com
```

### Troubleshooting

| Problem                                 | Solution                                                                                        |
| --------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Worker shows "could not renew lock"     | Ollama is slow on CPU. Set `MAX_LLM_CONCURRENCY=1` and restart                                  |
| LLM "Headers Timeout Error"             | Reduce `MAX_LLM_CONCURRENCY` or use a smaller model                                             |
| Scans stuck in QUEUED                   | Check worker: `docker compose logs pepper-worker`                                               |
| Port conflict                           | Change `PEPPER_PORT` in `.env`                                                                  |
| Can't reach Ollama on Linux             | Use host IP: `OLLAMA_HOST="http://$(hostname -I \| awk '{print $1}'):11434"`                    |
| SVN scan fails — "SVN CLI not found"    | Install subversion on the worker: `brew install subversion` (macOS) or `apt install subversion` |
| SVN scan fails — "Authorization failed" | Check the SVN username/password you entered when creating the scan                              |
| SVN scan fails — "path not found"       | Make sure the URL includes the correct path (e.g. `/trunk`, `/branches/main`)                   |

## Development

### Prerequisites

- **Node.js** 20+
- **Docker** (for Postgres, Redis, MinIO)
- **Subversion CLI** — required to scan SVN repositories:

  ```bash
  # macOS
  brew install subversion

  # Ubuntu / Debian
  sudo apt-get install -y subversion
  ```

### Setup

```bash
# 1. Install dependencies
npm install

# 2. Copy env and configure
cp .env.example .env

# 3. Start infrastructure (Postgres, Redis, MinIO)
docker compose up -d postgres redis minio

# 4. Apply migrations, push DB schema, and seed admin user
npm run db:setup    # = migrate deploy (idempotent) + db push + seed

# 5. Start the web server
npm run dev         # http://localhost:3000

# 6. In a separate terminal, start the worker
npm run worker
```

Login with `admin@pepper.local` / `pepper-admin-changeme` (or whatever you set in `.env`).

## CI/CD security features

Pepper ships with end-to-end pipeline security primitives:

- **SBOM generation** — every scan emits both **CycloneDX 1.5** and **SPDX 2.3**
  documents. Download via `/api/scans/<scanId>/artifacts/cyclonedx` (or `spdx`),
  or from the scan detail page.
- **Container scanning** — Dockerfiles and Compose files are parsed for image
  references and scanned with `trivy` when available. Falls back to image
  inventory when Trivy isn't installed.
- **Pre-commit hook** — install with
  `curl -fsSL $PEPPER_API_URL/api/precommit/install.sh | bash -s -- $PEPPER_API_URL <API_KEY>`.
  Blocks commits with HIGH/CRITICAL secrets or SAST issues.
- **Outbound integrations** — Slack, Jira (auto-tickets for severe findings),
  SIEM (CEF / LEEF / JSON over HTTPS or syslog), and code signing
  (cosign keyless via Fulcio + Rekor, or RSA fallback).
- **DAST** — integrates with [dapper](https://github.com/sundi133/dapper)
  via HTTP API, local Dapper CLI, or an automatic local Dapper workspace
  orchestration flow. Configure once under Settings → DAST, optionally paste a
  Dapper YAML config there, and set a `dastTargetUrl` per project.
- **CI/CD templates** — download ready-to-use GitHub Actions, GitLab CI and
  Jenkinsfile templates from `/api/cicd-templates/<platform>`.
- **API keys** — manage CI/IDE/precommit credentials under Settings → API Keys.
- **Audit log** — view security-relevant actions under Settings → Audit Log.
- **Trends** — historical severity, gate failures, and mean-time-to-resolve
  charts at `/trends`.
