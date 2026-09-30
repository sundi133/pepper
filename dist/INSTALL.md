# Pepper — On-Prem Installation Guide

Pepper runs as five Docker containers: the web app, a scan worker, PostgreSQL,
Redis and MinIO (object storage). You don't need the source code. This bundle
contains everything:

| File | Purpose |
|---|---|
| `docker-compose.yml` | The containers and how they connect |
| `.env.example` | Configuration template (copied to `.env`) |
| `setup.sh` | Optional guided setup (Linux / macOS) |
| `INSTALL.md` | This guide |
| `RUNBOOK.html` | Step-by-step install runbook with a full `.env` reference (open in a browser) |

## 1. Requirements

- **Server:** Linux x86-64 (amd64). Recommended 4 vCPU, 16 GB RAM, 100 GB disk (minimum 2 vCPU / 8 GB).
- **Docker Engine 24+** with the **Compose plugin** (`docker compose version` must work).
- **Inbound:** one port for the web UI (default `3000`, usually behind your HTTPS reverse proxy).
- **Outbound** (direct or through your proxy):
  - your Git servers (Azure DevOps Server, GitHub, GitLab, Bitbucket) to clone repositories;
  - your LLM endpoint (for example an internal gateway, Azure OpenAI or OpenRouter);
  - `api.osv.dev` for dependency vulnerability data (optional; see *Air-gapped* below);
  - Docker Hub, unless you install from an offline image archive (section 3).

## 2. Install (server with registry access)

```bash
mkdir -p /opt/pepper && cd /opt/pepper
# copy the bundle files here, then:
cp .env.example .env
chmod 600 .env
mkdir -p certs
```

Edit `.env`. At minimum set:

- `PEPPER_VERSION`: the version tag you were given, for example `sha-a0c538e`.
- `NEXTAUTH_URL`: the exact URL users will open, for example `https://pepper.yourcompany.local`.
- `NEXTAUTH_SECRET`, `POSTGRES_PASSWORD`, `MINIO_ROOT_PASSWORD`: long random values. Generate each with `openssl rand -hex 32` (use hex: `/` or `+` in the database password would break its connection URL).
- `ADMIN_EMAIL` and `ADMIN_PASSWORD`: the first administrator account.
- `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`: your AI model endpoint.

Then start Pepper:

```bash
docker compose pull
docker compose up -d
docker compose ps
```

The first start applies the database schema, which takes 1–3 minutes. When
`pepper-api` shows `healthy`, open `NEXTAUTH_URL` and sign in with
`ADMIN_EMAIL` / `ADMIN_PASSWORD`.

> `./setup.sh` does the same steps interactively. It generates the secrets,
> asks for the URL and version, pulls the images and waits until Pepper is up.

## 3. Air-gapped install (no registry access)

**On a machine with internet access**, download the images into one archive:

```bash
V=sha-a0c538e     # the Pepper version you were given
docker pull docker.io/sundi133/pepper-api:$V
docker pull docker.io/sundi133/pepper-worker:$V
docker pull postgres:16-alpine
docker pull redis:7-alpine
docker pull docker.io/chainguard/minio:latest
docker save -o pepper-images-$V.tar \
  docker.io/sundi133/pepper-api:$V docker.io/sundi133/pepper-worker:$V \
  postgres:16-alpine redis:7-alpine docker.io/chainguard/minio:latest
sha256sum pepper-images-$V.tar > pepper-images-$V.tar.sha256
```

Copy `pepper-images-$V.tar` (about 3 GB), its `.sha256` file and this bundle to
the server through your approved transfer process. Then, **on the server**:

```bash
cd /opt/pepper
sha256sum -c pepper-images-sha-a0c538e.tar.sha256
docker load -i pepper-images-sha-a0c538e.tar
cp .env.example .env && chmod 600 .env && mkdir -p certs   # then edit .env as in step 2
docker compose up -d        # no pull: the images are already loaded
```

**Using an internal registry instead** (Harbor, Artifactory, Nexus): after
`docker load`, retag and push the two Pepper images, then point `.env` at them:

```bash
docker tag docker.io/sundi133/pepper-api:$V    registry.yourcompany.local/pepper/pepper-api:$V
docker tag docker.io/sundi133/pepper-worker:$V registry.yourcompany.local/pepper/pepper-worker:$V
docker push registry.yourcompany.local/pepper/pepper-api:$V
docker push registry.yourcompany.local/pepper/pepper-worker:$V
```

```dotenv
PEPPER_API_IMAGE="registry.yourcompany.local/pepper/pepper-api"
PEPPER_WORKER_IMAGE="registry.yourcompany.local/pepper/pepper-worker"
```

**Without internet access:**

- **Dependency vulnerability data:** `api.osv.dev` isn't reachable. In
  *Settings → LLM Config*, set the vulnerability database to **Mirror** (your
  internal OSV mirror URL) or **Offline**. Offline skips dependency CVE lookups.
- **AI features:** these need a reachable LLM endpoint, such as your internal
  OpenAI-compatible gateway or a self-hosted model.
- **Unaffected:** rule-based SAST (OpenGrep), secrets and IaC checks work
  fully offline.

## 4. HTTPS

Put Pepper behind your existing reverse proxy or load balancer (nginx, IIS
ARR, F5), which terminates TLS and forwards to `http://<server>:3000`. Set
`NEXTAUTH_URL` to the public `https://` URL. Optionally set
`PEPPER_BIND_ADDRESS=127.0.0.1`, so the app is reachable only through the proxy
on the same host.

A minimal nginx example:

```nginx
server {
  listen 443 ssl;
  server_name pepper.yourcompany.local;
  ssl_certificate     /etc/nginx/tls/pepper.crt;
  ssl_certificate_key /etc/nginx/tls/pepper.key;
  client_max_body_size 500m;               # repository uploads
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;               # live scan progress streams
    proxy_buffering off;
  }
}
```

## 5. Internal certificates and proxy

If your Git server, LLM gateway or proxy uses an internal CA (including a
proxy that inspects TLS):

1. Put the CA certificate (PEM) in `/opt/pepper/certs/internal-ca.pem`.
2. Build a bundle of the public roots plus your CA. Git and the container
   scanner replace their trust store with it, so public sites must stay
   trusted:

   ```bash
   cat /etc/ssl/certs/ca-certificates.crt certs/internal-ca.pem > certs/ca-bundle.pem
   # RHEL: cat /etc/pki/tls/certs/ca-bundle.crt certs/internal-ca.pem > certs/ca-bundle.pem
   ```

3. Set these in `.env`:

   ```dotenv
   NODE_EXTRA_CA_CERTS="/certs/internal-ca.pem"
   GIT_SSL_CAINFO="/certs/ca-bundle.pem"
   SSL_CERT_FILE="/certs/ca-bundle.pem"
   ```

For an outbound proxy, set `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` in
`.env`. List internal hosts (for example your Azure DevOps Server) in
`NO_PROXY`. These apply to Pepper's containers only: for `docker compose pull`,
Docker itself needs the proxy in `/etc/docker/daemon.json` (then
`sudo systemctl restart docker`):

```json
{ "proxies": { "http-proxy": "http://proxy.yourcompany.local:8080",
               "https-proxy": "http://proxy.yourcompany.local:8080",
               "no-proxy": "localhost,127.0.0.1,.yourcompany.local" } }
```

`RUNBOOK.html` lists every host to allow on the proxy.

Apply either change with `docker compose up -d`.

## 6. Optional features

All of these are configured in `.env`; each section of `.env.example`
explains its settings.

- **Sign-in:** Microsoft Entra ID or SAML single sign-on.
- **Azure DevOps Server:** set `AZURE_DEVOPS_API_VERSION` (`6.0` for Server 2020, `7.0` for Server 2022). Connect it in *Settings → Integrations*.
- **Email** notifications (SMTP), **audit log retention**, and **scan concurrency**.
- **Data retention:** `UPLOAD_RETENTION_DAYS` deletes uploaded source archives after that many days; `SCAN_HISTORY_RETENTION_DAYS` trims old scan history and AI fix runs. Both keep everything by default.
- **Ticketing:** Azure Boards, Jira and Slack are configured in the UI, under *Settings → Integrations → Outbound*.

After changing `.env`, run `docker compose up -d`. Only the changed containers restart.

## 7. Upgrade

```bash
cd /opt/pepper
docker compose exec -T postgres pg_dump -U pepper pepper | gzip > backup-$(date +%F).sql.gz
# set PEPPER_VERSION in .env to the new tag, then:
docker compose pull          # air-gapped: docker load -i pepper-images-<new>.tar
docker compose up -d
```

Database changes are applied automatically when the new version starts.

## 8. Backup and restore

What to back up:

1. **The database:**

   ```bash
   docker compose exec -T postgres pg_dump -U pepper pepper | gzip > pepper-db.sql.gz
   ```

2. **Object storage** (reports, SBOMs, audit archives): the Docker volume `pepper_miniodata`.
3. **`.env`.** Keep it safe: `NEXTAUTH_SECRET` encrypts stored credentials and can't be recovered.

Restore into a fresh install (same `.env`):

```bash
docker compose up -d postgres
gunzip -c pepper-db.sql.gz | docker compose exec -T postgres psql -U pepper pepper
docker compose up -d
```

## 9. Operations

```bash
docker compose ps                         # status
docker compose logs -f pepper-api         # web app logs
docker compose logs -f pepper-worker      # scan logs
docker compose restart pepper-worker      # restart a service
docker compose up -d --scale pepper-worker=3   # more parallel scans
docker compose down                       # stop (data is kept in volumes)
```

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| `docker compose` says a variable is required | Set that variable in `.env` |
| `pepper-api` not healthy after 5 minutes | `docker compose logs pepper-api`; database password or disk space |
| Sign-in redirects to the wrong address | `NEXTAUTH_URL` must match the URL in the browser exactly |
| Scans stay *Queued* | `docker compose logs pepper-worker`; the worker must be running |
| Can't clone repositories | Proxy / `NO_PROXY`, internal CA (`GIT_SSL_CAINFO`), repository credentials |
| AI findings missing | *Settings → LLM Config → Test connection*; check `LLM_*` values and outbound access |
| `x509: certificate signed by unknown authority` | Internal CA not configured (section 5) |
