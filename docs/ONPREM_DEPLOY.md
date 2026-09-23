# On-prem Pepper deployment (Docker) — with SAML, Azure DevOps Server & internal CA

Single-VM, hardened deployment using `docker-compose.onprem.yml`. Only the app is
published (`:3000`); Postgres, Redis and MinIO stay on the internal compose
network. TLS is terminated by a reverse proxy you run in front.

## Sizing (pilot: < 50 repos, 1–2 concurrent scans)

| | Recommended |
|---|---|
| VM | 1 Linux host, Docker + Compose |
| CPU / RAM | **4 vCPU / 16 GB** (8 GB works with `WORKER_CONCURRENCY=1`) |
| Disk | 100 GB SSD |
| Backups | snapshot the `pgdata` volume nightly (findings/history live there) |

## Firewall

| Direction | Port | Why |
|---|---|---|
| users → Pepper | 443 | UI + API |
| Pepper → Azure DevOps Server | 443 | REST API + `git clone` |
| Azure DevOps Server → Pepper | 443 | service-hook webhooks (Basic-auth) |
| Pepper → LLM endpoint | 443 | SAST/zero-day analysis |
| Pepper → OSV / deps.dev | 443 | SCA CVE lookups — **or** set `vulnDbMode=offline` for air-gapped |

---

## 1. `.env`

Compose reads `.env` automatically and passes everything to the app + worker via
`env_file`. Required keys make compose fail fast if missing.

```bash
# ── Required ──
POSTGRES_PASSWORD=<strong>
NEXTAUTH_SECRET=<`openssl rand -base64 32`>
NEXTAUTH_URL=https://pepper.corp.local          # external hostname (TLS below)
ADMIN_EMAIL=admin@corp.local
ADMIN_PASSWORD=<strong>                          # first-login admin
MINIO_ROOT_USER=<strong>
MINIO_ROOT_PASSWORD=<strong>

# ── Worker sizing ──
WORKER_CONCURRENCY=2                             # 1 if RAM is tight
MAX_LLM_CONCURRENCY=5

# ── LLM (Anthropic direct, or an OpenAI-compatible gateway e.g. LiteLLM) ──
# Bedrock/Vertex are NOT native — front them with an OpenAI-compatible gateway.
LLM_PROVIDER=openai
LLM_BASE_URL=https://llm.corp.local/v1
LLM_API_KEY=<key>
LLM_MODEL=<your-model-id>

# ── SAML SSO ──
ENABLE_SAML_SSO=true
SAML_ENTRY_POINT=https://idp.corp.local/app/xxxx/sso/saml   # IdP SSO URL
SAML_IDP_CERT=MIID...                            # signing cert; bare base64 is fine
SAML_EMAIL_ATTR=                                 # blank → email/mail/nameID
SAML_NAME_ATTR=                                  # blank → displayName/cn
SAML_GROUP_ATTR=groups
SAML_ROLE_MAP={"pepper-admins":"ADMIN","appsec":"SECURITY","engineers":"DEVELOPER"}
SAML_DEFAULT_ROLE=VIEWER
# SAML_WANT_ASSERTIONS_SIGNED=false              # only if the IdP signs the <Response>

# ── Azure DevOps Server ──
AZURE_DEVOPS_API_VERSION=7.1                     # 6.0 for Server 2020, 5.0 for 2019
AZURE_DEVOPS_WEBHOOK_SECRET=<shared-secret>      # = the service-hook Basic-auth password

# ── Internal CA (trust ADO Server / LLM over internal HTTPS) ──
NODE_EXTRA_CA_CERTS=/certs/internal-ca.pem       # Node: API + fetch
GIT_SSL_CAINFO=/certs/internal-ca.pem            # git clone in the worker
```

## 2. Mount the internal CA — `docker-compose.override.yml`

`docker-compose.onprem.yml` has no cert volume, so add one (Compose auto-merges
`docker-compose.override.yml`):

```yaml
services:
  sast-api:
    volumes: ["./certs:/certs:ro"]
  sast-worker:
    volumes: ["./certs:/certs:ro"]
```

Place your internal CA chain (PEM) at `./certs/internal-ca.pem`. This is what
lets Pepper reach Azure DevOps Server and your LLM endpoint over internal HTTPS.
Skip this block entirely if those services use publicly-trusted certs or plain
HTTP on a trusted network.

## 3. TLS in front (reverse proxy)

The app serves plain HTTP on `:3000`; terminate TLS at a proxy on `:443` with
your `pepper.corp.local` certificate. **Caddy** is the least fuss:

```
pepper.corp.local {
  tls /certs/pepper.crt /certs/pepper.key
  reverse_proxy localhost:3000
}
```

nginx equivalent must forward the scheme so NextAuth knows it is HTTPS:

```nginx
location / {
  proxy_pass http://127.0.0.1:3000;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-For $remote_addr;
}
```

`NEXTAUTH_URL` **must** equal this hostname — the SAML ACS/metadata URLs and the
secure session cookie derive from it.

## 4. Bring it up

```bash
docker compose -f docker-compose.onprem.yml up -d --build
```

The API container runs `prisma migrate deploy` → `db push` → seed on boot
(`scripts/docker-entrypoint-api.sh`) — no manual DB steps. Watch it:

```bash
docker compose -f docker-compose.onprem.yml logs -f sast-api sast-worker
```

## 5. Configure the IdP and verify

**In your IdP**, create the SAML app with:
- **ACS / Reply URL:** `https://pepper.corp.local/api/auth/saml/acs`
- **Entity ID / Audience:** `https://pepper.corp.local/api/auth/saml/metadata`
- Release an **email** claim (required) and a **groups** claim (for roles).

**Verify:**
```bash
curl -s https://pepper.corp.local/api/health                 # ok
curl -s https://pepper.corp.local/api/auth/saml/status       # {"enabled":true}
```
The login page shows **"Sign in with SSO"**. First SSO login JIT-provisions the
user into the org with the role from their IdP groups (raise-only; never lowers).

## 6. Connect Azure DevOps Server

Log in → **Settings → Integrations → Azure DevOps → Connect**:
- **Organization / collection:** the collection name (e.g. `DefaultCollection`)
- **Server URL:** `https://ado.corp.local` (host + optional virtual dir)
- **PAT** scopes: `Code (Read & Write, Status)`, `Pull Request Threads (Read & Write)`, `Project and Team (Read)`

Then **New Scan → Azure DevOps → Browse & import → scan**. For push/PR
auto-scans, add three **Service Hooks** in ADO (Code pushed / PR created / PR
updated) pointing at `https://pepper.corp.local/api/webhooks/azure-devops` with
the `AZURE_DEVOPS_WEBHOOK_SECRET` in the Basic-auth password field.

---

## Common gotchas

- **TLS is your reverse proxy, not the container.** The app only speaks HTTP on 3000.
- **Internal CA volume is required** for internal-HTTPS ADO/LLM — Node needs
  `NODE_EXTRA_CA_CERTS`, git needs `GIT_SSL_CAINFO`. (Test only: `GIT_SSL_NO_VERIFY=true`.)
- **`NEXTAUTH_URL` must exactly equal** the external HTTPS hostname.
- **SAML signature:** if login fails with a signature error, the IdP signs the
  response, not the assertion → set `SAML_WANT_ASSERTIONS_SIGNED=false`.
- **Older ADO Server:** set `AZURE_DEVOPS_API_VERSION` (6.0 for 2020, 5.0 for 2019).
- **Bedrock/Vertex:** not native — put an OpenAI-compatible gateway (LiteLLM) in front.
