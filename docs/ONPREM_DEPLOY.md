# On-prem Pepper deployment (Docker) — with SAML, Azure DevOps Server & internal CA

> **Installing for a customer?** Give them the install bundle instead of this
> repository. It holds the compose file, `.env.example`, `setup.sh`,
> `INSTALL.md` and `RUNBOOK.html`, and runs the published images with no
> source code.
>
> - **Release (normal):** push a version tag, e.g.
>   `git tag v1.1.0 && git push origin v1.1.0`. CI builds the `1.1.0` images,
>   then publishes a GitHub Release with `pepper-install-1.1.0.tar.gz` / `.zip`
>   and SHA-256 checksums attached.
> - **By hand:** `scripts/package-install-bundle.sh <image-tag>` (any published
>   tag, e.g. `sha-7e34e25`) writes `release/pepper-install-<tag>.tar.gz`. Add
>   `IMAGES=1` to also write an offline image archive for air-gapped sites.
>
> This document covers building from source.

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
# Secrets in code are masked before any LLM request (default on). Files matching
# these globs are never sent; key/keystore files (*.pem, *.key, id_rsa, …) never are.
# LLM_MASK_SECRETS=true
# LLM_EXCLUDE_PATHS=config/prod/**,*.tfvars

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
# ── or Microsoft Entra ID (OpenID Connect; see docs/ENTRA_ID_SETUP.md) ──
# ENABLE_ENTRA_SSO=true
# ENTRA_TENANT_ID=<tenant-id>  ENTRA_CLIENT_ID=<client-id>  ENTRA_CLIENT_SECRET=<secret>
# ENTRA_ROLE_MAP={"Pepper.Admin":"ADMIN","Pepper.Security":"SECURITY"}

# ── Azure DevOps Server ──
AZURE_DEVOPS_API_VERSION=7.1                     # 6.0 for Server 2020, 5.0 for 2019
AZURE_DEVOPS_WEBHOOK_SECRET=<shared-secret>      # = the service-hook Basic-auth password

# ── Internal CA (trust ADO Server / LLM over internal HTTPS) ──
NODE_EXTRA_CA_CERTS=/certs/internal-ca.pem       # Node: API + fetch
GIT_SSL_CAINFO=/certs/internal-ca.pem            # git clone in the worker

# ── Outbound proxy (only if internet egress goes through a proxy) ──
HTTPS_PROXY=http://proxy.corp.local:3128
HTTP_PROXY=http://proxy.corp.local:3128
NO_PROXY=ado.corp.local,.corp.local              # internal hosts that must NOT use the proxy
```

### Outbound proxy

When egress goes through a proxy, set `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`
in `.env`. The images set `NODE_USE_ENV_PROXY=1`, so every outbound call from
Node (LLM providers, OSV / deps.dev / EPSS, repository APIs) uses the proxy;
`git`, `svn` and Trivy read the same variables.

- **`NO_PROXY` must list your internal hosts** — the Azure DevOps Server, an
  internal Ollama / LLM endpoint, SMTP relay. The compose files already append
  `localhost`, `127.0.0.1` and the internal services (`postgres`, `redis`,
  `minio`, `sast-api`, `sast-worker`).
- Proxy credentials go in the URL (`http://user:pass@proxy:3128`); they are
  redacted in logs.
- A proxy that intercepts TLS needs its CA in `NODE_EXTRA_CA_CERTS` /
  `GIT_SSL_CAINFO` (section 2).
- Check the startup logs of `sast-api` and `sast-worker` for
  `[proxy] outbound proxy active: …`. A warning there means Node will not use
  the proxy (see the message for why).
- Manual (non-Docker) installs: run Node ≥ 22.21 (or ≥ 24.5) and export
  `NODE_USE_ENV_PROXY=1` for both the web app and the worker.

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

## Rule-based SAST (OpenGrep)

The worker image ships [OpenGrep](https://github.com/opengrep/opengrep) (pinned,
checksum-verified) and the rule packs in `rules/opengrep/` — Pepper's own rules
plus GitLab's LGPL-3.0 rules. It runs fully offline on every FULL, SAST_ONLY and
PR scan, independent of the LLM. Findings appear as **SAST (Pattern)**.

- Add your own rules: mount a directory of OpenGrep/Semgrep YAML rules into the
  worker and set `OPENGREP_EXTRA_RULES=/path/in/container` (several: `:`-separated).
- Disable: `ENABLE_OPENGREP_SAST=false`.
- See `rules/opengrep/README.md` for which rule sets are bundled and why.

## Compiled-code scanning

Besides source, the worker scans compiled code: it decompiles artifacts it
finds in the checkout (or a single uploaded `.jar`, `.war`, `.ear`, `.apk`,
`.aab`, `.dll` or `.exe`) and runs AI SAST, OpenGrep and the secrets scanners
on the result. Everything runs offline inside the worker.

| Artifacts | Decompiler (in the worker image) | License |
|---|---|---|
| JAR, WAR, EAR, `.class` | Vineflower 1.12.0 | Apache-2.0 |
| APK, AAB, DEX | jadx 1.5.6 | Apache-2.0 |
| .NET DLL / EXE | ILSpy `ilspycmd` 11.1.0.9782 on the .NET 10 runtime | MIT (both) |
| (runs jadx and Vineflower) | OpenJDK 21 JRE, Alpine `openjdk21-jre-headless` | GPLv2 + Classpath Exception |

All are redistributable in a commercial product; they run as separate
processes and are not linked into Pepper. Versions and SHA-256 checksums are
pinned in `Dockerfile.worker`; notices are in `NOTICE` (in the image at
`/usr/share/doc/pepper/NOTICE`). The tools add about 375 MB to the worker
image (JRE ~190 MB, .NET runtime ~80 MB, jadx ~75 MB, ILSpy ~10 MB).

ilspycmd is a framework-dependent .NET tool (pure IL), so it runs on the musl
(Alpine) build of the .NET runtime: a build stage takes the runtime from
Microsoft's `dotnet/runtime:10.0.12-alpine3.24` image (pinned by digest) and
ilspycmd from its NuGet package (checksum-verified); no SDK is shipped, and it
runs with invariant globalization so ICU is not needed.

- **Findings** in decompiled code read `artifact!/file:line`, e.g.
  `app.apk!/com/example/Login.java:42` or `app.ear!/web.war!/WEB-INF/classes/…`,
  carry `metadata.decompiledFrom`, and are marked "Found in compiled code" in
  the finding detail. Their line numbers refer to the decompiled source.
- **Skipped, with a note on the scan page:** native (non-.NET) DLL/EXE, which
  cannot be decompiled to source; artifacts in dependency folders
  (`WEB-INF/lib`, `lib/`, `libs/`, `node_modules`, `packages/`, `.m2`, `.gradle`,
  `vendor`); well-known library assemblies (`System.*`, `Microsoft.*`,
  `Newtonsoft.Json` …); build output (`target/`, `build/`, `bin/` …) when the
  scan already contains that language's source; anything over the limits.
  Library packages inside an artifact (`android/`, `androidx/`, `kotlin/`,
  `com/google/`, `org/apache/` …) are not scanned — SCA covers dependencies.
- **Limits and settings:** `ENABLE_COMPILED_SCAN`, `COMPILED_SCAN_MAX_ARTIFACT_MB`,
  `COMPILED_SCAN_MAX_ARTIFACTS`, `COMPILED_SCAN_MAX_FILES`, `COMPILED_SCAN_MAX_OUTPUT_MB`,
  `COMPILED_SCAN_TIMEOUT_SECONDS`, `COMPILED_SCAN_TOTAL_TIMEOUT_SECONDS`,
  `COMPILED_SCAN_SKIP_THIRD_PARTY`, `COMPILED_SCAN_EXCLUDE_PACKAGES`,
  `COMPILED_SCAN_INCLUDE_PACKAGES` — see `dist/.env.example` and
  `docs/configuration.html`. Stop / Cancel kill a running decompiler; the
  decompiled source is deleted with the scan's work directory.
- **Disable:** `ENABLE_COMPILED_SCAN=false`.

## Common gotchas

- **TLS is your reverse proxy, not the container.** The app only speaks HTTP on 3000.
- **Internal CA volume is required** for internal-HTTPS ADO/LLM — Node needs
  `NODE_EXTRA_CA_CERTS`, git needs `GIT_SSL_CAINFO`. (Test only: `GIT_SSL_NO_VERIFY=true`.)
- **`NEXTAUTH_URL` must exactly equal** the external HTTPS hostname.
- **SAML signature:** if login fails with a signature error, the IdP signs the
  response, not the assertion → set `SAML_WANT_ASSERTIONS_SIGNED=false`.
- **Older ADO Server:** set `AZURE_DEVOPS_API_VERSION` (6.0 for 2020, 5.0 for 2019).
- **Bedrock/Vertex:** not native — put an OpenAI-compatible gateway (LiteLLM) in front.
