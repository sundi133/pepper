# Pepper On-Prem Deployment — Readiness Questionnaire

Please complete this before your Pepper on-prem install. It lets us size the
deployment, confirm prerequisites, and pre-stage configuration so install day is
smooth. Answer what you can; leave "not sure" where you'd like our guidance.

**Company:** ________________  **Primary technical contact:** ________________
**Target install date:** ________________  **Environment:** ☐ POC / pilot ☐ Production

---

## 1. Deployment target & orchestration

1.1 How will you run Pepper?
☐ Docker Compose (single VM) ☐ Kubernetes ☐ OpenShift ☐ Nomad ☐ Other: ______

1.2 Host OS / distro and version: ________________ (arch: ☐ x86-64 ☐ arm64)

1.3 Is the environment **air-gapped** (no outbound internet)? ☐ Yes ☐ No ☐ Partial (egress allowlist)

1.4 Do you need **high availability** (multi-node, no single point of failure), or is single-node acceptable? ☐ HA ☐ Single-node

1.5 Who owns/operates the infrastructure? ☐ Your platform team ☐ A managed provider ☐ Us (assisted)

## 2. Sizing & capacity

2.1 Roughly how many **repositories** will be onboarded? ________
Approx. total codebase size (LOC or GB): ________

2.2 Expected scan cadence: ☐ On every PR/push ☐ Nightly ☐ Weekly ☐ Ad-hoc

2.3 Peak **concurrent scans** you expect: ________
(drives `WORKER_CONCURRENCY` and worker node count)

2.4 Can you provide the baseline? Minimum: 4 vCPU / 8 GB RAM / 50 GB disk for a
pilot. Production scales with repos + concurrency.
Available for this deployment — vCPU: ____ RAM: ____ GB Disk: ____ GB

## 3. Datastores (bring-your-own or bundled)

Pepper needs PostgreSQL, Redis, and S3-compatible object storage. The bundled
compose ships all three; most production deployments point at managed ones.

3.1 **PostgreSQL 16** — ☐ Use bundled ☐ Bring your own (host/instance): ______________
Backup/retention owned by: ☐ You ☐ Us

3.2 **Redis 7** (job queue) — ☐ Use bundled ☐ Bring your own: ______________

3.3 **Object storage** (scan artifacts, SBOMs, reports) —
☐ Use bundled MinIO ☐ Existing S3-compatible (AWS S3, MinIO, Ceph, etc.)
Endpoint / bucket: ______________  TLS on the endpoint? ☐ Yes ☐ No

3.4 Data **retention** policy for scan artifacts and reports: ________________

## 4. AI / LLM provider (required for AI scanning + compliance mapping)

Pepper's LLM-driven SAST and agentic compliance mapping need a model provider.
This is the most important data-governance decision.

4.1 Which provider? ☐ **Ollama** (local, fully in-network — best for air-gapped)
☐ OpenAI ☐ Anthropic ☐ OpenRouter ☐ Azure OpenAI ☐ Self-hosted vLLM/other: ______

4.2 If a hosted API (OpenAI/Anthropic/etc.): is it **acceptable for source code and
finding metadata to leave your network** to that API? ☐ Yes ☐ No — must stay local

4.3 Preferred model(s): ________________ (e.g. gpt-4o, claude-sonnet, llama3.1)

4.4 If local (Ollama/vLLM): do you have a **GPU host**? ☐ Yes (type/VRAM: ______) ☐ CPU-only

4.5 Concurrency limit for LLM calls (`MAX_LLM_CONCURRENCY`), if you have a rate cap: ______

## 5. Networking, TLS & egress

5.1 What **hostname / URL** will users reach Pepper on? `https://` ______________
(sets `NEXTAUTH_URL`)

5.2 TLS: ☐ You provide certs ☐ Terminate at your ingress/LB ☐ Need guidance
Reverse proxy / ingress in front? ☐ nginx ☐ Traefik ☐ Cloud LB ☐ Istio ☐ Other: ____

5.3 If **not** air-gapped, can you allow outbound egress to the following (for the
features you enable)? Please confirm each you need:
☐ LLM API host (if hosted provider) ☐ OSV / EPSS / CISA KEV (dependency vuln data)
☐ Container registries (image scanning) ☐ Your VCS (GitHub/GitLab/etc.) ☐ SMTP relay

5.4 If air-gapped: you'll need offline mirrors for vuln data and an internal
registry. Do you already run these? ☐ Yes ☐ No ☐ Need guidance

## 6. Identity & access

6.1 Authentication: ☐ Built-in username/password ☐ **SSO required** (OIDC / SAML) — which IdP? ______________

6.2 Should self-service **public registration** be allowed, or admin-invite only?
☐ Open registration ☐ Invite-only (`ALLOW_PUBLIC_REGISTRATION=false`)

6.3 Initial admin account — email: ______________ (bootstrapped via `ADMIN_EMAIL` / `ADMIN_PASSWORD`)

6.4 Role model needed (Admin / Security / Developer / Viewer) — any custom mapping? ______________

## 7. Source control integration

Which systems host the code Pepper will scan? (check all)
☐ GitHub Cloud ☐ GitHub Enterprise Server (URL: ______)
☐ GitLab SaaS ☐ GitLab self-hosted (URL: ______)
☐ Bitbucket Cloud ☐ Azure DevOps ☐ Upload only (no VCS)

7.1 Preferred integration credential: ☐ OAuth app ☐ PAT ☐ App password (per system)
Who can create these on your side? ______________

7.2 Do you want **inbound webhooks** (auto-scan on PR/push)? ☐ Yes ☐ No
If yes, can your VCS reach the Pepper URL (network path / firewall)? ☐ Yes ☐ No ☐ Need guidance

## 8. Scanners in scope

Which scan types do you want enabled?
☐ SAST (pattern + AI) ☐ SCA (dependencies) ☐ Secrets ☐ IaC ☐ Container images
☐ DAST (dynamic) ☐ Zero-day / reachability

8.1 **Container scanning** — which registries hold your images, and how do we auth?
☐ Docker Hub ☐ ECR ☐ GCR ☐ GHCR ☐ Custom: ______  (credentials owner: ______)

8.2 **DAST** — target URL(s) to scan, if any: ______________

8.3 **Dependency vuln data** — ☐ Online (OSV/EPSS/KEV) ☐ Offline mirror (air-gapped)

## 9. Compliance reporting (optional)

9.1 Which frameworks do you need in compliance reports? (drives defaults)
☐ CWE Top 25 ☐ OWASP Top 10 ☐ OWASP ASVS ☐ OWASP API Top 10 ☐ NIST SSDF
☐ PCI DSS 4.0.1 ☐ ISO 27001:2022 ☐ SOC 2 ☐ NIST 800-53 ☐ HIPAA ☐ GDPR

9.2 Compliance mapping runs through your LLM (section 4). Confirm the model choice
there is acceptable for compliance-sensitive data. ☐ Confirmed

## 10. Notifications & secrets

10.1 **SMTP** for email notifications (scan complete, gate failures) —
Host: ______ Port: ______ TLS: ☐ Yes ☐ No From address: ______________ ☐ Not needed

10.2 How will you inject secrets (`POSTGRES_PASSWORD`, `NEXTAUTH_SECRET`, LLM API
keys, registry creds)? ☐ .env file ☐ Kubernetes Secrets ☐ Vault ☐ Cloud secret mgr: ______

10.3 Do you require a specific **audit-log retention** period? ______

## 11. Rollout & support

11.1 Success criteria for the POC / go-live: ______________________________________

11.2 Maintenance window / change-control constraints: ______________

11.3 Who signs off on production go-live? ______________

11.4 Anything else we should know (compliance mandates, data-classification rules,
prior tooling to migrate from): _____________________________________________________

---

*Return this to your Pepper contact. We'll reply with a sized architecture, a
pre-filled `.env`, and an install runbook tailored to your answers.*
