# Spec: Developer pre-push scan (`pepper scan`)

**Status:** Draft for review · **Owner:** TBD · **Author:** initial spec

## 1. Goal

Let a developer trigger a security scan **from their machine, before pushing**
to a PR — in a GitHub repo or any repo — without waiting for CI and without
needing the repo connected to Pepper first. Heavy analysis (SAST-LLM, **SCA**,
secrets, IaC, container) runs **in the cloud**; the developer gets results in
the terminal and a **downloadable report**, and can optionally have the push
**blocked** if the scan fails the build gate.

This is "shift-left, one step further left than CI": the code is scanned while
it is still only on the developer's laptop.

## 2. What already exists (do not rebuild)

This is ~90% wiring of shipped capability. Being explicit so we don't duplicate:

| Capability | Where | Reused as |
|---|---|---|
| API-key auth on scan creation | `requireAuth`→`verifyApiKey` (PR #81) | CLI authenticates with a `ppr_` key |
| Async cloud scan from an upload | `POST /api/scans` (multipart `file` = tarball, `data.scanType`) | the cloud scan itself |
| Scan-type selection incl. `SCA_ONLY`, `FULL`, `SECRETS_ONLY`… | `API_CREATE_SCAN_TYPES` | `--type` flag |
| Status polling | `GET /api/scans/{id}` | progress + completion |
| Downloadable artifacts | `GET /api/scans/{id}/artifacts/{type}` (SBOM CycloneDX/SPDX, VEX, SARIF, signature) | `--download` |
| Downloadable reports | `GET /api/scans/{id}/findings/export?format=csv\|pdf` | `--download` |
| Build gate pass/fail | `BuildGate` + gate eval in worker | `--gate` push blocking |
| **Fast synchronous** secrets/SAST-pattern check | `scripts/pepper-precommit.sh` + `POST /api/precommit/scan` | the **pre-commit** tier (see §3) |

**New work is the developer-side client and its UX**, plus a couple of small
server conveniences. No new scanner, no new scan engine.

## 3. Two tiers — keep them distinct

Pepper already has a **pre-commit** hook: synchronous, inline, seconds, secrets
+ high-severity SAST patterns only, blocks the commit. It exists for the "don't
even commit a secret" case and must stay as-is.

This spec adds a **pre-push** tier, which is a different tradeoff:

| | Pre-commit (exists) | **Pre-push (this spec)** |
|---|---|---|
| Trigger | `git commit` | `git push` or `pepper scan` |
| Where it runs | server, synchronous inline | server, **async cloud job** |
| Scanners | secrets + SAST pattern | **full**: SAST-LLM, SCA, secrets, IaC, container, K8s |
| Latency | ~1–3 s | ~30 s – few min |
| Blocks by default | yes (commit) | **no** (advisory); opt-in gate |
| Output | terminal only | terminal **+ downloadable report/SBOM/VEX** |

Rationale: SCA and SAST-LLM are too slow to block every commit, but valuable to
run once per push. Blocking is opt-in because a multi-minute hard block on every
push is hostile; teams that want enforcement turn it on.

## 4. Developer experience

### 4.1 CLI (primary)

```bash
# one-time
pepper login            # stores PEPPER_API_URL + PEPPER_API_KEY in ~/.pepper/config
# or: export PEPPER_API_URL, PEPPER_API_KEY

# scan the working tree before pushing
pepper scan                       # full scan of the current repo working tree
pepper scan --type sca            # SCA only (fast dependency/supply-chain pass)
pepper scan --diff origin/main    # scan only what this branch changed vs base
pepper scan --download ./report   # write SARIF + PDF + SBOM + VEX to ./report
pepper scan --gate                # exit non-zero if the build gate fails
pepper scan --wait=false          # fire-and-forget; print the scan URL and return
```

Terminal output (streamed while the cloud job runs):

```
pepper · scanning working tree (312 files, 41 deps) → cloud
  ✓ SCA            3 findings
  ✓ Secrets        0
  ✓ SAST (AI)      7 findings
  … Container      running
Result: 1 CRITICAL · 4 HIGH · 5 MEDIUM   (gate: FAIL — maxHigh 3)
Report: https://pepper.your-org.com/scans/clx…
Downloaded: ./report/{sarif.json, report.pdf, sbom.cyclonedx.json, openvex.json}
```

### 4.2 Git `pre-push` hook (opt-in enforcement)

```bash
pepper install-hook            # writes .git/hooks/pre-push
```

The hook runs `pepper scan --diff <pushed-range> --gate`. On gate failure it
prints findings and exits non-zero, so the push is refused. Escape hatch:
`git push --no-verify` (git-native, no special flag).

### 4.3 IDE / editor (later)

Out of scope for v1, but the same CLI is the backend for a future
"scan before push" button in the existing IDE integration.

## 5. Architecture / data flow

```
 developer machine                         Pepper cloud
 ────────────────                          ────────────
 pepper scan
   │ 1. resolve files (git; §6)
   │ 2. tar.gz working tree / diff
   │ 3. POST /api/scans  (multipart: file=tarball, data={scanType, source:PRECOMMIT-ish})
   │      Authorization: Bearer ppr_…                 │
   │                                                  ├─ upload → object store
   │                                                  ├─ enqueue scan job
   │ ← { scanId }                                     │
   │ 4. poll GET /api/scans/{scanId} until done ──────┤ worker runs scanners
   │ 5. GET artifacts + findings export ──────────────┤ (SCA in cloud)
   │ 6. render terminal summary, write ./report       │
   │ 7. exit code from gate (if --gate)               │
```

**Local** does: file selection, packaging, upload, poll, render, download, exit
code. **Cloud** does: all scanning. Exactly the "local trigger, SCA in cloud,
downloadable" model requested.

## 6. What gets scanned (file selection)

The scan source is the **working tree as it will be pushed**, not what's on the
remote. Options, in order of preference:

1. **`--diff <base>` (default for the hook):** `git diff --name-only <base>...HEAD`
   plus staged/unstaged changes → only changed files. Fast, and matches "before
   pushing this PR". SCA still needs the manifest/lockfiles even if unchanged, so
   the packager always includes dependency manifests (`package.json`, lockfiles,
   `requirements.txt`, `go.mod`, …) so the cloud SCA sees the full dependency set.
2. **Full working tree (default for `pepper scan`):** everything tracked +
   untracked-not-ignored, minus `.gitignore` and `SKIP_DIRECTORIES`
   (`node_modules`, `.git`, `dist`, `venv`, …). Reuses the same skip list the
   worker uses so behavior matches a normal scan.

Packaging rules: respect `.gitignore`; skip binaries (`BINARY_EXTENSIONS`) and
files over the size cap; hard cap the tarball at the existing `MAX_UPLOAD_SIZE`
(100 MB) and warn if exceeded.

## 7. Server changes (small)

Mostly reuse. Proposed additions, each optional:

1. **`SourceType` = `PRECOMMIT` already exists** — reuse it (or add `DEV_SCAN`)
   so these scans are attributable and can be excluded from trend baselines. A
   dev pre-push scan should **not** overwrite the project's canonical scan; see
   §9 open question on the `Scan.projectId` unique constraint.
2. **Ephemeral / throwaway scans:** a dev scan is transient. Either mark it
   `ephemeral=true` and reap after N days, or don't tie it to a project at all
   (scan-by-upload without a persisted project). Prevents dev scans from
   clobbering the project's real scan row.
3. **A combined result endpoint** `GET /api/scans/{id}/summary` returning gate
   result + severity counts + artifact URLs in one call, so the CLI polls once
   instead of stitching three endpoints. Nice-to-have.

No changes to scanners, the queue, or the worker.

## 8. Local-only mode (Phase 0, optional)

The request says "local is fine, then SCA in cloud." A pure-local fast path can
ship first, reusing the **existing** `/api/precommit/scan` synchronous route
(secrets + SAST pattern) as `pepper scan --local`, which needs no cloud job and
returns in seconds. This gives immediate value while the cloud pre-push flow is
built. It is explicitly **not** SCA — SCA is the cloud tier.

For a fully offline install, the same CLI points `PEPPER_API_URL` at the on-prem
Pepper; "cloud" just means "the Pepper server," which may be in the customer's
network. Nothing here requires Anthropic-hosted infrastructure.

## 9. Security & privacy

- **Auth:** API key (`ppr_`), which after #81 grants at most DEVELOPER — enough
  to create a scan and read its results, never to change policy or delete. Key
  read from env/`~/.pepper/config`, never logged.
- **What leaves the machine:** the source being scanned, over TLS to the
  configured Pepper URL. For on-prem/air-gapped that is the customer's own
  server. Document this plainly — developers must know their code is uploaded.
- **`.gitignore` respected** so `.env` and secrets-by-convention aren't shipped
  by accident (though secret *scanning* is a feature — an intentionally scanned
  file is different from silently uploading `.env.production`). Add an explicit
  `.pepperignore` for opt-out.
- **No secret persistence in the tarball path:** reuse existing upload handling.

## 10. Phased delivery

| Phase | Scope | Depends on |
|---|---|---|
| 0 | `pepper scan --local` over existing `/api/precommit/scan` (secrets/SAST-pattern, seconds, offline-capable) | nothing new |
| 1 | `pepper scan` → cloud `POST /api/scans` upload, poll, terminal summary | #81 (done) |
| 2 | `--download` (SARIF/PDF/SBOM/VEX via existing artifact endpoints) | phase 1 |
| 3 | `--diff` change-only packaging + dependency-manifest inclusion | phase 1 |
| 4 | `pepper install-hook` pre-push git hook + `--gate` push blocking | phase 1–3 |
| 5 | Ephemeral dev-scan handling so dev scans don't clobber the project scan | server §7 |

Phases 0–2 deliver the core ask. 3–5 are polish/enforcement.

## 11. Open questions for review

1. **Distribution of the CLI:** standalone binary (Go/Rust, no runtime),
   `npx @pepper/cli`, or a shell script like the current pre-commit installer?
   The existing hook is bash+python3; a single static binary is friendlier for
   "any repo / any language" teams.
2. **The `Scan.projectId` unique constraint** means one scan row per project and
   rescans delete the prior one. A dev pre-push scan must not wipe the project's
   canonical scan — hence §7.2 (ephemeral / project-less scans). Decide this
   before phase 1, since it shapes the API.
3. **Default scan type for the hook:** `FULL` (thorough, slower) vs `SCA_ONLY` +
   `SECRETS_ONLY` (fast, the highest-signal pre-push checks). Suggest fast by
   default, `--type full` to opt in.
4. **Default gate behavior:** advisory (never blocks) vs block-on-critical.
   Suggest advisory by default; enforcement is opt-in per §3.
5. **"Any repo" scope:** confirm v1 targets the local working tree via upload
   (works for GitHub, GitLab, Bitbucket, SVN, or no remote at all), rather than
   requiring the repo be connected to Pepper first.

## 12. Non-goals (v1)

- No new scanner or analysis capability — this reuses the cloud scan.
- No IDE plugin (the CLI is the substrate for a later one).
- No change to CI templates (they already exist and share the same API).
- No blocking the *commit* — that's the existing pre-commit tier.
