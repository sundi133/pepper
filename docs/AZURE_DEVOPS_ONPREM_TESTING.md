# Azure DevOps Server (on-prem) + testing the SAST integration

This guide covers connecting a self-hosted **Azure DevOps Server** to Pepper and
verifying the **full webhook → scan → PR-feedback loop** end to end.

> Azure DevOps comes in two flavours. **Services** is the cloud
> (`https://dev.azure.com/{org}`). **Server** is the self-hosted product
> (`https://{host}[/{virtualDir}]/{collection}`). Pepper supports both; the only
> difference at connect time is the **Server URL** field.

---

## 1. Connect Azure DevOps Server

Settings → Integrations → **Azure DevOps Services** → Connect:

| Field | Cloud (Services) | On-prem (Server) |
|---|---|---|
| **Organization / collection** | the `dev.azure.com/<org>` segment | the **collection** name, e.g. `DefaultCollection` |
| **Server URL** | *leave blank* | `https://tfs.company.com` or `https://tfs.company.com/tfs` (host + any virtual directory, up to but **not** including the collection) |
| **Personal Access Token** | PAT with the scopes below | same |

**PAT scopes:** `Code (read & write)`, `Pull Request Threads (read & write)`,
`Project and Team (read)`. Create it in ADO under *User settings → Personal
access tokens*.

**API version:** Pepper defaults to `7.1`, which suits recent Server releases.
For older ones set `AZURE_DEVOPS_API_VERSION` (e.g. `6.0` for Server 2020, `5.0`
for 2019).

On save, Pepper probes `{Server URL}/{collection}/_apis/connectionData` with the
PAT and rejects invalid credentials before storing anything.

### Import repositories

Once connected, open **Scan Hub → add source → Azure DevOps** to browse and
connect repositories (the listing works the same for cloud and Server), or paste
a repo reference manually:

- `Project/Repo` shorthand (uses the connected collection), or
- a full Server URL: `https://tfs.company.com/tfs/DefaultCollection/Project/_git/Repo`

Connecting a repo queues an initial scan and records the repo's clone URL, so the
worker clones on-prem repos over HTTPS using the PAT.

---

## 2. Set up the service hook (the webhook loop)

Azure DevOps Server can't HMAC-sign webhooks, so Pepper authenticates them with
**HTTP Basic auth**.

1. **In Pepper:** Settings → Integrations → **Webhook secrets** → set the
   **Azure DevOps basic auth password**. Copy the **Webhook URL**
   (`https://<pepper-host>/api/webhooks/azure-devops`).
2. **In Azure DevOps Server:** *Project/Collection Settings → Service hooks →
   Create subscription → Web Hooks*. ADO sends **one event per subscription**, so
   create three:
   - *Code pushed*
   - *Pull request created*
   - *Pull request updated*
   For each, set the **URL** to the Pepper Webhook URL and, under the HTTP
   settings, put the secret from step 1 in the **Basic authentication password**
   field.

**What each event does:**
- *Code pushed* to the default branch → re-runs SAST on the branch.
- *Pull request created/updated* → incremental scan of changed files → posts a
  **status check** and **inline review threads** back on the PR.

---

## 3. Test the full loop without waiting for a real push

Use the bundled tester to fire a realistic ADO service-hook payload at a running
Pepper and confirm a scan is queued. You need the **repository GUID** of a
connected project (from the ADO repo, or the Pepper repo listing).

```bash
# Simulate a push to the default branch
node scripts/ado-webhook-test.mjs \
  --url https://your-pepper-host \
  --secret "$AZURE_DEVOPS_WEBHOOK_SECRET" \
  --repo-id 11111111-2222-3333-4444-555555555555 \
  --event push --branch main
```

```bash
# Simulate a pull request update (drives the PR status + inline comments)
node scripts/ado-webhook-test.mjs \
  --url https://your-pepper-host \
  --secret "$AZURE_DEVOPS_WEBHOOK_SECRET" \
  --repo-id 11111111-2222-3333-4444-555555555555 \
  --event pr --pr 42 --branch feature/login
```

A successful call returns a `scanId` and `status`. If you get:
- **401** — the secret doesn't match Pepper's stored basic-auth password.
- **"No matching project found"** — no connected project has that `repo-id`.
- **"Event ignored"** (push) — the branch isn't the project's default branch.

---

## 4. Verify end to end

1. **Scan runs:** open **Scans** in Pepper — the queued scan should move to
   RUNNING then COMPLETED, with findings and a build-gate result.
2. **PR feedback (pr event):** on the ADO pull request, confirm the Pepper
   **status check** appears on the PR header and **inline review threads** are
   posted on changed lines. Re-running the same PR event does not duplicate
   threads (findings are de-duplicated by a hidden marker).
3. **Clone works:** the scan's logs show the repo cloned from your Server host
   over HTTPS with the PAT.

If the scan runs but PR feedback is missing, check that the PAT has
`Pull Request Threads (read & write)` and that the org connection's Server URL is
correct — PR posting uses the same `{Server URL}/{collection}` base as the probe.
