# Pull-request reviews on Azure DevOps, GitLab and Bitbucket

Status: Azure DevOps implemented (step 1). GitLab (step 2) and Bitbucket (step 3) to follow.
Owner: Pepper integrations.

The GitHub experience (`docs/PR_REVIEW_BOT_SPEC.md`) is that Pepper acts as a workload
identity and every pull request is reviewed with no per-repository setup. Developers use
`@pepper` commands, `.pepper.yaml` tunes it, and scans of different PRs don't cancel each
other. This document brings the same experience to the other three hosts, one at a time,
reusing the provider-neutral parts:

- `src/lib/pr-review/config.ts` (`.pepper.yaml`);
- `commands.ts`;
- `decision.ts`;
- the per-PR pause state (`PrReviewState`);
- scoped scan replacement.

**Rules for every step:**

- Existing connections, webhooks and repositories keep working unchanged.
- With no `.pepper.yaml`, reviews behave as today.
- Every new behaviour is additive or opt-in.

---

## Step 1: Azure DevOps

### 1.1 Today

- **Credential:** one PAT per Pepper organization, sent as `Basic :PAT`. It works for
  Services (`dev.azure.com/{org}`) and Server (`{serverUrl}/{collection}`).
- **Webhook:** `POST /api/webhooks/azure-devops`, authenticated by a Basic-auth password
  (per organization, or the `AZURE_DEVOPS_WEBHOOK_SECRET` env fallback).
  - `git.push` to the default branch triggers a scan;
  - `git.pullrequest.created` and `git.pullrequest.updated` trigger an incremental scan,
    including on every `updated` event (a reviewer vote, a title edit), even when the code
    didn't change.
- **Repositories** must be imported first: an event for an unknown repository is ignored.
- **PR feedback:** a summary thread, inline threads on changed files (at most 30) and a PR
  status (`succeeded`/`failed`). Nothing is posted while the scan is queued.
- **Not supported:** drafts, forks, `.pepper.yaml`, comment commands and service
  principals.

### 1.2 Workload identity: an Entra ID service principal (Services)

The Azure DevOps equivalent of a GitHub App is an **Entra ID service principal**: an app
registration in the customer's tenant, added to the Azure DevOps organization as a user
with the access it needs.

- **New connection type "Service principal"** (Azure DevOps Services only): the tenant ID,
  client ID and client secret, with the secret encrypted like the PAT.
- **Tokens:** Pepper requests one with client credentials
  (`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope
  `499b84ac-1321-427f-aa17-267ca6975798/.default`). It is cached in memory until 5 minutes
  before it expires (1 hour) and never stored.
- **API calls** send `Authorization: Bearer <token>`. **Git** gets the token as an HTTP
  header (`git -c http.extraHeader="Authorization: Bearer …"`), never inside the clone URL.
- **Checking it at connect time:** a token is requested and `/_apis/connectionData` is
  called. The identity's display name is shown as "Connected as …".
- **Azure DevOps Server** has no service principals. There, the recommended identity is a
  **dedicated service account's PAT** (not a person's), which is documented. The PAT
  connection is unchanged.

**Data:** `OrgAzureDevOpsConnection` gains `authType` (`"pat"` by default, or
`"service_principal"`), `tenantId`, `clientId` and `clientSecretEnc`, and `patEnc` becomes
nullable. The migration is additive. Existing rows are PAT connections, unchanged.

**Code:** `AzureDevOpsAuth` gains an optional `bearer` token. One header helper returns
`Bearer …` when it is set and `Basic …` otherwise. The clone and push paths (worker clone,
remediation) use the extra header for a bearer and the URL credential for a PAT, as today.

### 1.3 Zero-setup onboarding

A **project-level service hook** (one per Azure DevOps project, covering all its
repositories) is enough. When an event authenticated with an **organization's** webhook
secret arrives for a repository with no Pepper project, Pepper creates it:

- the repository id, name and Azure DevOps project name come from the payload;
- the clone URL is **built from the connection and those names**
  (`https://dev.azure.com/{org}/{project}/_git/{repo}`, or `{serverUrl}/{collection}/{project}/_git/{repo}`),
  never taken from the payload;
- `connectedViaAzure` is set, and the event is then handled normally.

Events authenticated only by the env fallback secret (no organization) don't onboard.

### 1.4 When a PR is reviewed

The same decision as on GitHub (`decision.ts`), with Azure DevOps facts:

| GitHub | Azure DevOps |
|---|---|
| `opened` | `git.pullrequest.created` |
| `synchronize` (new commits) | `git.pullrequest.updated` **when `lastMergeSourceCommit` differs from the last review of this PR** |
| `ready_for_review` | `updated` with `isDraft` turning false (reviewed only when drafts are skipped) |
| `draft` | `isDraft` |
| bot author | `createdBy.uniqueName` or `displayName` matching the bot pattern (`dependabot`, `renovate`, `[bot]`) |
| base branch | `targetRefName` without `refs/heads/` |
| fork | `forkSource` present; reviewed by fetching `refs/pull/{id}/merge` |

**Fewer duplicate scans:** an `updated` event whose source commit was already reviewed
(completed or in progress) is ignored. Today a reviewer vote rescans the same code.

**Fork authors:** commenting on or opening a PR in Azure DevOps requires access to the
repository, so authors and commenters count as collaborators. `forks: collaborators` reviews
every fork PR; `forks: none` still skips them.

**`.pepper.yaml`** is read from the **target branch** through the Items API
(`/_apis/git/repositories/{id}/items?path=/.pepper.yaml&versionDescriptor.version={branch}`).

**PR status:**

- `pending` ("Pepper: review queued") when a scan is queued (new; GitHub already does this);
- the existing `succeeded`/`failed` when it completes;
- `succeeded` with a reason for deliberate skips;
- `pending` for skipped fork PRs.

These all use the same status context (`pepper/security`).

### 1.5 `@pepper` commands

- **Event:** `ms.vss-code.git-pullrequest-comment-event`. Customers add it to the same
  service hook.
- **Parsing and authorization:** the same parser as GitHub (`@pepper`, first line only).
  Pepper's own comments are ignored (they carry Pepper's markers, or come from the
  connection's identity). System comments are ignored.
- **Acknowledgement:** a reply in the same thread (Azure DevOps has no reactions API that
  fits).

| Command | Azure DevOps |
|---|---|
| `review`, `full review` | queue a review of the PR's current source commit |
| `pause`, `resume` | `PrReviewState` (shared with GitHub) |
| `fix` | in a Pepper inline thread: a **remediation run** for that finding (the existing "Fix with AI" flow, provider-neutral), aimed at the PR's source branch. The reply links to the run; its PR appears on the PR when done |
| `help` | the command list |

### 1.6 Compatibility

- **PAT connections, service hooks, imported repositories, the summary and inline threads,
  and statuses:** unchanged.
- **Fewer scans** on `updated` events that don't change the code. That is intended, and no
  review of new code is lost.
- **New `pending` status while queued.** A branch policy that requires the Pepper status was
  already waiting on it; now it shows "queued" instead of nothing.
- **Onboarding** happens only for organization-secret webhooks, from repositories in
  projects whose hooks point at Pepper.
- **Migration:** additive (new nullable columns, `patEnc` becomes nullable).

### 1.7 Testing

- **Unit:**
  - token acquisition and caching (expiry, errors that never include the secret);
  - the auth header choice;
  - git clone arguments for bearer and for PAT;
  - mapping Azure DevOps events to the decision facts (created, updated with and without a
    new commit, draft to ready, fork);
  - comment-event command parsing, and ignoring Pepper's own comments;
  - the Items API config read;
  - onboarding (clone URL built, never from the payload; org-secret only).
- **Route:** the webhook with an organization secret for each event type; the env-secret
  path unchanged.
- **Regression:** the existing Azure DevOps tests pass, and the full suite.

---

## Step 2: GitLab

To follow. Outline:

- **Identity:** a group or project access token (a bot user), or a service account.
- **Webhooks:** group-level webhooks onboard every project in the group.
- **Events:** merge request events (`open`, `update` with `oldrev`, `reopen`, drafts), note
  events for `@pepper` commands, `.pepper.yaml` from the target branch, and commit
  statuses.

## Step 3: Bitbucket

To follow. Outline:

- **Identity:** workspace or repository access tokens instead of app passwords, which
  Atlassian is retiring.
- **Webhooks:** workspace-level webhooks.
- **Events:** `pullrequest:created` / `updated`, comment events for commands,
  `.pepper.yaml` from the destination branch, and build statuses.
