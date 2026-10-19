# Pull-request reviews on Azure DevOps, GitLab and Bitbucket

Status: Azure DevOps implemented (step 1), GitLab implemented (step 2). Bitbucket (step 3) to follow.
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

### 2.1 Today

- **Credential:** one access token per Pepper organization (`PRIVATE-TOKEN`), on gitlab.com
  or self-managed. It is checked with `GET /user`. Any token that answers works, but the UI
  only describes personal tokens.
- **Webhook:** `POST /api/webhooks/gitlab`, `X-Gitlab-Token` against per-organization secrets
  or `GITLAB_WEBHOOK_SECRET`. It handles only `merge_request` `open` and `update`.
  - It matches the project by a **substring** of `path_with_namespace` in `repoUrl` (so
    `acme/api` also matches `acme/api-legacy`).
  - It cancels **every** active scan of the project.
  - It queues an incremental scan **without credentials**, so private repositories can't be
    cloned.
  - It rescans on every `update` (labels, title, assignee).
- **Not supported:** push to the default branch, reopen, notes, drafts, forks,
  `.pepper.yaml`, commit statuses, repository import and AI remediation.
- **After the scan:** a summary note and inline discussions on the merge request.

### 2.2 Workload identity: group or project access tokens

GitLab's workload identity is a **group or project access token** (a bot user that belongs
to the group, with a role and an expiry), or a service account's token (GitLab Premium).
They use the same API as a personal token, so the connection doesn't change shape:

- **At connect time** Pepper also calls `GET /personal_access_tokens/self` for the token's
  name, scopes and expiry. It shows "Connected as <bot> (group access token, expires …)"
  and warns when it is a **personal** token, or expires within 30 days.
- **Scopes needed:** `api` (comments, statuses, merge requests) and `read_repository`
  (clone); `write_repository` for AI fix branches. Role: Developer.
- **Storage:** `OrgGitLabConnection` gains `tokenKind`, `tokenScopes` and `tokenExpiresAt`
  (display only), and `commitStatuses` (§2.5). The migration is additive.

### 2.3 Authenticated clone

Webhook and import jobs carry `useOrgGitLabToken`. The worker embeds `oauth2:<token>` in the
clone URL **only when the repository is on the connection's host**, so the token is never
sent elsewhere. It is used for the clone, fork fetch and incremental diff; the URL, with its
credential, never leaves the worker (same as Bitbucket and Azure DevOps PATs).

### 2.4 Zero-setup onboarding

A **group webhook** (Premium; on Free, one project hook each) covers every project in the
group. An event authenticated with an **organization's** secret for an unknown project
creates it:

- the GitLab project id and path come from the payload;
- the clone URL is built from the **connection's host** and the path
  (`{host}/{path_with_namespace}.git`), never taken from `git_http_url`;
- it gets `gitlabProjectId`, `gitlabNamespace` and `connectedViaGitlab` (new column).

Projects are matched by `gitlabProjectId` first (exact), then by an **exact** path match on
the stored URL. There is no more substring matching.

### 2.5 When a merge request is reviewed

| GitHub | GitLab (`merge_request`) |
|---|---|
| `opened` | `open` |
| `reopened` | `reopen` |
| `synchronize` | `update` **with `oldrev`** (new commits); other updates are ignored |
| `ready_for_review` | `update` with `changes.draft` going from true to false (reviewed when drafts are skipped) |
| draft | `object_attributes.draft` (or `work_in_progress`) |
| bot author | the author's username matches the bot pattern, including GitLab's `project_<id>_bot…` and `group_<id>_bot…` |
| fork | `source_project_id ≠ target_project_id`; reviewed by fetching `refs/merge-requests/<iid>/head` from the target project |
| collaborator | the user's access level on the project is Developer (30) or higher (`GET /projects/:id/members/all/:user_id`) |

- **`push` to the default branch** now scans it, as on the other hosts.
- **Concurrency:** scans use the scoped slot (per merge request, or per branch for pushes).
- **Base:** the merge request's `diff_refs.base_sha`, read through the API, is the diff base.
- **`.pepper.yaml`** is read from the **target branch**
  (`GET /projects/:id/repository/files/.pepper.yaml/raw?ref=…`).
- **Commit status** (new): `pending` ("Pepper: review queued") when a scan is queued, then
  `success` or `failed` when it completes, as name `pepper/security`, on the merge request's
  head commit. Deliberate skips post `success` with the reason; forks from outside
  contributors post `pending`.
  - **Opt-in per connection** (`commitStatuses`). A failed external status fails the
    commit's pipeline, which blocks the merge under "Pipelines must succeed". Existing
    connections keep today's behaviour (off). The connect form defaults it on for new
    connections, and a switch on the GitLab card changes it (`PATCH
    /api/integrations/gitlab/connect`).

### 2.6 `@pepper` commands (note events)

- **Event:** `object_kind: note` with `noteable_type: MergeRequest`. "Comments" must be
  enabled on the webhook.
- **Who may run them:** Developer access or higher. Pepper's own notes (markers) and bots are
  ignored.
- **Replies** go in the same discussion; the command note gets an 👀 award emoji.
- **Commands:** `review`, `full review`, `pause`, `resume`, `help`, and `fix` in a Pepper
  inline discussion.

### 2.7 AI remediation on GitLab

`gitlab` becomes a remediation provider:

- **Which repositories:** the repository's host equals the connection's host, or the
  project is GitLab-connected.
- **Credentials:** the connection token as `oauth2:<token>` for clone and push. They are
  used only when the repository is on the connection's host.
- **The merge request:** `POST /projects/:path/merge_requests` (with
  `remove_source_branch`).

So "Fix with AI" in Pepper and `@pepper fix` both work for GitLab repositories.

### 2.8 Compatibility

- **Existing connections, secrets, notes and inline discussions:** unchanged.
- **Project matching:** an exact match on the GitLab project id or the path. A project that
  used to match only by substring (a different repository with a longer name) no longer
  matches. That substring match was a bug.
- **New behaviour on existing webhooks:**
  - fewer scans (`update` without new commits is ignored);
  - push events scan the default branch (GitLab enables "Push events" by default on a new
    hook, so existing hooks will start sending them);
  - private repositories now clone;
  - scans of different merge requests no longer cancel each other;
  - fork merge requests from members below Developer wait for `@pepper review` (they used to
    scan the target's default branch by mistake).
- **Commit statuses:** off for existing connections (§2.5), so no merge is newly blocked.
- **Without a GitLab connection:** merge requests are still scanned, as today, with the
  default configuration and no statuses.
- **Migration:** additive (`connectedViaGitlab`, the token metadata columns).

### 2.9 Testing

- **Unit:**
  - token kind and expiry detection;
  - the clone credential only on the connection's host;
  - event mapping (open, update with and without `oldrev`, draft to ready, reopen, fork,
    push);
  - collaborator access levels;
  - note commands;
  - the raw-file config read;
  - commit status calls;
  - onboarding (URL from the connection host, exact matching);
  - the GitLab remediation provider (the resolve, credential, host and MR calls).
- **Regression:** the existing GitLab and remediation tests pass, and the full suite.

## Step 3: Bitbucket

To follow. Outline:

- **Identity:** workspace or repository access tokens instead of app passwords, which
  Atlassian is retiring.
- **Webhooks:** workspace-level webhooks.
- **Events:** `pullrequest:created` / `updated`, comment events for commands,
  `.pepper.yaml` from the destination branch, and build statuses.
