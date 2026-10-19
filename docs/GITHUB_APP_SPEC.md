# GitHub App connection: a workload identity for GitHub

Status: phase 1 implemented; on-prem setup steps in `docs/GITHUB_APP_SETUP.md`. Owner: Pepper integrations.

## 1. Problem

An organization connects GitHub to Pepper with **one person's OAuth token**
(`OrgGithubConnection`, one row per organization, scopes `repo read:user`). Every GitHub call
Pepper makes for that organization uses it:

- cloning private repositories;
- listing repositories and branches;
- PR comments and commit statuses;
- incremental PR diffs;
- AI fix pull requests.

For an enterprise this means:

1. **Over-privileged.** The `repo` scope grants read and write on every private repository the
   person can reach, in every GitHub organization they belong to, not only the repositories
   Pepper scans.
2. **Tied to a person.** When they leave, lose access or revoke the token, all scans and PR
   feedback stop. Classic OAuth tokens don't expire, and nobody owns rotation.
3. **Wrong attribution.** Comments, statuses and fix PRs appear as that person, so audits
   can't tell Pepper's actions from theirs.
4. **One account only.** A company with several GitHub organizations can connect only one
   identity, and it has to belong to all of them.

## 2. Goals

1. **A workload identity.** Pepper acts as a GitHub App (`<app-name>[bot]`), installed by
   the customer on the organizations and repositories they choose, with fine-grained
   permissions and tokens that last one hour.
2. **Several installations per Pepper organization:** one per GitHub organization or account.
3. **Nothing breaks.** Existing OAuth connections keep working, unchanged, and nothing is
   migrated automatically. The App is opt-in and, where installed, takes precedence for the
   repositories it covers.
4. **Works for SaaS and on-prem:**
   - on sast.votal.ai, Votal registers one App that customers install;
   - on-prem, each customer registers their own App (Pepper documents the settings and
     provides an App manifest).
5. **Safe installation linking.** An installation can only be attached to a Pepper
   organization by someone who has access to that installation on GitHub.

**Non-goals for phase 1** (section 11):

- GitHub Enterprise Server: today's code is hard-wired to `api.github.com`;
- one-click App registration through the manifest flow;
- per-developer attribution of fix PRs;
- syncing GitHub repository permissions into Pepper's visibility.

## 3. How a GitHub App works here

| | OAuth today | GitHub App |
|---|---|---|
| Identity | a person | the App (`pepper[bot]`) |
| Scope | everything the person can access | the repositories selected at installation |
| Permissions | `repo`: full read and write | fine-grained, below |
| Token lifetime | no expiry | 1 hour, minted on demand, never stored |
| Survives people leaving | no | yes |
| Several GitHub organizations | one identity for all | one installation each |

**Permissions requested** (repository level):

| Permission | Level | Used for |
|---|---|---|
| Metadata | read | required by GitHub |
| Contents | read and write | clone (read); push the fix branch for AI fix PRs (write) |
| Pull requests | read and write | PR summary and inline comments, opening fix PRs, PR diffs |
| Commit statuses | read and write | pending and result status on commits |

**Webhook events:** `push`, `pull_request`, `installation`, `installation_repositories`.

An on-prem customer who wants no write access at all can register their App with Contents
**read**. Fix PRs then fail with a clear message, and everything else works.

## 4. Configuration (environment)

| Variable | |
|---|---|
| `GITHUB_APP_ID` | numeric App id |
| `GITHUB_APP_SLUG` | the App's URL name, used to build the install link |
| `GITHUB_APP_PRIVATE_KEY` | PEM, or base64 of the PEM; never logged |
| `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` | the App's OAuth credentials, used only to verify who is installing (section 5) |
| `GITHUB_APP_WEBHOOK_SECRET` | the App's webhook secret |

The App is "configured" when the id, slug, private key, client id and client secret are all
set. Otherwise the UI shows only the existing OAuth connection, exactly as today.

In the App's settings on GitHub:

- **Callback URL:** `<pepper>/api/integrations/github/app/setup`, with "Request user
  authorization (OAuth) during installation" enabled. With that option on, GitHub sends the
  user to the Callback URL after installing, not to a Setup URL;
- **Webhook URL:** `<pepper>/api/webhooks/github`.

## 5. Installing and linking (security-critical)

1. An Admin or Security user clicks **Install GitHub App**. Pepper creates the same signed,
   expiring state it uses for OAuth (organization, user and return path in an HMAC cookie)
   and redirects to `https://github.com/apps/<slug>/installations/new?state=…`.
2. The user chooses an account and repositories on GitHub.
3. GitHub redirects to the callback URL with `installation_id`, `setup_action`, `code`
   and `state`. `setup_action=request` means an owner must approve it first, so Pepper
   explains that and links nothing.
4. Pepper:
   1. verifies `state` (signature, expiry, a dedicated cookie, and that it belongs to the
      signed-in user and organization, who must still be Admin or Security);
   2. exchanges `code` for a user token (App client id and secret);
   3. **calls `GET /user/installations` with that token and requires `installation_id` to be
      in the list.** This proves the person who installed can access this installation. The
      user token is then discarded.
   4. fetches the installation with the App JWT (`GET /app/installations/{id}`) for its
      account login and type, and whether it is suspended;
   5. stores the link.

Without step 4.3, anyone could attach another company's installation to their own Pepper
organization by editing `installation_id` in the URL, and read its code. The check is
mandatory: the endpoint refuses to link when the App's OAuth credentials are missing.

**Rules for linking:**

- An installation can belong to only one Pepper organization (`installationId` is unique).
- Linking one already linked elsewhere is refused, and the audit log records the attempt.
- Removing it in Pepper unlinks it. Uninstalling on GitHub is caught by the `installation`
  webhook.

Audit log actions: `github_app.installed`, `github_app.removed`, `github_app.link_refused`.

## 6. Data model

```prisma
model OrgGithubAppInstallation {
  id             String    @id @default(cuid())
  organizationId String
  installationId BigInt    @unique
  accountLogin   String    // GitHub org or user login (the repositories' owner)
  accountType    String    // "Organization" | "User"
  repositorySelection String  // "all" | "selected"
  suspendedAt    DateTime?
  createdBy      String?
  createdAt      DateTime  @default(now())
  updatedAt      DateTime  @updatedAt
  organization   Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)
  @@index([organizationId])
}
```

The migration is additive: one new table, no change to existing tables. **No token is
stored.** Installation tokens are minted from the private key when needed and cached in
memory until 5 minutes before they expire.

## 7. Choosing a token

A new `resolveGithubToken(organizationId, repo?)`, where `repo` is `{ owner, name }` or
null, decides which credential to use:

1. The App is configured and the organization has a non-suspended installation whose
   `accountLogin` equals `repo.owner` (case-insensitive): **use that installation's token**.
2. Otherwise, the organization has an OAuth connection: **use the OAuth token** (today's
   behaviour).
3. Otherwise, there is no `repo` and exactly one installation (listing calls): use that
   installation.
4. Otherwise: no token, which every caller already handles.

It returns `{ token, source: "app" | "oauth", installationId? }`.

`getOrgGithubAccessToken(organizationId, repo?)` keeps its signature (with `repo` added as an
optional parameter) and delegates to it. A caller that doesn't pass `repo` behaves exactly as
today when an OAuth connection exists.

| Call site | Change |
|---|---|
| Worker clone (`scan-processor`, `useOrgGithubToken`) | pass owner and name parsed from the repository URL |
| `scan-create` (decides OAuth clone) | "has GitHub access for this repository", from the resolver |
| PR comments and status (`github-pr-comment`) | pass `githubOwner`/`githubRepoName` |
| Incremental PR diff (`incremental-scan-files`) | pass the project's owner and name |
| AI fix PR (`open-pr` route, `resolveGithubPrTokenForOrg`, `remediation/repo-target`) | pass the repository; the source becomes `github_app` or `github_oauth` |
| Connect a repository by URL (`connect-manual-github-repository`) | pass the parsed owner and name |
| Branches (`/api/integrations/github/branches`) | pass owner and name |
| List repositories (`/repositories`, `connect-github-repositories`) | union of the OAuth user's repositories (`/user/repos`, as today) and each installation's repositories (`/installation/repositories`), deduplicated by GitHub id; each item says `via: "app" \| "oauth"` |
| `getOrgGithubAccessTokenOrThrow` | validates OAuth tokens with `GET /user` as today. App tokens are freshly minted and not validated that way (installation tokens can't call `/user`). It **never deletes the OAuth connection because an App token failed** |
| Disconnect GitHub (`DELETE /api/integrations/github`) | unchanged: OAuth only. Installations are removed separately |

## 8. Webhooks

- `/api/webhooks/github` keeps accepting deliveries signed with an organization's webhook
  secret, as today.
- It also accepts deliveries signed with `GITHUB_APP_WEBHOOK_SECRET` when the payload carries
  `installation.id`. The organization is then the installation's organization: the
  repository is looked up only within that organization, never across all of them.
- **Installation lifecycle:**
  - `installation` `deleted` unlinks the installation;
  - `suspend` and `unsuspend` set and clear `suspendedAt`;
  - `new_permissions_accepted` is logged.
- `installation_repositories` needs no stored state, because repositories are listed live.
- `push` and `pull_request` events from the App trigger the same scans as repository
  webhooks do today. With the App installed, customers no longer have to add a webhook per
  repository.
- Clone URLs still come from the project's stored `repoUrl`, never from the payload.

## 9. UI (Settings → Integrations → GitHub)

- When the App is configured, a **GitHub App (recommended)** block shows:
  - the linked installations (account, all or selected repositories, suspended), each with
    **Configure on GitHub** (repository selection) and **Remove**;
  - **Install GitHub App** to add another organization.
- The existing OAuth block becomes **Personal connection (legacy)**, unchanged in function.
  When both exist, a note says: "Repositories covered by the GitHub App use it; others use
  `<login>`'s connection. Disconnect the personal connection once every repository is
  covered."
- The repository picker shows which credential each repository uses.

## 10. Compatibility: will it break existing setups?

| Setup | After this change |
|---|---|
| OAuth connected, App not configured (every customer today) | **Identical.** The resolver returns the OAuth token everywhere, and the UI is the same apart from the "legacy" label (which appears only when the App is configured) |
| OAuth connected, App configured but not installed | Identical, plus an **Install GitHub App** button |
| OAuth and App, App covers some owners | Those owners' repositories use the App; the others keep OAuth |
| App only | Everything works through the App for covered owners. Repositories of other owners have no token: the same "connect GitHub" errors as today |
| App uninstalled on GitHub | The webhook unlinks it, and those repositories fall back to OAuth if it exists |
| On-prem upgrade | The migration adds one table. Without the `GITHUB_APP_*` settings nothing changes |

Repository webhooks set up with per-organization secrets keep working.

## 11. Phases

1. **This change:** environment-configured App, the secure installation flow, the resolver
   and all call sites, App webhooks, the UI, the migration and the docs (an App manifest
   JSON and on-prem setup steps in `docs/`).
2. **One-click registration** for on-prem admins with GitHub's App manifest flow.
   **GitHub Enterprise Server** (`GITHUB_API_URL`, together with the existing OAuth code).
3. **Developer-attributed fix PRs** through user-to-server tokens, opt-in per user, and
   **repository visibility** in Pepper mirrored from GitHub permissions.

## 12. Testing

- **Unit:**
  - JWT signing (RS256 header, claims, clock skew);
  - the installation token cache (reuse, refresh 5 minutes before expiry, a 401 or 404
    marks the installation suspended or removed);
  - the resolver: owner match, case-insensitivity, suspended installations skipped, OAuth
    fallback, the single-installation listing case, no token.
- **Routes:**
  - install redirect (role, state);
  - setup callback: bad or expired state; code exchange failure; **installation not in
    `/user/installations` is refused**; installation already linked to another
    organization is refused and audited; success creates the link;
  - remove;
  - webhooks: App signature, installation lifecycle events, a push from an installation
    scans only within its organization.
- **Regression:** the existing GitHub tests pass unchanged, and a run with no `GITHUB_APP_*`
  variables behaves exactly as before (OAuth everywhere).
