# Pull-request security review that works like CodeRabbit

Status: implemented (phase 1). Builds on the GitHub App (`docs/GITHUB_APP_SPEC.md`, #159). Owner: Pepper
integrations.

## 1. Goal

Install the Pepper GitHub App, and every pull request in the selected repositories gets a
security review with no other setup. Developers talk to it in the pull request, and teams
tune it with a file in the repository. The same experience as CodeRabbit, for security
findings.

| CodeRabbit | Pepper today | Pepper after this change |
|---|---|---|
| Install the App, done | Import repositories, add a webhook and secret per repository | Install the App, done: repositories are onboarded on their first pull request or push |
| Reviews every PR, every push | Incremental scan on PR opened or synchronize (once the repository is imported) | Same, plus reopened; drafts and bot PRs can be skipped in `.pepper.yaml` (reviewed by default, as today) |
| Summary comment and inline comments | Summary comment, inline comments on changed lines (max 30), commit status | Same, plus a "reply `@pepper fix`" hint on inline comments for repositories served by the App |
| `@coderabbitai review`, `full review`, `pause`, `resume`, `help` | none | `@pepper review`, `full review`, `pause`, `resume`, `fix`, `help` |
| `.coderabbit.yaml` | none | `.pepper.yaml` |
| No personal tokens | personal OAuth token or pasted PAT | the App only; personal connections can be turned off per organization |

## 2. Zero-setup onboarding

A `pull_request` or `push` event arrives through the App (`docs/GITHUB_APP_SPEC.md` §8)
for a repository with no Pepper project yet. Pepper then:

1. creates the project in the installation's linked organization (owner, name, GitHub
   repository id, clone URL, default branch from the payload; `connectedViaGithub`);
2. handles the event as for any project: the PR scan, or the default-branch scan on push.

No baseline scan is queued when the App is installed, which keeps AI cost under the
customer's control. The first pull request is the first scan. Repositories removed from the
installation keep their history; they just stop receiving events.

The payload is trusted only for the repository's identity, and only because the delivery is
signed with the App's secret and the installation is linked. The clone URL is built from
the owner and name (`https://github.com/<owner>/<repo>.git`), never taken from the payload.

## 3. When a pull request is reviewed

| Event | Action |
|---|---|
| `pull_request` `opened`, `reopened`, `ready_for_review` | incremental scan of the head commit |
| `pull_request` `synchronize` (new commits) | incremental scan of the new head (the previous one is superseded) |
| Draft PR | reviewed (as today); with `reviews.drafts: false`, skipped and reviewed when marked ready. With drafts reviewed, "ready for review" doesn't rescan the unchanged commit |
| Author is a bot (`[bot]` login, Dependabot, Renovate) | reviewed (as today: dependency bumps matter); skipped with `reviews.bots: false` |
| Base branch not in `reviews.base_branches` (default: the default branch and `*`) | skipped |
| PR paused (`@pepper pause`) | skipped until `@pepper resume` |
| `reviews.auto: false` in `.pepper.yaml` | only on `@pepper review` |

When a scan is skipped, the commit status says why ("Pepper: skipped, draft"). Deliberate
skips (draft, bot, paused, settings) post `success`, so a required check doesn't hang. A fork
PR from an outside contributor gets **`pending`**, so a required check keeps blocking until a
collaborator comments `@pepper review`.

**Concurrent pull requests.** Today a new webhook scan cancels **every** active scan of the
repository: PR B's review cancels PR A's, and a push to the default branch cancels all of
them. From now on, a new scan replaces only the active scan for the **same PR** (for PR
scans) or the **same branch outside any PR** (for push scans). Scans of other PRs and
branches continue. Manual scans and rescans keep today's behaviour (`docs/` scan history).

**Fork PRs.** Their head branch doesn't exist in the base repository. They are reviewed by
cloning `refs/pull/<n>/head`. `@pepper fix` refuses them, because a fix branch can't be
pushed to a fork.

## 4. Conversation (`issue_comment` and `pull_request_review_comment`)

Commands are recognized when a comment starts with `@pepper` or `@<app-slug>`, are
case-insensitive, and take the first line only.

| Command | Effect |
|---|---|
| `@pepper review` | incremental scan of the PR's current head |
| `@pepper full review` | full scan (all scanners, all files) of the PR's head branch |
| `@pepper pause` / `@pepper resume` | stop or restart automatic reviews of this PR |
| `@pepper fix` (in reply to a Pepper inline comment) | opens an AI fix pull request for that finding against the PR's branch (the existing agentic fix flow) |
| `@pepper help` | lists the commands |

**Who may run commands:** the comment's `author_association` must be `OWNER`, `MEMBER` or
`COLLABORATOR`. Bots, including Pepper itself, are ignored. Anyone else gets a short "only
repository collaborators can run Pepper commands" reply, once per PR.

**Acknowledgement:** an 👀 reaction on the command comment. `help`, `pause`, `resume` and
refusals also get a reply.

Triage decisions (false positive, accepted risk) stay in Pepper: they need the Security
role, and a PR comment author can't be mapped to a Pepper user safely yet.

## 5. `.pepper.yaml`

Read from the PR's **base** branch, so a PR can't switch its own review off. It falls back to
the default branch, and to the defaults if the file is absent or invalid. An invalid file
produces one PR comment saying what's wrong; it never blocks the review.

```yaml
reviews:
  auto: true                 # review every PR automatically
  drafts: true               # false: skip drafts, review when marked ready
  bots: true                 # false: skip Dependabot/Renovate/[bot] PRs
  forks: collaborators       # collaborators | all | none
  base_branches: ["*"]       # glob patterns; default: every base branch
  scan: incremental          # incremental | full
comments:
  summary: true
  inline: true
  inline_min_severity: INFO     # INFO | LOW | MEDIUM | HIGH | CRITICAL (MEDIUM recommended)
  max_inline: 30
paths:
  exclude: ["docs/**", "**/*.md", "test/fixtures/**"]
```

Unknown keys are ignored. Values are validated (zod), and `max_inline` is capped at 50.
`paths.exclude` also removes files from the scan, not just from the comments.

## 6. No personal tokens

1. **Organization policy:** a new setting under Settings → Integrations, "Allow personal
   GitHub connections" (`OrgSettings.allowPersonalGithub`, default true). When it is off:
   - "Connect GitHub" is hidden and its endpoint refuses;
   - the resolver ignores an existing personal connection, so only the App is used;
   - pasting a token on New Scan is refused for github.com URLs covered by the App.
   An Admin or Security user changes it, and the change is audited.
2. **Pasted tokens are no longer kept in Redis:**
   - the token goes into the job only encrypted (`repoTokenEnc`, the same encryption as
     stored integration tokens);
   - the worker decrypts it at clone time;
   - the credentialed URL is no longer stored in job data. Completed jobs, kept for history,
     contain no usable secret.
3. **Unused settings removed:** `GITHUB_PR_TOKEN` and `GITHUB_TOKEN` disappear from
   `.env.example`. No code reads them.

## 7. App changes

- **Events:** add `issue_comment` and `pull_request_review_comment` (both covered by the
  existing Pull requests permission for PR comments), and keep `push` and `pull_request`.
- **Permissions:** unchanged. Contents read is used for `.pepper.yaml`, and Pull requests
  write for replies and reactions.
- `docs/GITHUB_APP_SETUP.md` gets the new events.

## 8. Data

- `PrReviewState` (new, additive): `projectId`, `prNumber`, `paused`, `pausedBy`, `updatedAt`;
  unique on (`projectId`, `prNumber`).
- `OrgSettings.allowPersonalGithub Boolean @default(true)` (additive column).
- The job gains `repoTokenEnc?: string` and `pathExcludes?: string[]`. The credentialed
  `repoUrl` from a pasted token is no longer set.

## 9. Compatibility

- **Repository webhooks with organization secrets, and projects imported through OAuth:**
  unchanged, including PR scans on opened and synchronize. The draft, bot, base-branch,
  pause and config rules apply to them too, since they are part of reviewing a PR. With no
  `.pepper.yaml` the defaults reproduce today's behaviour: drafts and bot PRs are reviewed
  exactly as before.
- **Commands, onboarding and the config file** need the App's events. Without the App,
  nothing new happens.
- **Pasted tokens** keep working; they are only stored differently in the job.
- **Deploy order:** a worker older than this change can't decrypt `repoTokenEnc` and
  `svnPasswordEnc`, so a pasted-token clone or an SVN checkout queued by a new API would run
  without its credential. Docker Compose upgrades both images together. On Railway, **deploy
  the worker before the API**.
- **`allowPersonalGithub`** defaults to true, so nothing changes until an admin turns it off.

## 10. Testing

- **Unit:**
  - command parsing: prefixes, slug mention, case, first line only, unknown commands;
  - authorization by `author_association`, and bots ignored;
  - `.pepper.yaml`: defaults, valid, invalid with an error message, globs, caps;
  - the review decision table (§3);
  - onboarding: a new project from the payload, the clone URL from owner and name (never
    the payload), an existing project reused.
- **Routes:** webhook flows for opened, draft, ready_for_review, bot PR, paused PR, and each
  command; refusal for non-collaborators; App-only.
- **Policy:**
  - personal connection refused or ignored when the setting is off;
  - the resolver uses only the App;
  - a pasted token is encrypted in the job and never present in its stored data.
- **Regression:** the existing webhook and PR comment tests pass, and the full suite.

## 11. Later

- Learning from dismissed findings (suppression suggestions in the PR).
- Mapping PR authors to Pepper users, for triage from the PR.
- Configuration inherited from the organization (org-level `.pepper.yaml` in a `.github`
  repository).
- The same experience for GitLab, Bitbucket and Azure DevOps through their webhooks.
