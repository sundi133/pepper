# Bitbucket Cloud: access tokens and pull-request reviews

Design: `docs/PR_REVIEW_PROVIDERS_SPEC.md` §3.

> **App passwords no longer work.** Atlassian removed them on July 28, 2026. A Pepper
> connection made with an app password fails until you reconnect with a token.

## 1. Connect with an access token

An access token belongs to a workspace, project or repository, not to a person. It keeps
working when people leave.

1. Create the token:
   - **Workspace settings → Access tokens** (Bitbucket Premium) covers every repository.
   - Otherwise use **Project settings → Access tokens**, or **Repository settings → Access
     tokens**.
2. Give it these permissions:
   - **Repositories:** Read and Write (Write for AI fix branches);
   - **Pull requests:** Read and Write;
   - optionally **Admin**, so Pepper can check fork authors' and commenters' permissions.
3. In Pepper, go to **Settings → Integrations → Bitbucket Cloud → Connect Bitbucket**. Choose
   **Access token** and paste the token and the workspace slug. Pepper checks it against the
   workspace's repositories.

An Atlassian **API token** (Atlassian account → Security → API tokens, with Bitbucket
repository and pull-request scopes) also works. It belongs to a person, though.

Tokens are only ever sent to `bitbucket.org`.

## 2. One workspace webhook

In **Workspace settings → Webhooks → Add webhook** (or per repository, under Repository
settings → Webhooks):

- **URL:** `https://<pepper>/api/webhooks/bitbucket`.
- **Secret:** **Bitbucket webhook secret** from Pepper's Webhook secrets card.
- **Triggers:**
  - **Repository push**;
  - **Pull request created**;
  - **Pull request updated**;
  - **Pull request comment created** (for `@pepper` commands).

With your organization's secret, repositories appear in Pepper on their first pull request
or push.

## 3. What happens on a pull request

- **When it's reviewed:**
  - when it's created;
  - when new commits arrive (edits to the title, description or reviewers don't rescan);
  - when a draft is published, if drafts are skipped.
- **Forks:** Bitbucket has no pull-request refs, so Pepper clones the fork. The token must be
  able to read it. With `forks: collaborators` (the default), the author needs a verified
  Write permission (which needs Admin on the token); otherwise someone with write access
  comments `@pepper review`.
- **Status:** `INPROGRESS` while queued, then the summary comment, inline comments and a
  `SUCCESSFUL` or `FAILED` build status. Build statuses need `NEXTAUTH_URL` for their link.
- **Commands:** `@pepper review`, `full review`, `pause`, `resume`, `help`, and `@pepper fix`
  in reply to a Pepper inline comment.
  - People with write access can run them.
  - When the token can't check permissions, anyone who can comment on a private repository
    can run them, but no one on a public one.
- **`.pepper.yaml`** on the destination branch configures it. The format is the same as on
  GitHub (`docs/GITHUB_APP_SETUP.md`).
