# GitLab: workload identity and merge-request reviews

Design: `docs/PR_REVIEW_PROVIDERS_SPEC.md` §2.

## 1. Connect with a group access token

A group (or project) access token belongs to a bot user of the group, not to a person: it
keeps working when people leave.

1. In the group: **Settings → Access tokens → Add new token**.
   - **Role:** Developer.
   - **Scopes:** `api`, `read_repository`, and `write_repository` (for AI fix branches).
   - **Expiry:** as your policy allows. Pepper warns 30 days before it expires.
2. In Pepper: **Settings → Integrations → GitLab → Connect GitLab**. Paste the token, and the
   host for self-managed GitLab. Pepper shows "Connected as group_…_bot (group or project
   access token, expires …)".

On GitLab Free, use one project access token per project, or a service account's token
(GitLab Premium). A personal access token still works, with a warning.

**Commit statuses:** the switch on the GitLab card posts `pepper/security` on each merge
request. A failed status blocks the merge when the project requires pipelines to succeed.
It is on by default for new connections and off for connections made before it existed.

## 2. One group webhook

In the group: **Settings → Webhooks → Add new webhook** (GitLab Premium; on Free, add the
same hook to each project):

- **URL:** `https://<pepper>/api/webhooks/gitlab`.
- **Secret token:** **GitLab webhook secret token** from Pepper's Webhook secrets card.
- **Triggers:**
  - **Push events**;
  - **Merge request events**;
  - **Comments** (for `@pepper` commands).

With your organization's secret, projects appear in Pepper on their first merge request or
push to the default branch. They are cloned from the connected host with the token.

## 3. What happens on a merge request

- **When it's reviewed:**
  - when it's opened or reopened;
  - when new commits are pushed (edits to the title, labels or assignees don't rescan);
  - when a draft is marked ready, if drafts are skipped.
- **Forks:** reviewed through `refs/merge-requests/<iid>/head` when the author has Developer
  access. Otherwise a Developer comments `@pepper review`.
- **Feedback:** a summary note and inline discussions, plus the commit status when that is on.
- **Commands** (Developer access or higher), in any merge-request comment:
  - `@pepper review`;
  - `full review`;
  - `pause`;
  - `resume`;
  - `help`;
  - `@pepper fix` in one of Pepper's inline discussions, which opens a fix merge request
    into the merge request's branch.
- **`.pepper.yaml`** on the target branch configures it. The format is the same as on GitHub
  (`docs/GITHUB_APP_SETUP.md`).
