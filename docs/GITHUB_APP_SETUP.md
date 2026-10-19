# Set up the Pepper GitHub App

Connect GitHub as a **GitHub App** instead of one person's account: Pepper acts as
`<your-app>[bot]` on the organizations and repositories you choose, with fine-grained
permissions and one-hour tokens. Design: `docs/GITHUB_APP_SPEC.md`.

- **sast.votal.ai:** the App is already registered. An Admin or Security user opens
  **Settings → Integrations → GitHub → Install GitHub App**.
- **On-prem:** register your own App once (below), add five settings to `.env`, and restart.

Existing OAuth ("personal") connections keep working. Where both exist, repositories owned
by an account with the App installed use the App, and the rest use the personal connection.

## 1. Register the App (on-prem, once)

On GitHub, go to your organization's **Settings → Developer settings → GitHub Apps → New
GitHub App**, and fill in:

| Field | Value |
|---|---|
| GitHub App name | for example `Pepper SAST (yourcompany)` |
| Homepage URL | your Pepper URL, for example `https://pepper.yourcompany.com` |
| Callback URL | `https://pepper.yourcompany.com/api/integrations/github/app/setup` |
| Request user authorization (OAuth) during installation | **checked** (Pepper uses it to check who is installing) |
| Webhook: Active | checked |
| Webhook URL | `https://pepper.yourcompany.com/api/webhooks/github` |
| Webhook secret | a long random value (for example `openssl rand -hex 32`) |

**Repository permissions:**

| Permission | Access |
|---|---|
| Contents | Read and write (Read-only turns off AI fix pull requests) |
| Pull requests | Read and write |
| Commit statuses | Read and write |
| Metadata | Read (set automatically) |

- **Subscribe to events:** Push, Pull request.
- **Where can this GitHub App be installed?** "Only on this account" is enough for one
  GitHub organization. Choose "Any account" if Pepper should be installed on several.

After creating it:

1. Note the **App ID**, the **Client ID** and the App's URL name, its **slug** (the last
   part of `https://github.com/apps/<slug>`).
2. **Generate a client secret.**
3. **Generate a private key** (a `.pem` file).

## 2. Configure Pepper

Add to `.env` on the Pepper server, then restart the API and the worker:

```bash
GITHUB_APP_ID="123456"
GITHUB_APP_SLUG="pepper-sast-yourcompany"
GITHUB_APP_CLIENT_ID="Iv23li..."
GITHUB_APP_CLIENT_SECRET="..."
GITHUB_APP_WEBHOOK_SECRET="..."              # the webhook secret from step 1
# The private key: the PEM on one line with \n, or base64 of the file:
#   base64 -i pepper-app.private-key.pem | tr -d '\n'
GITHUB_APP_PRIVATE_KEY="LS0tLS1CRUdJTi..."
```

Keep the private key and client secret secret: they let Pepper act as the App. Pepper never
logs them and never stores installation tokens.

## 3. Install it

In Pepper, an Admin or Security user goes to **Settings → Integrations → GitHub → Install
GitHub App**:

1. Choose the GitHub organization and the repositories (all, or selected).
2. GitHub asks you to authorize the App. Pepper uses this once, to confirm your account
   can see the installation. That way, nobody can link someone else's installation.
3. You return to Pepper, and the installation is listed.

Repeat **Install on another organization** for each GitHub organization.
**Configure on GitHub** changes which repositories are included. Unlinking in Pepper keeps
the App installed on GitHub; uninstall it there to revoke access. Uninstalling on GitHub
also unlinks it in Pepper.

With the App installed you no longer need a webhook per repository: push and pull request
events arrive through the App.

## 4. Move off the personal connection

1. Install the App on every GitHub organization whose repositories Pepper scans.
2. On **Settings → Integrations**, check that the repository picker shows "App" for your
   repositories.
3. Click **Disconnect GitHub** on the "Personal connection (legacy)".
4. Scans, PR comments and fix PRs now run as the App.

## Troubleshooting

| Message | Fix |
|---|---|
| "Start the installation from Pepper" | Install from Pepper's Integrations page, not from GitHub's App page (Pepper must issue the state) |
| "Your GitHub account can't access that installation" | Sign in to GitHub as a member who can see the installation (an organization owner) |
| "GitHub did not return an installation" | Turn on **Request user authorization (OAuth) during installation**, and check that the Callback URL is Pepper's `/api/integrations/github/app/setup` |
| "The installation was requested" | An organization owner must approve the request on GitHub; then install from Pepper again |
| "already linked to another Pepper organization" | Unlink it in the other Pepper organization first |
| The App block is missing in Pepper | A `GITHUB_APP_*` setting is missing or the private key is invalid (see the API log) |
