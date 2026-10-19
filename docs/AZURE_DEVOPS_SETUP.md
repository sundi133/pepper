# Azure DevOps: workload identity and pull-request reviews

Design: `docs/PR_REVIEW_PROVIDERS_SPEC.md` §1.

## 1. Connect with a service principal (Azure DevOps Services)

A service principal is an identity for Pepper, not a person: it keeps working when people
leave, and its tokens last an hour.

1. In **Entra ID → App registrations → New registration**, create an app, for example
   `Pepper SAST`. No redirect URI is needed.
2. Under **Certificates & secrets → New client secret**, note the value. Also note the
   **Application (client) ID** and the **Directory (tenant) ID**.
3. In **Azure DevOps → Organization settings → Users → Add users**, add the app by name with
   **Basic** access, to the projects Pepper should scan.
4. Give it access to the repositories, at the project or repository level (**Project
   settings → Repositories → Security**):
   - **Read**;
   - **Contribute** (for AI fix branches);
   - **Contribute to pull requests** (for comments and statuses).
5. In Pepper, go to **Settings → Integrations → Azure DevOps → Connect**. Choose **Service
   principal (Entra ID)** and enter the organization, tenant ID, client ID and secret. Pepper
   gets a token, checks it, and shows "Connected as … (service principal)".

For **Azure DevOps Server** (on-prem) there are no service principals. Create a dedicated
service account, give it the same permissions, and connect with **its** PAT (scopes: Code
read & write, Pull Request Threads read & write, Project and Team read).

## 2. One service hook per project

In **Project settings → Service hooks → Create subscription → Web Hooks**, add one
subscription per event:

- **Code pushed**;
- **Pull request created**;
- **Pull request updated**;
- **Pull request commented on** (for `@pepper` commands).

For each subscription:

- **Repository:** leave it empty (all repositories).
- **URL:** `https://<pepper>/api/webhooks/azure-devops`.
- **Basic authentication:** username empty, password = **Azure DevOps basic auth password**
  from Pepper's Webhook secrets card.

Repositories appear in Pepper on their first pull request or push.

## 3. What happens on a pull request

- **When it's reviewed:**
  - when it's created;
  - when new commits arrive (updates that don't change the code, such as votes or title
    edits, don't rescan);
  - when a draft is published, if drafts are skipped.
- **Status and feedback:** a `pending` status while queued, then the summary thread, inline
  threads and a `succeeded` or `failed` status.
- **Commands** in any PR comment: `@pepper review`, `full review`, `pause`, `resume`, `help`,
  and `@pepper fix` in one of Pepper's inline threads (a fix PR into the PR's branch).
- **`.pepper.yaml`** on the target branch configures it. The format is the same as on GitHub
  (`docs/GITHUB_APP_SETUP.md`).
