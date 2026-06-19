# Integration Setup Guide

This guide explains how to set up OAuth and credentials for GitHub, Bitbucket, and Azure DevOps integrations in Pepper.

## GitHub

### Setup via OAuth (Recommended)

1. **Admin Configuration** (one-time setup):
   - Set up a GitHub OAuth app in your GitHub organization or personal account
   - Go to **Settings → Developer settings → OAuth Apps → New OAuth App**
   - Fill in:
     - **Application name**: Pepper
     - **Homepage URL**: `https://your-pepper-domain.com`
     - **Authorization callback URL**: `https://your-pepper-domain.com/api/integrations/github/callback`
   - Copy the **Client ID** and **Client Secret**
   - Set environment variables:
     ```bash
     GITHUB_OAUTH_CLIENT_ID=<your-client-id>
     GITHUB_OAUTH_CLIENT_SECRET=<your-client-secret>
     # OR use legacy names:
     GITHUB_ID=<your-client-id>
     GITHUB_SECRET=<your-client-secret>
     ```

2. **User Setup**:
   - Go to **Settings → Integrations**
   - Click **Connect GitHub**
   - You'll be redirected to GitHub to authorize
   - Select which repositories Pepper can access
   - Once authorized, you can import repositories and scan pull requests

3. **Features**:
   - Import repositories from your GitHub account
   - Automatic scanning of pull requests
   - Post review comments and status checks
   - Create AI-powered fix pull requests

---

## Bitbucket Cloud

### Setup via OAuth (Recommended) or App Password

Bitbucket supports both OAuth (recommended) and app passwords. Which one you use depends on whether your admin has configured Bitbucket OAuth.

**How to tell which method you'll use:**
- Go to **Settings → Integrations**
- Click **Connect Bitbucket**
  - If redirected to Bitbucket's authorization page → **OAuth is configured** (recommended)
  - If shown a form asking for credentials → **OAuth is not configured** (use app password as fallback)

#### Troubleshooting: "Why am I still seeing a credential form?"

**Reason:** OAuth is not configured on your server.

**Solution:** Your admin needs to:
1. Create a Bitbucket OAuth consumer
2. Set the `BITBUCKET_OAUTH_CLIENT_ID` and `BITBUCKET_OAUTH_CLIENT_SECRET` environment variables
3. Restart Pepper

Until then, you can use the app password method as a fallback.

#### Option 1: OAuth (Recommended)

**Admin Configuration** (one-time setup):
- Create a Bitbucket OAuth consumer in your workspace
- Go to **Workspace settings → OAuth consumers → Create new app**
- Fill in:
  - **Name**: Pepper
  - **Callback URL**: `https://your-pepper-domain.com/api/integrations/bitbucket/callback`
  - **Permissions**: Select:
    - `account` - Read your account information
    - `repository` - Read and modify your repositories
    - `pullrequest:read` - Read pull requests
- Copy the **Client ID** and **Client Secret**
- Set environment variables:
  ```bash
  BITBUCKET_OAUTH_CLIENT_ID=<your-client-id>
  BITBUCKET_OAUTH_CLIENT_SECRET=<your-client-secret>
  # OR use legacy names:
  BITBUCKET_ID=<your-client-id>
  BITBUCKET_SECRET=<your-client-secret>
  ```

**User Setup in Pepper**:
- Go to **Settings → Integrations**
- Find **Bitbucket Cloud** and click **Connect**
- You'll be redirected to Bitbucket to authorize
- Grant the required permissions
- Once authorized, you can import repositories and scan pull requests

#### Option 2: App Password (Fallback)

If OAuth is not configured, you can use app passwords:

1. **Get Your Bitbucket App Password**:
   - Go to **Bitbucket.org → Account Settings → Personal Bitbucket settings**
   - Click **App passwords** or go to `https://bitbucket.org/account/settings/app-passwords/new`
   - Click **Create app password**
   - Fill in:
     - **Label**: Pepper
     - **Permissions**: Select:
       - `repository:read`
       - `pullrequest:read`
       - `account:read`
   - Click **Create** and copy the generated password (you won't see it again)

2. **User Setup in Pepper**:
   - Go to **Settings → Integrations**
   - Find **Bitbucket Cloud** and click **Connect**
   - Fill in:
     - **Username**: Your Bitbucket username
     - **App Password**: The password you created above
     - **Workspace**: (Optional) Your Bitbucket workspace slug
   - Click **Connect**

3. **Import Repositories**:
   - Go to **Scans → New Scan**
   - Select **Bitbucket** as the source
   - Click **Refresh** to load your repositories
   - Select a repository and branch
   - Start scanning

4. **Features**:
   - Import repositories from Bitbucket Cloud
   - Scan pull requests
   - Post inline comments and build status updates
   - Works with personal and team workspaces

---

## Azure DevOps

### Setup with Personal Access Token (PAT)

Azure DevOps uses Personal Access Tokens for integration.

1. **Get Your Azure DevOps PAT**:
   - Go to **Azure DevOps** → Your organization
   - Click **User Settings** (top-right) → **Personal access tokens**
   - Click **+ New Token**
   - Fill in:
     - **Name**: Pepper
     - **Organization**: Select your organization
     - **Expiration**: Choose an appropriate duration (e.g., 1 year)
     - **Scopes**: Select:
       - `Code (read)` - Read source code
       - `Pull Request Threads (read & write)` - For PR reviews
   - Click **Create Token** and copy it (you won't see it again)

2. **User Setup in Pepper**:
   - Go to **Settings → Integrations**
   - Find **Azure DevOps** and click **Connect**
   - Fill in:
     - **Organization**: Your Azure DevOps organization name (the part after `dev.azure.com/`)
     - **PAT**: The token you created above
   - Click **Connect**

3. **Import Repositories**:
   - Go to **Scans → New Scan**
   - Select **Azure DevOps** as the source
   - Click **Refresh** to load your repositories
   - Select a repository and branch
   - Start scanning

4. **Features**:
   - Import repositories from Azure DevOps Services
   - Scan pull requests
   - Post review threads and status checks
   - Integrates with Azure Pipelines

---

## Comparison: OAuth vs App Passwords/PATs

| Feature | GitHub OAuth | Bitbucket OAuth | Bitbucket App Password | Azure DevOps PAT |
|---------|--------------|-----------------|----------------------|------------------|
| Setup Complexity | Medium (admin config) | Medium (admin config) | Low | Low |
| Token Refresh | Automatic | Automatic | Manual (when expires) | Manual (when expires) |
| Scopes | Selected per auth | Selected per auth | Created once | Selected per token |
| User Setup | OAuth flow | OAuth flow | Enter credentials | Enter credentials |
| Security | High (no password shared) | High (no password shared) | Medium (password shared) | Medium (token shared) |
| Recommended | Yes | Yes | Fallback only | N/A |

---

## Troubleshooting

### GitHub
- **OAuth not configured error**: Admin needs to set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET`
- **Callback URL mismatch**: Ensure the callback URL in GitHub OAuth app matches your Pepper domain

### Bitbucket
- **Invalid credentials**: Double-check username and app password
- **Repository not found**: Ensure you have access to the repository in Bitbucket
- **Workspace not loaded**: Leave workspace blank to access all workspaces you have access to

### Azure DevOps
- **Invalid PAT**: PAT may have expired or was revoked
- **Organization not found**: Use just the organization name, not the full URL
- **Insufficient permissions**: Ensure PAT has "Code (read)" scope enabled

---

## Security Best Practices

1. **Use dedicated credentials**: Create separate app passwords/PATs for Pepper
2. **Limit scopes**: Grant only the minimum permissions needed
3. **Rotate credentials**: Periodically rotate app passwords and PATs
4. **Monitor access**: Check integration activity in your VCS provider's logs
5. **Environment variables**: For admin setup, use environment variables, not hardcoded values

---

## Disconnecting Integrations

To disconnect an integration:

1. Go to **Settings → Integrations**
2. Find the integration and click **Disconnect**
3. Confirm the action

This will immediately revoke Pepper's access and stop any automated scanning.
