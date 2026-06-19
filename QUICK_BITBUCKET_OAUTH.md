# Quick: Enable Bitbucket OAuth in 5 Minutes

## Problem
You're seeing a credential form instead of being redirected to Bitbucket OAuth.

## Solution
Your admin needs to set 2 environment variables.

## For Admins

### 1. Create Bitbucket OAuth Consumer (3 minutes)

Go to your **Bitbucket Workspace**:

1. Click **Workspace settings** → **OAuth consumers**
2. Click **Create new application**
3. Fill in:
   - **Name**: `Pepper`
   - **Callback URL**: `https://your-pepper-domain.com/api/integrations/bitbucket/callback`
     - Replace `your-pepper-domain.com` with your actual Pepper domain
   - **Permissions**: Check these boxes:
     - ☑ `account` - Read your account information
     - ☑ `repository` - Read and modify repositories
     - ☑ `pullrequest:read` - Read pull requests

4. Click **Save**
5. You'll see **Client ID** and **Client secret**

### 2. Set Environment Variables (2 minutes)

Add to your Pepper environment (`.env`, Docker, Kubernetes, etc.):

```bash
BITBUCKET_OAUTH_CLIENT_ID=your-client-id-here
BITBUCKET_OAUTH_CLIENT_SECRET=your-client-secret-here
```

Examples:
- **Docker**: Add to `.env` file and restart: `docker compose restart`
- **Kubernetes**: Update secret and restart: `kubectl rollout restart deployment/pepper`
- **Manual**: Update `.env` and restart your service

### 3. Restart Pepper

Restart your application for changes to take effect.

### 4. Test It

1. Go to **Settings → Integrations**
2. Click **Connect Bitbucket**
3. You should now be redirected to Bitbucket to authorize

✅ **If redirected to Bitbucket** = OAuth is working!
❌ **If you still see a form** = Check that:
   - Environment variables are set (no typos)
   - Pepper was restarted
   - Values don't have extra spaces

## Why This Matters

With OAuth:
- ✅ No password sharing
- ✅ Automatic token refresh
- ✅ Better security
- ✅ One-click setup for users

Without OAuth:
- Users must create and share app passwords
- Passwords expire manually
- Less secure

## Need Help?

See `BITBUCKET_OAUTH_SETUP.md` for detailed troubleshooting.
