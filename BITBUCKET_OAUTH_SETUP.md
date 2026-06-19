# Bitbucket OAuth Setup Guide

## Overview

Bitbucket integration supports both OAuth (recommended) and app passwords. OAuth provides a better user experience and is more secure.

## For End Users

### I'm seeing a form asking for credentials, not OAuth!

This means **OAuth is not configured** on your Pepper server.

**You have two options:**

1. **Ask your admin to set up OAuth** (recommended)
   - Takes 5 minutes
   - Better security
   - No password sharing
   - Automatic token refresh

2. **Use app password as fallback** (temporary)
   - Works immediately
   - Create in Bitbucket account settings
   - Less secure (password shared)
   - Expires manually

## For Administrators

### Step 1: Create Bitbucket OAuth Consumer

1. **Log in to Bitbucket** as an admin
2. Go to **Workspace settings** → **OAuth consumers**
3. Click **Create new application**
4. Fill in the form:
   - **Name**: `Pepper` (or your app name)
   - **Callback URL**: `https://your-pepper-domain.com/api/integrations/bitbucket/callback`
   - **Permissions** → Check these:
     - ✓ `account` - Read your account information
     - ✓ `repository` - Read and modify your repositories  
     - ✓ `pullrequest:read` - Read pull requests

5. Click **Save**

6. You'll see **Client ID** and **Client secret**
   - **Copy both values** (you'll need them in step 2)

### Step 2: Set Environment Variables

Add these to your Pepper environment (`.env` or deployment config):

```bash
BITBUCKET_OAUTH_CLIENT_ID=<paste-client-id-here>
BITBUCKET_OAUTH_CLIENT_SECRET=<paste-client-secret-here>
```

**Alternative names** (for backwards compatibility):
```bash
BITBUCKET_ID=<client-id>
BITBUCKET_SECRET=<client-secret>
```

### Step 3: Restart Pepper

Restart your Pepper application for the environment variables to take effect.

```bash
# Docker example
docker compose restart

# Kubernetes example
kubectl rollout restart deployment/pepper

# Manual deployment
systemctl restart pepper
```

### Step 4: Verify OAuth is Working

1. Open Pepper and go to **Settings → Integrations**
2. Find **Bitbucket Cloud**
3. Click **Connect**
4. You should be redirected to Bitbucket to authorize
   - ✓ OAuth is configured correctly
5. If you see a form instead
   - ✗ Environment variables not set or Pepper not restarted

## How It Works

### OAuth Flow (When Configured)

```
User clicks "Connect Bitbucket"
         ↓
Pepper redirects to Bitbucket
         ↓
User authorizes Pepper
         ↓
Bitbucket redirects back with auth code
         ↓
Pepper exchanges code for access token
         ↓
Pepper stores encrypted token in database
         ↓
User can import repos and scan PRs
```

### App Password Flow (Fallback)

```
User clicks "Connect Bitbucket"
         ↓
Form appears asking for credentials
         ↓
User creates app password in Bitbucket
         ↓
User enters username + app password
         ↓
Pepper stores encrypted credentials
         ↓
User can import repos and scan PRs
```

## Security Comparison

| Aspect | OAuth | App Password |
|--------|-------|--------------|
| **Password Shared** | No | Yes (with Pepper) |
| **Token Refresh** | Automatic | Manual |
| **Revocation** | Easy (Bitbucket settings) | Manual delete |
| **Scopes** | Selected by user | Pre-defined |
| **User Experience** | One-click auth | Manual entry |
| **Expiration** | Server-managed | User-managed |

## Troubleshooting

### Users still see the credential form

**Check:**
- [ ] Environment variables are set with correct values
- [ ] Pepper was restarted after setting environment variables
- [ ] No typos in variable names (case-sensitive)
- [ ] Values don't have extra spaces or quotes

**To verify:**
```bash
# Check if variables are set (Linux/Mac)
echo $BITBUCKET_OAUTH_CLIENT_ID

# Check in Docker
docker exec <container-name> printenv | grep BITBUCKET
```

### OAuth redirect fails

**Check:**
- [ ] Callback URL in Bitbucket OAuth consumer matches exactly:
  - Should be: `https://your-pepper-domain.com/api/integrations/bitbucket/callback`
  - Check for trailing slashes, protocol (https), domain spelling
  
**To fix:**
1. Go to Bitbucket → Workspace settings → OAuth consumers
2. Edit the Pepper consumer
3. Update "Callback URL" to match exactly
4. Save

### "This app doesn't have permission to..."

**Cause:** Permissions not checked during setup

**To fix:**
1. Go to Bitbucket → Workspace settings → OAuth consumers
2. Edit the Pepper consumer
3. Make sure these are checked:
   - ✓ `account`
   - ✓ `repository`
   - ✓ `pullrequest:read`
4. Save and have users reconnect

## Disabling OAuth (Fallback to App Password)

If you need to disable OAuth temporarily:

1. Comment out the environment variables:
   ```bash
   # BITBUCKET_OAUTH_CLIENT_ID=xxx
   # BITBUCKET_OAUTH_CLIENT_SECRET=xxx
   ```

2. Restart Pepper

3. Users will see the app password form instead

## Migrating from App Password to OAuth

Existing users with app passwords can:

1. Go to **Settings → Integrations**
2. Click **Disconnect**
3. Click **Connect Bitbucket** (will use OAuth this time)

Their old app password remains valid in Bitbucket until manually revoked.

## Revoking Bitbucket Access

**To revoke all Pepper access:**

1. Go to Bitbucket → **Personal settings** → **Authorized applications**
2. Find "Pepper"
3. Click **Revoke**

This immediately disconnects Pepper from all Bitbucket repositories.

## Next Steps

- [See Bitbucket integration documentation](./INTEGRATION_SETUP.md#bitbucket-cloud)
- [See main README](./README.md) for other integrations
