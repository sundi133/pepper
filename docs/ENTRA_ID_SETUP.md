# Microsoft Entra ID sign-in (on-prem Pepper)

Pepper can sign users in with **Microsoft Entra ID** (formerly Azure AD) in two
ways. Pick one:

| | **OpenID Connect** (recommended) | **SAML 2.0** |
|---|---|---|
| Button on the login page | "Sign in with Microsoft" | "Sign in with SSO" |
| Roles from | App roles or security groups | App roles or security groups |
| More than 150–200 groups ("overage") | Handled (mapped groups are checked with Graph) | Only app roles apply |
| Setup guide | This page | [SAML_SSO_SETUP.md](./SAML_SSO_SETUP.md) and [the SAML section below](#using-saml-with-entra-instead) |

Both are **single-tenant**: one Entra tenant for the whole Pepper install. Email
and password sign-in keeps working alongside SSO.

---

## 1. Register Pepper in Entra

In the [Microsoft Entra admin center](https://entra.microsoft.com):

1. **Identity → Applications → App registrations → New registration**
   - Name: `Pepper`
   - Supported account types: **Accounts in this organizational directory only
     (single tenant)**
   - Redirect URI: platform **Web**,
     `https://<pepper-host>/api/auth/callback/entra`
2. Copy the **Application (client) ID** and **Directory (tenant) ID** from the
   Overview page.
3. **Certificates & secrets → New client secret**. Copy the secret **value**. Note
   the expiry date, because sign-in stops working when the secret expires.
4. **API permissions**: the default **Microsoft Graph → User.Read (delegated)** is
   all Pepper needs. It is used only to check group membership when a user is in
   too many groups for the token. No admin-consented directory permissions are
   required.

## 2. Decide how roles are assigned

Pepper roles are **ADMIN > SECURITY > DEVELOPER > VIEWER**. When a user matches
several entries, the highest role wins. Users who match nothing get
`ENTRA_DEFAULT_ROLE` (default `VIEWER`), or are refused when
`ENTRA_REQUIRE_ROLE=true`.

### Option A: app roles (recommended)

App roles always fit in the token (no overage) and are easy to read in the map.

1. In the app registration, open **App roles → Create app role** four times:

   | Display name | Value | Allowed member types |
   |---|---|---|
   | Pepper Admin | `Pepper.Admin` | Users/Groups |
   | Pepper Security | `Pepper.Security` | Users/Groups |
   | Pepper Developer | `Pepper.Developer` | Users/Groups |
   | Pepper Viewer | `Pepper.Viewer` | Users/Groups |

2. **Enterprise applications → Pepper → Users and groups → Add user/group**, and
   assign each group or user a role.
3. Map the values:

   ```bash
   ENTRA_ROLE_MAP='{"Pepper.Admin":"ADMIN","Pepper.Security":"SECURITY","Pepper.Developer":"DEVELOPER","Pepper.Viewer":"VIEWER"}'
   ```

### Option B: security groups

1. **Token configuration → Add groups claim → Security groups**. For the ID
   token, choose **Group ID**.
   - Prefer **Groups assigned to the application** (under the same dialog) so
     only relevant groups are sent. This avoids overage for users who belong to
     hundreds of groups.
2. Entra sends group **object IDs** (GUIDs), not names. Copy them from
   **Groups → <group> → Object ID** and map them:

   ```bash
   ENTRA_ROLE_MAP='{"3f1c…-admins-object-id":"ADMIN","9a2d…-appsec-object-id":"SECURITY"}'
   ```

You can mix app role values and group IDs in the same map.

**Groups overage.** A user in more than 200 groups gets no `groups` claim;
Entra signals "overage" instead. Pepper then asks Microsoft Graph
(`POST /me/checkMemberGroups`, User.Read) whether the user is in **the group
IDs from your map**, and nothing else. If Graph isn't reachable (for example
an egress policy blocks `graph.microsoft.com`), only app roles apply and a
warning is logged. Turn the lookup off with `ENTRA_GROUP_OVERAGE_LOOKUP=false`.

## 3. Limit who can sign in

- In **Enterprise applications → Pepper → Properties**, set **Assignment
  required?** to **Yes**. Entra then refuses anyone not assigned to the app.
- Set `ENTRA_REQUIRE_ROLE=true` so Pepper also refuses users who match nothing in
  `ENTRA_ROLE_MAP`.
- **Guest (B2B) accounts are refused** unless `ENTRA_ALLOW_GUESTS=true`.
- Tokens from any other tenant are refused. `common` / `organizations` /
  `consumers` can't be configured.

## 4. Configure Pepper

Add to the `.env` used by the app (`docker-compose` `env_file`), then restart:

```bash
ENABLE_ENTRA_SSO="true"
ENTRA_TENANT_ID="<directory-tenant-id>"          # GUID (or verified domain)
ENTRA_CLIENT_ID="<application-client-id>"
ENTRA_CLIENT_SECRET="<client-secret-value>"
ENTRA_ROLE_MAP='{"Pepper.Admin":"ADMIN","Pepper.Security":"SECURITY","Pepper.Developer":"DEVELOPER"}'
# Optional
ENTRA_DEFAULT_ROLE="VIEWER"          # role when nothing matches
ENTRA_REQUIRE_ROLE="false"           # "true" = refuse users who match nothing
ENTRA_ROLE_SYNC="raise"              # or "exact" (see below)
ENTRA_DEFAULT_ORG_SLUG=""            # org to add users to; blank = oldest org
ENTRA_ALLOW_GUESTS="false"
ENTRA_GROUP_OVERAGE_LOOKUP="true"
SESSION_MAX_AGE_HOURS=""             # shorter sessions (default 30 days)
```

`NEXTAUTH_URL` must be the public `https://<pepper-host>` so the redirect URI
matches the app registration exactly.

**National clouds.** For Azure Government or 21Vianet, also set
`ENTRA_AUTHORITY_HOST` (e.g. `https://login.microsoftonline.us`) and
`ENTRA_GRAPH_URL` (e.g. `https://graph.microsoft.us`).

**Outbound access.** The Pepper app server must reach `login.microsoftonline.com`
(and `graph.microsoft.com` for the overage lookup). Behind a proxy, set
`HTTPS_PROXY` / `NO_PROXY` as described in [ONPREM_DEPLOY.md](./ONPREM_DEPLOY.md).

## 5. What happens at sign-in

1. Pepper validates the ID token: signature, issuer (your tenant), audience,
   nonce, PKCE and state.
2. It checks the tenant, guest status and email, then works out the role.
3. **First sign-in:** the user is created and added to the organization with
   that role. If a Pepper account with the same email already exists (for
   example an admin created before SSO), the Microsoft sign-in is **linked** to
   it. That is safe because only your tenant's tokens are accepted.
4. **Later sign-ins:**
   - `ENTRA_ROLE_SYNC=raise` (default) can raise a role but never lowers it, so a
     mapping mistake can't lock an admin out.
   - `ENTRA_ROLE_SYNC=exact` makes Entra authoritative: the role is set to what
     Entra grants, including downgrades. The organization's **last admin is never
     demoted**. Every change is written to the audit log.

**Removing access.** A user removed from the app or its groups can't sign in
again. A session that already exists lasts until it expires (30 days by
default). Set `SESSION_MAX_AGE_HOURS` (for example `12`) to make removals take
effect sooner. Automatic deprovisioning through SCIM is not supported yet.

## 6. Troubleshooting

| Message on the login page / log | Cause | Fix |
|---|---|---|
| "Your Microsoft account isn't assigned to Pepper" (`entra_no_role`) | `ENTRA_REQUIRE_ROLE=true` and no app role / group matched | Assign the user an app role or add them to a mapped group; check the GUIDs in `ENTRA_ROLE_MAP` |
| "Guest accounts can't sign in" (`entra_guest`) | B2B guest | Use a member account, or set `ENTRA_ALLOW_GUESTS=true` |
| "belongs to a different organization" (`entra_tenant`) | Token from another tenant | Check `ENTRA_TENANT_ID` |
| "no email address or user principal name" (`entra_no_email`) | Neither `email` nor UPN claim | Add the optional `email` claim under **Token configuration** |
| Entra shows **AADSTS50011** | Redirect URI mismatch | Register exactly `https://<pepper-host>/api/auth/callback/entra`; check `NEXTAUTH_URL` |
| Entra shows **AADSTS7000215** | Wrong / expired client secret | Create a new secret and update `ENTRA_CLIENT_SECRET` |
| Log: `Entra sign-in disabled: misconfigured` | Missing value or multi-tenant ID | The log line says which setting |
| Log: `Entra groups overage: Graph lookup failed` | Graph unreachable | Allow `graph.microsoft.com`, use app roles, or "Groups assigned to the application" |

## Using SAML with Entra instead

Follow [SAML_SSO_SETUP.md](./SAML_SSO_SETUP.md). In Entra create **Enterprise
applications → New application → Create your own → Integrate any other
application (non-gallery)**, then under **Single sign-on → SAML**:

| Entra field | Value |
|---|---|
| Identifier (Entity ID) | `https://<pepper-host>/api/auth/saml/metadata` |
| Reply URL (ACS) | `https://<pepper-host>/api/auth/saml/acs` |
| Sign on URL | `https://<pepper-host>/api/auth/saml/login` |

- Copy the **Login URL** into `SAML_ENTRY_POINT` and the **Certificate (Base64)**
  into `SAML_IDP_CERT`.
- Entra's email, name, groups
  (`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) and role
  (`…/claims/role`) claims are read automatically. You don't need to set
  `SAML_GROUP_ATTR`.
- Map group object IDs or app role values in `SAML_ROLE_MAP`, as in step 2.
- SAML tokens carry at most 150 groups. Above that Entra sends a link instead,
  which Pepper can't follow, and logs a warning. Use app roles or "Groups
  assigned to the application".
- SAML only ever raises roles. Use OpenID Connect for exact role sync.
