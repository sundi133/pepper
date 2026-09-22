# SAML SSO setup (on-prem Pepper)

Pepper supports enterprise **SAML 2.0 single sign-on** against one org-wide
identity provider (Okta, Entra/Azure AD, OneLogin, Ping, …).

> **Scope.** This is the **single global IdP** model — one IdP for the whole
> install, configured via environment variables. It fits **self-hosted,
> single-tenant** Pepper. Multi-tenant SaaS (per-organization IdPs, e.g. the
> hosted `sast.votal.ai`) is a separate, future capability and is **not** covered
> here.

> **Off by default.** SSO is inert unless `ENABLE_SAML_SSO=true` **and** the IdP
> entry point + signing cert are set. Email/password and GitHub login are
> unchanged when it is off.

---

## 1. Configure your IdP

Create a SAML app in your IdP with:

| Setting | Value |
|---|---|
| **ACS / Reply URL** | `https://<pepper-host>/api/auth/saml/acs` |
| **SP Entity ID / Audience** | `https://<pepper-host>/api/auth/saml/metadata` |
| **NameID** | email or persistent |
| **Attributes to release** | an **email** claim (required); a **groups** claim (for role mapping) |

Pepper also publishes SP metadata at
`https://<pepper-host>/api/auth/saml/metadata` once SSO is enabled, if your IdP
prefers metadata import.

Then copy the IdP's **SSO URL** and its **token-signing certificate** — from the
IdP's metadata `<X509Certificate>` element. You can paste the **raw base64**
(with or without the `-----BEGIN/END CERTIFICATE-----` lines); Pepper wraps it to
PEM automatically.

## 2. Set the environment on Pepper

The on-prem stack loads `.env` into the app and worker (`env_file: .env`), so add
these to your on-prem `.env`:

```bash
ENABLE_SAML_SSO=true
SAML_ENTRY_POINT=https://idp.company.com/app/xxxx/sso/saml     # IdP SSO URL
SAML_IDP_CERT=MIID...                                          # IdP signing cert (base64)
# Attribute mapping (defaults shown; override to match your IdP):
SAML_EMAIL_ATTR=                                               # blank → email/mail/nameID
SAML_GROUP_ATTR=groups
# Role mapping — IdP group → Pepper role; highest-privilege match wins:
SAML_ROLE_MAP={"pepper-admins":"ADMIN","appsec":"SECURITY","engineers":"DEVELOPER"}
SAML_DEFAULT_ROLE=VIEWER                                       # when no group matches
# Only if your IdP signs the <Response> instead of the <Assertion>:
# SAML_WANT_ASSERTIONS_SIGNED=false
```

Bring the stack up (or restart the app to pick up new env):

```bash
docker compose -f docker-compose.onprem.yml up -d
```

`NEXTAUTH_URL` must already be your real external URL (`https://<pepper-host>`) —
the ACS/metadata URLs and the login redirect are derived from it.

## 3. Sign in

The login page now shows **"Sign in with SSO"**. On first login a user is
just-in-time provisioned into the organization (see `SAML_DEFAULT_ORG_SLUG`;
blank = the oldest org) with the role derived from their IdP groups.

- Roles can be **raised** by SSO but never lowered — a misconfigured group map
  cannot lock an admin out. (Deprovisioning is a future SCIM capability.)

---

## Test it locally without a real IdP

Use the SimpleSAMLphp test IdP to exercise the whole flow on a laptop.

**1. Start the IdP** (any host port; internal port stays 8080):

```bash
docker run --name saml-idp -p 8080:8080 \
  -e SIMPLESAMLPHP_SP_ENTITY_ID=http://localhost:3000/api/auth/saml/metadata \
  -e SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE=http://localhost:3000/api/auth/saml/acs \
  -d kristophjunge/test-saml-idp
```

**2. Get its signing cert** (bare base64, newline-safe):

```bash
curl -s http://localhost:8080/simplesaml/saml2/idp/metadata.php \
  | tr -d '\n\r' | grep -oE 'X509Certificate>[^<]+' | head -1 | sed 's/X509Certificate>//'
```

**3. Point Pepper at it.** The **dev** compose (`docker-compose.yml`) does *not*
use `env_file`, so for local testing add a `docker-compose.override.yml`
(auto-merged, not committed):

```yaml
services:
  sast-api:
    environment:
      ENABLE_SAML_SSO: "true"
      SAML_ENTRY_POINT: "http://localhost:8080/simplesaml/saml2/idp/SSOService.php"
      SAML_IDP_CERT: "<paste the base64 from step 2>"
      SAML_EMAIL_ATTR: "email"
      SAML_GROUP_ATTR: "eduPersonAffiliation"
      SAML_ROLE_MAP: '{"group1":"ADMIN","group2":"DEVELOPER"}'
      SAML_DEFAULT_ROLE: "VIEWER"
```

```bash
docker compose up -d sast-api
```

**4. Log in** at http://localhost:3000/login → **Sign in with SSO**. The IdP
**login name is `user1`**, not the email:

| IdP username | password | email released | group → role |
|---|---|---|---|
| `user1` | `user1pass` | `user1@example.com` | group1 → **ADMIN** |
| `user2` | `user2pass` | `user2@example.com` | group2 → **DEVELOPER** |

**Clean up:**

```bash
docker rm -f saml-idp && rm docker-compose.override.yml && docker compose up -d sast-api
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No "Sign in with SSO" button | `ENABLE_SAML_SSO` unset, or entry point / cert missing | Set all three; restart the app |
| `idpCert is not in PEM format or in base64 format` | Cert value malformed (e.g. two certs concatenated, or truncated) | Re-extract a single `<X509Certificate>` — bare base64 is fine |
| `Invalid signature` / `Invalid document signature` | Wrong signing cert, **or** signature-location mismatch | Verify the cert is the IdP's *signing* cert; if the IdP signs only the response, set `SAML_WANT_ASSERTIONS_SIGNED=false` |
| Login page shows "Your SSO account has no email address" | IdP released no email claim | Release an email attribute; set `SAML_EMAIL_ATTR` to its name |
| IdP says "Incorrect username or password" | Using the email as the login name on the test IdP | Log in with `user1` / `user1pass` (email is only the released attribute) |
