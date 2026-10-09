## Universal review checklist (all languages)
Review like a senior security engineer: understand what the code is for, then ask how an attacker or a concurrent/failed request breaks it.

**Authentication & authorization**
- Every request path to data or a privileged action checks identity AND ownership/role/tenant on the server. A record loaded by a client-supplied id before an ownership or tenant scope check is IDOR (CWE-639/862).
- Tenant/org/account ids from URL or body must never override the authenticated session's tenant.
- Sibling handlers that carry an auth guard/extractor/middleware the reviewed handler lacks are strong evidence of a missing check.
- Passwords: adaptive hash (bcrypt/argon2/scrypt), never md5/sha*. Session tokens cryptographically random, rotated on login/privilege change, expire.
- JWT: signature verified (decode ≠ verify), algorithm pinned, exp/iss/aud checked, secret not weak or hard-coded.

**Input → sink**
- SQL/NoSQL/LDAP/XPath built by concatenation or interpolation; command execution through a shell; template rendering of user strings; eval/dynamic code; deserialization of untrusted bytes into arbitrary types; file paths from input without canonicalize+allowlist; outbound HTTP to user-supplied URLs without host allowlist (SSRF, incl. redirects and internal IPs); redirects to user URLs (open redirect).
- Client-side validation is never a control. Validate type, range, length and enum on the server.

**Business logic (highest value, hardest to see)**
- Amounts, quantities, prices, discounts and refunds: negative, zero, overflow, currency mismatch, rounding, refund > captured, double refund.
- State machines: can a step be skipped, replayed or run out of order (capture before authorize, confirm twice, cancel after settle)?
- Idempotency: retried requests, webhooks and jobs must not duplicate payments, emails or other external side effects; webhooks verify signature and reject replays.
- Race conditions / TOCTOU: check-then-act on balances, inventory, coupons, limits without a lock, transaction or atomic update.
- Mass assignment: request body bound straight into a model can set role, owner, price, status.

**Errors, logging, data**
- Swallowed errors that turn a failed security check into success (fail-open). Broad catch that hides auth/validation failures.
- Error responses leaking stack traces, SQL, internal ids or secrets. Different messages/timing for valid vs invalid users (enumeration).
- Secrets, tokens, card data or PII written to logs, analytics, prompts or error trackers.
- Weak crypto: ECB, static IV/nonce, unauthenticated CBC, Math.random-class RNG for secrets, home-made crypto, disabled TLS verification.

**Availability**
- Unbounded input size, recursion, regex on user input (ReDoS), unpaginated queries, missing rate limits on login/OTP/reset/export/expensive endpoints.

**Severity guide**
- CRITICAL: unauthenticated RCE, auth bypass, cross-tenant data access, money movement abuse.
- HIGH: authenticated injection, IDOR on sensitive data, stored XSS, SSRF to internal network.
- MEDIUM: reflected XSS, CSRF on state change, info leak, missing rate limit on auth.
- LOW: hardening gaps with no direct exploit path.
