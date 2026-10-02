# Scan precision: what a scan is allowed to report

A finding a customer opens and immediately dismisses costs more trust than a
finding we never showed. This is the bar each rule-based scanner must meet, and
how it is checked.

## Principles

1. **A match is not a finding.** A detector matching is evidence, not a verdict.
   Each match must also pass a check that a real value or a real defect is
   present.
2. **Report once.** One issue is one finding: not once per build stage, per
   advisory database, or per manifest that mentions the same package.
3. **First-party is not third-party.** The repository's own packages are never
   looked up in public registries by name.
4. **Triage is respected.** A finding marked false positive leaves the list,
   the tab counts and the scan totals.
5. **Precision changes are measured.** Run the scanners on a real repository
   before and after, and read every finding that appears or disappears.

## Secrets (pattern scanner, pre-commit endpoint)

Reported:

- Provider token formats (AWS, GitHub, GitLab, Slack, Stripe secret keys,
  Google, SendGrid, npm, OpenAI, Anthropic, Azure storage, Slack webhooks).
- An AWS secret access key **only next to its name**.
- Private keys with real key material between BEGIN and END.
- Database URLs with credentials for a host someone could reach.
- `api_key` / `secret_key` / `client_secret` with a generated-looking value.
- Any secret-named setting holding 32+ characters of key material
  (`GENERIC_SECRET`, High, lower confidence).

Never reported:

- Format strings, shell variables and templates (`{}`, `${VAR}`, `<key>`).
- Local or placeholder databases, and stand-in passwords on a service name.
- Descriptions of a value (`"paypal_secret_key"`), examples, placeholders.
- A key header with no body, or with a template for a body.
- UUIDs, hashes, prefixed identifiers (`pm_…`), long identifier names.
- Stripe publishable keys; Google keys in `google-services.json` /
  `GoogleService-Info.plist` (public by design).
- `GENERIC_SECRET` in tests, examples and API documentation.

Severity: test paths and Rust `#[cfg(test)]` modules are one level lower.

The AI secrets pass applies a narrower guard: a value that is wholly a
reference, template or stand-in is dropped whatever the model said.

Retired detectors (`AWS_SECRET_KEY` = any 40 base64 characters,
`HEROKU_API_KEY` = any UUID): their open findings in existing scans are closed
as false positives when the worker starts.

## Container (Dockerfile)

- Runtime checks (runs as root, no healthcheck) apply to the **final stage**,
  following `FROM <earlier stage>` for what it inherits.
- Tag and digest checks apply to external base images only: not `scratch`, an
  earlier stage, or an image chosen by a build `ARG`. Digest pinning is
  reported once per Dockerfile, and not on top of a floating-tag finding.
- A hardcoded secret needs a secret-named variable **and** a literal value:
  not a `$VAR`, a path, `--mount=type=secret`, or a name such as `AUTHOR`.
- Missing `LABEL`s are not reported.

## Dependencies (SCA)

- A lock file's versions replace the manifest's ranges, including a workspace
  root lock file for its members (Cargo, npm, yarn, pnpm).
- Workspace and path crates are not dependencies.
- One vulnerability is one finding, whichever databases list it (GHSA,
  RUSTSEC, PYSEC, GO); the most severe record is kept, the other ids become
  aliases.

## Reference measurement

`juspay/hyperswitch` (13,969 files), rule-based scanners, AI passes off:

| Category     | Before | After | Notes                                             |
|--------------|-------:|------:|---------------------------------------------------|
| Secrets      |     28 |     6 | 26 false removed; 4 real config keys newly found  |
| Container    |     38 |    12 |                                                   |
| Dependencies |    231 |   166 | duplicates and first-party crates                 |

Each remaining secrets finding was read and is a real hardcoded key.
