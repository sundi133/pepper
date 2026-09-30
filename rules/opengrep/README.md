# OpenGrep rules (rule-based SAST)

Pepper's `SAST_PATTERN` scanner runs [OpenGrep](https://github.com/opengrep/opengrep)
(LGPL-2.1) with the packs listed in `packs.json`. Everything runs offline.

| Pack | Path | License | Notes |
|---|---|---|---|
| `pepper` | `pepper/` | Pepper (proprietary) | Written by Pepper; every rule has a test fixture. |
| `gitlab-lgpl` | `third_party/gitlab-lgpl/` | LGPL-3.0 | Vendored **unmodified** from GitLab `sast-rules` (`rules/lgpl`); see `SOURCE.md`. Noisy rules are disabled via `excludeRules` in `packs.json`, not by editing files. |

## What is deliberately NOT bundled

- `semgrep-rules` / `opengrep-rules` and GitLab `rules/lgpl-cc/` — Commons Clause
  (no right to sell a product whose value derives from the rules).
- GitLab `rules/gitlab/` — GitLab EE license.
- GitLab's older analyzer-derived rules (`c/`, `csharp/`, `java/`, …) — labelled
  MIT but translated from analyzers with other licenses (LGPL/GPL/Apache);
  pending legal review.

## Customer rule packs

Set `OPENGREP_EXTRA_RULES` to one or more directories (`:`-separated) of
OpenGrep/Semgrep YAML rules mounted into the worker. They run alongside the
bundled packs; findings are labelled with the directory name.

## Writing and testing Pepper rules

Each rule `pepper/<lang>/<name>.yaml` has a fixture `<name>.<ext>` with
`// ruleid: <id>` above lines that must match and `// ok: <id>` above lines
that must not. Run:

    opengrep test rules/opengrep/pepper

Guidelines: prefer `mode: taint` from real request sources for injection
rules; include `ok:` cases for the common safe idioms; set `metadata.cwe`,
`metadata.confidence` (HIGH/MEDIUM/LOW — LOW is filtered out), and put the
remediation after `Fix:` in the message. Keep rule text ASCII.
