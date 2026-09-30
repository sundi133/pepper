# GitLab SAST rules — LGPL-3.0 subset (vendored, unmodified)

- Source: https://gitlab.com/gitlab-org/security-products/sast-rules
- Path: `rules/lgpl/` at commit `53bf5cf` (2026-09-21)
- License: GNU Lesser General Public License v3.0 — see `LICENSE` in this
  directory. Rules originate from mobsfscan / njsscan (LGPL-3.0); each rule
  file keeps its original license header.

These files are redistributed unmodified. Pepper does not edit them; noisy
rules are disabled from Pepper's configuration (`rules/opengrep/packs.json`,
`excludeRules`) instead. To update, replace this directory with the same path
from a newer commit and update the commit above.

Not vendored on purpose: `rules/lgpl-cc/` (Commons Clause — no right to sell)
and `rules/gitlab/` (GitLab EE license).
