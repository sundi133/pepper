# AI SAST evaluation harness

Measures how accurate Pepper's AI scanners are (AI SAST and zero-day), per
app, language and vulnerability class. Design: `docs/AI_SAST_ACCURACY_SPEC.md`.

## Run

```bash
# llm.env: LLM_PROVIDER, LLM_BASE_URL, LLM_MODEL, LLM_API_KEY (keep it out of git)
LLM_ENV=~/llm.env eval/run.sh --runs 2 --label my-change
LLM_ENV=~/llm.env eval/run.sh --apps vampi,govwa --label quick
```

Options: `--apps a,b` (default: all in `corpus.json`), `--runs N` (AI output
varies; use 2–3 for decisions), `--scans SAST_ONLY,ZERO_DAY_ONLY`, `--label`.
The scan runs in the worker image (`EVAL_IMAGE`, default `sundi133/pepper-worker:1.1.9`)
with this checkout's `src/` mounted over it, so it measures your working tree.
Each run costs model credit.

Output in `eval/results/<label>/`: `report.md` (recall and precision per app,
recall per class, the pipeline counters, missed issues), `summary.json`, and
per app and run the scored findings (`<app>-runN.json`) and the scan log.

## Measure a deployed Pepper (e.g. sast.votal.ai)

1. Scan each corpus app **at its pinned commit** with a FULL scan. URL scans
   use the repo's current default branch, which can move and shift line
   numbers, so prefer uploading a zip of the pinned commit:
   `git -C eval/.cache/<app> archive --format=zip -o <app>.zip HEAD` (after a
   local run has cloned it), or any checkout of the commit in `corpus.json`.
2. On each scan page, export the findings as CSV.
3. Score them:

```bash
npx tsx eval/score-export.ts vampi=~/Downloads/vampi.csv govwa=~/Downloads/govwa.csv \
  dvws-node=... dvwa=... java-vuln=... rw-node=... rw-go=... rw-spring=...
```

Only AI SAST and zero-day findings are scored unless `--all` is given. The
report (`eval/results/export-<date>.md`) lists recall per class, missed issues,
and every unlabelled or safe-code finding to review.

## Corpus and labels

- `corpus.json`: apps pinned to a commit. `vulnerable` apps are deliberately
  insecure; `clean` apps are ordinary codebases for false-positive pressure.
- `truth/<app>.json`: `expected` (real issues, with file, line range, class,
  accepted CWEs), `must_not_report` (safe code that looks risky), `debatable`
  (hardening; neither credited nor penalized), and optionally `include` (scan
  only these files).

## Scoring

- **Hit:** same file, within the labelled lines ±10, same class or an accepted
  CWE. Each expected issue is credited once; extra hits are duplicates.
- **Safe-code hit:** a finding on `must_not_report` code (a false positive).
- **Unlabelled:** anything else. It may be a real issue the labels miss, so it
  is listed for review. `Precision ≥` counts unlabelled findings as false (a
  lower bound); `Precision (labelled)` leaves them out.
- **Recall:** expected issues found / expected issues.

After reviewing a run's unlabelled findings, add them to the truth file as
`expected` or `must_not_report`, so later runs score them automatically.

## Rules

- Never tune prompts or code to a corpus app: no app names, file names or
  patterns copied from it. A gap found here must be fixed in a way that
  would also catch the same bug written differently.
- A change ships only if recall for authorization and business logic does not
  drop in any language.
