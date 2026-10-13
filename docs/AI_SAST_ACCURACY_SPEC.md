# AI SAST accuracy: evaluation harness and precision plan

Status: proposal. Owner: Pepper scanning. Builds on `docs/SCAN_PRECISION_SPEC.md`
(rule-based scanners) and covers the AI scanners: AI SAST (`SAST_LLM`), zero-day
(`ZERO_DAY`) and AI secrets (`SECRETS_LLM`).

## 1. Problem

A recent scan was triaged at **45% true positive, 55% false positive** (54 credible
findings of roughly 120). Customers judge the product on the first page of findings,
and at that rate they learn to ignore it.

We also can't currently answer basic questions about our own accuracy:

- Which kinds of findings are false: authorization, injection, configuration, hardening?
- Did a prompt, model or filter change make things better or worse?
- Where in the pipeline is a finding lost or let through?

Every quality fix in October was found by hand-running scans and reading logs:

- **Empty OpenRouter balance** turned into "no findings".
- **A cut-off validator answer** silently removed every candidate.
- **The evidence check** dropped authorization findings.
- **The confidence floor** dropped unconfirmed logic flaws.

None of these would have shipped if we measured accuracy routinely.

The authorization and business-logic findings are the product's core (see #150), so
**precision must not be bought by losing recall on them**.

## 2. Goals

| Metric (benchmark corpus, median of 3 runs) | 1.1.8 baseline | Target |
|---|---|---|
| Precision, all AI findings | measure first (one scan: 45%) | ≥ 75% |
| Precision, authorization / business logic | measure | ≥ 70% |
| Recall, authorization / business logic | measure | not lower than baseline; then ≥ 80% |
| Recall, injection | measure | not lower than baseline |
| Run-to-run spread (finding count) | 6–12 on VAmPI | within ±20% |

**Non-goals:**

- Rule-based scanner precision (covered by the existing spec).
- Model training or fine-tuning.

## 3. Part A — Evaluation harness

### A1. Corpus

Pinned commits of deliberately vulnerable apps, chosen to span the languages and
frameworks customers use, plus real codebases for false-positive pressure:

| App | Stack | Why |
|---|---|---|
| VAmPI | Python / Flask | IDOR, mass assignment, auth bypass, JWT, debug exposure |
| OWASP Juice Shop | Node / Express / Angular | broad web coverage, business logic |
| NodeGoat | Node / Express | OWASP Top 10, session, injection |
| crAPI | Python, Java, Go microservices | BOLA/BFLA across services |
| brokencrystals | NestJS | JWT variants, template injection |
| DVWA | PHP | classic injection, file inclusion |
| vulnerable-apps/vuln-graphql-api | GraphQL | resolver authorization |
| juspay/hyperswitch (subset) | Rust | large real codebase: false positives only |
| 2–3 internal or customer-consented repos | mixed | realistic false-positive pressure |

Large repos are evaluated on a fixed file subset to bound cost.

### A2. Ground truth format

One YAML file per app (`eval/corpus/<app>/truth.yaml`), versioned with the corpus
commit:

```yaml
app: vampi
commit: f16052d
expected:            # real issues the scanner should report
  - id: vampi-bola-books
    file: api_views/books.py
    lines: [45, 60]
    class: authorization        # authorization | business-logic | injection | crypto |
                                # authentication | data-exposure | config | hardening
    cwe: [CWE-639, CWE-284, CWE-862]
    severity: HIGH
must_not_report:     # known safe code that looks risky
  - id: vampi-orm-query
    file: models/book_model.py
    lines: [20, 30]
    reason: SQLAlchemy filter_by is parameterized
debatable:           # neither credited nor penalized
  - id: vampi-no-rate-limit
    file: api_views/users.py
    class: hardening
```

### A3. Matching and metrics

- **Match rule:** a reported finding matches an expected item when it's in the same
  file, overlaps the line range widened by ±10 lines, and has the same class (or a CWE
  in the item's list). Each expected item is matched at most once; further matches count
  as duplicates, not false positives.
- **Scoring:**
  - Unmatched findings outside `debatable` are **false positives**.
  - Hits on `must_not_report` are **false positives** that block the release (A6).
  - Unmatched expected items are **misses**.
- **Report:** precision, recall and F1, broken down by scanner, class, severity and model.
- **Also reported:**
  - Severity accuracy.
  - Duplicate ratio.
  - Share of findings shown as "not confirmed".
  - Tokens, cost and wall time per app.
  - Spread across runs (median, min, max).

### A4. Drop ledger

Every stage that can keep or remove a finding records it, with the stage name and the
reason. The stages are:

1. Chunk analysis.
2. Confidence floor.
3. Layer filter.
4. CWE-798 hand-off.
5. Evidence check.
6. Validation pass: confirmed, rejected or not judged.
7. Quality gates.
8. Dedupe.
9. Suppression rules.

The ledger is stored per scan, in `Scan.scannerProgress.SAST_LLM.ledger` or a new
artifact. It is shown in the harness report as a funnel:

`candidates 15 → evidence 15 → validator 12 (3 rejected: titles…) → gates 10 → dedupe 10`

This is how the October regressions were found; it should never again take a debugging
session.

### A5. Runner

```bash
npm run eval -- --corpus vampi,juice-shop --model moonshotai/kimi-k3 --runs 3
```

- Calls `runScanners` directly, like the scratch harness used in October. No database,
  queue or UI is needed.
- **Live mode** calls the model, for prompt and model changes.
- **Replay mode** records model requests and responses keyed by a hash of the prompt and
  chunk, and replays them. That makes evaluating changes to code after the model
  (filters, gates, dedupe, parsing) deterministic and free.
- Writes `eval/results/<date>-<git sha>-<model>.json` and a markdown summary with
  per-class tables, plus a comparison against the last baseline on `main`.

### A6. Regression gates

- **On every PR touching `src/scanners/**` or `src/lib/llm-*`:** replay mode on the full
  corpus. The PR fails if, compared with the baseline:
  - authorization or business-logic recall drops at all;
  - any other class's recall drops by more than 5 points;
  - precision drops by more than 3 points;
  - any `must_not_report` item is hit.
- **Nightly:** live mode on a two-app subset with the production model. Alert on drift,
  for example a model update or provider change.
- **Before each release:** live mode on the full corpus. Results are attached to the
  GitHub release.

### A7. Production feedback loop

- Each finding records the prompt version and model that produced it
  (`metadata.promptVersion`, `metadata.model`).
- A triage dashboard (admin only) shows, per class, rule, prompt version and model:
  - share marked False Positive;
  - share Resolved or ticketed;
  - share left open.
- Opted-in organizations' False Positive verdicts with a reason are exported (code
  excluded) as candidate `must_not_report` entries for review.

## 4. Part B — Precision improvements

**Order of work:** measure first (B0), then the changes expected to remove the most
false positives without touching recall. Each item names its measure.

### B0. Classify the false positives we have

Before changing code, label the ~66 false positives from the 45/55 scan by cause:

- no attacker-controlled input;
- guard exists elsewhere (middleware, decorator, service);
- framework default makes it safe;
- test, example or dev-only code;
- hardening, not a vulnerability;
- duplicate of another finding;
- wrong severity only;
- hallucinated code.

The ranking below assumes the usual distribution and should be re-ordered by what B0
shows.

### B1. Repository facts for both AI passes

A static pre-pass builds a compact fact sheet per repository, including it in the
existing repo context:

- route → handler map;
- global and per-route middleware, guards and decorators (Express `app.use`, NestJS
  `@UseGuards`, Flask `before_request` and decorators, Django middleware and
  permission classes, Spring Security config, FastAPI dependencies);
- ORM scoping helpers;
- template auto-escaping defaults;
- dev vs prod config files.

- **Removes:** "missing authentication / authorization" findings where a global guard
  exists, and XSS findings in auto-escaped templates. These are probably the largest
  class of authorization false positives.
- **Measure:** authorization precision on Juice Shop, NodeGoat and crAPI.

### B2. Structured verdicts in the validation pass

Today the validator rejects by leaving a candidate out, which hides the reason and
can't be told apart from a cut-off answer. Change the contract so every candidate gets
a verdict:

```json
{ "index": 2, "verdict": "confirmed|rejected|needs_context",
  "reason": "...", "evidence": [{ "file": "...", "line": 41 }] }
```

- A `rejected` verdict must cite the line of the guard or sanitizer. A rejection
  without a cited line is treated as `needs_context`.
- `needs_context` triggers one re-validation with the files the candidate's handler
  imports and its callers, within a size limit.
- Reasons go into the drop ledger and the finding (shown to users for unconfirmed
  findings).
- **Measure:** validator precision and recall on the corpus, and the share of
  `needs_context`.

### B3. Separate hardening from vulnerabilities

Missing security headers, debug flags in dev config, no rate limiting and verbose errors
become a **Hardening** tier:

- shown in their own tab;
- excluded from severity counts, the grade and build gates unless an organization opts
  in.

They are real advice but not vulnerabilities, and they inflate both the false-positive
count and severity totals.

- **Measure:** these move out of "false positive" into "hardening"; vulnerability
  precision rises accordingly.

### B4. Second opinion instead of silent keep for unconfirmed logic findings

#150 keeps authorization and logic findings the validator doesn't confirm. To keep
recall and recover precision:

- Run one independent check with a differently framed prompt ("act as the developer:
  why is this safe?").
- If it also fails to find a guard, the finding stays (labelled unconfirmed).
- If it cites a guard line, the finding moves to a **Needs review** filter instead of
  the main list, the same pattern as the false-positive toggle: never deleted, not in
  the headline.
- **Measure:** authorization recall unchanged, authorization precision up.

### B5. Root-cause dedupe across files and scanners

- The same pattern in N handlers becomes one finding with N locations.
- AI SAST and rule-based SAST hits on the same line become one finding (extend
  `areRootCauseDuplicates`).
- **Measure:** duplicate ratio.

### B6. Calibrated floors per class

- Replace the single confidence floor (0.65 first pass, 0.75 final) with per-class
  floors fitted on the corpus to reach target precision. Recall for authorization and
  logic is held at baseline.
- Severity calibration is checked the same way, as severity accuracy.

### B7. Scope rules

- Extend the existing test-path and example rules to cover:
  - dev-only config (`docker-compose.dev.yml`, `config/development.*`);
  - generated code;
  - vendored code;
  - dead code (no route or caller in the repository facts from B1).
- **Measure:** false positives with "test, example or dev-only" cause from B0.

### B8. Exploit validation

`ENABLE_EXPLOIT_VALIDATION` already exists and is off by default.

- Evaluate it on the corpus for HIGH and CRITICAL findings.
- Turn it on by default if it raises precision without lowering recall, at acceptable
  cost.

### B9. Learn from customer triage

`buildFpExamplesForPrompt` already feeds an organization's false-positive notes back to
the AI.

- Measure its effect with an A/B on the corpus, using seeded notes.
- Add auto-suggested suppression rules when the same rule and path pattern is marked
  False Positive three times.

## 5. Phases

1. **Harness:** A1–A5 on VAmPI, Juice Shop and NodeGoat, plus the drop ledger; publish
   the 1.1.8 baseline, then B0 classification.
2. **Biggest wins:** B1 repository facts, B2 structured verdicts, B3 hardening tier.
   Each change lands with before/after numbers.
3. **Gates and calibration:** A6 CI gates, B5 dedupe, B6 per-class floors, B4 second
   opinion.
4. **Feedback:** A7 dashboard, B8 exploit validation evaluation, B9 triage learning.
   Grow the corpus.

## 6. Open questions

- Which scan produced the 45/55 figure, and who labelled it (a person or an AI triage)?
  B0 needs that list.
- Production model or models to optimize for: `moonshotai/kimi-k3` today, and which
  non-reasoning fallback?
- Evaluation budget: live runs cost model credit (one VAmPI AI SAST run ≈ a few cents;
  Juice Shop several times more). Nightly subset and pre-release full run only?
- May we include customer repositories in the corpus (consent, storage), or only
  public apps plus anonymized patterns?
- Should Hardening (B3) count toward the grade and build gates by default?
