# Compliance Reporting — Design Spec

**Status:** Draft · **Owner:** Security Platform · **Scope:** SAST/SCA/IaC/Container findings → framework control mappings and per-scan compliance reports

Frameworks in scope (all of them):
CWE & CWE Top 25 · OWASP Top 10 · OWASP ASVS · OWASP API Security Top 10 · NIST SSDF · PCI DSS 4.0.1 · ISO/IEC 27001:2022 · SOC 2 · NIST 800-53 · HIPAA · GDPR

---

## 1. Goal

Let a user pick one or more compliance frameworks for a completed scan and get a **reproducible, auditor-credible** report that maps each finding to named framework controls, states remediation status, and — critically — is honest about what SAST can and cannot attest.

Non-goal: claiming a codebase "is compliant." SAST produces *evidence toward* controls; it does not certify compliance.

---

## 2. Where we are today

| Piece | Location | Notes |
|---|---|---|
| Compliance API (generate + cache) | `src/app/api/scans/[scanId]/compliance/route.ts` | Runs **all** frameworks; caches in `scan.scannerProgress._complianceReport` |
| LLM finding→control mapper | `src/lib/compliance/llm-mapper.ts` | Batches 15 findings + full control catalog per LLM call; **non-deterministic** |
| Framework loader/parser | `src/lib/compliance/pdf-parser.ts` | Loads `compliance/*.pdf` + `*.json` → `{controlId,title,summary,checklist,evidence}` |
| Bundled frameworks | `compliance/` | `ISO27001.pdf`, `OWASP.pdf`, `SOC2.json`, `CIS_Docker_Benchmark.json` |
| Deterministic CWE→OWASP table | `src/scanners/sast/owasp-mapper.ts` | `owasp2024`/`owaspApi`/`owaspLlm`; **the right pattern, under-used** |
| Report UI | `src/app/(dashboard)/scans/[scanId]/compliance/page.tsx` | Framework checkboxes filter **display only** |
| PDF report | `src/lib/pdf-report.ts` | Has its own OWASP coverage section |
| Finding model | `prisma/schema.prisma:319` | `cweId`, `cveId`, `ruleId`, `scanner`, `severity`, `status`, `metadata` JSON |

### Three problems to fix

1. **Non-deterministic mapping.** Same commit can map to different controls run-to-run. Auditors require reproducibility.
2. **Cost/latency.** Every framework runs on every generation, all via LLM (284 findings × N frameworks × batches).
3. **Three unsynced CWE tables.** `owasp-mapper.ts` (authoritative, multi-taxonomy), a duplicate 2021-only `CWE_OWASP_MAP` in `pdf-report.ts`, and the LLM mapper. OWASP data also lives only in `Finding.metadata` JSON, so it is **not queryable**. Consolidate to one source of truth.

---

## 3. What compliance stakeholders actually care about in SAST

Auditors/GRC do not want vuln counts. They want *evidence for a control tied to a remediation lifecycle*.

| Requirement | Why | Have today |
|---|---|---|
| **Traceability** finding → CWE → named control → status | Audit narrative: "control requires X; here's our test for X; here are open gaps" | `cweId`, `status` |
| **Scope/coverage honesty** — what SAST *can* / *cannot* attest | Overclaiming ("HIPAA compliant") destroys credibility | ❌ build |
| **Determinism / reproducibility** | Report must regenerate identically for the same commit | `commitSha`; ❌ mapping is LLM |
| **Remediation lifecycle + risk acceptance w/ sign-off** | Controls manage findings; zero findings ≠ pass. Who accepted risk, when, why | `ACCEPTED_RISK`, `statusNote`, `statusUpdatedBy/At`, `AuditLog` |
| **Documented severity/risk methodology** | "How do you prioritize?" needs a consistent answer | `riskScore` 1–100, exploitability scoring |
| **Point-in-time + trend** | SOC2/ISO assess operating effectiveness *over a period* | `commitSha`, scan history; ❌ per-control trend |
| **Immutable, exportable artifact** (scan id, commit, timestamp, framework **version**) | Evidence must be pinnable | PDF/CSV; ❌ version stamp |
| **Recognized taxonomy** (CWE/OWASP) | Auditors trust CWE refs over vendor labels | `cweId` |
| **FP / suppression governance** | Noise must be justified + tracked | `SuppressionRule` w/ reason/source |

**The one rule that separates a credible report from a toy:** state per-control whether SAST provides evidence, and **never infer "compliant" from "no findings."**

---

## 4. Architecture

### 4.1 Mapping engine — agentic (default) + deterministic grounding

**Decision (updated):** the primary engine is **LLM-driven and agentic**, for high-accuracy contextual reasoning. The deterministic CWE crosswalk is **not** the final answer — it is the agent's **grounding tool** (candidate controls + real control text), which is what keeps the LLM accurate instead of hallucinating control IDs. Two modes, selectable via `?mode=`:

**`mode=deep` (default) — agentic** (`agentic-mapper.ts`):
```
1. GROUND  (code) — crosswalk priors + full control catalog (real requirement text)
2. REASON  (LLM)  — which controls apply, relevance, grounded justification, confidence 0–1
3. VERIFY  (LLM)  — adversarial critique: uphold / downgrade / reject each mapping
4. VALIDATE(code) — drop controls not in catalog + rejected mappings
```
Cost gating: only findings with a grounded prior (crosswalk hit or activity match) reach the LLM for a given framework; the rest map to nothing with no LLM call. Graceful degradation: on LLM error the batch keeps its deterministic priors.

**`mode=fast` — deterministic** (`crosswalk-mapper.ts`): CWE crosswalk only, no LLM. Instant, reproducible, free — the audit-reproducibility escape hatch, and the grounding source for deep mode.

The gateway (`llm-gateway.ts`) forces JSON output and has **no tool-calling**, so "agentic" is a code-orchestrated multi-step loop, portable across OpenAI / Anthropic / Ollama. Per-framework results cache keyed by `slug::mode`. Each mapping carries `confidence`, `verified`, and `verificationNote`, surfaced in the UI.

> This inverts the earlier "deterministic-first, LLM-as-fallback" recommendation. Reproducibility is preserved via `mode=fast` plus low-temperature + caching in deep mode; accuracy comes from grounding + adversarial self-verification.

### 4.2 Coverage model (make scope explicit)

Every control carries a **coverage class**, independent of findings:

- `assessable` — SAST can produce evidence (e.g. ISO A.8.28 Secure Coding, PCI 6.2.4)
- `partial` — SAST covers part (e.g. OWASP API BOLA — sometimes detectable)
- `not-assessable` — process/physical (e.g. HIPAA workforce training, SOC2 CC1.x)

Report renders three buckets per framework:
1. **Gaps found** — assessable + mapped findings
2. **No issues detected** — assessable + zero findings (≠ "pass")
3. **Not covered by SAST** — needs other evidence

This is the credibility layer.

### 4.3 Framework-as-data (no code per framework)

Extend the JSON control schema already loaded by `pdf-parser.ts` with coverage + a CWE crosswalk per control:

```jsonc
{
  "controlId": "6.2.4",
  "title": "Address common software attacks",
  "coverage": "assessable",
  "cweMapping": ["CWE-89","CWE-79","CWE-78","CWE-94","CWE-611","CWE-502","CWE-918"]
}
```

At load time build the reverse index `CWE → [{framework, controlId, relevance}]`. New framework = new JSON file, zero code.

### 4.4 Generation-time selection + persistence

- API: `GET /api/scans/[scanId]/compliance?frameworks=owasp-top10,pci-dss-4` — map only the requested set; cache **per framework** so re-runs are incremental.
- Persist per-org **enabled frameworks** on `OrgSettings` so the UI defaults to what the customer cares about (a PCI shop shouldn't see HIPAA noise).
- Optional `FindingControlMapping` table (`findingId, framework, controlId, relevance, source: crosswalk|llm`) so mappings are queryable → powers trend + PDF without recompute, and fixes the "OWASP data only in metadata JSON" problem.

### 4.5 Framework versioning

Stamp every report with framework id **+ version** (`OWASP Top 10:2021`, `PCI DSS 4.0.1`, `ISO 27001:2022`) and crosswalk version. Auditors need to know which revision was mapped.

### 4.6 Consolidate the three CWE tables

Make `src/scanners/sast/owasp-mapper.ts` the single source of truth. Delete `CWE_OWASP_MAP`/`CWE_CATEGORY_MAP` in `pdf-report.ts` and have the PDF import from the shared module. All framework crosswalks live as data (§4.3), not scattered code.

---

## 5. Per-framework mapping cookbook

The join mechanism differs — some are pure CWE crosswalks, some are scanner/activity-level.

| Framework | Version | Mechanism | Anchor controls SAST feeds | Source of truth |
|---|---|---|---|---|
| **CWE / CWE Top 25** | 2024 | Direct — `finding.cweId`; Top 25 = set membership | The CWE; badge "in Top 25 Most Dangerous" | MITRE CWE Top 25 |
| **OWASP Top 10** | 2021 | Deterministic CWE→category | A01–A10 | OWASP per-category CWE lists — complete existing `owasp2024` table |
| **OWASP API Top 10** | 2023 | CWE→category, flag `partial` | API1 BOLA, API3 BOPLA, API7 SSRF from CWE; API4/API6 need runtime | `owaspApi` seeds |
| **OWASP ASVS** | 4.0.3 / 5.0 | CWE→requirement id | V5 Validation/Encoding, V6 Crypto, V7 Errors, V4 Access Control, V9 Comms | ASVS ships CWE refs per requirement |
| **NIST SSDF** | SP 800-218 | **Activity-level**, not per-CWE | PW.5 (secure coding), PW.7/PW.8 (review/test), RV.1 (identify vulns) | SAST existence = evidence for PW.7/8; findings = RV.1 |
| **PCI DSS** | 4.0.1 | CWE→6.2.4 sub-attack; all findings→6.3.1 | 6.2.4 (injection/XSS/CSRF/…), 6.3.1 (identify vulns), 6.4.x web apps | Req 6.2.4 enumerates attack types → CWE |
| **ISO/IEC 27001** | 2022 | Scanner/category-level + some CWE | A.8.28 (secure coding), A.8.29 (security testing), A.8.25/8.26, A.8.8 (SCA vulns) | `ISO27001.pdf` |
| **SOC 2** | TSC 2017 | Scanner/category-level | CC7.1 (vuln detection), CC8.1 (change mgmt), CC6.x (access-control findings) | `SOC2.json` |
| **NIST 800-53** | Rev 5 | CWE→control + activity | SI-10 (input validation→injection CWEs), SC-13 (crypto CWEs), RA-5 (scanning), SA-11 (dev testing), SI-2 (flaw remediation) | 800-53 catalog |
| **HIPAA Security Rule** | 45 CFR 164 | Category-level, mostly `partial`/`not-assessable` | §164.312(e) transmission→TLS/crypto, §164.312(a) access→authz, §164.308(a)(1) risk analysis | Mark administrative safeguards `not-assessable` |
| **GDPR** | 2016/679 | Category-level, mostly `partial` | Art 32(1)(a) encryption→crypto, 32(1)(b) integrity→injection/access, Art 25 by-design | Rest `not-assessable` — evidence indirect |

**Two families:**
- **CWE crosswalks** (build lookup tables): CWE Top 25, OWASP Top 10, OWASP API, OWASP ASVS, PCI DSS (6.2.4), NIST 800-53 (input/crypto controls).
- **Activity/scanner-level** (honest coverage classing matters most, much is out of SAST reach): NIST SSDF, ISO 27001, SOC 2, HIPAA, GDPR.

---

## 6. Data model changes

```prisma
// New — queryable mappings (replaces "OWASP only in metadata JSON")
model FindingControlMapping {
  id         String   @id @default(cuid())
  findingId  String
  framework  String   // "pci-dss-4" | "owasp-top10-2021" | ...
  controlId  String   // "6.2.4"
  relevance  String   // "direct" | "supporting" | "related"
  source     String   // "crosswalk" | "llm"
  finding    Finding  @relation(fields: [findingId], references: [id], onDelete: Cascade)
  @@index([findingId])
  @@index([framework, controlId])
}
```

- `OrgSettings.enabledComplianceFrameworks String[]` — default framework set per org.
- Control JSON schema gains `coverage` + `cweMapping[]` (§4.3).
- (Optional) `ComplianceFramework` / `ComplianceControl` tables to move catalogs off the filesystem for true multi-tenant control sets.

---

## 7. API contract (target)

```
GET /api/scans/{scanId}/compliance?frameworks=owasp-top10-2021,pci-dss-4
→ {
    scanId, commitSha, generatedAt,
    reports: [{
      framework: "PCI DSS", version: "4.0.1", crosswalkVersion: "2024.1",
      coverage: { assessable: 12, partial: 3, notAssessable: 8 },
      buckets: {
        gapsFound:       [{ controlId, title, findingCount, criticalHighCount, findings:[...] }],
        noIssuesDetected:[{ controlId, title }],
        notCovered:      [{ controlId, title, reason }]
      },
      statusCounts: { open, inProgress, resolved, falsePositive, acceptedRisk }
    }]
  }
```

Each mapped finding annotated with `{ controlId, relevance, source, reasoning }`.

---

## 8. Phasing

1. ✅ **Backbone (DONE)** — `coverage` + `cweMapping[]` + `appliesTo` added to the control schema (`pdf-parser.ts`); deterministic engine in `crosswalk-mapper.ts`; framework JSON authored for all 11 frameworks (`compliance/*.json`). Tests in `crosswalk-mapper.test.ts`.
2. ✅ **Coverage honesty (DONE, API + UI)** — 3-bucket view (`gapsFound` / `noIssuesDetected` / `notCovered`) in the API response and rendered on the compliance page. PDF still pending.
3. ⏳ **Selection & cost (PARTIAL)** — `?frameworks=` + `?refresh=1` params and per-framework caching (`_complianceByFramework`) done. Per-org enabled-frameworks default and UI slug-passing still pending.
4. ⏳ **LLM demotion (DONE for deterministic frameworks)** — deterministic frameworks never call the LLM; `llm-mapper.ts` is now fallback-only for frameworks without crosswalk data (ISO PDF, OWASP PDF, CIS). Using the LLM to author reasoning text for CWE-less findings is still pending.
5. ✅ **Consolidation (DONE)** — `owasp-mapper.ts` is now the single source of truth. Added `getCweCategory()` (short weakness label) and `getOwasp2024Code()` (bare "A03:2021" code). `pdf-report.ts`'s duplicate `CWE_OWASP_MAP` + `CWE_CATEGORY_MAP` deleted; it imports the shared helpers. The PDF's OWASP labels now match the finding metadata the scanner already tags. A data-integrity test (`compliance-data.test.ts`) validates every framework's CWE ids, scanner names, and coverage values.
6. ⏳ **Audit polish** — framework-version stamp (✅ in API response), `FindingControlMapping` table for trend, remediation-SLA flags, risk-acceptance sign-off in export. **Table/SLA not started.**

### Catalog completeness (all frameworks, full control sets)

Every framework now ships its complete catalog at reporting altitude, each control
coverage-classed (`assessable` / `partial` / `not-assessable`):

| Framework | Controls | Assessable | Partial | Not-assessable | Mapping |
|---|---|---|---|---|---|
| ISO/IEC 27001:2022 (Annex A) | 93 | 10 | 24 | 59 | deterministic |
| SOC 2 (CC1.1–CC9.2 + A/PI) | 36 | 8 | 6 | 22 | deterministic |
| NIST 800-53 Rev 5 (SAST-scoped) | 28 | 12 | 15 | 1 | deterministic |
| CWE Top 25 (2024) | 25 | 25 | 0 | 0 | deterministic |
| HIPAA Security Rule | 20 | 4 | 6 | 10 | deterministic |
| PCI DSS 4.0.1 | 20 | 6 | 11 | 3 | deterministic |
| NIST SSDF | 19 | 5 | 8 | 6 | deterministic |
| OWASP ASVS 4.0.3 (V1–V14) | 14 | 8 | 4 | 2 | deterministic |
| GDPR (security-scoped) | 12 | 1 | 5 | 6 | deterministic |
| OWASP API Top 10 (2023) | 10 | 5 | 3 | 2 | deterministic |
| OWASP Top 10 (2021) | 10 | 8 | 2 | 0 | deterministic |

800-53 and GDPR carry an in-file `scopeNote` documenting that they are mapped at
the SAST-relevant-control level, not the full ~1000-control baseline / 99 articles.

**Resolved — duplicate OWASP:** `OWASP.pdf` was removed (superseded by the
deterministic `OWASP_Top10_2021.json`). **Resolved — ISO on LLM path:** the loader
now dedupes by slug preferring the deterministic framework, so the new 93-control
`ISO27001_2022.json` supersedes `ISO27001.pdf` automatically (PDF left on disk,
ignored).

**Remaining LLM-mapped:** only `CIS_Docker_Benchmark.json` (24 controls) — not in
the target framework list; add `appliesTo: {scanners:["CONTAINER","IAC"]}` to make
it deterministic when desired.

---

## 9. Open questions

- Move control catalogs from `compliance/` files into DB tables for per-tenant customization, or keep file-bundled + per-org overrides?
- ASVS/800-53 are large — ship curated SAST-relevant subsets first, or full catalogs with coverage flags?
- Remediation SLAs (PCI requires timely fixes) — configurable per-org gate, or report-only for now?
