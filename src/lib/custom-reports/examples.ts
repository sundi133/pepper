/** Starter templates offered in the template editor. */
export const EXAMPLE_TEMPLATES = [
  {
    name: "Monthly security status",
    description: "One-page status for engineering leadership.",
    instructions:
      "Audience: engineering managers and the CTO. Plain language, no code. Lead with business risk, keep each section short, and end every section with a concrete next step.",
    body: `# Security status — {{scan.repository}}

Scan of branch {{scan.branch}} (commit {{scan.commit}}), completed {{scan.date}}.

## Summary

Two or three sentences: overall risk posture and the single most important action.

| Severity | Findings |
| --- | --- |
| Critical | {{findings.critical_count}} |
| High | {{findings.high_count}} |
| Medium | {{findings.medium_count}} |
| Low | {{findings.low_count}} |

## Top risks

The five most important open issues, one bullet each: what it is, why it matters, where it is.

## Changes since the previous scan

New and fixed findings since the last scan, and whether the trend is improving.

## Dependencies

Vulnerable or license-flagged third-party packages worth upgrading first.

## Recommended actions

A numbered list of the next steps, most urgent first.
`,
  },
  {
    name: "Audit evidence",
    description: "Compliance-oriented summary for auditors.",
    instructions:
      "Audience: external auditors. Formal tone. Be precise about what the scan does and does not cover; cite findings for every gap.",
    body: `# Application security assessment

## Scope

Repository, branch, commit, scan type and date, and which scanners ran.

## Results overview

Findings by severity and status, including how many were triaged as accepted risk.

## Compliance mapping

For OWASP Top 10 and PCI DSS: the controls with gaps found, each with the findings that affect it.

## Open critical and high findings

| Ref | Severity | Finding | Location | Status |
| --- | --- | --- | --- | --- |

## Limitations

What this automated scan cannot assess.
`,
  },
];
