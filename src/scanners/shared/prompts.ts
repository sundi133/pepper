/** Centralized LLM prompt fragments — avoid duplicating long policy blocks. */

export const SAST_PASS1_PROMPT = `You are performing PASS 1 (candidate discovery) of a deep security code audit.
Report only credible vulnerability CANDIDATES with concrete evidence from the chunk.
Confidence 0.65-0.79 = candidate for pass-2 validation; 0.80+ only if exploit path is fully visible in chunk.

Return JSON:
{
  "candidates": [
    {
      "title": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "what/where/why in 2-4 sentences",
      "startLine": <int>,
      "endLine": <int>,
      "cweId": "CWE-XXX",
      "confidence": <0.65-1.0>,
      "weaknessClass": "e.g. IDOR, SQLi, SSRF",
      "metadata": {
        "route": null,
        "method": null,
        "parameter": null,
        "sink": null,
        "attackPath": "...",
        "impact": "...",
        "remediation": "...",
        "stepsToReproduce": ["..."],
        "validationSteps": ["..."]
      }
    }
  ]
}
If none: {"candidates": []}`;

export const SAST_PASS2_PROMPT = `You are performing PASS 2 (cross-file validation) of a security audit.
Given repository context (routes, auth boundaries, sinks) and candidate findings, validate each candidate.
Only confirm findings where the exploit path holds with available context. Reject duplicates of generic lint noise.
Confirmed findings need confidence >= 0.80 and full remediation.

Return JSON:
{
  "findings": [
    {
      "title": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "structured: what, where, why exploitable",
      "startLine": <int>,
      "endLine": <int>,
      "cweId": "CWE-XXX",
      "confidence": <0.80-1.0>,
      "weaknessClass": "...",
      "metadata": {
        "route", "method", "parameter", "sink",
        "attackPath", "impact", "remediation",
        "stepsToReproduce", "validationSteps", "evidence", "confidenceReason"
      }
    }
  ]
}`;

export const SECRETS_AI_PROMPT = `You are a secrets auditor reviewing source/config for REAL leaked credentials.
NEVER report: placeholders, env var names only, examples, test fixtures, redacted values, checksums, public IDs, localhost demos.
For each TRUE secret (confidence >= 0.80) return:
{
  "findings": [{
    "title": "...",
    "severity": "CRITICAL|HIGH",
    "credentialType": "AWS|GitHub|...",
    "maskedValue": "first4…last4 only",
    "startLine": <int>,
    "endLine": <int>,
    "whyReal": "...",
    "provider": "...",
    "impact": "...",
    "remediation": "1.revoke 2.remove 3.purge git 4.secret manager 5.pre-commit",
    "confidence": <0.80-1.0>
  }]
}
If none: {"findings": []}`;

export const SCA_TRIAGE_PROMPT = `Triage OSV CVE findings. Do NOT invent CVEs. Group duplicate CVEs per package@version.
For each kept finding add: directDependency (bool), reachable (bool), exploitPreconditions, prioritized fixVersion, remediation.
Suppress dev-only/test-only unless CRITICAL and reachable.

Return JSON: { "triaged": [{ "osvId", "keep": true|false, "reason", "metadata": {...} }] }`;

export const MALICIOUS_VALIDATION_PROMPT = `Validate supply-chain risk from EVIDENCE only (metadata, install scripts, typosquat signals, OSV MAL-*).
Do NOT emit findings for "new package" or "no repository" alone.
Emit only if credible malicious/suspicious risk (confidence >= 0.80).

Return JSON: { "findings": [{ "packageName", "version", "title", "severity", "suspiciousBehavior", "evidence", "whyNotBenign", "installImpact", "remediation", "confidence" }] }`;

export const CONTAINER_CONFIG_PROMPT = `Review Dockerfile/compose for dangerous container CONFIG (not CVEs).
Check: root user, privileged, host network/pid/ipc, docker.sock, dangerous caps, :latest tags, no digest, no resource limits, writable root FS.
Return JSON findings with remediation and validationSteps. Category CONTAINER_CONFIG. Confidence >= 0.80.`;

export const ZERO_DAY_VALIDATION_PROMPT = `Cross-file exploit-chain analysis for NOVEL business-logic or chain bugs NOT already covered by standard CWE patterns.
Use route map, authz map, data-flow, high-risk workflows, AI/agent boundaries.
Confidence >= 0.80. Do not duplicate obvious injection/authz already reported in pass-1 SAST candidates.`;
