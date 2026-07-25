/**
 * VEX (Vulnerability Exploitability eXchange) document generation.
 *
 * An SBOM says which components are present; a VEX says whether the
 * vulnerabilities in those components actually affect the product. Without one,
 * a consumer scanning the SBOM re-derives every CVE and has no way to know which
 * ones were already assessed and dismissed.
 *
 * Statements are built from the adjudicated state of record — the stored
 * findings and their statuses — rather than from scanner internals, so a VEX
 * reflects decisions a human can be held to:
 *
 *   OPEN / IN_PROGRESS  -> affected            (with an action statement)
 *   FALSE_POSITIVE      -> not_affected        (with a justification)
 *   ACCEPTED_RISK       -> affected            (acknowledged, not remediated)
 *   RESOLVED            -> fixed
 *
 * Emits OpenVEX 0.2.0 and CycloneDX 1.5 VEX. Both are generated from one
 * statement model so they cannot disagree.
 */

import { randomUUID } from "crypto";

/** OpenVEX status values. https://github.com/openvex/spec */
export type VexStatus =
  | "not_affected"
  | "affected"
  | "fixed"
  | "under_investigation";

/**
 * The only justifications OpenVEX permits for `not_affected`. A justification
 * outside this list is not valid VEX, so anything we cannot map to one of these
 * is expressed as a free-text impact statement instead of a guessed enum.
 */
export type VexJustification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export interface VexStatement {
  /** CVE or advisory identifier. */
  vulnerabilityId: string;
  /** Advisory aliases (e.g. the GHSA when vulnerabilityId is a CVE). */
  aliases?: string[];
  description?: string;
  status: VexStatus;
  /** Required by spec for not_affected unless impactStatement is given. */
  justification?: VexJustification;
  /** Free-text reason, used when no spec justification is defensible. */
  impactStatement?: string;
  /** What to do about it — required by spec for `affected`. */
  actionStatement?: string;
  /** PURL of the vulnerable component this statement is about. */
  subcomponentPurl?: string;
  packageName?: string;
  packageVersion?: string;
  severity?: string;
  /** ISO timestamp of the underlying decision, when known. */
  timestamp?: string;
}

export interface VexMetadata {
  productName: string;
  /** PURL or other identifier for the product being described. */
  productId: string;
  scanId: string;
  commitSha?: string;
  branch?: string;
  /** ISO timestamp; defaults to now. */
  generatedAt?: string;
  /** Who is making these assertions. */
  author?: string;
}

/** Finding shape this module needs. Kept minimal so callers can pass DB rows. */
export interface VexSourceFinding {
  cveId?: string | null;
  ruleId?: string | null;
  title?: string | null;
  severity?: string | null;
  status?: string | null;
  statusNote?: string | null;
  statusUpdatedAt?: Date | string | null;
  metadata?: unknown;
}

const OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0";
const DEFAULT_AUTHOR = "Pepper";

function readMetadata(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

// ─── Status and justification mapping ────────────────────────────────────────

export function statusForFinding(status: string | null | undefined): VexStatus {
  switch ((status || "OPEN").toUpperCase()) {
    case "FALSE_POSITIVE":
      return "not_affected";
    case "RESOLVED":
      return "fixed";
    // An accepted risk is still an affected product — VEX has no "we decided to
    // live with it" status, and claiming not_affected would be false.
    case "ACCEPTED_RISK":
    case "OPEN":
    case "IN_PROGRESS":
    default:
      return "affected";
  }
}

/**
 * Derive a spec justification from triage evidence.
 *
 * Returns undefined when no listed justification genuinely applies — the caller
 * then falls back to an impact statement carrying the real reason. Inventing a
 * justification would make the VEX assert something we did not establish.
 */
export function justificationForFinding(
  finding: VexSourceFinding,
): VexJustification | undefined {
  const meta = readMetadata(finding.metadata);
  const note = (finding.statusNote || "").toLowerCase();
  const reason = (readString(meta.confidenceReason) || "").toLowerCase();
  const haystack = `${note} ${reason}`;

  // A dev/test-only dependency is not part of the distributed product.
  if (meta.isDev === true || /\bdev(elopment)?[- ]only\b|\btest[- ]only\b/.test(haystack)) {
    return "component_not_present";
  }

  // Explicitly determined unreachable during triage.
  if (meta.reachable === false || meta.reachability === "unreachable") {
    return "vulnerable_code_not_in_execute_path";
  }

  if (/not imported|never imported|unused depend|not used/.test(haystack)) {
    return "vulnerable_code_not_present";
  }
  if (/not reachable|unreachable|not in execute path|never called/.test(haystack)) {
    return "vulnerable_code_not_in_execute_path";
  }
  if (/not attacker[- ]controll|cannot be controlled|no attacker input/.test(haystack)) {
    return "vulnerable_code_cannot_be_controlled_by_adversary";
  }
  if (/mitigat|waf|already patched|compensating control/.test(haystack)) {
    return "inline_mitigations_already_exist";
  }

  return undefined;
}

function actionStatementFor(finding: VexSourceFinding): string {
  const meta = readMetadata(finding.metadata);
  const fixVersion = readString(meta.fixVersion);
  const pkg = readString(meta.packageName);
  const introducedBy = readString(meta.introducedBy);

  const upgradeAdvice =
    fixVersion && pkg
      ? introducedBy && introducedBy !== pkg
        ? `Upgrade ${pkg} to ${fixVersion} or later; it is introduced by ${introducedBy}, so upgrade that dependency or pin an override.`
        : `Upgrade ${pkg} to ${fixVersion} or later.`
      : undefined;

  // An accepted risk must state the acceptance decision. Emitting generic
  // upgrade advice here would misrepresent the organisation's position as
  // "remediation pending" when it has formally chosen not to remediate.
  if ((finding.status || "").toUpperCase() === "ACCEPTED_RISK") {
    const rationale =
      finding.statusNote?.trim() || "Risk formally accepted; no remediation planned.";
    return upgradeAdvice
      ? `Risk accepted: ${rationale} A fix is available: ${upgradeAdvice}`
      : `Risk accepted: ${rationale}`;
  }

  const remediation = readString(meta.remediation);
  if (remediation) return remediation;
  if (upgradeAdvice) return upgradeAdvice;

  return "Under remediation — see the finding for details.";
}

/**
 * Build VEX statements from stored findings.
 *
 * Only findings carrying a vulnerability identifier can be described, since a
 * VEX statement is keyed by one. Findings for the same vulnerability and
 * component are collapsed so the document has one statement per assertion.
 */
export function buildVexStatements(
  findings: VexSourceFinding[],
  options: { purlFor?: (name: string, version: string, ecosystem: string) => string } = {},
): VexStatement[] {
  const byKey = new Map<string, VexStatement>();

  for (const finding of findings) {
    const meta = readMetadata(finding.metadata);
    const vulnId = readString(finding.cveId) || readString(meta.osvId);
    if (!vulnId) continue;

    const packageName = readString(meta.packageName);
    const packageVersion = readString(meta.packageVersion);
    const ecosystem = readString(meta.ecosystem);

    const subcomponentPurl =
      packageName && packageVersion && ecosystem && options.purlFor
        ? options.purlFor(packageName, packageVersion, ecosystem)
        : undefined;

    const key = `${vulnId}::${subcomponentPurl || packageName || ""}`;
    const status = statusForFinding(finding.status);

    const statement: VexStatement = {
      vulnerabilityId: vulnId,
      aliases:
        readString(meta.osvId) && readString(meta.osvId) !== vulnId
          ? [readString(meta.osvId) as string]
          : undefined,
      description: readString(finding.title),
      status,
      subcomponentPurl,
      packageName,
      packageVersion,
      severity: readString(finding.severity),
      timestamp:
        finding.statusUpdatedAt instanceof Date
          ? finding.statusUpdatedAt.toISOString()
          : readString(finding.statusUpdatedAt),
    };

    if (status === "not_affected") {
      const justification = justificationForFinding(finding);
      if (justification) {
        statement.justification = justification;
      } else {
        // Spec requires one of justification or impact_statement. Carry the real
        // reason rather than asserting a justification we cannot support.
        statement.impactStatement =
          finding.statusNote?.trim() ||
          readString(meta.confidenceReason) ||
          "Assessed as not affecting this product; see the finding for details.";
      }
    } else if (status === "affected") {
      statement.actionStatement = actionStatementFor(finding);
    }

    // Prefer a decided status over a default OPEN one if duplicates appear.
    const existing = byKey.get(key);
    if (!existing || (existing.status === "affected" && status !== "affected")) {
      byKey.set(key, statement);
    }
  }

  return [...byKey.values()].sort((a, b) =>
    a.vulnerabilityId.localeCompare(b.vulnerabilityId),
  );
}

/** Minimal shape of a triage-suppressed vulnerability. */
export interface VexSuppressedInput {
  vulnerabilityId: string;
  advisoryId?: string;
  title?: string;
  severity?: string;
  packageName?: string;
  packageVersion?: string;
  ecosystem?: string;
  reason: string;
  assessedBy?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Build `not_affected` statements for CVEs automated triage ruled out.
 *
 * These never became findings, so without this they would be absent from the
 * VEX entirely — the consumer would re-derive them from the SBOM with no idea
 * they had already been assessed. The assessor is disclosed in the impact
 * statement: a reader is entitled to know a machine made the call, and to weigh
 * it differently from a human sign-off.
 */
export function buildSuppressedVexStatements(
  suppressed: VexSuppressedInput[],
  options: {
    purlFor?: (name: string, version: string, ecosystem: string) => string;
  } = {},
): VexStatement[] {
  const byKey = new Map<string, VexStatement>();

  for (const entry of suppressed) {
    if (!entry.vulnerabilityId) continue;

    const subcomponentPurl =
      entry.packageName && entry.packageVersion && entry.ecosystem && options.purlFor
        ? options.purlFor(
            entry.packageName,
            entry.packageVersion,
            entry.ecosystem,
          )
        : undefined;

    // Reuse the same justification mapping the adjudicated path uses, so an
    // automated and a human decision with the same rationale are expressed
    // identically.
    const justification = justificationForFinding({
      statusNote: entry.reason,
      metadata: entry.metadata,
    });

    const disclosure =
      entry.assessedBy === "automated-triage"
        ? "Assessed by automated triage (not reviewed by a human): "
        : "";

    const statement: VexStatement = {
      vulnerabilityId: entry.vulnerabilityId,
      aliases:
        entry.advisoryId && entry.advisoryId !== entry.vulnerabilityId
          ? [entry.advisoryId]
          : undefined,
      description: entry.title,
      status: "not_affected",
      subcomponentPurl,
      packageName: entry.packageName,
      packageVersion: entry.packageVersion,
      severity: entry.severity,
      // Always carry the disclosure, alongside a justification when one applies.
      impactStatement: `${disclosure}${entry.reason}`,
      ...(justification ? { justification } : {}),
    };

    const key = `${entry.vulnerabilityId}::${subcomponentPurl || entry.packageName || ""}`;
    if (!byKey.has(key)) byKey.set(key, statement);
  }

  return [...byKey.values()];
}

/**
 * Merge adjudicated and triage-suppressed statements.
 * A stored finding always wins over an automated suppression for the same
 * vulnerability and component, since it reflects a later, stronger decision.
 */
export function mergeVexStatements(
  fromFindings: VexStatement[],
  fromSuppressed: VexStatement[],
): VexStatement[] {
  const key = (s: VexStatement) =>
    `${s.vulnerabilityId}::${s.subcomponentPurl || s.packageName || ""}`;

  const merged = new Map<string, VexStatement>();
  for (const s of fromSuppressed) merged.set(key(s), s);
  for (const s of fromFindings) merged.set(key(s), s);

  return [...merged.values()].sort((a, b) =>
    a.vulnerabilityId.localeCompare(b.vulnerabilityId),
  );
}

// ─── OpenVEX 0.2.0 ───────────────────────────────────────────────────────────

export function generateOpenVex(
  statements: VexStatement[],
  meta: VexMetadata,
): string {
  const timestamp = meta.generatedAt || new Date().toISOString();
  const author = meta.author || DEFAULT_AUTHOR;

  const doc = {
    "@context": OPENVEX_CONTEXT,
    "@id": `https://openvex.dev/docs/pepper/${meta.scanId}-${randomUUID()}`,
    author,
    timestamp,
    version: 1,
    tooling: "Pepper",
    statements: statements.map((s) => {
      const product: Record<string, unknown> = { "@id": meta.productId };
      if (s.subcomponentPurl) {
        product.subcomponents = [{ "@id": s.subcomponentPurl }];
      }

      return {
        vulnerability: {
          name: s.vulnerabilityId,
          ...(s.aliases?.length ? { aliases: s.aliases } : {}),
          ...(s.description ? { description: s.description } : {}),
        },
        products: [product],
        status: s.status,
        ...(s.justification ? { justification: s.justification } : {}),
        ...(s.impactStatement ? { impact_statement: s.impactStatement } : {}),
        ...(s.actionStatement ? { action_statement: s.actionStatement } : {}),
        ...(s.timestamp ? { timestamp: s.timestamp } : {}),
      };
    }),
  };

  return JSON.stringify(doc, null, 2);
}

// ─── CycloneDX 1.5 VEX ───────────────────────────────────────────────────────

/** CycloneDX analysis state, which uses different vocabulary from OpenVEX. */
function cycloneDxState(status: VexStatus): string {
  switch (status) {
    case "not_affected":
      return "not_affected";
    case "fixed":
      return "resolved";
    case "under_investigation":
      return "in_triage";
    case "affected":
    default:
      return "exploitable";
  }
}

/** CycloneDX justification vocabulary, which is narrower than OpenVEX's. */
function cycloneDxJustification(
  justification: VexJustification | undefined,
): string | undefined {
  switch (justification) {
    case "component_not_present":
      return "component_not_present";
    case "vulnerable_code_not_present":
      return "code_not_present";
    case "vulnerable_code_not_in_execute_path":
      return "code_not_reachable";
    case "vulnerable_code_cannot_be_controlled_by_adversary":
      return "requires_configuration";
    case "inline_mitigations_already_exist":
      return "protected_by_mitigating_control";
    default:
      return undefined;
  }
}

export function generateCycloneDxVex(
  statements: VexStatement[],
  meta: VexMetadata,
): string {
  const timestamp = meta.generatedAt || new Date().toISOString();

  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: "Pepper", name: "pepper-vex", version: "1.0.0" }],
      component: {
        "bom-ref": meta.productId,
        type: "application",
        name: meta.productName,
        version: meta.commitSha || "0.0.0",
      },
    },
    vulnerabilities: statements.map((s) => ({
      id: s.vulnerabilityId,
      ...(s.description ? { description: s.description } : {}),
      ...(s.severity
        ? { ratings: [{ severity: s.severity.toLowerCase() }] }
        : {}),
      analysis: {
        state: cycloneDxState(s.status),
        ...(s.justification
          ? { justification: cycloneDxJustification(s.justification) }
          : {}),
        ...(s.impactStatement || s.actionStatement
          ? { detail: s.impactStatement || s.actionStatement }
          : {}),
        ...(s.actionStatement && s.status === "affected"
          ? { response: ["update"] }
          : {}),
      },
      affects: [
        {
          ref: s.subcomponentPurl || meta.productId,
        },
      ],
    })),
  };

  return JSON.stringify(doc, null, 2);
}

/** Counts by status, for logging and scan summaries. */
export function summarizeVex(
  statements: VexStatement[],
): Record<VexStatus, number> {
  const summary: Record<VexStatus, number> = {
    affected: 0,
    not_affected: 0,
    fixed: 0,
    under_investigation: 0,
  };
  for (const s of statements) summary[s.status]++;
  return summary;
}
