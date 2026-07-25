/**
 * Turns deps.dev license data into policy findings and attaches licenses to
 * dependencies for SBOM output.
 *
 * Only policy violations become findings. A compliant dependency produces no
 * finding at all — the SBOM is where the full license inventory lives.
 */

import type { Dependency, RawFinding } from "../types";
import {
  dependencyKey,
  type DepsDevVersionInfo,
} from "./deps-dev-client";
import {
  defaultLicensePolicy,
  evaluateLicenses,
  shouldReport,
  type LicensePolicy,
  type LicenseVerdict,
} from "./license-policy";

/**
 * Copy dependencies with their declared licenses attached, so the SBOM can
 * report real licenses instead of NOASSERTION.
 */
export function attachLicenses(
  dependencies: Dependency[],
  infoByKey: Map<string, DepsDevVersionInfo>,
): Dependency[] {
  if (infoByKey.size === 0) return dependencies;

  return dependencies.map((dep) => {
    const info = infoByKey.get(dependencyKey(dep));
    if (!info || info.licenses.length === 0) return dep;
    return { ...dep, licenses: info.licenses };
  });
}

function severityFor(verdict: LicenseVerdict): RawFinding["severity"] {
  // License obligations bind regardless of dependency depth — a copyleft
  // transitive dependency still affects distribution — so severity is not
  // reduced for transitive dependencies.
  if (verdict === "denied") return "HIGH";
  if (verdict === "warn") return "LOW";
  return "INFO";
}

function titleFor(
  verdict: LicenseVerdict,
  dep: Dependency,
  expression: string,
): string {
  if (verdict === "denied") {
    return `Disallowed license ${expression} in ${dep.name}@${dep.version}`;
  }
  if (verdict === "warn") {
    return `License requires review: ${expression} in ${dep.name}@${dep.version}`;
  }
  return `Undetermined license for ${dep.name}@${dep.version}`;
}

function descriptionFor(
  verdict: LicenseVerdict,
  dep: Dependency,
  expression: string,
  matchedLicense: string | undefined,
  isDirect: boolean,
): string {
  const depth = isDirect
    ? "a direct dependency"
    : "a transitive dependency (pulled in by another package)";

  if (verdict === "unknown") {
    return (
      `The license for ${dep.name}@${dep.version} (${dep.ecosystem}) could not be ` +
      `determined from registry metadata. This is ${depth}.\n\n` +
      `Confirm the license in the package's repository before distributing.`
    );
  }

  const matched = matchedLicense ? ` (matched \`${matchedLicense}\`)` : "";
  const consequence =
    verdict === "denied"
      ? `\`${expression}\`${matched} is disallowed by the configured license policy. ` +
        `Strong copyleft and source-available licenses can require you to publish ` +
        `your own source or restrict commercial redistribution.`
      : `\`${expression}\`${matched} is permitted but carries obligations worth ` +
        `reviewing — typically source disclosure for modifications to the library itself.`;

  return (
    `${dep.name}@${dep.version} (${dep.ecosystem}) is ${depth}.\n\n${consequence}\n\n` +
    `Declared license: ${expression}`
  );
}

function remediationFor(verdict: LicenseVerdict, dep: Dependency): string {
  if (verdict === "denied") {
    return (
      `Replace ${dep.name} with a permissively licensed alternative, or obtain a ` +
      `commercial license from the author. If the license is acceptable for this ` +
      `project, add it to the license policy allow list instead of suppressing ` +
      `each finding.`
    );
  }
  if (verdict === "warn") {
    return (
      `Confirm the obligations are acceptable for how you distribute this project. ` +
      `Add the license to the policy allow list once reviewed.`
    );
  }
  return `Determine the license from the package repository and record the outcome.`;
}

/**
 * Build license policy findings for the dependencies that violate policy.
 */
export function buildLicenseFindings(
  dependencies: Dependency[],
  infoByKey: Map<string, DepsDevVersionInfo>,
  directDependencies: Set<string> = new Set(),
  policy: LicensePolicy = defaultLicensePolicy(),
): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const dep of dependencies) {
    const info = infoByKey.get(dependencyKey(dep));
    // No metadata at all: unsupported ecosystem or lookup failure. Staying
    // silent is correct — absence of data is not a policy violation.
    if (!info) continue;

    const evaluation = evaluateLicenses(info.licenses, policy);
    if (!shouldReport(evaluation.verdict, policy)) continue;

    const isDirect = directDependencies.has(dep.name);
    const expression = evaluation.expression || "unknown";

    findings.push({
      scanner: "SCA",
      severity: severityFor(evaluation.verdict),
      title: titleFor(evaluation.verdict, dep, expression),
      description: descriptionFor(
        evaluation.verdict,
        dep,
        expression,
        evaluation.matchedLicense,
        isDirect,
      ),
      filePath: dep.sourceFile,
      ruleId: `LICENSE-${evaluation.verdict.toUpperCase()}`,
      // CWE-1357: reliance on a component with an unclear or restrictive licence.
      cweId: "CWE-1357",
      confidence: 1.0,
      metadata: {
        packageName: dep.name,
        packageVersion: dep.version,
        ecosystem: dep.ecosystem,
        licenseExpression: expression,
        licenseVerdict: evaluation.verdict,
        licensePolicyPattern: evaluation.matchedPattern,
        matchedLicense: evaluation.matchedLicense,
        directDependency: isDirect,
        sourceRepo: info.sourceRepo,
        isDeprecated: info.isDeprecated,
        remediation: remediationFor(evaluation.verdict, dep),
        evidenceSource: "deps.dev",
      },
    });
  }

  return findings;
}
