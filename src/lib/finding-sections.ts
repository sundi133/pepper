/**
 * Section grouping for the scan detail page.
 *
 * Extracted so the count behaviour is testable without rendering the page: the
 * bug this guards against silently removed an entire scanner's tab.
 */

export interface SectionFinding {
  scanner: string;
}

export const FINDING_SECTIONS = [
  {
    id: "SAST",
    title: "SAST Findings",
    // SAST_PATTERN is currently quarantined and emits nothing, but it belongs
    // here rather than in Other if it is ever re-enabled.
    scanners: ["SAST_LLM", "SAST_PATTERN"],
    description: "Static application security findings",
  },
  {
    id: "SECRETS",
    title: "Secrets Findings",
    // Both secret scanners belong in one tab. SECRETS_PATTERN was previously
    // unmapped, so a high-volume scanner fell into "Other" — 778 of 976
    // findings on one scan — and crowded every other category off the page.
    scanners: ["SECRETS_LLM", "SECRETS_PATTERN"],
    description: "Leaked or exposed credential findings",
  },
  {
    id: "SCA",
    title: "SCA Findings",
    scanners: ["SCA"],
    description: "Known vulnerable dependency findings",
  },
  {
    id: "MALICIOUS_PKG",
    title: "Supply Chain Findings",
    scanners: ["MALICIOUS_PKG"],
    description: "Malicious package, typosquat, and install-script findings",
  },
  {
    id: "IAC",
    title: "IaC Findings",
    scanners: ["IAC"],
    description: "Infrastructure, cloud, container, and CI/CD findings",
  },
  {
    id: "CONTAINER",
    title: "Container Findings",
    scanners: ["CONTAINER"],
    description: "Docker image and container security findings",
  },
  {
    id: "K8S",
    title: "Kubernetes Findings",
    scanners: ["K8S"],
    description: "Kubernetes manifest and workload security findings",
  },
  {
    id: "ZERO_DAY",
    title: "Zero-Day Findings",
    scanners: ["ZERO_DAY"],
    description: "Business logic, IDOR, race, and advanced AI findings",
  },
];

/**
 * Group the loaded findings into sections.
 *
 * `scannerCounts` carries per-scanner totals across the whole scan, which is
 * what the tabs display. Deriving tab counts from the loaded page instead made a
 * whole category vanish: the API returns at most 500 findings, and with severity
 * sorting a scan with 400+ criticals filled the page entirely, so lower-severity
 * SCA findings fell outside it and their section — being empty — was dropped. A
 * section is kept whenever the scan has findings for it, even when none are on
 * this page, so the tab reports a truthful total and says how many are shown.
 */
export function groupFindingsBySection<T extends SectionFinding>(
  findings: T[],
  scannerCounts: Record<string, number> = {},
) {
  const groupedScannerNames = new Set(
    FINDING_SECTIONS.flatMap((section) => section.scanners),
  );

  const totalFor = (scanners: string[]) =>
    scanners.reduce((sum, name) => sum + (scannerCounts[name] ?? 0), 0);

  const hasCounts = Object.keys(scannerCounts).length > 0;

  const sections = FINDING_SECTIONS.map((section) => {
    const loaded = findings.filter((finding) =>
      section.scanners.includes(finding.scanner),
    );
    // Fall back to the loaded count when the API did not supply totals.
    const total = hasCounts ? totalFor(section.scanners) : loaded.length;
    return { ...section, findings: loaded, total };
  }).filter((section) => section.total > 0);

  const ungrouped = findings.filter(
    (finding) => !groupedScannerNames.has(finding.scanner),
  );
  const ungroupedTotal = hasCounts
    ? Object.entries(scannerCounts)
        .filter(([scanner]) => !groupedScannerNames.has(scanner))
        .reduce((sum, [, count]) => sum + count, 0)
    : ungrouped.length;

  if (ungroupedTotal > 0) {
    sections.push({
      id: "OTHER",
      title: "Other Findings",
      scanners: [],
      description: "Findings from scanners that do not have a dedicated group",
      findings: ungrouped,
      total: ungroupedTotal,
    });
  }

  return sections;
}
