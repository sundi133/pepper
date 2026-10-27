import type { ScanJobData } from "@/lib/queue";

/**
 * Scanner groups a user can combine on one scan. Each maps to the existing
 * single-module scan type `<id>_ONLY`; a scan running some but not all of them
 * is stored as FULL (or INCREMENTAL) plus `Scan.scanModules`.
 */
export const SCAN_MODULES = [
  {
    id: "SAST",
    label: "SAST",
    description: "Source-code vulnerabilities: AI code review plus rule-based patterns.",
    needsAi: false,
  },
  {
    id: "SCA",
    label: "SCA",
    description: "Vulnerable dependencies and malicious packages.",
    needsAi: false,
  },
  {
    id: "SECRETS",
    label: "Secrets",
    description: "Leaked credentials: pattern matching, plus AI review when enabled.",
    needsAi: false,
  },
  {
    id: "IAC",
    label: "IaC",
    description:
      "Infrastructure-as-code misconfigurations (Terraform, CloudFormation, Helm). Rule-based checks always run; AI review needs LLM SAST.",
    needsAi: false,
  },
  {
    id: "ZERO_DAY",
    label: "Zero-day",
    description: "Cross-file business-logic and exploit-chain analysis.",
    needsAi: true,
  },
  {
    id: "CONTAINER",
    label: "Container",
    description: "Dockerfiles and container image review (Trivy when available).",
    needsAi: false,
  },
  {
    id: "K8S",
    label: "Kubernetes",
    description:
      "Kubernetes manifests (Deployments, RBAC, NetworkPolicies). Rule-based checks always run; AI review needs LLM SAST.",
    needsAi: false,
  },
] as const;

export type ScanModuleId = (typeof SCAN_MODULES)[number]["id"];

export const SCAN_MODULE_IDS = SCAN_MODULES.map((m) => m.id) as ScanModuleId[];

const MODULE_LABEL = Object.fromEntries(SCAN_MODULES.map((m) => [m.id, m.label])) as Record<
  ScanModuleId,
  string
>;

function onlyTypeFor(id: ScanModuleId): ScanJobData["scanType"] {
  return `${id}_ONLY` as ScanJobData["scanType"];
}

/** The module a `<id>_ONLY` scan type runs, if it is one. */
function moduleOfOnlyType(scanType: string): ScanModuleId | undefined {
  const id = scanType.endsWith("_ONLY") ? scanType.slice(0, -"_ONLY".length) : "";
  return (SCAN_MODULE_IDS as string[]).includes(id) ? (id as ScanModuleId) : undefined;
}

/**
 * Canonical form of a user's selection. One module becomes its `_ONLY` type
 * and every module becomes plain FULL, so existing scans, reports and filters
 * keep working; only a genuine combination carries `scanModules`. A changed-
 * files (INCREMENTAL) scan keeps its type and narrows by modules.
 */
export function normalizeScanSelection(
  scanType: ScanJobData["scanType"],
  scanModules?: readonly string[] | null,
): { scanType: ScanJobData["scanType"]; scanModules: ScanModuleId[] } {
  const picked = SCAN_MODULE_IDS.filter((id) => scanModules?.includes(id));
  if (picked.length === 0 || picked.length === SCAN_MODULE_IDS.length) {
    return { scanType, scanModules: [] };
  }
  if (scanType === "INCREMENTAL") return { scanType, scanModules: picked };
  if (picked.length === 1) return { scanType: onlyTypeFor(picked[0]), scanModules: [] };
  return { scanType: "FULL", scanModules: picked };
}

/** Whether a scan of this type and module list runs the given module. */
export function scanIncludesModule(
  scanType: string,
  scanModules: readonly string[] | null | undefined,
  module: ScanModuleId,
): boolean {
  if (scanModules && scanModules.length > 0) return scanModules.includes(module);
  if (scanType === "FULL" || scanType === "INCREMENTAL") return true;
  return moduleOfOnlyType(scanType) === module;
}

/** The modules a scan runs, in display order. */
export function selectedScanModules(
  scanType: string,
  scanModules?: readonly string[] | null,
): ScanModuleId[] {
  return SCAN_MODULE_IDS.filter((id) => scanIncludesModule(scanType, scanModules, id));
}

/** Human label for a scan's mode, e.g. "All scanners", "SAST + Secrets", "PR Diff · SCA". */
export function scanModeLabel(scanType: string, scanModules?: readonly string[] | null): string {
  const modules = selectedScanModules(scanType, scanModules);
  const names =
    modules.length === SCAN_MODULE_IDS.length
      ? "All scanners"
      : modules.map((id) => MODULE_LABEL[id]).join(" + ");
  if (scanType === "INCREMENTAL") {
    return modules.length === SCAN_MODULE_IDS.length ? "PR Diff" : `PR Diff · ${names}`;
  }
  return names || scanType;
}

/** Scan types users can pick on New Scan (webhooks may still use INCREMENTAL internally). */
export const MANUAL_SCAN_TYPE_OPTIONS: ReadonlyArray<{
  value: ScanJobData["scanType"];
  label: string;
  description: string;
}> = [
  {
    value: "FULL",
    label: "All",
    description:
      "Runs every enabled scanner: SAST, SCA, secrets, IaC, zero-day, container, and Kubernetes.",
  },
  {
    value: "INCREMENTAL",
    label: "PR Diff",
    description:
      "Scans only files changed in a pull request or between two commits. Supply a PR number or base SHA to diff against. Great for CI pipelines: surface new issues without re-triaging the full backlog.",
  },
  ...SCAN_MODULES.map((m) => ({
    value: onlyTypeFor(m.id),
    label: m.label,
    description: m.description,
  })),
];

export const API_CREATE_SCAN_TYPES = [
  "FULL",
  "INCREMENTAL",
  "SAST_ONLY",
  "SCA_ONLY",
  "SECRETS_ONLY",
  "IAC_ONLY",
  "ZERO_DAY_ONLY",
  "CONTAINER_ONLY",
  "K8S_ONLY",
] as const satisfies readonly ScanJobData["scanType"][];

/**
 * Parse the optional body of a rescan request.
 *
 * A rescan with no body reuses the original scan's type, which is the
 * historical behaviour. A body may specify `scanType` to change the depth —
 * typically FULL, to pick up SCA, SBOM and VEX on a project whose last scan
 * used a narrower mode.
 */
export function parseRescanBody(
  rawBody: string,
):
  | { ok: true; scanType?: ScanJobData["scanType"]; scanModules?: string[] }
  | { ok: false; error: string } {
  if (!rawBody || !rawBody.trim()) return { ok: true };

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return { ok: false, error: "Invalid request body" };
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "Invalid request body" };
  }

  const rawModules = (parsed as { scanModules?: unknown }).scanModules;
  if (
    rawModules !== undefined &&
    (!Array.isArray(rawModules) ||
      !rawModules.every((m) => (SCAN_MODULE_IDS as string[]).includes(m)))
  ) {
    return { ok: false, error: "Invalid scanModules" };
  }
  const scanModules = rawModules as string[] | undefined;

  const value = (parsed as { scanType?: unknown }).scanType;
  // An explicitly absent scanType is valid and means "reuse the original".
  if (value === undefined || value === null) return { ok: true, scanModules };

  if (
    typeof value !== "string" ||
    !(API_CREATE_SCAN_TYPES as readonly string[]).includes(value)
  ) {
    return { ok: false, error: "Invalid scanType" };
  }

  return { ok: true, scanType: value as ScanJobData["scanType"], scanModules };
}
