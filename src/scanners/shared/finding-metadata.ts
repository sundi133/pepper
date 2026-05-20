/** Standardized finding metadata across all scanners (backward-compatible via Record). */
export interface FindingMetadata {
  scanner?: string;
  category?: string;
  weaknessClass?: string;
  evidence?: string;
  attackPath?: string;
  stepsToReproduce?: string[];
  impact?: string;
  remediation?: string;
  validationSteps?: string[];
  affectedComponent?: string;
  route?: string;
  method?: string;
  parameter?: string;
  sink?: string;
  packageName?: string;
  packageVersion?: string;
  image?: string;
  fixedVersion?: string;
  confidenceReason?: string;
  /** Secrets-specific */
  credentialType?: string;
  maskedValue?: string;
  provider?: string;
  /** SCA-specific */
  ecosystem?: string;
  directDependency?: boolean;
  reachable?: boolean;
  exploitPreconditions?: string;
  /** IaC / container config */
  exposedAsset?: string;
  environment?: string;
  findingLayer?: string;
  /** DAST */
  url?: string;
  /** Dedupe helpers */
  duplicateGroup?: string;
  [key: string]: unknown;
}

export function mergeMetadata(
  base?: Record<string, unknown>,
  extra?: Partial<FindingMetadata>,
): Record<string, unknown> {
  return { ...(base || {}), ...(extra || {}) };
}
