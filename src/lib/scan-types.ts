import type { ScanJobData } from "@/lib/queue";

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
      "Runs every enabled scanner: SAST, SCA, secrets, IaC, zero-day, container, and DAST.",
  },
  {
    value: "SAST_ONLY",
    label: "SAST",
    description: "LLM source-code analysis only.",
  },
  {
    value: "SCA_ONLY",
    label: "SCA",
    description: "Dependency vulnerabilities and malicious package checks.",
  },
  {
    value: "SECRETS_ONLY",
    label: "Secrets",
    description: "AI review for leaked credentials in source files.",
  },
  {
    value: "IAC_ONLY",
    label: "IaC",
    description:
      "Infrastructure-as-code misconfigurations (Terraform, K8s, CloudFormation, etc.). Requires LLM SAST.",
  },
  {
    value: "ZERO_DAY_ONLY",
    label: "Zero-day",
    description:
      "Cross-file business-logic and exploit-chain analysis. Requires LLM SAST.",
  },
  {
    value: "CONTAINER_ONLY",
    label: "Container",
    description: "Dockerfile and image vulnerability review (Trivy when available).",
  },
  {
    value: "DAST_ONLY",
    label: "DAST",
    description: "Dynamic testing against the project DAST target URL.",
  },
] as const;

export const API_CREATE_SCAN_TYPES = [
  "FULL",
  "SAST_ONLY",
  "SCA_ONLY",
  "SECRETS_ONLY",
  "IAC_ONLY",
  "ZERO_DAY_ONLY",
  "CONTAINER_ONLY",
  "DAST_ONLY",
] as const satisfies readonly ScanJobData["scanType"][];
