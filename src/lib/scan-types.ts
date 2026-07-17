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
      "Runs every enabled scanner: SAST, SCA, secrets, IaC, zero-day, container, and Kubernetes.",
  },
  {
    value: "INCREMENTAL",
    label: "PR Diff",
    description:
      "Scans only files changed in a pull request or between two commits. Supply a PR number or base SHA to diff against. Great for CI pipelines — surface new issues without re-triaging the full backlog.",
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
    description:
      "Container, serverless, and VM image artifact review (Trivy when available).",
  },
  {
    value: "K8S_ONLY",
    label: "Kubernetes",
    description:
      "Kubernetes manifest security analysis (Deployments, RBAC, NetworkPolicies, etc.). Requires LLM SAST.",
  },
] as const;


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
