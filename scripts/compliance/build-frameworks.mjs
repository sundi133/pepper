#!/usr/bin/env node
/**
 * Regenerate the requirement-level compliance catalogs in compliance/ from
 * their upstream sources:
 *
 *   OWASP ASVS 4.0.3 (CC BY-SA 4.0)   OWASP/ASVS@v4.0.3
 *     4.0/docs_en/OWASP Application Security Verification Standard 4.0.3-en.flat.json
 *   CIS mappings (MIT)                aquasecurity/trivy-checks
 *     pkg/compliance/{k8s-cis-1.23,eks-cis-1.4,aws-cis-1.4}.yaml
 *
 * Usage:
 *   scripts/compliance/fetch-sources.sh <dir>        # or download by hand
 *   node scripts/compliance/build-frameworks.mjs <dir> [trivy-checks-sha]
 *
 * Output is deterministic, so regenerating from the same sources is a no-op.
 */
import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const [srcDir, trivySha = "main"] = process.argv.slice(2);
if (!srcDir) {
  console.error("usage: build-frameworks.mjs <source-dir> [trivy-checks-sha]");
  process.exit(1);
}
const outDir = path.join(process.cwd(), "compliance");
const write = (file, data) => {
  fs.writeFileSync(path.join(outDir, file), JSON.stringify(data, null, 2) + "\n");
  console.log(`wrote compliance/${file}: ${data.controls.length} controls`);
};

// ─── OWASP ASVS 4.0.3 ────────────────────────────────────────────────────────

/** Chapters whose requirements are about design / process rather than code. */
const ASVS_DESIGN_CHAPTERS = new Set(["V1"]);

function cleanAsvsText(s) {
  return s
    .replace(/\s*\(\[C\d+\]\([^)]*\)(,\s*\[C\d+\]\([^)]*\))*\)/g, "") // proactive-control refs
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1") // other markdown links → text
    .replace(/\s+/g, " ")
    .trim();
}

function shortTitle(text) {
  // First sentence, not fooled by "e.g." / "i.e." / "etc.".
  const firstSentence = text.split(/(?<!\b(?:e\.g|i\.e|etc|vs)\.)(?<=\.)\s+(?=[A-Z(])/)[0];
  const t = firstSentence.length <= 160 ? firstSentence : `${text.slice(0, 157).trimEnd()}…`;
  return t.replace(/\.$/, "");
}

function buildAsvs() {
  const src = JSON.parse(fs.readFileSync(path.join(srcDir, "asvs-4.0.3.flat.json"), "utf8"));
  // The standard keeps numbered "[DELETED, …]" placeholders; they aren't requirements.
  const active = src.requirements.filter((r) => !/^\[DELETED/i.test(r.req_description.trim()));
  const controls = active.map((r) => {
    const text = cleanAsvsText(r.req_description);
    const cwe = String(r.cwe ?? "").trim();
    const levels = [r.level1, r.level2, r.level3].map((v, i) => (String(v).trim() ? i + 1 : 0)).filter(Boolean);
    const coverage = !cwe ? "not-assessable" : ASVS_DESIGN_CHAPTERS.has(r.chapter_id) ? "partial" : "assessable";
    return {
      controlId: r.req_id,
      chunkId: `ASVS-4.0.3-${r.req_id}`,
      type: "ASVS_Requirement",
      theme: `${r.chapter_id} ${r.chapter_name}`,
      subclause: `${r.section_id} ${r.section_name}`,
      title: shortTitle(text),
      summary: text,
      levels,
      coverage,
      cweMapping: cwe ? [`CWE-${cwe.replace(/\D/g, "")}`] : [],
      implementationChecklist: [],
      evidenceExamples: [],
    };
  });
  write("OWASP_ASVS.json", {
    name: "OWASP ASVS",
    version: "4.0.3",
    revision: "4.0.3-requirements",
    fileName: "OWASP_ASVS.json",
    source: "OWASP Application Security Verification Standard 4.0.3, https://github.com/OWASP/ASVS (tag v4.0.3)",
    license: "CC BY-SA 4.0 — © OWASP Foundation. Requirement text unchanged except markdown links removed; this file is shared under the same license.",
    mapping: "Official per-requirement CWE from ASVS 4.0.3. Levels: 1 = L1, 2 = L2, 3 = L3. Requirements the standard marks [DELETED] are omitted.",
    controls,
  });
}

// ─── CIS (via trivy-checks compliance specs) ────────────────────────────────

const CIS_SECTIONS = {
  k8s: {
    "1.1": "Control Plane Node Configuration Files",
    "1.2": "API Server",
    "1.3": "Controller Manager",
    "1.4": "Scheduler",
    "2": "etcd",
    "3.1": "Authentication and Authorization",
    "3.2": "Logging",
    "4.1": "Worker Node Configuration Files",
    "4.2": "Kubelet",
    "5.1": "RBAC and Service Accounts",
    "5.2": "Pod Security Standards",
    "5.3": "Network Policies and CNI",
    "5.4": "Secrets Management",
    "5.5": "Extensible Admission Control",
    "5.7": "General Policies",
  },
  eks: {
    "2.1": "Logging",
    "3.1": "Worker Node Configuration Files",
    "3.2": "Kubelet",
    "4.1": "RBAC and Service Accounts",
    "4.2": "Pod Security Standards",
    "4.3": "CNI Plugin",
    "4.4": "Secrets Management",
    "4.5": "Extensible Admission Control",
    "4.6": "General Policies",
    "5.1": "Image Registry and Image Scanning",
    "5.2": "Identity and Access Management (IAM)",
    "5.3": "AWS EKS Key Management Service",
    "5.4": "Cluster Networking",
    "5.5": "Authentication and Authorization",
    "5.6": "Other Cluster Configurations",
  },
  aws: {
    "1": "Identity and Access Management",
    "2.1": "Simple Storage Service (S3)",
    "2.2": "Elastic Compute Cloud (EC2)",
    "2.3": "Relational Database Service (RDS)",
    "3": "Logging",
    "4": "Monitoring",
    "5": "Networking",
  },
};

function sectionFor(kind, id) {
  const parts = String(id).split(".");
  for (let n = parts.length; n > 0; n--) {
    const key = parts.slice(0, n).join(".");
    if (CIS_SECTIONS[kind][key] && key !== String(id)) return `${key} ${CIS_SECTIONS[kind][key]}`;
  }
  const top = parts[0];
  return CIS_SECTIONS[kind][top] ? `${top} ${CIS_SECTIONS[kind][top]}` : `Section ${top}`;
}

/**
 * CIS AWS Foundations 1.4 controls that Terraform / CloudFormation can show,
 * which Trivy's spec (written for live-account scans) leaves out. Pepper's own
 * mapping; every check id was confirmed against `trivy config` output.
 */
const AWS_IAC_SUPPLEMENT = [
  { id: "2.1.5", name: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'", checks: ["AWS-0086", "AWS-0087", "AWS-0091", "AWS-0093", "AWS-0094"] },
  { id: "2.2.1", name: "Ensure EBS volume encryption is enabled", checks: ["AWS-0026", "AWS-0131"] },
  { id: "2.3.1", name: "Ensure that encryption is enabled for RDS Instances", checks: ["AWS-0079", "AWS-0080"] },
  { id: "3.1", name: "Ensure CloudTrail is enabled in all regions", checks: ["AWS-0014"] },
  { id: "3.2", name: "Ensure CloudTrail log file validation is enabled", checks: ["AWS-0016"] },
  { id: "3.7", name: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", checks: ["AWS-0015"] },
  { id: "3.9", name: "Ensure VPC flow logging is enabled in all VPCs", checks: ["AWS-0178"] },
  { id: "5.2", name: "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports", checks: ["AWS-0107"] },
];

const normalizeCheck = (id) => String(id).trim().toUpperCase().replace(/^AVD-/, "");
const idSort = (a, b) => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? -1) - (pb[i] ?? -1);
    if (d) return d;
  }
  return 0;
};

/**
 * One CIS benchmark. Controls backed by checks Pepper's IaC scan runs on code
 * (`codePrefixes`) map deterministically by rule id; everything else (node
 * files, cluster flags, account settings) needs a live environment and is
 * reported as not assessable from code.
 */
function buildCis({ file, kind, name, version, out, codePrefixes, partial, supplement = [] }) {
  const spec = yaml.load(fs.readFileSync(path.join(srcDir, file), "utf8")).spec;
  const byId = new Map();
  const supplemented = new Set();
  for (const s of supplement) {
    if (spec.controls.some((c) => String(c.id) === s.id)) continue;
    spec.controls.push({ id: s.id, name: s.name, description: s.name, checks: s.checks.map((id) => ({ id })) });
    supplemented.add(s.id);
  }
  for (const c of spec.controls) {
    const id = String(c.id);
    const prev = byId.get(id);
    const checks = (c.checks ?? []).map((k) => normalizeCheck(k.id));
    if (prev) {
      prev.checks.push(...checks);
      continue;
    }
    byId.set(id, { id, name: String(c.name).replace(/\s+/g, " ").trim(), description: String(c.description ?? c.name).replace(/\s+/g, " ").trim(), checks });
  }
  const controls = [...byId.values()]
    .sort((a, b) => idSort(a.id, b.id))
    .map((c) => {
      const ruleMapping = [...new Set(c.checks.filter((k) => codePrefixes.some((p) => k.startsWith(`${p}-`))))].sort();
      const manual = /\(Manual\)/i.test(c.name);
      return {
        controlId: c.id,
        chunkId: `${out.replace(/\.json$/, "")}-${c.id}`,
        type: "CIS_Benchmark",
        theme: sectionFor(kind, c.id),
        title: c.name.replace(/^Ensure (that )?/i, (m) => m).replace(/\s*\((Manual|Automated)\)$/i, ""),
        summary: c.description,
        coverage: ruleMapping.length ? (partial ? "partial" : "assessable") : "not-assessable",
        ruleMapping,
        ...(manual ? { assessment: "manual" } : {}),
        ...(supplemented.has(c.id) ? { mappingSource: "pepper" } : {}),
        implementationChecklist: [],
        evidenceExamples: ruleMapping.length ? [`Pepper IaC checks: ${ruleMapping.join(", ")}`] : [],
      };
    });
  write(out, {
    name,
    version,
    fileName: out,
    source: `Control ids, titles and check mappings from aquasecurity/trivy-checks pkg/compliance/${file} (MIT) @ ${trivySha}`,
    license: "Mapping data MIT (Aqua Security). CIS® and CIS Benchmarks® are trademarks of the Center for Internet Security; the full benchmark text is available from cisecurity.org.",
    mapping: `Deterministic by rule id for checks Pepper runs on code (${codePrefixes.join(", ")}). Other controls need a running cluster / account and are listed as not assessable from code.${
      supplemented.size ? ` Controls marked mappingSource "pepper" (${[...supplemented].join(", ")}) are Pepper's IaC mapping, not part of the upstream spec.` : ""
    }`,
    controls,
  });
}

buildAsvs();
buildCis({ file: "k8s-cis-1.23.yaml", kind: "k8s", name: "CIS Kubernetes Benchmark", version: "1.23", out: "CIS_Kubernetes_Benchmark.json", codePrefixes: ["KSV"] });
buildCis({ file: "eks-cis-1.4.yaml", kind: "eks", name: "CIS Amazon EKS Benchmark", version: "1.4", out: "CIS_EKS_Benchmark.json", codePrefixes: ["KSV", "AWS"], partial: true });
buildCis({ file: "aws-cis-1.4.yaml", kind: "aws", name: "CIS AWS Foundations Benchmark", version: "1.4", out: "CIS_AWS_Foundations_Benchmark.json", codePrefixes: ["AWS"], partial: true, supplement: AWS_IAC_SUPPLEMENT });
