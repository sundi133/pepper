import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { applyQualityGates } from "../shared/quality-gates";
import { getScanners } from "../index";
import {
  buildTrivyConfigArgs,
  loadIacPolicy,
  mapTrivyConfigResults,
  misconfigScannersFor,
  normalizeCheckId,
  runTrivyIacScanner,
  type TrivyConfigOutput,
  type TrivyMisconfig,
} from "./trivy-config";

const POLICY_FILE = path.join(process.cwd(), "rules", "trivy", "iac-policy.json");
const policy = loadIacPolicy(POLICY_FILE, {});

function m(id: string, severity: string, over: Partial<TrivyMisconfig> = {}): TrivyMisconfig {
  const { CauseMetadata: cause, ...rest } = over;
  return {
    ...rest,
    ID: id,
    Title: rest.Title ?? `Title ${id}`,
    Description: `Description ${id}`,
    Message: `Message ${id}`,
    Resolution: `Resolve ${id}`,
    Severity: severity,
    Status: rest.Status ?? "FAIL",
    References: [`https://avd.aquasec.com/misconfig/${id.toLowerCase()}`],
    CauseMetadata: {
      Resource: "aws_s3_bucket.data",
      StartLine: 3,
      EndLine: 5,
      Code: { Lines: [{ Number: 3, Content: "  privileged: true", IsCause: true }] },
      ...cause,
    },
  };
}

describe("IaC policy", () => {
  it("normalizes check ids across Trivy versions", () => {
    expect(normalizeCheckId("KSV017")).toBe("KSV-0017");
    expect(normalizeCheckId("aws-0107")).toBe("AWS-0107");
    expect(normalizeCheckId("DS-0002")).toBe("DS-0002");
  });

  it("loads the bundled policy with env overrides", () => {
    expect(policy.minSeverity).toBe("HIGH");
    expect(policy.excludeChecks.has("KSV-0118")).toBe(true);
    expect(policy.misconfigScanners).not.toContain("dockerfile");
    const custom = loadIacPolicy(POLICY_FILE, { IAC_MIN_SEVERITY: "medium", IAC_EXCLUDE_CHECKS: "AWS-0107, ksv9" });
    expect(custom.minSeverity).toBe("MEDIUM");
    expect(custom.excludeChecks.has("AWS-0107")).toBe(true);
    expect(custom.excludeChecks.has("KSV-0009")).toBe(true);
  });

  it("picks scanners by scan type", () => {
    expect(misconfigScannersFor("K8S_ONLY", policy)).toEqual(["kubernetes", "helm"]);
    expect(misconfigScannersFor("IAC_ONLY", policy)).not.toContain("kubernetes");
    expect(misconfigScannersFor("FULL", policy)).toEqual(policy.misconfigScanners);
  });

  it("runs offline without telemetry or version checks", () => {
    const args = buildTrivyConfigArgs({ policy, scanners: ["terraform"], outputFile: "/tmp/o.json", target: "." });
    for (const flag of ["--skip-check-update", "--disable-telemetry", "--skip-version-check"]) expect(args).toContain(flag);
    expect(args[args.indexOf("--severity") + 1]).toBe("LOW,MEDIUM,HIGH,CRITICAL");
  });
});

describe("mapTrivyConfigResults", () => {
  const output: TrivyConfigOutput = {
    Results: [
      {
        Target: "k8s/deploy.yaml",
        Type: "kubernetes",
        Misconfigurations: [
          m("KSV-0017", "HIGH", { Title: "Privileged", CauseMetadata: { Resource: "Deployment/api" } }),
          m("KSV-0118", "HIGH"),
          m("KSV-0011", "LOW"),
          m("KSV-0012", "HIGH", { Status: "PASS" }),
        ],
      },
      {
        Target: "tf/main.tf",
        Type: "terraform",
        Misconfigurations: [
          m("AWS-0107", "HIGH", { Title: "Unrestricted SSH ingress", CauseMetadata: { Resource: "aws_security_group.ssh", StartLine: 7, EndLine: 7 } }),
          m("AWS-0086", "HIGH"),
          m("AWS-0087", "HIGH"),
          m("AWS-0091", "HIGH"),
          m("AWS-0093", "HIGH"),
          m("AWS-0094", "LOW"),
        ],
      },
      { Target: "chart/templates/deployment.yaml", Type: "helm", Misconfigurations: [m("KSV-0017", "HIGH", { CauseMetadata: { Resource: "Deployment/web" } })] },
    ],
  };
  const findings = mapTrivyConfigResults(output, policy);

  it("keeps HIGH+ failures, drops excluded / below-threshold / passing checks", () => {
    expect(findings.map((f) => f.ruleId).sort()).toEqual(
      ["AWS-0107", "AWS-S3-PUBLIC-ACCESS-BLOCK", "KSV-0017", "KSV-0017"].sort(),
    );
  });

  it("routes Kubernetes/Helm to K8S and Terraform to IAC", () => {
    const byFile = Object.fromEntries(findings.map((f) => [f.filePath, f.scanner]));
    expect(byFile).toEqual({
      "k8s/deploy.yaml": "K8S",
      "chart/templates/deployment.yaml": "K8S",
      "tf/main.tf": "IAC",
    });
  });

  it("collapses the S3 public-access checks into one finding per bucket", () => {
    const g = findings.find((f) => f.ruleId === "AWS-S3-PUBLIC-ACCESS-BLOCK")!;
    expect(g.metadata).toMatchObject({ checkIds: ["AWS-0086", "AWS-0087", "AWS-0091", "AWS-0093", "AWS-0094"], resource: "aws_s3_bucket.data" });
    expect(g.description).toContain("**Fix:** Add an aws_s3_bucket_public_access_block");
  });

  it("carries a fix, the offending lines and the exact check as weakness class", () => {
    const f = findings.find((x) => x.ruleId === "AWS-0107")!;
    expect(f).toMatchObject({ severity: "HIGH", startLine: 7, snippet: "3:   privileged: true", confidence: 0.95 });
    expect(f.description).toContain("**Fix:** Resolve AWS-0107");
    expect(f.metadata).toMatchObject({ engine: "trivy", weaknessClass: "AWS-0107", resource: "aws_security_group.ssh" });
  });

  it("passes the IaC / K8S quality gates", () => {
    expect(applyQualityGates(findings)).toHaveLength(findings.length);
  });
});

describe("scanner registration", () => {
  const off = { enableLlmSast: false, enableLlmSecrets: false };
  it("runs rule-based IaC even when LLM analysis is off", () => {
    for (const t of ["FULL", "IAC_ONLY", "K8S_ONLY"]) {
      expect(getScanners(t, off).map((s) => s.name)).toContain("IAC_RULES");
    }
    expect(getScanners("SCA_ONLY", off).map((s) => s.name)).not.toContain("IAC_RULES");
  });
});

// End-to-end with the real binary (skipped when Trivy isn't installed).
const TRIVY = process.env.TRIVY_BIN || "trivy";
const hasTrivy = spawnSync(TRIVY, ["--version"], { encoding: "utf8" }).status === 0;

describe.skipIf(!hasTrivy)("trivy config end-to-end", () => {
  it("finds Terraform, Kubernetes and rendered Helm misconfigurations offline", async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "iac-e2e-"));
    const w = (p: string, s: string) => {
      fs.mkdirSync(path.dirname(path.join(work, p)), { recursive: true });
      fs.writeFileSync(path.join(work, p), s);
    };
    w("infra/main.tf", 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n  instance_class = "db.t3.micro"\n  publicly_accessible = true\n}\n');
    w("deploy/api.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: api\nspec:\n  hostNetwork: true\n  containers:\n    - name: api\n      image: acme/api:1.0\n");
    w("charts/web/Chart.yaml", "apiVersion: v2\nname: web\nversion: 0.1.0\n");
    w("charts/web/values.yaml", "privileged: true\n");
    w(
      "charts/web/templates/pod.yaml",
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: nginx:1.25\n      securityContext:\n        privileged: {{ .Values.privileged }}\n",
    );
    const findings = await runTrivyIacScanner({
      workDir: work,
      fileList: [],
      scanType: "FULL",
      orgSettings: { llmProvider: "", llmBaseUrl: "", llmModel: "", enableLlmSast: false, enableLlmSecrets: false, osvApiUrl: "", vulnDbMode: "offline" },
    });
    fs.rmSync(work, { recursive: true });
    const got = findings.map((f) => `${f.scanner} ${f.ruleId} ${f.filePath}`).sort();
    expect(got).toContain("IAC AWS-0180 infra/main.tf");
    expect(got).toContain("K8S KSV-0009 deploy/api.yaml");
    expect(got.some((g) => g.startsWith("K8S KSV-0017 charts/web"))).toBe(true);
    expect(got.some((g) => g.includes("KSV-0118"))).toBe(false);
  }, 180_000);
});
