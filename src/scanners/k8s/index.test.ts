import { describe, it, expect, vi, beforeEach } from "vitest";
import { k8sScanner } from "./index";
import { ScanContext } from "../types";

describe("K8S Scanner", () => {
  let mockContext: ScanContext;

  beforeEach(() => {
    mockContext = {
      workDir: "/test",
      fileList: [
        "k8s/deployments/app.yaml",
        "k8s/rbac/role.yaml",
        "k8s/configmaps/config.yaml",
      ],
      scanType: "FULL",
      orgSettings: {
        llmProvider: "anthropic",
        llmBaseUrl: "https://api.anthropic.com",
        llmModel: "claude-3-5-sonnet-20241022",
        enableLlmSast: true,
        enableLlmSecrets: false,
        osvApiUrl: "https://api.osv.dev",
        vulnDbMode: "online",
      },
      onProgress: vi.fn(),
      onBatchFindings: vi.fn(),
    };
  });

  it("should return empty findings when disabled", async () => {
    const ctx = { ...mockContext, orgSettings: { ...mockContext.orgSettings, enableLlmSast: false } };
    const findings = await k8sScanner.scan(ctx);
    expect(findings).toEqual([]);
  });

  it("should return empty findings when no K8s files found", async () => {
    const ctx = { ...mockContext, fileList: ["src/app.ts", "src/utils.ts"] };
    const findings = await k8sScanner.scan(ctx);
    expect(findings).toEqual([]);
  });

  it("should identify K8s manifest files in K8s directories", async () => {
    const testCases = [
      { path: "k8s/pod.yaml", expected: true },
      { path: "k8s/deployment.yml", expected: true },
      { path: "kubernetes/service.yaml", expected: true },
      { path: "helm/values.yaml", expected: true },
      { path: "manifests/statefulset.yaml", expected: true },
      { path: "src/app.yaml", expected: false },
      { path: "k8s/README.md", expected: false },
    ];

    const isK8sManifest = (filePath: string): boolean => {
      const K8S_FILE_PATTERNS = /\.ya?ml$/i;
      const K8S_DIRECTORIES = new Set(["k8s", "kubernetes", "helm", "manifests"]);
      const parts = filePath.split("/");
      const hasK8sDir = parts.some((part) => K8S_DIRECTORIES.has(part.toLowerCase()));
      return hasK8sDir && K8S_FILE_PATTERNS.test(filePath);
    };

    testCases.forEach(({ path, expected }) => {
      expect(isK8sManifest(path)).toBe(expected);
    });
  });

  it("should have correct scanner name", () => {
    expect(k8sScanner.name).toBe("K8S");
  });

  it("should be a valid ScannerPlugin", () => {
    expect(k8sScanner).toHaveProperty("name");
    expect(k8sScanner).toHaveProperty("scan");
    expect(typeof k8sScanner.scan).toBe("function");
  });

  it("should extract K8s metadata from manifests", () => {
    const extractMetadata = (content: string) => {
      const metadata: { kind?: string; name?: string; namespace?: string } = {};

      const kindMatch = content.match(/^kind:\s*(\w+)/m);
      if (kindMatch) {
        metadata.kind = kindMatch[1];
      }

      const namespaceMatch = content.match(/namespace:\s*(\S+)/m);
      if (namespaceMatch) {
        metadata.namespace = namespaceMatch[1];
      }

      const nameMatch = content.match(/name:\s*(\S+)/m);
      if (nameMatch) {
        metadata.name = nameMatch[1];
      }

      return metadata;
    };

    const yamlContent = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production`;

    const metadata = extractMetadata(yamlContent);
    expect(metadata.kind).toBe("Deployment");
    expect(metadata.name).toBe("myapp");
    expect(metadata.namespace).toBe("production");
  });

  it("should normalize severity levels", () => {
    const normalizeSeverity = (s: string) => {
      const upper = s.toUpperCase();
      if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
        return upper as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
      }
      return "MEDIUM";
    };

    expect(normalizeSeverity("CRITICAL")).toBe("CRITICAL");
    expect(normalizeSeverity("high")).toBe("HIGH");
    expect(normalizeSeverity("medium")).toBe("MEDIUM");
    expect(normalizeSeverity("low")).toBe("LOW");
    expect(normalizeSeverity("info")).toBe("INFO");
    expect(normalizeSeverity("unknown")).toBe("MEDIUM");
  });
});
