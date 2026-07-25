/**
 * Coverage-gap reporting for container image scanning.
 *
 * These tests mock child_process rather than relying on whether Trivy happens
 * to be installed on the host, so they behave identically on a developer laptop
 * and in the worker image (which bundles Trivy).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

type ExecCallback = (
  err: Error | null,
  result?: { stdout: string; stderr: string },
) => void;

/** Controls what the mocked `trivy` binary does for the current test. */
const trivyBehavior = {
  installed: false,
  scanResult: null as unknown,
  scanFails: false,
};

vi.mock("child_process", () => ({
  execFile: (
    _cmd: string,
    args: string[],
    _opts: unknown,
    callback?: ExecCallback,
  ) => {
    const cb = (typeof _opts === "function" ? _opts : callback) as ExecCallback;

    if (args[0] === "--version") {
      return trivyBehavior.installed
        ? cb(null, { stdout: "Version: 0.58.1\n", stderr: "" })
        : cb(new Error("spawn trivy ENOENT"));
    }

    if (trivyBehavior.scanFails) {
      return cb(new Error("failed to pull image: unauthorized"));
    }
    return cb(null, {
      stdout: JSON.stringify(trivyBehavior.scanResult ?? { Results: [] }),
      stderr: "",
    });
  },
}));

const { containerScanner } = await import("./index");

function makeWorkdir(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-coverage-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

const orgSettings = {
  llmProvider: "openai",
  llmBaseUrl: "",
  llmModel: "",
  enableLlmSast: false,
  enableLlmSecrets: false,
  osvApiUrl: "",
  vulnDbMode: "offline" as const,
};

async function scan(files: Record<string, string>) {
  const workDir = makeWorkdir(files);
  try {
    return await containerScanner.scan({
      workDir,
      fileList: Object.keys(files),
      scanType: "CONTAINER_ONLY",
      orgSettings,
    });
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

const DOCKERFILE = { Dockerfile: "FROM nginx:1.25\n" };

beforeEach(() => {
  trivyBehavior.installed = false;
  trivyBehavior.scanResult = null;
  trivyBehavior.scanFails = false;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("when Trivy is unavailable", () => {
  it("reports the coverage gap instead of silently finding nothing", async () => {
    const findings = await scan(DOCKERFILE);

    const gap = findings.filter(
      (f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE",
    );
    expect(gap).toHaveLength(1);
    expect(gap[0].severity).toBe("INFO");
    expect(gap[0].metadata?.category).toBe("SCAN_COVERAGE_GAP");
  });

  it("states that no findings does not mean the images are clean", async () => {
    const findings = await scan(DOCKERFILE);
    const gap = findings.find(
      (f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE",
    );
    expect(gap!.description).toMatch(/does NOT mean/i);
  });

  it("names the images that went unscanned", async () => {
    const findings = await scan({
      Dockerfile: "FROM nginx:1.25\n",
      "docker-compose.yml":
        "services:\n  api:\n    image: ghcr.io/acme/api:1.0.0\n",
    });

    const gap = findings.find(
      (f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE",
    );
    expect(gap!.metadata?.images).toContain("nginx:1.25");
    expect(gap!.metadata?.unscannedImageCount).toBeGreaterThanOrEqual(1);
  });

  it("emits one aggregated finding, not one per image", async () => {
    const findings = await scan({
      Dockerfile: "FROM nginx:1.25\nFROM redis:7\n",
      "docker-compose.yml":
        "services:\n  a:\n    image: ghcr.io/acme/a:1\n  b:\n    image: ghcr.io/acme/b:1\n",
    });

    expect(
      findings.filter((f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE"),
    ).toHaveLength(1);
  });

  it("does not report a gap when there are no scannable images", async () => {
    // An AMI reference is inventory only — no image CVE scan applies to it.
    const findings = await scan({
      "infra/main.tf":
        'resource "aws_instance" "web" {\n  ami = "ami-0abcdef1234567890"\n}\n',
    });

    expect(
      findings.filter((f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE"),
    ).toHaveLength(0);
  });

  it("does not report a gap when no images were discovered at all", async () => {
    const findings = await scan({ "src/index.ts": "console.log()\n" });
    expect(findings).toHaveLength(0);
  });
});

describe("when Trivy is available", () => {
  beforeEach(() => {
    trivyBehavior.installed = true;
  });

  it("does not report a scanner-unavailable gap", async () => {
    const findings = await scan(DOCKERFILE);
    expect(
      findings.filter((f) => f.ruleId === "CONTAINER-SCANNER-UNAVAILABLE"),
    ).toHaveLength(0);
  });

  it("reports images it could not pull as a coverage gap", async () => {
    trivyBehavior.scanFails = true;

    const findings = await scan(DOCKERFILE);

    const gap = findings.filter(
      (f) => f.ruleId === "CONTAINER-IMAGE-UNSCANNABLE",
    );
    expect(gap).toHaveLength(1);
    expect(gap[0].severity).toBe("INFO");
    expect(gap[0].description).toMatch(/NOT assessed/i);
    expect(gap[0].metadata?.images).toContain("nginx:1.25");
  });

  it("reports no gap when every image scans successfully", async () => {
    trivyBehavior.scanResult = { Results: [] };

    const findings = await scan(DOCKERFILE);

    expect(
      findings.filter((f) => f.metadata?.category === "SCAN_COVERAGE_GAP"),
    ).toHaveLength(0);
  });

  it("still emits CVE findings alongside coverage reporting", async () => {
    trivyBehavior.scanResult = {
      Results: [
        {
          Target: "nginx:1.25 (debian 12.4)",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2024-0001",
              PkgName: "openssl",
              InstalledVersion: "3.0.11",
              FixedVersion: "3.0.13",
              Severity: "HIGH",
              Title: "OpenSSL flaw",
            },
          ],
        },
      ],
    };

    const findings = await scan(DOCKERFILE);

    const cves = findings.filter((f) => f.cveId === "CVE-2024-0001");
    expect(cves).toHaveLength(1);
    expect(
      findings.filter((f) => f.metadata?.category === "SCAN_COVERAGE_GAP"),
    ).toHaveLength(0);
  });
});
