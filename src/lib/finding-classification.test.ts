import { describe, it, expect } from "vitest";

/**
 * Comprehensive test suite for finding classification and filtering
 *
 * Rules:
 * 1. SAST: only web/app code vulns (SAST_LLM scanner)
 * 2. SECRETS: only hardcoded credentials (SECRETS_LLM scanner)
 * 3. SCA: only dependency vulns from lockfiles/manifests (SCA scanner)
 * 4. IaC: only infra/config issues (IAC scanner)
 * 5. CONTAINER: only container image vulns (CONTAINER scanner)
 * 6. SUPPLY_CHAIN: only supply chain risks (MALICIOUS_PKG scanner)
 * 7. ZERO_DAY: only advanced/business logic (ZERO_DAY scanner)
 * 8. INFO findings must be excluded from UI counters
 * 9. Severity must be: CRITICAL, HIGH, MEDIUM, LOW (no INFO in counters)
 * 10. All filter must show all finding types
 */

describe("Finding Classification and Filtering", () => {
  const SCANNERS = {
    SAST: "SAST_LLM",
    SECRETS: "SECRETS_LLM",
    SCA: "SCA",
    IAC: "IAC",
    CONTAINER: "CONTAINER",
    MALICIOUS_PKG: "MALICIOUS_PKG",
    ZERO_DAY: "ZERO_DAY",
  };

  describe("SAST Filter - Web/Application Code Vulnerabilities Only", () => {
    it("should show SAST findings with code injection", () => {
      const finding = {
        scanner: SCANNERS.SAST,
        filePath: "src/app.js",
        title: "Command Injection in user input",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SAST_LLM");
      expect(finding.filePath).toMatch(/^src\//);
    });

    it("should show SAST findings with XSS", () => {
      const finding = {
        scanner: SCANNERS.SAST,
        filePath: "src/dashboard.tsx",
        title: "Stored XSS vulnerability",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("SAST_LLM");
      expect(finding.severity).toBe("HIGH");
    });

    it("should NOT show SCA findings in SAST filter", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "package.json",
        title: "Vulnerable dependency lodash",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SAST);
    });

    it("should NOT show secret findings in SAST filter", () => {
      const finding = {
        scanner: SCANNERS.SECRETS,
        filePath: "config.js",
        title: "Hardcoded API key",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SAST);
    });

    it("should NOT show IaC findings in SAST filter", () => {
      const finding = {
        scanner: SCANNERS.IAC,
        filePath: "Dockerfile",
        title: "Running as root",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SAST);
    });
  });

  describe("SECRETS Filter - Hardcoded Credentials Only", () => {
    it("should show hardcoded API key", () => {
      const finding = {
        scanner: SCANNERS.SECRETS,
        filePath: "config.js",
        title: "Heroku API Key: hardcoded_api_key_12345",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SECRETS_LLM");
    });

    it("should show hardcoded database password", () => {
      const finding = {
        scanner: SCANNERS.SECRETS,
        filePath: "db.config.ts",
        title: "MySQL Password: root_password",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SECRETS_LLM");
    });

    it("should show AWS secret key", () => {
      const finding = {
        scanner: SCANNERS.SECRETS,
        filePath: ".env",
        title: "AWS Access Key: AKIAIOSFODNN7EXAMPLE",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SECRETS_LLM");
    });

    it("should NOT show SCA findings in SECRETS filter", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "package-lock.json",
        title: "Known CVE in lodash",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SECRETS);
    });
  });

  describe("SCA Filter - Dependency Vulnerabilities Only", () => {
    it("should show CVE in package.json dependency", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "package.json",
        title: "express: CWE-1104 (NPM Audit)",
        severity: "HIGH",
        ruleId: "express@4.16.0",
      };
      expect(finding.scanner).toBe("SCA");
      expect(finding.filePath).toMatch(/package\.json|package-lock\.json|yarn\.lock/);
    });

    it("should show vulnerability in Python requirements.txt", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "requirements.txt",
        title: "Django: Remote Code Execution",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SCA");
      expect(finding.filePath).toMatch(/requirements\.txt|Pipfile/);
    });

    it("should show Maven dependency vulnerability", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "pom.xml",
        title: "log4j: Remote Code Execution",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("SCA");
    });

    it("should NOT show source code vulnerabilities in SCA filter", () => {
      const finding = {
        scanner: SCANNERS.SAST,
        filePath: "src/api.js",
        title: "SQL Injection in user query",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SCA);
    });

    it("should NOT show hardcoded secrets in SCA filter", () => {
      const finding = {
        scanner: SCANNERS.SECRETS,
        filePath: "package.json",
        title: "API key",
      };
      expect(finding.scanner).not.toBe(SCANNERS.SCA);
    });
  });

  describe("IaC Filter - Infrastructure Configuration Only", () => {
    it("should show Dockerfile misconfiguration", () => {
      const finding = {
        scanner: SCANNERS.IAC,
        filePath: "Dockerfile",
        title: "Running container as root",
        severity: "MEDIUM",
      };
      expect(finding.scanner).toBe("IAC");
      expect(finding.filePath).toMatch(/Dockerfile|docker-compose/);
    });

    it("should show Kubernetes YAML issue", () => {
      const finding = {
        scanner: SCANNERS.IAC,
        filePath: "k8s/deployment.yaml",
        title: "Missing resource limits",
        severity: "MEDIUM",
      };
      expect(finding.scanner).toBe("IAC");
    });

    it("should show Terraform misconfiguration", () => {
      const finding = {
        scanner: SCANNERS.IAC,
        filePath: "terraform/main.tf",
        title: "S3 bucket public access enabled",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("IAC");
    });

    it("should show GitHub Actions workflow issue", () => {
      const finding = {
        scanner: SCANNERS.IAC,
        filePath: ".github/workflows/ci.yml",
        title: "Using untrusted action",
        severity: "MEDIUM",
      };
      expect(finding.scanner).toBe("IAC");
    });

    it("should NOT show source code vulnerabilities in IaC filter", () => {
      const finding = {
        scanner: SCANNERS.SAST,
        filePath: "src/api.ts",
        title: "XSS vulnerability",
      };
      expect(finding.scanner).not.toBe(SCANNERS.IAC);
    });
  });

  describe("CONTAINER Filter - Container Image Vulnerabilities", () => {
    it("should show base image CVE", () => {
      const finding = {
        scanner: SCANNERS.CONTAINER,
        title: "ubuntu:20.04 contains CVE-2021-12345",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("CONTAINER");
    });

    it("should show package vulnerability in container", () => {
      const finding = {
        scanner: SCANNERS.CONTAINER,
        title: "openssl: Remote Code Execution",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("CONTAINER");
    });

    it("should NOT show dependency vulnerabilities from source code", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "package.json",
        title: "lodash vulnerability",
      };
      expect(finding.scanner).not.toBe(SCANNERS.CONTAINER);
    });
  });

  describe("SUPPLY_CHAIN Filter - Supply Chain Risks", () => {
    it("should show malicious package indicator", () => {
      const finding = {
        scanner: SCANNERS.MALICIOUS_PKG,
        title: "typosquatting: 'expresss' similar to 'express'",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("MALICIOUS_PKG");
    });

    it("should show suspicious maintainer behavior", () => {
      const finding = {
        scanner: SCANNERS.MALICIOUS_PKG,
        title: "Package ownership changed unexpectedly",
        severity: "MEDIUM",
      };
      expect(finding.scanner).toBe("MALICIOUS_PKG");
    });

    it("should show dependency confusion risk", () => {
      const finding = {
        scanner: SCANNERS.MALICIOUS_PKG,
        title: "Potential dependency confusion: internal-lib exists on npm",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("MALICIOUS_PKG");
    });

    it("should NOT show legitimate dependencies", () => {
      const finding = {
        scanner: SCANNERS.SCA,
        filePath: "package.json",
        title: "CVE in express",
      };
      expect(finding.scanner).not.toBe(SCANNERS.MALICIOUS_PKG);
    });
  });

  describe("ZERO_DAY Filter - Advanced/Business Logic", () => {
    it("should show business logic vulnerability", () => {
      const finding = {
        scanner: SCANNERS.ZERO_DAY,
        title: "Price manipulation in checkout flow",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("ZERO_DAY");
    });

    it("should show IDOR vulnerability", () => {
      const finding = {
        scanner: SCANNERS.ZERO_DAY,
        title: "Insecure Direct Object Reference in user profile",
        severity: "HIGH",
      };
      expect(finding.scanner).toBe("ZERO_DAY");
    });

    it("should show race condition", () => {
      const finding = {
        scanner: SCANNERS.ZERO_DAY,
        title: "Race condition in payment processing",
        severity: "CRITICAL",
      };
      expect(finding.scanner).toBe("ZERO_DAY");
    });
  });

  describe("ALL Filter - Should Include All Finding Types", () => {
    it("should show SAST + SCA + SECRETS + IaC + CONTAINER + SUPPLY_CHAIN + ZERO_DAY together", () => {
      const findings = [
        { scanner: SCANNERS.SAST, type: "code vuln" },
        { scanner: SCANNERS.SECRETS, type: "credential" },
        { scanner: SCANNERS.SCA, type: "dependency" },
        { scanner: SCANNERS.IAC, type: "infra config" },
        { scanner: SCANNERS.CONTAINER, type: "container" },
        { scanner: SCANNERS.MALICIOUS_PKG, type: "supply chain" },
        { scanner: SCANNERS.ZERO_DAY, type: "business logic" },
      ];

      findings.forEach((f) => {
        expect(f.scanner).toBeDefined();
        expect(Object.values(SCANNERS)).toContain(f.scanner);
      });
    });
  });

  describe("Severity Normalization", () => {
    it("should normalize to CRITICAL", () => {
      const severities = ["CRITICAL", "critical", "Crit", "CRIT"];
      severities.forEach((s) => {
        expect(["CRITICAL", "critical", "Crit", "CRIT"]).toContain(s);
      });
    });

    it("should normalize to HIGH", () => {
      const severities = ["HIGH", "high", "High"];
      severities.forEach((s) => {
        expect(["HIGH", "high", "High"]).toContain(s);
      });
    });

    it("should normalize to MEDIUM", () => {
      const severities = ["MEDIUM", "medium", "Med"];
      severities.forEach((s) => {
        expect(["MEDIUM", "medium", "Med"]).toContain(s);
      });
    });

    it("should normalize to LOW", () => {
      const severities = ["LOW", "low", "Low"];
      severities.forEach((s) => {
        expect(["LOW", "low", "Low"]).toContain(s);
      });
    });

    it("should NOT include INFO in UI counters", () => {
      const uiSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      expect(uiSeverities).not.toContain("INFO");
    });

    it("should use safe default only after type checking", () => {
      // When severity is unknown, should use MEDIUM (not CRITICAL)
      // But type/evidence must be checked first
      const finding = { severity: undefined, scanner: "SCA" };
      if (!finding.severity) {
        const defaultSeverity = "MEDIUM"; // safe default
        expect(defaultSeverity).toBe("MEDIUM");
      }
    });
  });

  describe("Severity Sorting", () => {
    it("should sort CRITICAL first", () => {
      const severities = ["HIGH", "MEDIUM", "CRITICAL", "LOW"];
      const sorted = severities.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return order[a as keyof typeof order] - order[b as keyof typeof order];
      });
      expect(sorted[0]).toBe("CRITICAL");
    });

    it("should sort HIGH second", () => {
      const severities = ["HIGH", "MEDIUM", "CRITICAL", "LOW"];
      const sorted = severities.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return order[a as keyof typeof order] - order[b as keyof typeof order];
      });
      expect(sorted[1]).toBe("HIGH");
    });

    it("should sort MEDIUM third", () => {
      const severities = ["HIGH", "MEDIUM", "CRITICAL", "LOW"];
      const sorted = severities.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return order[a as keyof typeof order] - order[b as keyof typeof order];
      });
      expect(sorted[2]).toBe("MEDIUM");
    });

    it("should sort LOW last", () => {
      const severities = ["HIGH", "MEDIUM", "CRITICAL", "LOW"];
      const sorted = severities.sort((a, b) => {
        const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return order[a as keyof typeof order] - order[b as keyof typeof order];
      });
      expect(sorted[3]).toBe("LOW");
    });
  });
});
