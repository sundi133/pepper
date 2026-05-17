import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { dastScanner } from "./index";

describe("dast scanner", () => {
  it("skips when no target URL is configured", async () => {
    const findings = await dastScanner.scan({
      workDir: "/tmp",
      fileList: [],
      scanType: "DAST_ONLY",
      orgSettings: {
        llmProvider: "openai",
        llmBaseUrl: "",
        llmModel: "",
        enableLlmSast: false,
        enableLlmSecrets: false,
        osvApiUrl: "",
        vulnDbMode: "offline",
        dastEnabled: true,
      },
    });
    expect(findings).toHaveLength(0);
  });

  describe("HTTP-mode integration with dapper", () => {
    const originalFetch = global.fetch;
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
      global.fetch = originalFetch;
    });

    it("polls dapper until completion and maps findings", async () => {
      let pollCount = 0;
      global.fetch = vi.fn(async (url, init) => {
        const u = String(url);
        if (init?.method === "POST" && u.endsWith("/scans")) {
          return new Response(JSON.stringify({ id: "scan_xyz" }), {
            status: 200,
          });
        }
        pollCount++;
        if (pollCount < 2) {
          return new Response(JSON.stringify({ status: "RUNNING" }), {
            status: 200,
          });
        }
        return new Response(
          JSON.stringify({
            status: "COMPLETED",
            findings: [
              {
                id: "DAPPER-001",
                title: "Reflected XSS",
                severity: "HIGH",
                description: "Reflected XSS in /search",
                url: "https://target/search?q=<script>",
                cwe: "CWE-79",
                confidence: 0.92,
              },
            ],
          }),
          { status: 200 },
        );
      }) as typeof global.fetch;

      const promise = dastScanner.scan({
        workDir: "/tmp",
        fileList: [],
        scanType: "DAST_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
          dastEnabled: true,
          dastTargetUrl: "https://target",
          dastEndpoint: "http://dapper:8080",
          dastApiKey: "ppr_xxx",
        },
      });

      // Two polling cycles
      await vi.advanceTimersByTimeAsync(15_000);
      await vi.advanceTimersByTimeAsync(15_000);
      const findings = await promise;
      expect(findings).toHaveLength(1);
      expect(findings[0].title).toBe("Reflected XSS");
      expect(findings[0].cweId).toBe("CWE-79");
      expect(findings[0].severity).toBe("HIGH");
      expect(findings[0].metadata?.dapperScan).toBe("scan_xyz");
    });
  });
});
