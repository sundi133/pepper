import { Dependency, RawFinding } from "../types";

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    ranges?: Array<{
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references?: Array<{ type: string; url: string }>;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] }>;
}

export async function queryOsvBatch(
  dependencies: Dependency[],
  apiUrl = "https://api.osv.dev",
): Promise<RawFinding[]> {
  if (dependencies.length === 0) return [];

  const findings: RawFinding[] = [];
  const batchSize = 1000;

  for (let i = 0; i < dependencies.length; i += batchSize) {
    const batch = dependencies.slice(i, i + batchSize);
    const queries: OsvQuery[] = batch.map((dep) => ({
      package: { name: dep.name, ecosystem: dep.ecosystem },
      version: dep.version,
    }));

    try {
      const response = await fetch(`${apiUrl}/v1/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) continue;

      const data: OsvBatchResponse = await response.json();

      for (let j = 0; j < data.results.length; j++) {
        const vulns = data.results[j]?.vulns;
        if (!vulns || vulns.length === 0) continue;

        const dep = batch[j];

        for (const vuln of vulns) {
          const severity = cvssToSeverity(vuln.severity);
          const cveId = vuln.aliases?.find((a) => a.startsWith("CVE-"));
          const fixVersion = getFixVersion(vuln);

          findings.push({
            scanner: "SCA",
            severity,
            title: `${vuln.id}: ${vuln.summary || "Vulnerability in " + dep.name}`,
            description: buildDescription(vuln, dep, fixVersion),
            filePath: dep.sourceFile,
            startLine: dep.sourceLine,
            endLine: dep.sourceLine,
            snippet: dep.sourceSnippet,
            ruleId: vuln.id,
            cveId,
            confidence: 1.0,
            metadata: {
              packageName: dep.name,
              packageVersion: dep.version,
              ecosystem: dep.ecosystem,
              sourceFile: dep.sourceFile,
              sourceLine: dep.sourceLine,
              osvId: vuln.id,
              fixVersion,
              references: vuln.references?.map((r) => r.url),
            },
          });
        }
      }
    } catch {
      // OSV API unavailable, skip this batch
      continue;
    }
  }

  return findings;
}

function cvssToSeverity(
  severity?: OsvVulnerability["severity"],
): RawFinding["severity"] {
  if (!severity || severity.length === 0) return "MEDIUM";

  const cvss = severity.find((s) => s.type === "CVSS_V3");
  if (!cvss) return "MEDIUM";

  const score = parseFloat(cvss.score);
  if (isNaN(score)) return "MEDIUM";

  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

function getFixVersion(vuln: OsvVulnerability): string | undefined {
  for (const affected of vuln.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

function buildDescription(
  vuln: OsvVulnerability,
  dep: Dependency,
  fixVersion?: string,
): string {
  let desc = vuln.details || vuln.summary || "No description available.";
  desc += `\n\nPackage: ${dep.name}@${dep.version} (${dep.ecosystem})`;
  if (fixVersion) {
    desc += `\nFix: Upgrade to version ${fixVersion} or later.`;
  }
  return desc;
}
