import { RawFinding } from "./types";

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration: { level: string };
  properties?: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; endLine?: number };
    };
  }>;
  fingerprints?: Record<string, string>;
}

export function buildSarif(findings: RawFinding[]): SarifLog {
  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
    const ruleId = finding.ruleId || finding.title.replace(/\s+/g, "-");

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description.substring(0, 500) },
        defaultConfiguration: {
          level: severityToSarifLevel(finding.severity),
        },
        properties: {
          tags: [finding.cweId, finding.scanner].filter(Boolean) as string[],
        },
      });
    }

    const result: SarifResult = {
      ruleId,
      level: severityToSarifLevel(finding.severity),
      message: { text: finding.description },
    };

    if (finding.filePath) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.filePath },
            ...(finding.startLine
              ? {
                  region: {
                    startLine: finding.startLine,
                    endLine: finding.endLine ?? finding.startLine,
                  },
                }
              : {}),
          },
        },
      ];
    }

    results.push(result);
  }

  return {
    $schema:
      "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Pepper",
            version: "1.0.0",
            informationUri: "https://github.com/pepper-security/pepper",
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };
}

function severityToSarifLevel(severity: string): string {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    case "INFO":
      return "note";
    default:
      return "warning";
  }
}
