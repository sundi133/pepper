import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import type { RawFinding } from "../types";
import { enrichFinding } from "../shared/finding-normalize";
import { SCA_TRIAGE_PROMPT } from "../shared/prompts";
import { LLM_MIN_CONFIDENCE_DEFAULT } from "@/lib/constants";
import { logger } from "@/lib/logger";

interface TriageEntry {
  osvId: string;
  keep: boolean;
  reason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Build a map of package-name → import/require snippets found in the codebase.
 * This gives the triage LLM real evidence of whether a vulnerable package is
 * actually imported (and thus potentially reachable) or unused.
 */
function collectImportEvidence(
  workDir: string,
  fileList: string[],
  packageNames: Set<string>,
): Map<string, string[]> {
  const evidence = new Map<string, string[]>();
  if (packageNames.size === 0) return evidence;

  // Build regex that matches import/require of any of the target packages
  const escaped = [...packageNames].map((p) =>
    p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
  );
  const pattern = new RegExp(
    `(?:import\\s.*?|require\\s*\\(\\s*['"])(?:${escaped.join("|")})`,
  );

  const SOURCE_EXT = new Set([
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".go", ".rs", ".rb", ".java", ".kt", ".scala",
    ".php", ".cs", ".fs", ".dart", ".ex", ".exs", ".swift",
  ]);

  const MAX_FILES = 500;
  let scanned = 0;

  for (const rel of fileList) {
    if (scanned >= MAX_FILES) break;
    const ext = path.extname(rel).toLowerCase();
    if (!SOURCE_EXT.has(ext)) continue;

    try {
      const content = fs.readFileSync(path.join(workDir, rel), "utf-8");
      if (content.length > 512_000) continue; // skip very large files
      scanned++;

      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (!pattern.test(lines[i])) continue;
        for (const pkg of packageNames) {
          if (lines[i].includes(pkg)) {
            const snippets = evidence.get(pkg) || [];
            if (snippets.length < 3) {
              snippets.push(`${rel}:${i + 1}: ${lines[i].trim()}`);
              evidence.set(pkg, snippets);
            }
          }
        }
      }
    } catch {
      continue;
    }
  }
  return evidence;
}

/** Group CVE findings by package@version and apply AI triage. */
export async function triageScaFindings(
  findings: RawFinding[],
  llmConfig: {
    provider: string;
    baseUrl: string;
    apiKey?: string;
    model: string;
  },
  codeContext?: { workDir: string; fileList: string[] },
): Promise<RawFinding[]> {
  if (findings.length === 0) return [];

  const grouped = new Map<string, RawFinding[]>();
  for (const f of findings) {
    const meta = f.metadata || {};
    const key = `${meta.ecosystem}:${meta.packageName}:${meta.packageVersion}`;
    const list = grouped.get(key) || [];
    list.push(f);
    grouped.set(key, list);
  }

  const deduped: RawFinding[] = [];
  for (const [, group] of grouped) {
    const byCve = new Map<string, RawFinding>();
    for (const f of group) {
      const id = f.cveId || f.ruleId || f.title;
      if (!byCve.has(id)) byCve.set(id, f);
    }
    deduped.push(...byCve.values());
  }

  // Collect import evidence once for all unique package names in this batch
  const allPkgNames = new Set<string>();
  for (const f of deduped) {
    const pkg = f.metadata?.packageName as string;
    if (pkg) allPkgNames.add(pkg);
  }
  const importEvidence =
    codeContext && allPkgNames.size > 0
      ? collectImportEvidence(codeContext.workDir, codeContext.fileList, allPkgNames)
      : new Map<string, string[]>();

  const client = createLlmClient(llmConfig);
  const BATCH = 20;
  const triaged: RawFinding[] = [];

  for (let i = 0; i < deduped.length; i += BATCH) {
    const batch = deduped.slice(i, i + BATCH);
    const summary = batch.map((f) => {
      const pkg = f.metadata?.packageName as string;
      const imports = pkg ? importEvidence.get(pkg) : undefined;
      return {
        osvId: f.ruleId,
        cveId: f.cveId,
        package: pkg,
        version: f.metadata?.packageVersion,
        ecosystem: f.metadata?.ecosystem,
        severity: f.severity,
        fixVersion: f.metadata?.fixVersion,
        importEvidence: imports || "no imports found in scanned source files",
      };
    });

    try {
      const raw = await analyzeWithLlm(
        client,
        llmConfig.model,
        SCA_TRIAGE_PROMPT,
        JSON.stringify({ vulnerabilities: summary }, null, 2),
      );
      const parsed = parseLlmJsonResponse<{ triaged: TriageEntry[] }>(raw, {
        triaged: [],
      });
      const decisionMap = new Map(
        (parsed.triaged || []).map((t) => [t.osvId, t]),
      );

      for (const f of batch) {
        const decision = decisionMap.get(f.ruleId || "");
        if (decision && !decision.keep) continue;

        const meta = {
          ...(f.metadata || {}),
          ...(decision?.metadata || {}),
          duplicateGroup: `${f.metadata?.packageName}@${f.metadata?.packageVersion}`,
          confidenceReason: decision?.reason || "OSV advisory with AI triage",
        };

        triaged.push(
          enrichFinding(
            { ...f, confidence: f.confidence ?? 1 },
            meta,
            {
              whatIsWrong: f.title,
              where: `${f.metadata?.packageName}@${f.metadata?.packageVersion}`,
              whyExploitable:
                (meta.exploitPreconditions as string) ||
                "Vulnerable dependency version is in use.",
              fix:
                (meta.remediation as string) ||
                (f.metadata?.fixVersion
                  ? `Upgrade to ${f.metadata.fixVersion} or later.`
                  : "Upgrade to a patched version per advisory."),
              validation: "Re-run SCA after lockfile update; confirm vulnerable function unreachable or removed",
            },
          ),
        );
      }
    } catch (err) {
      logger.warn({ err }, "SCA triage batch failed — keeping OSV findings");
      triaged.push(...batch);
    }
  }

  // SCA findings are database-confirmed (confidence=1.0 from OSV); do not
  // filter them by the LLM confidence floor which is meant for LLM-generated
  // findings.  The AI triage already removed low-value entries via keep=false.
  return triaged;
}
