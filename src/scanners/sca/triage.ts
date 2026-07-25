import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import type { RawFinding, SuppressedVulnerability } from "../types";
import { enrichFinding } from "../shared/finding-normalize";
import { SCA_TRIAGE_PROMPT } from "../shared/prompts";
import {
  SCA_TRIAGE_ADVISORY_CHARS,
  SCA_TRIAGE_ADVISORY_CHARS_OLLAMA,
  SCA_TRIAGE_BATCH_SIZE,
  SCA_TRIAGE_BATCH_SIZE_OLLAMA,
} from "@/lib/constants";
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
    `(?:from\\s+['"]|require\\s*\\(\\s*['"]|import\\s+['"])(?:${escaped.join("|")})`,
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

/**
 * Trim advisory prose to a character budget on a word boundary.
 * The advisory is the primary evidence the triage LLM reasons over, so it is
 * truncated rather than omitted when it exceeds the budget.
 */
function truncateAdvisory(text: string | undefined, maxChars: number): string {
  if (!text) return "no advisory text available";
  const collapsed = text.replace(/\s+/g, " ").trim();
  if (collapsed.length <= maxChars) return collapsed;
  const cut = collapsed.slice(0, maxChars);
  const lastSpace = cut.lastIndexOf(" ");
  return `${lastSpace > maxChars * 0.6 ? cut.slice(0, lastSpace) : cut}… [truncated]`;
}

/** Turn a dropped finding into a record that can become a VEX statement. */
function toSuppressed(
  finding: RawFinding,
  reason: string,
): SuppressedVulnerability {
  const meta = finding.metadata || {};
  const vulnerabilityId =
    finding.cveId || (meta.osvId as string | undefined) || finding.ruleId || "";
  return {
    vulnerabilityId,
    advisoryId:
      finding.ruleId && finding.ruleId !== vulnerabilityId
        ? finding.ruleId
        : undefined,
    title: finding.title,
    severity: finding.severity,
    packageName: meta.packageName as string | undefined,
    packageVersion: meta.packageVersion as string | undefined,
    ecosystem: meta.ecosystem as string | undefined,
    reason,
    assessedBy: "automated-triage",
    metadata: {
      epssScore: meta.epssScore,
      cisaKevListed: meta.cisaKevListed,
      introducedBy: meta.introducedBy,
      dependencyPathText: meta.dependencyPathText,
      fixVersion: meta.fixVersion,
    },
  };
}

export interface ScaTriageResult {
  /** Findings that survived triage and will be reported. */
  kept: RawFinding[];
  /**
   * Vulnerabilities triage ruled out. Returned rather than dropped so they can
   * be asserted as VEX `not_affected` statements; they are never persisted as
   * findings.
   */
  suppressed: SuppressedVulnerability[];
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
): Promise<ScaTriageResult> {
  if (findings.length === 0) return { kept: [], suppressed: [] };

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

  // Local models run with a much smaller context window (Ollama does not set
  // num_ctx), so shrink both the per-advisory budget and the batch size.
  const isOllama = llmConfig.provider.toLowerCase() === "ollama";
  const advisoryChars = isOllama
    ? SCA_TRIAGE_ADVISORY_CHARS_OLLAMA
    : SCA_TRIAGE_ADVISORY_CHARS;
  const BATCH = isOllama
    ? SCA_TRIAGE_BATCH_SIZE_OLLAMA
    : SCA_TRIAGE_BATCH_SIZE;

  const triaged: RawFinding[] = [];
  const suppressed: SuppressedVulnerability[] = [];

  for (let i = 0; i < deduped.length; i += BATCH) {
    const batch = deduped.slice(i, i + BATCH);
    const summary = batch.map((f) => {
      const meta = f.metadata || {};
      const pkg = meta.packageName as string;
      const imports = pkg ? importEvidence.get(pkg) : undefined;
      const risk = meta.supplyChainRisk as
        | { directDependency?: boolean; transitiveSeverity?: string }
        | undefined;

      return {
        osvId: f.ruleId,
        cveId: f.cveId,
        cweId: f.cweId,
        package: pkg,
        version: meta.packageVersion,
        ecosystem: meta.ecosystem,
        severity: f.severity,
        fixVersion: meta.fixVersion,
        // The advisory text is the evidence for keep/drop and for
        // exploitPreconditions — without it the model can only guess from the ID.
        advisory: truncateAdvisory(f.description, advisoryChars),
        // Exploitation signals (already fetched upstream in sca/index.ts).
        epssScore: meta.epssScore,
        cisaKevListed: meta.cisaKevListed,
        cisaKevRansomwareUse: meta.cisaKevRansomwareUse,
        directDependency: risk?.directDependency,
        transitiveSeverity: risk?.transitiveSeverity,
        // Why this package is in the tree, when it could be established.
        introducedBy: meta.introducedBy,
        dependencyPath: meta.dependencyPathText,
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
      // The advisory excerpt each verdict was based on, so a keep/drop decision
      // stays auditable after enrichFinding() rewrites the description.
      const advisoryByOsvId = new Map(
        summary.map((s) => [s.osvId, s.advisory]),
      );

      for (const f of batch) {
        const decision = decisionMap.get(f.ruleId || "");
        if (decision && !decision.keep) {
          // Carry the decision out for VEX instead of discarding it.
          suppressed.push(
            toSuppressed(
              f,
              decision.reason || "Assessed by automated triage as not applicable",
            ),
          );
          continue;
        }

        const meta = {
          ...(f.metadata || {}),
          ...(decision?.metadata || {}),
          duplicateGroup: `${f.metadata?.packageName}@${f.metadata?.packageVersion}`,
          confidenceReason: decision?.reason || "OSV advisory with AI triage",
          // Preserve the evidence behind the verdict — enrichFinding() below
          // replaces `description` with the structured summary, dropping the
          // advisory prose that the triage decision was actually based on.
          advisoryExcerpt: advisoryByOsvId.get(f.ruleId),
          triagedByLlm: !!decision,
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
  return { kept: triaged, suppressed };
}
