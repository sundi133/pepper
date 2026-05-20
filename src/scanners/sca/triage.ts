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

/** Group CVE findings by package@version and apply AI triage. */
export async function triageScaFindings(
  findings: RawFinding[],
  llmConfig: {
    provider: string;
    baseUrl: string;
    apiKey?: string;
    model: string;
  },
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

  const client = createLlmClient(llmConfig);
  const BATCH = 20;
  const triaged: RawFinding[] = [];

  for (let i = 0; i < deduped.length; i += BATCH) {
    const batch = deduped.slice(i, i + BATCH);
    const summary = batch.map((f) => ({
      osvId: f.ruleId,
      cveId: f.cveId,
      package: f.metadata?.packageName,
      version: f.metadata?.packageVersion,
      ecosystem: f.metadata?.ecosystem,
      severity: f.severity,
      fixVersion: f.metadata?.fixVersion,
    }));

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

  return triaged.filter((f) => (f.confidence ?? 1) >= LLM_MIN_CONFIDENCE_DEFAULT);
}
