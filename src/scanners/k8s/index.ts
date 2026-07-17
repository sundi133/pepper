import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { enrichFinding } from "../shared/finding-normalize";
import { K8S_MANIFEST_PROMPT } from "../shared/prompts";
import { applySeverityCalibration } from "@/lib/severity-calibration";
import {
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  K8S_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const K8S_FILE_PATTERNS = /\.ya?ml$/i;
const K8S_DIRECTORIES = new Set(["k8s", "kubernetes", "helm", "manifests"]);

interface K8sLlmFinding {
  title: string;
  severity: string;
  description: string;
  risk?: string[];
  affectedFiles?: string[];
  vulnerableExample?: string;
  startLine?: number;
  endLine?: number;
  filePath?: string;
  fix?: string;
  bestPractices?: string[];
  cweId?: string;
  confidence?: number;
  metadata?: {
    resourceType?: string;
    namespace?: string;
    resourceName?: string;
    issueCategory?: string;
  };
}

function isK8sDirectory(filePath: string): boolean {
  const parts = filePath.split(path.sep);
  return parts.some((part) => K8S_DIRECTORIES.has(part.toLowerCase()));
}

function isK8sManifest(filePath: string): boolean {
  return K8S_FILE_PATTERNS.test(filePath);
}

function extractK8sMetadata(content: string): {
  kind?: string;
  name?: string;
  namespace?: string;
} {
  const metadata: { kind?: string; name?: string; namespace?: string } = {};

  // Extract kind (e.g., "kind: Deployment")
  const kindMatch = content.match(/^kind:\s*(\w+)/m);
  if (kindMatch) {
    metadata.kind = kindMatch[1];
  }

  // Extract namespace from metadata.namespace
  const namespaceMatch = content.match(/namespace:\s*(\S+)/m);
  if (namespaceMatch) {
    metadata.namespace = namespaceMatch[1];
  }

  // Extract name from metadata.name
  const nameMatch = content.match(/name:\s*(\S+)/m);
  if (nameMatch) {
    metadata.name = nameMatch[1];
  }

  return metadata;
}

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}

export const k8sScanner: ScannerPlugin = {
  name: "K8S",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    if (!ctx.orgSettings.enableLlmSast) return [];

    const client = createLlmClient({
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      apiKey: ctx.orgSettings.llmApiKey,
      model: ctx.orgSettings.llmModel,
    });

    const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
    const maxResponseTokens = isOllama
      ? OLLAMA_MAX_RESPONSE_TOKENS
      : LLM_MAX_RESPONSE_TOKENS;

    // Discover K8s manifest files
    const k8sFiles = ctx.fileList.filter(
      (f) => isK8sDirectory(f) && isK8sManifest(f),
    );

    logger.info({ totalFiles: ctx.fileList.length, k8sFiles: k8sFiles.length }, "K8S file discovery");

    if (k8sFiles.length === 0) return [];

    ctx.onProgress?.(`K8S: discovered ${k8sFiles.length} manifest file(s)`);

    const findings: RawFinding[] = [];
    const processedFiles = new Set<string>();

    // Process manifests in batches to avoid token limits
    for (let i = 0; i < k8sFiles.length; i += 10) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = k8sFiles.slice(i, i + 10);
      const manifestBundles: string[] = [];
      const fileMetadata: Map<string, { kind?: string; name?: string; namespace?: string }> = new Map();

      for (const filePath of batch) {
        try {
          const fullPath = path.join(ctx.workDir, filePath);
          const content = fs.readFileSync(fullPath, "utf-8");

          if (!content.trim()) continue;

          const metadata = extractK8sMetadata(content);
          fileMetadata.set(filePath, metadata);

          manifestBundles.push(`### ${filePath}\n\`\`\`yaml\n${content.slice(0, 15000)}\n\`\`\``);
          processedFiles.add(filePath);
        } catch (err) {
          logger.debug({ err, filePath }, "Failed to read K8s manifest");
          continue;
        }
      }

      if (manifestBundles.length === 0) continue;

      ctx.onProgress?.(`K8S: analyzing ${batch.length} manifest(s)...`);

      const userContent = `Analyze the following Kubernetes manifests for security misconfigurations:\n\n${manifestBundles.join("\n\n")}`;

      try {
        const raw = await analyzeWithLlm(
          client,
          ctx.orgSettings.llmModel,
          K8S_MANIFEST_PROMPT,
          userContent,
          { maxTokens: maxResponseTokens },
        );

        const parsed = parseLlmJsonResponse<{ findings: K8sLlmFinding[] }>(
          raw,
          { findings: [] },
        );

        const batchFindings = (parsed.findings || [])
          .filter(
            (f) =>
              f.title &&
              f.severity &&
              f.filePath &&
              processedFiles.has(f.filePath) &&
              (f.confidence ?? 0) >= K8S_MIN_CONFIDENCE_DEFAULT,
          )
          .map((f) => {
            const metadata = fileMetadata.get(f.filePath || "");
            const base: RawFinding = applySeverityCalibration({
              scanner: "K8S",
              severity: normalizeSeverity(f.severity),
              title: f.title,
              description: f.description,
              filePath: f.filePath,
              startLine: f.startLine,
              endLine: f.endLine,
              snippet: f.vulnerableExample,
              cweId: f.cweId,
              confidence: f.confidence,
              ruleId: `K8S-${f.metadata?.issueCategory || "CONFIG"}`,
              metadata: {
                ...(f.metadata || {}),
                resourceType: metadata?.kind || f.metadata?.resourceType,
                namespace: metadata?.namespace || f.metadata?.namespace || "default",
                resourceName: metadata?.name || f.metadata?.resourceName,
              },
            });

            return enrichFinding(
              base,
              {
                ...base.metadata,
                remediation: f.fix || "Apply the recommended security configuration",
              } as Record<string, unknown>,
            );
          });

        findings.push(...batchFindings);

        if (batchFindings.length > 0 && ctx.onBatchFindings) {
          await ctx.onBatchFindings("K8S", batchFindings);
        }
      } catch (err) {
        logger.error({ err }, "K8s manifest analysis failed");
        continue;
      }
    }

    if (findings.length > 0) {
      ctx.onProgress?.(`K8S: found ${findings.length} security issue(s)`);
    }

    return findings;
  },
};
