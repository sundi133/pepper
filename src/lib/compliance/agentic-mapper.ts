/**
 * Agentic compliance mapping engine (Tier 2, high-accuracy).
 *
 * LLM-driven, but grounded and self-verifying so it reasons with high accuracy
 * instead of hallucinating controls:
 *
 *   1. GROUND  (code) — the deterministic CWE crosswalk supplies candidate
 *                       controls per finding; the full control catalog (with
 *                       real requirement text) is provided for discovery.
 *   2. REASON  (LLM)  — decide which controls truly apply, assign relevance,
 *                       write a justification grounded in the control's text,
 *                       and a 0–1 confidence.
 *   3. VERIFY  (LLM)  — an adversarial pass critiques each proposed mapping and
 *                       upholds / downgrades / rejects it.
 *   4. VALIDATE(code) — drop controls not in the catalog and rejected mappings.
 *
 * The gateway forces JSON output and has no tool-calling, so the "agent" is a
 * code-orchestrated multi-step loop — portable across OpenAI/Anthropic/Ollama.
 *
 * Cost control: only findings that have a grounded prior (crosswalk hit or
 * activity match) are sent to the LLM for a given framework; findings with no
 * plausible connection map to nothing without an LLM call.
 */
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
  LlmConfig,
  LlmClient,
} from "@/lib/llm-gateway";
import { ComplianceFramework } from "./pdf-parser";
import { mapFindingsDeterministic, controlCoverage } from "./crosswalk-mapper";
import {
  FindingForMapping,
  FindingComplianceResult,
  ControlMapping,
} from "./llm-mapper";
import { logger } from "@/lib/logger";

const REASON_SYSTEM = `You are an expert compliance auditor mapping software security findings to compliance framework controls with high accuracy.

For each finding, decide which controls in the provided catalog it genuinely relates to. You are given "crosswalk hints" (controls a deterministic CWE mapping already flagged) — treat them as strong priors, but you may add controls the hints missed or drop hints that do not truly apply. Ground every decision in what the control actually requires.

Rules:
1. Use ONLY controlIds that appear in the catalog. Never invent controlIds.
2. Classify each mapping: "direct" (the finding violates/exercises exactly what the control governs), "supporting" (the finding indicates a gap in a supporting control), or "related" (tangential).
3. Justify each mapping in 1–2 sentences that reference the control's requirement and the finding's specifics.
4. Give each mapping a confidence from 0.0 to 1.0 (how certain you are it truly applies).
5. Be precise, not exhaustive: a typical finding maps to 1–4 controls. Do not pad.
6. If a finding maps to no control in this framework, return an empty controls array for it.`;

const VERIFY_SYSTEM = `You are a skeptical compliance reviewer verifying proposed finding→control mappings. For EACH proposed mapping, decide:
- "uphold": the reasoning is sound and grounded in the control's requirement.
- "downgrade": plausible but weaker than claimed (e.g. "related", not "direct"), or thin justification.
- "reject": the control does not actually apply, or the reasoning is wrong/hallucinated.

Be strict — default to "reject" or "downgrade" when the justification does not clearly tie the finding to the control's requirement. Return a corrected confidence (0.0–1.0) for each.`;

interface CatalogControl {
  controlId: string;
  title: string;
  theme: string;
  coverage: string;
  summary: string;
  requirements: string;
}

function buildCatalog(framework: ComplianceFramework): CatalogControl[] {
  return framework.controls.map((c) => ({
    controlId: c.controlId,
    title: c.title,
    theme: c.theme || "",
    coverage: controlCoverage(c),
    summary: (c.summary || "").slice(0, 220),
    requirements: (c.implementationChecklist || []).slice(0, 3).join("; "),
  }));
}

function catalogText(catalog: CatalogControl[]): string {
  return catalog
    .map(
      (c) =>
        `- ${c.controlId} | ${c.title} | coverage:${c.coverage} | ${c.summary}${c.requirements ? ` | requires: ${c.requirements}` : ""}`,
    )
    .join("\n");
}

const REASON_BATCH = 8; // findings per reasoning call — agentic reasoning needs room

export async function mapFindingsAgentic(
  findings: FindingForMapping[],
  framework: ComplianceFramework,
  llmConfig: LlmConfig,
  onProgress?: (message: string) => void,
): Promise<FindingComplianceResult[]> {
  const client = createLlmClient(llmConfig);
  const catalog = buildCatalog(framework);
  const validIds = new Set(catalog.map((c) => c.controlId));
  const catalogStr = catalogText(catalog);

  // Ground: deterministic priors per finding.
  const priors = new Map<string, ControlMapping[]>();
  for (const r of mapFindingsDeterministic(findings, framework)) {
    priors.set(r.findingId, r.controls);
  }

  // Gate: only findings with a grounded prior go to the LLM for this framework.
  const findingsById = new Map(findings.map((f) => [f.id, f]));
  const candidates = findings.filter(
    (f) => (priors.get(f.id)?.length ?? 0) > 0,
  );
  const results = new Map<string, ControlMapping[]>();
  for (const f of findings) results.set(f.id, []); // default: maps to nothing

  onProgress?.(
    `Agentic mapping: ${candidates.length}/${findings.length} findings grounded for ${framework.name}`,
  );

  for (let i = 0; i < candidates.length; i += REASON_BATCH) {
    const batch = candidates.slice(i, i + REASON_BATCH);
    const batchNum = Math.floor(i / REASON_BATCH) + 1;
    const totalBatches = Math.ceil(candidates.length / REASON_BATCH);
    onProgress?.(
      `${framework.name}: reasoning about ${batch.length} findings (batch ${batchNum}/${totalBatches})`,
    );

    try {
      let mapped = await reasonBatch(
        client,
        llmConfig.model,
        batch,
        priors,
        catalogStr,
        framework.name,
      );
      const proposed = Array.from(mapped.values()).reduce(
        (n, c) => n + c.length,
        0,
      );
      onProgress?.(
        `${framework.name}: verifying ${proposed} proposed mapping(s) (batch ${batchNum}/${totalBatches})`,
      );
      mapped = await verifyBatch(
        client,
        llmConfig.model,
        batch,
        findingsById,
        mapped,
        framework.name,
      );
      // Validate against catalog and store.
      let kept = 0;
      for (const [findingId, controls] of mapped) {
        const valid = controls.filter((c) => validIds.has(c.controlId));
        kept += valid.length;
        results.set(findingId, valid);
      }
      onProgress?.(
        `${framework.name}: kept ${kept} verified mapping(s) (batch ${batchNum}/${totalBatches})`,
      );
    } catch (err) {
      logger.error(
        { err, framework: framework.name, batchNum },
        "Agentic mapping batch failed; falling back to crosswalk priors",
      );
      // Graceful degradation: keep the deterministic priors for this batch.
      for (const f of batch) {
        results.set(f.id, priors.get(f.id) || []);
      }
    }
  }

  return findings.map((f) => ({
    findingId: f.id,
    controls: results.get(f.id) || [],
  }));
}

function findingBlock(f: FindingForMapping, priorIds: string[]): string {
  return `[Finding ${f.id}]
Title: ${f.title}
Severity: ${f.severity} | Scanner: ${f.scanner} | CWE: ${f.cweId || "N/A"} | File: ${f.filePath || "N/A"}
Description: ${(f.description || "").slice(0, 300)}
Crosswalk hints (strong priors): ${priorIds.length ? priorIds.join(", ") : "none"}`;
}

async function reasonBatch(
  client: LlmClient,
  model: string,
  batch: FindingForMapping[],
  priors: Map<string, ControlMapping[]>,
  catalogStr: string,
  frameworkName: string,
): Promise<Map<string, ControlMapping[]>> {
  const findingList = batch
    .map((f) =>
      findingBlock(
        f,
        (priors.get(f.id) || []).map((c) => c.controlId),
      ),
    )
    .join("\n\n");

  const user = `## Framework: ${frameworkName}

## Control catalog:
${catalogStr}

## Findings to map:
${findingList}

Return STRICT JSON:
{"mappings":[{"findingId":"<id>","controls":[{"controlId":"<exact id from catalog>","relevance":"direct|supporting|related","reasoning":"<grounded 1-2 sentences>","confidence":0.0}]}]}`;

  const raw = await analyzeWithLlm(client, model, REASON_SYSTEM, user, {
    temperature: 0.1,
    maxTokens: 8192,
  });

  interface RawMap {
    findingId: string;
    controls?: Array<{
      controlId: string;
      relevance?: string;
      reasoning?: string;
      confidence?: number;
    }>;
  }
  const parsed = parseLlmJsonResponse<{ mappings?: RawMap[] }>(raw, {});
  const mappings =
    parsed.mappings || parseLlmJsonResponse<RawMap[]>(raw, []) || [];

  const out = new Map<string, ControlMapping[]>();
  const catalogById = new Map<string, { title: string; theme: string }>();
  // titles/themes are looked up in verify/store; here just normalize structure.
  for (const m of Array.isArray(mappings) ? mappings : []) {
    if (!m?.findingId) continue;
    out.set(
      m.findingId,
      (m.controls || []).map((c) => ({
        controlId: c.controlId,
        title: catalogById.get(c.controlId)?.title || c.controlId,
        theme: catalogById.get(c.controlId)?.theme || "Unknown",
        relevance: normalizeRelevance(c.relevance),
        reasoning: c.reasoning || "",
        confidence: clampConfidence(c.confidence),
      })),
    );
  }
  // Fill titles/themes from priors where available (they carry real titles).
  for (const [fid, controls] of out) {
    const priorById = new Map(
      (priors.get(fid) || []).map((c) => [c.controlId, c]),
    );
    for (const c of controls) {
      const p = priorById.get(c.controlId);
      if (p) {
        c.title = p.title;
        c.theme = p.theme;
      }
    }
  }
  return out;
}

async function verifyBatch(
  client: LlmClient,
  model: string,
  batch: FindingForMapping[],
  findingsById: Map<string, FindingForMapping>,
  mapped: Map<string, ControlMapping[]>,
  frameworkName: string,
): Promise<Map<string, ControlMapping[]>> {
  // Flatten proposals for the critique prompt.
  const proposals: Array<{ findingId: string; control: ControlMapping }> = [];
  for (const [findingId, controls] of mapped) {
    for (const c of controls) proposals.push({ findingId, control: c });
  }
  if (proposals.length === 0) return mapped;

  const proposalList = proposals
    .map((p, i) => {
      const f = findingsById.get(p.findingId);
      return `[${i}] finding=${p.findingId} (${f?.title || ""}; CWE ${f?.cweId || "N/A"}) → control=${p.control.controlId} relevance=${p.control.relevance} conf=${p.control.confidence}
   reasoning: ${p.control.reasoning}`;
    })
    .join("\n");

  const user = `## Framework: ${frameworkName}

## Proposed mappings to verify:
${proposalList}

For each index, return a verdict. STRICT JSON:
{"verdicts":[{"index":0,"verdict":"uphold|downgrade|reject","relevance":"direct|supporting|related","confidence":0.0,"note":"<short>"}]}`;

  const raw = await analyzeWithLlm(client, model, VERIFY_SYSTEM, user, {
    temperature: 0.0,
    maxTokens: 4096,
  });
  interface Verdict {
    index: number;
    verdict?: string;
    relevance?: string;
    confidence?: number;
    note?: string;
  }
  const parsed = parseLlmJsonResponse<{ verdicts?: Verdict[] }>(raw, {});
  const verdicts = parsed.verdicts || [];
  const byIndex = new Map(verdicts.map((v) => [v.index, v]));

  // Apply verdicts; rebuild the per-finding maps.
  const out = new Map<string, ControlMapping[]>();
  for (const f of batch) out.set(f.id, []);
  proposals.forEach((p, i) => {
    const v = byIndex.get(i);
    const verdict = v?.verdict || "uphold"; // if verifier silent, keep as upheld
    if (verdict === "reject") return; // drop
    const control: ControlMapping = {
      ...p.control,
      relevance:
        verdict === "downgrade" && v?.relevance
          ? normalizeRelevance(v.relevance)
          : p.control.relevance,
      confidence: clampConfidence(v?.confidence ?? p.control.confidence),
      verified: verdict === "uphold",
      verificationNote: v?.note || undefined,
    };
    out.get(p.findingId)!.push(control);
  });
  return out;
}

function normalizeRelevance(
  r?: string,
): "direct" | "supporting" | "related" {
  if (r === "direct" || r === "supporting" || r === "related") return r;
  return "related";
}

function clampConfidence(c?: number): number | undefined {
  if (typeof c !== "number" || Number.isNaN(c)) return undefined;
  return Math.min(1, Math.max(0, c));
}
