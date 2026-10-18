/**
 * Logic-flaw passes of the zero-day scanner (docs/LOGIC_FLAW_DETECTION_SPEC.md):
 *   map pass → verified endpoint map → rules R1–R5 → confirmation
 *            → traits → pattern regions P1–P6 → pattern review
 * Errors never escape: a failed pass logs and contributes nothing.
 */
import { analyzeWithLlm, parseLlmJsonResponseDetailed, type createLlmClient } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";
import type { RawFinding } from "../../types";
import {
  MAP_SYSTEM_PROMPT,
  batchFiles,
  mapUserContent,
  mergeEntryPoints,
  normalizePath,
  selectMapFiles,
  verifyMapAnswer,
  type EntryPoint,
  type LogicMap,
  type Ownership,
  type TraitRegion,
} from "./map";
import { findCandidates, type Candidate } from "./rules";
import { CONFIRM_SYSTEM_PROMPT, confirmUserContent, findingsFromConfirmation } from "./confirm";
import { PATTERNS, findingsFromPatternAnswer, patternSystemPrompt, patternUserContent, selectRegions, type Region } from "./patterns";
import { SourceFiles, mapPool } from "./source";

export interface LogicOptions {
  workDir: string;
  fileList: string[];
  client: ReturnType<typeof createLlmClient>;
  model: string;
  maxResponseTokens: number;
  endpointMap: boolean;
  patternPack: boolean;
  maxMapFiles: number;
  maxCandidates: number;
  maxRegions: number;
  concurrency: number;
  minConfidence: number;
  signal?: AbortSignal;
  onProgress?: (msg: string) => void;
}

export interface LogicLedger {
  sourceFiles: number;
  mapFiles: number;
  mapBatches: number;
  mapBatchesFailed: number;
  entryPointsReported: number;
  entryPoints: number;
  factsDiscarded: number;
  traits: number;
  candidates: number;
  candidatesCapped: number;
  confirmed: number;
  rejected: number;
  unsure: number;
  confirmEvidenceFailed: number;
  regions: number;
  patternFindings: number;
  patternEvidenceFailed: number;
  patternLowConfidence: number;
  callsFailed: number;
  [rule: string]: number;
}

/** Budget of numbered source per map request (~11k tokens): leaves room for the answer. */
const MAP_BATCH_CHARS = 40_000;
const CONFIRM_BATCH = 4;
const PATTERN_BATCH = 6;
const PATTERN_BATCH_CHARS = 24_000;
const REGIONS_PER_PATTERN = 12;

export interface LogicResult {
  findings: RawFinding[];
  map: LogicMap | null;
  ledger: LogicLedger;
}

const newLedger = (): LogicLedger => ({
  sourceFiles: 0, mapFiles: 0, mapBatches: 0, mapBatchesFailed: 0, entryPointsReported: 0, entryPoints: 0,
  factsDiscarded: 0, traits: 0, candidates: 0, candidatesCapped: 0, confirmed: 0, rejected: 0, unsure: 0,
  confirmEvidenceFailed: 0, regions: 0, patternFindings: 0, patternEvidenceFailed: 0, patternLowConfidence: 0, callsFailed: 0,
});

/** Files the keyword prefilter reads for the pattern pack beyond the map's files. */
const MAX_UNREAD_FILES = 400;

function asker(o: LogicOptions, ledger: LogicLedger) {
  return async (system: string, user: string): Promise<{ value: unknown; ok: boolean }> => {
    if (o.signal?.aborted) return { value: null, ok: false };
    try {
      const raw = await analyzeWithLlm(o.client, o.model, system, user, { maxTokens: o.maxResponseTokens, temperature: 0.1 });
      const parsed = parseLlmJsonResponseDetailed<unknown>(raw, null);
      return { value: parsed.value, ok: parsed.status === "ok" && parsed.value !== null };
    } catch (err) {
      ledger.callsFailed++;
      logger.warn({ err }, "Logic pass: AI request failed");
      return { value: null, ok: false };
    }
  };
}

export interface MapState { src: SourceFiles; map: LogicMap; known: Set<string>; ledger: LogicLedger }

/** Map pass: read the code into a verified endpoint map (spec §4.1–4.2). Never throws. */
export async function buildLogicMap(o: LogicOptions): Promise<MapState> {
  const src = new SourceFiles(o.workDir);
  const ledger = newLedger();
  const ask = asker(o, ledger);
  const entries: EntryPoint[] = [];
  const ownership: Ownership[] = [];
  const traits: TraitRegion[] = [];
  let known = new Set<string>();
  try {
    const { selected, sourceCount } = selectMapFiles(src, o.fileList, o.maxMapFiles);
    ledger.sourceFiles = sourceCount;
    ledger.mapFiles = selected.length;
    known = new Set(selected);
    if (selected.length) {
      o.onProgress?.(`Logic review: mapping entry points in ${selected.length} of ${sourceCount} source files…`);
      const batches = batchFiles(src, selected, MAP_BATCH_CHARS);
      ledger.mapBatches = batches.length;
      const runBatch = async (batch: Parameters<typeof mapUserContent>[1], depth: number): Promise<void> => {
        const { value, ok } = await ask(MAP_SYSTEM_PROMPT, mapUserContent(src, batch));
        if (!ok) {
          // Usually a cut-off answer: retry once in two halves.
          if (depth === 0 && batch.length > 1) {
            const mid = Math.ceil(batch.length / 2);
            await runBatch(batch.slice(0, mid), 1);
            await runBatch(batch.slice(mid), 1);
            return;
          }
          ledger.mapBatchesFailed++;
          if (!value) return;
        }
        const v = verifyMapAnswer(value, src, known);
        entries.push(...v.entryPoints);
        ownership.push(...v.ownership);
        traits.push(...v.traits);
        ledger.entryPointsReported += v.reported;
        ledger.factsDiscarded += v.discarded;
      };
      await mapPool(batches, o.concurrency, (b) => runBatch(b, 0));
    }
  } catch (err) {
    logger.error({ err }, "Logic map pass failed; continuing without it");
  }
  const entryPoints = mergeEntryPoints(entries);
  ledger.entryPoints = entryPoints.length;
  ledger.traits = traits.length;
  const map: LogicMap = {
    entryPoints,
    ownership,
    traits,
    filesRead: [...known],
    ledger: { batches: ledger.mapBatches, batchesFailed: ledger.mapBatchesFailed, entryPointsReported: ledger.entryPointsReported, entryPointsKept: entryPoints.length, factsDiscarded: ledger.factsDiscarded, traitsKept: traits.length },
  };
  return { src, map, known, ledger };
}

/** Rules + confirmation, and the pattern pack, over a built map (spec §4.3–5). Never throws. */
export async function runLogicChecks(o: LogicOptions, state: MapState): Promise<LogicResult> {
  const { src, map, known, ledger } = state;
  const ask = asker(o, ledger);
  const findings: RawFinding[] = [];
  try {
    if (o.endpointMap && map.entryPoints.length) {
      const { candidates, byRule, capped } = findCandidates(map, o.maxCandidates);
      ledger.candidates = candidates.length;
      ledger.candidatesCapped = capped;
      for (const [k, n] of Object.entries(byRule)) ledger[`rule${k}`] = n;
      if (candidates.length) {
        o.onProgress?.(`Logic review: confirming ${candidates.length} authorization gap candidate(s)…`);
        const groups: Candidate[][] = [];
        for (let i = 0; i < candidates.length; i += CONFIRM_BATCH) groups.push(candidates.slice(i, i + CONFIRM_BATCH));
        await mapPool(groups, o.concurrency, async (group) => {
          const { value } = await ask(CONFIRM_SYSTEM_PROMPT, confirmUserContent(src, map, group));
          const r = findingsFromConfirmation(value, group, src, known);
          ledger.confirmed += r.confirmed;
          ledger.rejected += r.rejected;
          ledger.unsure += r.unsure;
          ledger.confirmEvidenceFailed += r.evidenceFailed;
          findings.push(...r.findings.filter((f) => (f.confidence ?? 0) >= o.minConfidence));
        });
      }
    }

    if (o.patternPack) {
      const unread: string[] = [];
      for (const f of o.fileList) {
        if (unread.length >= MAX_UNREAD_FILES) break;
        if (!known.has(f) && selectMapFiles(src, [f], 1).selected.length > 0) unread.push(f);
      }
      const regions = selectRegions(src, map.traits, unread, REGIONS_PER_PATTERN, o.maxRegions);
      ledger.regions = regions.length;
      const regionKnown = new Set(regions.map((r) => r.file));
      const jobs: Region[][] = [];
      for (const p of PATTERNS) {
        let cur: Region[] = [];
        let size = 0;
        for (const r of regions.filter((x) => x.pattern.id === p.id)) {
          const chars = (src.lines(r.file) ?? []).slice(r.startLine - 1, r.endLine).join("\n").length;
          if (cur.length && (cur.length >= PATTERN_BATCH || size + chars > PATTERN_BATCH_CHARS)) {
            jobs.push(cur);
            cur = [];
            size = 0;
          }
          cur.push(r);
          size += chars;
        }
        if (cur.length) jobs.push(cur);
      }
      if (jobs.length) {
        o.onProgress?.(`Logic review: checking ${regions.length} code region(s) for incident patterns…`);
        await mapPool(jobs, o.concurrency, async (group) => {
          const { value } = await ask(patternSystemPrompt(group[0].pattern), patternUserContent(src, group));
          const r = findingsFromPatternAnswer(value, group, src, regionKnown, o.minConfidence);
          ledger.patternFindings += r.findings.length;
          ledger.patternEvidenceFailed += r.evidenceFailed;
          ledger.patternLowConfidence += r.lowConfidence;
          findings.push(...r.findings);
        });
      }
    }
  } catch (err) {
    logger.error({ err }, "Logic checks failed; continuing with the main zero-day pass");
  }

  logger.info({ logicLedger: ledger }, "Logic passes complete");
  if (ledger.sourceFiles > ledger.mapFiles) {
    o.onProgress?.(`Logic review covered ${ledger.mapFiles} of ${ledger.sourceFiles} source files (LOGIC_MAP_MAX_FILES)`);
  }
  return { findings, map, ledger };
}

/** Both phases in order. */
export async function runLogicPasses(o: LogicOptions): Promise<LogicResult> {
  return runLogicChecks(o, await buildLogicMap(o));
}

/** Compact endpoint table for the main zero-day prompt (spec §4.6). */
export function endpointTable(map: LogicMap, maxRows = 120): string {
  if (!map.entryPoints.length) return "";
  const rows = map.entryPoints.slice(0, maxRows).map((e) => {
    const guards = e.guards.map((g) => `${g.name}(${g.kind}${g.order === "after" ? ",after" : ""})`).join(" ") || "-";
    const filters = [...new Set(e.dataAccess.map((d) => `${d.resource}:${d.filteredBy}`))].join(" ") || "-";
    return `  ${e.kind} ${e.method} ${e.path || normalizePath(e.path)} | guards: ${guards} | data: ${filters} | ${e.handler ? `${e.handler.file}:${e.handler.startLine}` : `${e.file}:${e.line}`}`;
  });
  const more = map.entryPoints.length > maxRows ? `\n  … ${map.entryPoints.length - maxRows} more` : "";
  return `ENTRY POINTS (verified against the source; guards and how each data access is filtered):\n${rows.join("\n")}${more}`;
}
