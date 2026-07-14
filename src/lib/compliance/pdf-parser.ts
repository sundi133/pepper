/**
 * Parses compliance framework PDFs with [CHUNK_START]/[CHUNK_END] structure.
 * Extracts all controls with their full metadata for LLM context.
 */
import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import { logger } from "@/lib/logger";

/** Whether SAST can produce evidence toward a control. */
export type Coverage = "assessable" | "partial" | "not-assessable";

export interface ComplianceControl {
  controlId: string;
  chunkId: string;
  type: string; // "AnnexA_Control" | "ISO27001_Requirement"
  theme: string;
  title: string;
  summary: string;
  implementationChecklist: string[];
  evidenceExamples: string[];
  clauseId?: string;
  subclause?: string;

  /**
   * Whether SAST/SCA findings can attest to this control at all. Drives the
   * three-bucket report (gaps found / no issues detected / not covered by SAST).
   * Defaults to "assessable" when a deterministic mapping exists, else "partial".
   */
  coverage?: Coverage;

  /**
   * Deterministic crosswalk: CWE ids that map DIRECTLY to this control
   * (e.g. ["CWE-89","CWE-79"]). A finding carrying one of these CWEs is a
   * direct gap for this control. Reproducible, no LLM required.
   */
  cweMapping?: string[];

  /**
   * Activity-level evidence: this control is supported by the mere existence
   * of a finding from these scanners (empty/omitted `scanners` = any scanner).
   * Models "a SAST finding is evidence toward 'identify vulnerabilities'
   * controls" (PCI 6.3.1, NIST RV.1, SA-11, RA-5, SSDF PW.7/PW.8).
   */
  appliesTo?: { scanners?: string[] };
}

export interface ComplianceFramework {
  name: string;
  /** Framework revision, stamped into every report (e.g. "4.0.1", "2021", "Rev 5"). */
  version?: string;
  fileName: string;
  controls: ComplianceControl[];
  /** Full text catalog for LLM context — all controls as a compact reference */
  controlCatalog: string;
}

/**
 * Parse a single compliance PDF file (text extracted from structured chunks).
 * Expects [CHUNK_START]/[CHUNK_END] delimiters.
 */
export function parseCompliancePdf(
  filePath: string,
): ComplianceFramework | null {
  try {
    // Read PDF as text — works because these PDFs are text-based
    // In production, use a proper PDF parser; for now, we exec pdftotext
    let text: string;

    try {
      // Try pdftotext first (most accurate)
      text = execFileSync("pdftotext", ["-layout", filePath, "-"], {
        encoding: "utf-8",
        timeout: 30000,
        windowsHide: process.platform === "win32",
      });
    } catch {
      // Fallback: read as-is (some PDFs are already text-like)
      text = fs.readFileSync(filePath, "utf-8");
    }

    if (!text || text.length < 100) {
      logger.warn({ filePath }, "Compliance PDF is empty or too short");
      return null;
    }

    const controls = parseComplianceControls(text);

    // Determine framework name from filename
    const basename = path.basename(filePath, ".pdf");
    const name = basename.includes("27001")
      ? "ISO/IEC 27001:2022"
      : basename.toUpperCase().includes("OWASP")
        ? "OWASP Top 10:2025"
      : basename.includes("SOC2")
        ? "SOC 2"
        : basename.includes("PCI")
          ? "PCI DSS"
          : basename.includes("HIPAA")
            ? "HIPAA"
            : basename;

    // Build compact control catalog for LLM context
    const controlCatalog = controls
      .map(
        (c) => `${c.controlId} | ${c.title} | ${c.summary.substring(0, 150)}`,
      )
      .join("\n");

    logger.info(
      { framework: name, controls: controls.length, filePath },
      "Compliance framework parsed",
    );

    return {
      name,
      fileName: path.basename(filePath),
      controls,
      controlCatalog,
    };
  } catch (err) {
    logger.error({ err, filePath }, "Failed to parse compliance PDF");
    return null;
  }
}

function parseComplianceControls(text: string): ComplianceControl[] {
  if (text.includes("[CHUNK_START]")) {
    return parseChunkedControls(text);
  }

  if (text.includes("BEGIN_CATEGORY:") && text.includes("CATEGORY_ID:")) {
    return parseOwaspTop10Controls(text);
  }

  return [];
}

function parseChunkedControls(text: string): ComplianceControl[] {
  const controls: ComplianceControl[] = [];
  const chunks = text.split("[CHUNK_START]").slice(1);

  for (const chunk of chunks) {
    const endIdx = chunk.indexOf("[CHUNK_END]");
    const content = endIdx >= 0 ? chunk.substring(0, endIdx) : chunk;

    const control = parseChunk(content.trim());
    if (control) {
      controls.push(control);
    }
  }

  return controls;
}

function parseChunk(content: string): ComplianceControl | null {
  const lines = content.split("\n").map((l) => l.trim());

  const getValue = (prefix: string): string => {
    const line = lines.find((l) => l.startsWith(prefix));
    return line ? line.substring(prefix.length).trim() : "";
  };

  const getList = (prefix: string): string[] => {
    const result: string[] = [];
    let inSection = false;
    for (const line of lines) {
      if (line.startsWith(prefix)) {
        inSection = true;
        continue;
      }
      if (inSection) {
        if (line.startsWith("- ")) {
          result.push(line.substring(2).trim());
        } else if (
          line.length === 0 ||
          line.startsWith("ControlTitle:") ||
          line.startsWith("Summary:") ||
          line.startsWith("ImplementationChecklist:") ||
          line.startsWith("EvidenceExamples:") ||
          line.startsWith("KeyRequirements:") ||
          line.startsWith("TypicalEvidence:")
        ) {
          inSection = false;
        }
      }
    }
    return result;
  };

  const controlId = getValue("ControlID:") || getValue("ClauseID:");
  const chunkId = getValue("ChunkID:");
  const type = getValue("Type:");
  const theme = getValue("Theme:");
  const title = getValue("ControlTitle:") || getValue("Title:");
  const summary = getValue("Summary:");

  if (!controlId || !title) return null;

  const implementationChecklist =
    getList("ImplementationChecklist:").length > 0
      ? getList("ImplementationChecklist:")
      : getList("KeyRequirements:");

  const evidenceExamples =
    getList("EvidenceExamples:").length > 0
      ? getList("EvidenceExamples:")
      : getList("TypicalEvidence:");

  return {
    controlId,
    chunkId,
    type,
    theme,
    title,
    summary,
    implementationChecklist,
    evidenceExamples,
    clauseId: getValue("ClauseID:") || undefined,
    subclause: getValue("Subclause:") || undefined,
  };
}

function parseOwaspTop10Controls(text: string): ComplianceControl[] {
  const controls: ComplianceControl[] = [];
  const categoryBlocks = text.split("BEGIN_CATEGORY:").slice(1);

  for (const block of categoryBlocks) {
    const endIdx = block.indexOf("END_CATEGORY:");
    const content = endIdx >= 0 ? block.substring(0, endIdx) : block;
    const control = parseOwaspCategory(content.trim());
    if (control) {
      controls.push(control);
    }
  }

  return controls;
}

function parseOwaspCategory(content: string): ComplianceControl | null {
  const lines = content.split("\n").map((line) => line.trim()).filter(Boolean);

  const getValue = (prefix: string): string => {
    const line = lines.find((entry) => entry.startsWith(prefix));
    return line ? line.substring(prefix.length).trim() : "";
  };

  const categoryId = getValue("CATEGORY_ID:");
  const categoryName = getValue("CATEGORY_NAME:");
  if (!categoryId || !categoryName) return null;

  const descriptions = collectOwaspSectionText(lines, "Description");
  const indicators = collectOwaspSectionText(lines, "Common indicators");
  const recommendedControls = collectOwaspSectionText(
    lines,
    "Recommended controls",
  );

  const summary = descriptions.join(" ").trim();
  const evidenceExamples = indicators.length > 0 ? indicators : descriptions;

  return {
    controlId: categoryId,
    chunkId: `${categoryId}.CATEGORY`,
    type: "OWASP_Top10_Category",
    theme: "OWASP Top 10",
    title: categoryName,
    summary,
    implementationChecklist: recommendedControls,
    evidenceExamples,
  };
}

function collectOwaspSectionText(lines: string[], sectionName: string): string[] {
  const results: string[] = [];
  let inSection = false;

  for (const line of lines) {
    if (line === `SECTION: ${sectionName}`) {
      inSection = true;
      continue;
    }

    if (!inSection) continue;

    if (
      line.startsWith("SECTION:") ||
      line.startsWith("BEGIN_CATEGORY:") ||
      line.startsWith("END_CATEGORY:")
    ) {
      break;
    }

    if (line.startsWith("CHUNK_ID:")) {
      continue;
    }

    if (line.startsWith("TEXT:")) {
      const value = line.substring("TEXT:".length).trim();
      if (value) {
        results.push(value);
      }
      continue;
    }

    const previous = results[results.length - 1];
    if (previous && !line.includes(":")) {
      results[results.length - 1] = `${previous} ${line}`.trim();
    }
  }

  return results;
}

/**
 * Parse a compliance framework from a JSON file.
 * Expects the file to match the ComplianceFramework interface directly.
 */
function parseComplianceJson(filePath: string): ComplianceFramework | null {
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw) as ComplianceFramework;

    if (!data.name || !Array.isArray(data.controls) || data.controls.length === 0) {
      logger.warn({ filePath }, "Compliance JSON missing name or controls");
      return null;
    }

    if (!data.controlCatalog) {
      data.controlCatalog = data.controls
        .map((c) => `${c.controlId} | ${c.title} | ${(c.summary || "").substring(0, 150)}`)
        .join("\n");
    }

    data.fileName = data.fileName || path.basename(filePath);

    logger.info(
      { framework: data.name, controls: data.controls.length, filePath },
      "Compliance framework loaded from JSON",
    );

    return data;
  } catch (err) {
    logger.error({ err, filePath }, "Failed to parse compliance JSON");
    return null;
  }
}

/**
 * Load all compliance frameworks from the compliance/ directory.
 * Call once at startup or first use; results are cached.
 */
let _frameworkCache: ComplianceFramework[] | null = null;

export function loadAllFrameworks(): ComplianceFramework[] {
  if (_frameworkCache) return _frameworkCache;

  const dir = path.join(process.cwd(), "compliance");

  if (!fs.existsSync(dir)) {
    logger.info({ dir }, "No compliance directory found");
    _frameworkCache = [];
    return [];
  }

  const files = fs.readdirSync(dir);
  const pdfs = files.filter((f) => f.endsWith(".pdf"));
  const jsons = files.filter((f) => f.endsWith(".json"));
  const frameworks: ComplianceFramework[] = [];

  for (const pdf of pdfs) {
    const fw = parseCompliancePdf(path.join(dir, pdf));
    if (fw && fw.controls.length > 0) {
      frameworks.push(fw);
    }
  }

  for (const jsonFile of jsons) {
    const fw = parseComplianceJson(path.join(dir, jsonFile));
    if (fw && fw.controls.length > 0) {
      frameworks.push(fw);
    }
  }

  // Deduplicate frameworks that share a name/slug (e.g. an ISO PDF and an ISO
  // JSON). Prefer the deterministic one (carries CWE crosswalk / appliesTo data)
  // so a hand-authored JSON supersedes a PDF parsed for LLM mapping.
  const isDeterministic = (f: ComplianceFramework) =>
    f.controls.some(
      (c) => (c.cweMapping && c.cweMapping.length > 0) || c.appliesTo,
    );
  const slugOf = (name: string) =>
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  const bySlug = new Map<string, ComplianceFramework>();
  for (const f of frameworks) {
    const slug = slugOf(f.name);
    const existing = bySlug.get(slug);
    if (!existing) {
      bySlug.set(slug, f);
    } else if (!isDeterministic(existing) && isDeterministic(f)) {
      logger.info(
        { framework: f.name, superseded: existing.fileName, winner: f.fileName },
        "Compliance framework deduplicated (deterministic wins)",
      );
      bySlug.set(slug, f);
    } else {
      logger.info(
        { framework: f.name, dropped: f.fileName, kept: existing.fileName },
        "Compliance framework deduplicated (duplicate dropped)",
      );
    }
  }
  const deduped = Array.from(bySlug.values());

  logger.info(
    {
      frameworks: deduped.length,
      totalControls: deduped.reduce((a, f) => a + f.controls.length, 0),
    },
    "Compliance frameworks loaded",
  );

  _frameworkCache = deduped;
  return deduped;
}

/** Clear the framework cache (e.g., after uploading new PDFs) */
export function clearFrameworkCache() {
  _frameworkCache = null;
}
