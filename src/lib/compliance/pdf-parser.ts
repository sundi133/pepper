/**
 * Parses compliance framework PDFs with [CHUNK_START]/[CHUNK_END] structure.
 * Extracts all controls with their full metadata for LLM context.
 */
import * as fs from "fs";
import * as path from "path";
import { logger } from "@/lib/logger";

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
}

export interface ComplianceFramework {
  name: string;
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
    const { execSync } = require("child_process");
    let text: string;

    try {
      // Try pdftotext first (most accurate)
      text = execSync(`pdftotext -layout "${filePath}" -`, {
        encoding: "utf-8",
        timeout: 30000,
      });
    } catch {
      // Fallback: read as-is (some PDFs are already text-like)
      text = fs.readFileSync(filePath, "utf-8");
    }

    if (!text || text.length < 100) {
      logger.warn({ filePath }, "Compliance PDF is empty or too short");
      return null;
    }

    const controls: ComplianceControl[] = [];
    const chunks = text.split("[CHUNK_START]").slice(1); // Skip preamble

    for (const chunk of chunks) {
      const endIdx = chunk.indexOf("[CHUNK_END]");
      const content = endIdx >= 0 ? chunk.substring(0, endIdx) : chunk;

      const control = parseChunk(content.trim());
      if (control) {
        controls.push(control);
      }
    }

    // Determine framework name from filename
    const basename = path.basename(filePath, ".pdf");
    const name = basename.includes("27001")
      ? "ISO/IEC 27001:2022"
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

/**
 * Load all compliance frameworks from the compliance/ directory.
 * Call once at startup or first use; results are cached.
 */
let _frameworkCache: ComplianceFramework[] | null = null;

export function loadAllFrameworks(
  complianceDir?: string,
): ComplianceFramework[] {
  if (_frameworkCache) return _frameworkCache;

  const dir = complianceDir || path.join(process.cwd(), "compliance");

  if (!fs.existsSync(dir)) {
    logger.info({ dir }, "No compliance directory found");
    _frameworkCache = [];
    return [];
  }

  const pdfs = fs.readdirSync(dir).filter((f) => f.endsWith(".pdf"));
  const frameworks: ComplianceFramework[] = [];

  for (const pdf of pdfs) {
    const fw = parseCompliancePdf(path.join(dir, pdf));
    if (fw && fw.controls.length > 0) {
      frameworks.push(fw);
    }
  }

  logger.info(
    {
      frameworks: frameworks.length,
      totalControls: frameworks.reduce((a, f) => a + f.controls.length, 0),
    },
    "Compliance frameworks loaded",
  );

  _frameworkCache = frameworks;
  return frameworks;
}

/** Clear the framework cache (e.g., after uploading new PDFs) */
export function clearFrameworkCache() {
  _frameworkCache = null;
}
