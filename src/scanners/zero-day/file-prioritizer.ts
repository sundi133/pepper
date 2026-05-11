/**
 * Identifies high-priority files for zero-day / business logic analysis.
 * Zero-day detection is expensive (LLM), so we focus on security-critical code paths first,
 * then fill remaining budget with other source files for broader coverage.
 */

import {
  ZERO_DAY_MAX_FILES,
  ZERO_DAY_PRIORITY_FILES,
} from "@/lib/constants";

const CRITICAL_PATTERNS = [
  // Auth & access control (IDOR targets)
  /(^|[/_.-])(auth|login|session|token|oauth|permission|policy|authorize|authorization|rbac|acl)([/_.-]|$)/i,
  /access[-_]?control/i,
  /(^|[/_.-])(password|secret|key[-_]?manage)([/_.-]|$)/i,
  /(^|[/_.-])(admin|guard|middleware|serializer|controller|view|views|api)([/_.-]|$)/i,
  // Financial / business-critical (business logic targets)
  /(^|[/_.-])(payment|billing|checkout|transaction|transfer|wallet|balance|invoice|order|cart|pricing|discount|coupon|subscription|refund|credit)([/_.-]|$)/i,
  // Crypto
  /(^|[/_.-])(crypto|encrypt|decrypt|hash|sign|verify)([/_.-]|$)/i,
  // AI / agent trust boundaries
  /(^|[/_.-])llm([/_.-]|$)/i,
  /ai[-_]?agent/i,
  /(^|[/_.-])mcp([/_.-]|$)/i,
  /tool[-_]?call/i,
  /(^|[/_.-])prompt([/_.-]|$)/i,
];

const HIGH_PATTERNS = [
  // API endpoints & routing (IDOR targets)
  /(^|[/_.-])(api|controller|route|resolver)([/_.-]|$)/i,
  /server[-_]?action/i,
  /(^|[/_.-])(handler|webhook|endpoint)([/_.-]|$)/i,
  // Resource CRUD (IDOR + business logic targets)
  /(^|[/_.-])(upload|download|export|import|user|account|profile|tenant|org|member|invite|role)([/_.-]|$)/i,
  // Data access (race condition targets)
  /(^|[/_.-])(serialize|serializer|deserialize|database|query|repository|model)([/_.-]|$)/i,
  // Background processing (race condition targets)
  /(^|[/_.-])(service|worker|queue|job|event|consumer)([/_.-]|$)/i,
  // Business logic flows
  /(^|[/_.-])(workflow|approval|confirm|register|signup|onboard)([/_.-]|$)/i,
];

export type FilePriority = "critical" | "high" | "normal";

export function prioritizeFiles(
  fileList: string[],
): { priority: FilePriority; path: string }[] {
  const result: { priority: FilePriority; path: string }[] = [];

  for (const file of fileList) {
    const lower = file.toLowerCase();

    if (CRITICAL_PATTERNS.some((p) => p.test(lower))) {
      result.push({ priority: "critical", path: file });
    } else if (HIGH_PATTERNS.some((p) => p.test(lower))) {
      result.push({ priority: "high", path: file });
    } else {
      result.push({ priority: "normal", path: file });
    }
  }

  const priorityOrder = { critical: 0, high: 1, normal: 2 };
  return result.sort(
    (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority],
  );
}

/**
 * Select files for zero-day scanning.
 * Takes high-priority paths first (up to ZERO_DAY_PRIORITY_FILES), then other
 * files until ZERO_DAY_MAX_FILES total (order preserved from prioritizeFiles).
 */
export function selectZeroDayFiles(
  fileList: string[],
  maxTotal: number = ZERO_DAY_MAX_FILES,
  maxPriority: number = ZERO_DAY_PRIORITY_FILES,
): string[] {
  const prioritized = prioritizeFiles(fileList);
  const priorityPaths = prioritized
    .filter((f) => f.priority !== "normal")
    .slice(0, maxPriority)
    .map((f) => f.path);

  const seen = new Set(priorityPaths);
  const out = [...priorityPaths];

  for (const f of prioritized) {
    if (out.length >= maxTotal) break;
    if (!seen.has(f.path)) {
      seen.add(f.path);
      out.push(f.path);
    }
  }

  return out;
}
