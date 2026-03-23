/**
 * Identifies high-priority files for zero-day / business logic analysis.
 * Zero-day detection is expensive (LLM), so we focus on security-critical code paths.
 */

const CRITICAL_PATTERNS = [
  // Auth & access control (IDOR targets)
  /auth/i,
  /login/i,
  /session/i,
  /token/i,
  /oauth/i,
  /permission/i,
  /access[-_]?control/i,
  /rbac/i,
  /acl/i,
  /password/i,
  /secret/i,
  /key[-_]?manage/i,
  // Financial / business-critical (business logic targets)
  /payment/i,
  /billing/i,
  /checkout/i,
  /transaction/i,
  /transfer/i,
  /wallet/i,
  /balance/i,
  /invoice/i,
  /order/i,
  /cart/i,
  /pricing/i,
  /discount/i,
  /coupon/i,
  /subscription/i,
  /plan/i,
  /refund/i,
  /credit/i,
  // Crypto
  /crypto/i,
  /encrypt/i,
  /decrypt/i,
  /hash/i,
];

const HIGH_PATTERNS = [
  // API endpoints & routing (IDOR targets)
  /api/i,
  /controller/i,
  /route/i,
  /handler/i,
  /middleware/i,
  /webhook/i,
  /endpoint/i,
  // Resource CRUD (IDOR + business logic targets)
  /upload/i,
  /download/i,
  /export/i,
  /import/i,
  /admin/i,
  /user/i,
  /account/i,
  /profile/i,
  /tenant/i,
  /org/i,
  /member/i,
  /invite/i,
  /role/i,
  // Data access (race condition targets)
  /serialize/i,
  /deserialize/i,
  /parse/i,
  /database/i,
  /query/i,
  /repository/i,
  /model/i,
  // Background processing (race condition targets)
  /service/i,
  /worker/i,
  /queue/i,
  /job/i,
  // Business logic flows
  /workflow/i,
  /approval/i,
  /verify/i,
  /confirm/i,
  /register/i,
  /signup/i,
  /onboard/i,
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

  // Sort: critical first, then high, skip normal
  const priorityOrder = { critical: 0, high: 1, normal: 2 };
  return result.sort(
    (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority],
  );
}

/**
 * Select files for zero-day scanning.
 * Returns at most maxFiles, prioritizing critical and high files.
 */
export function selectZeroDayFiles(
  fileList: string[],
  maxFiles = 50,
): string[] {
  const prioritized = prioritizeFiles(fileList);
  return prioritized
    .filter((f) => f.priority !== "normal")
    .slice(0, maxFiles)
    .map((f) => f.path);
}
