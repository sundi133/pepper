/**
 * Compute the next run time for a scan schedule.
 */
export function computeNextRun(
  frequency: string,
  from: Date = new Date(),
): Date {
  const next = new Date(from);

  switch (frequency) {
    case "DAILY":
      next.setUTCDate(next.getUTCDate() + 1);
      next.setUTCHours(2, 0, 0, 0); // 2am UTC
      break;
    case "WEEKLY":
      // Next Monday at 2am UTC
      const daysUntilMonday = (8 - next.getUTCDay()) % 7 || 7;
      next.setUTCDate(next.getUTCDate() + daysUntilMonday);
      next.setUTCHours(2, 0, 0, 0);
      break;
    case "BIWEEKLY":
      const daysUntilNextMonday = (8 - next.getUTCDay()) % 7 || 7;
      next.setUTCDate(next.getUTCDate() + daysUntilNextMonday + 7);
      next.setUTCHours(2, 0, 0, 0);
      break;
    case "MONTHLY":
      next.setUTCMonth(next.getUTCMonth() + 1, 1);
      next.setUTCHours(2, 0, 0, 0);
      break;
    default:
      // Default: daily
      next.setUTCDate(next.getUTCDate() + 1);
      next.setUTCHours(2, 0, 0, 0);
  }

  return next;
}
