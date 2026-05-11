import pino from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL || "info",
});

export function createScanLogger(scanId: string) {
  return logger.child({ scanId });
}
