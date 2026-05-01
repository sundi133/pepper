import pino from "pino";

function createLogger() {
  const level = process.env.LOG_LEVEL || "info";
  if (process.env.NODE_ENV !== "development") return pino({ level });

  try {
    return pino({
      level,
      transport: { target: "pino-pretty", options: { colorize: true } },
    });
  } catch {
    return pino({ level });
  }
}

export const logger = createLogger();

export function createScanLogger(scanId: string) {
  return logger.child({ scanId });
}
