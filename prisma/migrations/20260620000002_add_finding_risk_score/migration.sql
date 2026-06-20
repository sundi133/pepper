-- Risk score: 1–100 composite derived from severity, scanner type, confidence,
-- and file-path sensitivity. Stored so findings can be sorted server-side.
ALTER TABLE "Finding" ADD COLUMN IF NOT EXISTS "riskScore" INTEGER;
CREATE INDEX IF NOT EXISTS "Finding_scanId_riskScore_idx" ON "Finding"("scanId", "riskScore" DESC);
