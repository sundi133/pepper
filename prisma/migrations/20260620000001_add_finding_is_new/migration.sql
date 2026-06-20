-- Track whether a finding is new (vs. persisting from a previous scan).
-- null = no previous scan to compare against (first scan or legacy data).
-- true = finding did not appear in the immediately previous completed scan.
-- false = finding was already present in the previous scan.
ALTER TABLE "Finding" ADD COLUMN IF NOT EXISTS "isNew" BOOLEAN;
CREATE INDEX IF NOT EXISTS "Finding_scanId_isNew_idx" ON "Finding"("scanId", "isNew");
