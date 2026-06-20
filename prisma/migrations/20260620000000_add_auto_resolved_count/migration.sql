-- Track how many previously-open findings were auto-resolved by each scan,
-- and how many findings in this scan are genuinely new (vs. persisting).
ALTER TABLE "Scan" ADD COLUMN IF NOT EXISTS "autoResolvedCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Scan" ADD COLUMN IF NOT EXISTS "newFindingCount" INTEGER NOT NULL DEFAULT 0;
