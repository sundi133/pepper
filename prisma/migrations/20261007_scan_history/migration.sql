-- Scan history: a repository keeps every scan instead of only its latest, so
-- the one-scan-per-project unique index goes and a lookup index replaces it.
-- Idempotent. Downgrading to a version with the unique index fails once a
-- repository has more than one scan; delete the older scans first.

DROP INDEX IF EXISTS "Scan_projectId_key";
CREATE INDEX IF NOT EXISTS "Scan_projectId_createdAt_idx" ON "Scan"("projectId", "createdAt");
