-- Point-in-time copy of each snapshotted scan's findings, so any two scan
-- versions of a repository can be compared after rescans replace the Scan
-- row. Idempotent.

ALTER TABLE "ScanSnapshot" ADD COLUMN IF NOT EXISTS "findingsCaptured" BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS "ScanSnapshotFinding" (
  "id" TEXT NOT NULL,
  "snapshotId" TEXT NOT NULL,
  "fingerprint" TEXT NOT NULL,
  "findingId" TEXT,
  "scanner" "Scanner" NOT NULL,
  "severity" "Severity" NOT NULL,
  "status" "FindingStatus" NOT NULL,
  "title" TEXT NOT NULL,
  "filePath" TEXT,
  "startLine" INTEGER,
  "ruleId" TEXT,
  "cweId" TEXT,
  "cveId" TEXT,
  CONSTRAINT "ScanSnapshotFinding_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "ScanSnapshotFinding_snapshotId_idx" ON "ScanSnapshotFinding"("snapshotId");

DO $$ BEGIN
  ALTER TABLE "ScanSnapshotFinding" ADD CONSTRAINT "ScanSnapshotFinding_snapshotId_fkey"
    FOREIGN KEY ("snapshotId") REFERENCES "ScanSnapshot"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
