-- Per-repository scan history for trends, and remediation runs that outlive
-- rescans (a rescan replaces the project's single Scan row). Idempotent.

CREATE TABLE IF NOT EXISTS "ScanSnapshot" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "scanType" "ScanType" NOT NULL,
  "branch" TEXT,
  "commitSha" TEXT,
  "completedAt" TIMESTAMP(3) NOT NULL,
  "criticalCount" INTEGER NOT NULL DEFAULT 0,
  "highCount" INTEGER NOT NULL DEFAULT 0,
  "mediumCount" INTEGER NOT NULL DEFAULT 0,
  "lowCount" INTEGER NOT NULL DEFAULT 0,
  "infoCount" INTEGER NOT NULL DEFAULT 0,
  "filesScanned" INTEGER NOT NULL DEFAULT 0,
  "gateResult" "GateResult" NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ScanSnapshot_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "ScanSnapshot_scanId_key" ON "ScanSnapshot"("scanId");
CREATE INDEX IF NOT EXISTS "ScanSnapshot_projectId_completedAt_idx" ON "ScanSnapshot"("projectId", "completedAt");
CREATE INDEX IF NOT EXISTS "ScanSnapshot_organizationId_completedAt_idx" ON "ScanSnapshot"("organizationId", "completedAt");

DO $$ BEGIN
  ALTER TABLE "ScanSnapshot" ADD CONSTRAINT "ScanSnapshot_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Seed history with every scan that already completed.
INSERT INTO "ScanSnapshot" (
  "id", "organizationId", "projectId", "scanId", "scanType", "branch", "commitSha",
  "completedAt", "criticalCount", "highCount", "mediumCount", "lowCount",
  "infoCount", "filesScanned", "gateResult"
)
SELECT
  gen_random_uuid()::text, p."organizationId", s."projectId", s."id", s."scanType",
  s."branch", s."commitSha", s."completedAt", s."criticalCount", s."highCount",
  s."mediumCount", s."lowCount", s."infoCount", s."filesScanned", s."gateResult"
FROM "Scan" s
JOIN "Project" p ON p."id" = s."projectId"
WHERE s."status" = 'COMPLETED' AND s."completedAt" IS NOT NULL
ON CONFLICT ("scanId") DO NOTHING;

-- Remediation runs: keyed by project, scan link becomes optional.
ALTER TABLE "RemediationRun" ADD COLUMN IF NOT EXISTS "projectId" TEXT;
ALTER TABLE "RemediationRun" ALTER COLUMN "scanId" DROP NOT NULL;

UPDATE "RemediationRun" r
SET "projectId" = s."projectId"
FROM "Scan" s
WHERE r."scanId" = s."id" AND r."projectId" IS NULL;

CREATE INDEX IF NOT EXISTS "RemediationRun_projectId_createdAt_idx" ON "RemediationRun"("projectId", "createdAt");

ALTER TABLE "RemediationRun" DROP CONSTRAINT IF EXISTS "RemediationRun_scanId_fkey";
ALTER TABLE "RemediationRun" ADD CONSTRAINT "RemediationRun_scanId_fkey"
  FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE SET NULL ON UPDATE CASCADE;
