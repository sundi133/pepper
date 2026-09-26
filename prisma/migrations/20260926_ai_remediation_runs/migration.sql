-- AI remediation runs: sequential per-finding fixes shipped as one PR, with an
-- append-only event log the UI streams. Idempotent.

DO $$ BEGIN
  CREATE TYPE "RemediationStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE "RemediationItemStatus" AS ENUM ('PENDING', 'ANALYZING', 'FIXING', 'VALIDATING', 'FIXED', 'FAILED', 'SKIPPED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "RemediationRun" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "createdBy" TEXT,
  "status" "RemediationStatus" NOT NULL DEFAULT 'QUEUED',
  "provider" TEXT,
  "repoUrl" TEXT,
  "baseBranch" TEXT,
  "headBranch" TEXT,
  "prUrl" TEXT,
  "prNumber" INTEGER,
  "errorMessage" TEXT,
  "fixedCount" INTEGER NOT NULL DEFAULT 0,
  "failedCount" INTEGER NOT NULL DEFAULT 0,
  "cancelRequested" BOOLEAN NOT NULL DEFAULT false,
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "RemediationRun_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "RemediationItem" (
  "id" TEXT NOT NULL,
  "runId" TEXT NOT NULL,
  "findingId" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "status" "RemediationItemStatus" NOT NULL DEFAULT 'PENDING',
  "title" TEXT NOT NULL,
  "severity" TEXT NOT NULL,
  "filePath" TEXT,
  "analysis" TEXT,
  "diff" TEXT,
  "summary" TEXT,
  "validation" JSONB,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "error" TEXT,
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  CONSTRAINT "RemediationItem_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "RemediationEvent" (
  "id" TEXT NOT NULL,
  "runId" TEXT NOT NULL,
  "seq" INTEGER NOT NULL,
  "itemId" TEXT,
  "type" TEXT NOT NULL,
  "data" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "RemediationEvent_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "RemediationRun_organizationId_createdAt_idx" ON "RemediationRun"("organizationId", "createdAt");
CREATE INDEX IF NOT EXISTS "RemediationRun_scanId_createdAt_idx" ON "RemediationRun"("scanId", "createdAt");
CREATE INDEX IF NOT EXISTS "RemediationItem_runId_position_idx" ON "RemediationItem"("runId", "position");
CREATE UNIQUE INDEX IF NOT EXISTS "RemediationEvent_runId_seq_key" ON "RemediationEvent"("runId", "seq");

DO $$ BEGIN
  ALTER TABLE "RemediationRun" ADD CONSTRAINT "RemediationRun_scanId_fkey"
    FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "RemediationItem" ADD CONSTRAINT "RemediationItem_runId_fkey"
    FOREIGN KEY ("runId") REFERENCES "RemediationRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "RemediationEvent" ADD CONSTRAINT "RemediationEvent_runId_fkey"
    FOREIGN KEY ("runId") REFERENCES "RemediationRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
