-- Azure Boards integration: new integration kind plus a table linking each
-- finding (by cross-scan fingerprint) to the work item filed for it.
-- Idempotent.

ALTER TYPE "IntegrationKind" ADD VALUE IF NOT EXISTS 'AZURE_BOARDS';

CREATE TABLE IF NOT EXISTS "FindingTicket" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "integrationId" TEXT,
  "system" TEXT NOT NULL,
  "target" TEXT NOT NULL,
  "fingerprint" TEXT NOT NULL,
  "scanner" TEXT NOT NULL,
  "branch" TEXT,
  "findingId" TEXT,
  "externalId" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "missedScans" INTEGER NOT NULL DEFAULT 0,
  "fixedNotifiedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "FindingTicket_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "FindingTicket_projectId_system_target_fingerprint_key"
  ON "FindingTicket"("projectId", "system", "target", "fingerprint");
CREATE INDEX IF NOT EXISTS "FindingTicket_findingId_idx" ON "FindingTicket"("findingId");
CREATE INDEX IF NOT EXISTS "FindingTicket_organizationId_idx" ON "FindingTicket"("organizationId");

DO $$ BEGIN
  ALTER TABLE "FindingTicket" ADD CONSTRAINT "FindingTicket_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "FindingTicket" ADD CONSTRAINT "FindingTicket_integrationId_fkey"
    FOREIGN KEY ("integrationId") REFERENCES "IntegrationConfig"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
