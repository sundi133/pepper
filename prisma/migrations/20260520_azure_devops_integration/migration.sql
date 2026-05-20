-- Pepper Azure DevOps Services integration
-- Mirrors prisma/migrations/20260520_bitbucket_integration. Idempotent —
-- every CREATE / ALTER uses IF NOT EXISTS so re-running against a DB
-- that was previously synced via `prisma db push` is a no-op.

-- ─── Project columns ────────────────────────────────────────────────

ALTER TABLE "Project"
  ADD COLUMN IF NOT EXISTS "azureOrganization" TEXT,
  ADD COLUMN IF NOT EXISTS "azureProjectName"  TEXT,
  ADD COLUMN IF NOT EXISTS "azureRepoId"       TEXT,
  ADD COLUMN IF NOT EXISTS "azureRepoName"     TEXT,
  ADD COLUMN IF NOT EXISTS "connectedViaAzure" BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS "Project_organizationId_azureRepoId_key"
  ON "Project" ("organizationId", "azureRepoId");

-- ─── OrgAzureDevOpsConnection ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS "OrgAzureDevOpsConnection" (
  "id"                TEXT NOT NULL,
  "organizationId"    TEXT NOT NULL,
  "azureOrganization" TEXT NOT NULL,
  "azureUser"         TEXT,
  "patEnc"            TEXT NOT NULL,
  "createdAt"         TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"         TIMESTAMP(3) NOT NULL,
  CONSTRAINT "OrgAzureDevOpsConnection_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "OrgAzureDevOpsConnection_organizationId_key"
  ON "OrgAzureDevOpsConnection" ("organizationId");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'OrgAzureDevOpsConnection_organizationId_fkey'
  ) THEN
    ALTER TABLE "OrgAzureDevOpsConnection"
      ADD CONSTRAINT "OrgAzureDevOpsConnection_organizationId_fkey"
      FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
      ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;
