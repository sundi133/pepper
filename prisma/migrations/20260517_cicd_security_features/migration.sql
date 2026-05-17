-- Pepper CI/CD security features
-- Idempotent: safe to run against a DB that was previously synced via
-- `prisma db push`, or against a fresh DB after the baseline schema has been
-- applied. Every CREATE / ALTER uses IF NOT EXISTS so the migration is
-- a no-op when the objects already exist.

-- ─── Enum extensions ───────────────────────────────────────────────

ALTER TYPE "Scanner" ADD VALUE IF NOT EXISTS 'CONTAINER';
ALTER TYPE "Scanner" ADD VALUE IF NOT EXISTS 'DAST';

ALTER TYPE "ScanType" ADD VALUE IF NOT EXISTS 'CONTAINER_ONLY';
ALTER TYPE "ScanType" ADD VALUE IF NOT EXISTS 'DAST_ONLY';

ALTER TYPE "SourceType" ADD VALUE IF NOT EXISTS 'CONTAINER_IMAGE';
ALTER TYPE "SourceType" ADD VALUE IF NOT EXISTS 'DAST_TARGET';
ALTER TYPE "SourceType" ADD VALUE IF NOT EXISTS 'PRECOMMIT';

ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'SBOM_SPDX';
ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'CONTAINER_REPORT';
ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'DAST_REPORT';
ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'SIGNATURE';

-- ─── IntegrationKind enum (new) ────────────────────────────────────

DO $$ BEGIN
  CREATE TYPE "IntegrationKind" AS ENUM ('JIRA', 'SLACK', 'SIEM', 'DAST', 'CODE_SIGNING');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- ─── IntegrationConfig table (new) ─────────────────────────────────

CREATE TABLE IF NOT EXISTS "IntegrationConfig" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "kind" "IntegrationKind" NOT NULL,
  "name" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT true,
  "configEnc" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "IntegrationConfig_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "IntegrationConfig_organizationId_kind_idx"
  ON "IntegrationConfig" ("organizationId", "kind");

DO $$ BEGIN
  ALTER TABLE "IntegrationConfig"
    ADD CONSTRAINT "IntegrationConfig_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- ─── OrgSettings: DAST + code signing columns ──────────────────────

ALTER TABLE "OrgSettings"
  ADD COLUMN IF NOT EXISTS "dastEnabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "dastEndpoint" TEXT,
  ADD COLUMN IF NOT EXISTS "dastApiKeyEnc" TEXT,
  ADD COLUMN IF NOT EXISTS "codeSigningEnabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "codeSigningMode" TEXT NOT NULL DEFAULT 'keyless',
  ADD COLUMN IF NOT EXISTS "codeSigningKeyEnc" TEXT,
  ADD COLUMN IF NOT EXISTS "codeSigningIdentity" TEXT;

-- ─── Project: per-project DAST target ──────────────────────────────

ALTER TABLE "Project"
  ADD COLUMN IF NOT EXISTS "dastTargetUrl" TEXT;
