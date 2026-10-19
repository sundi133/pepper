-- GitHub App installations linked to organizations (docs/GITHUB_APP_SPEC.md).
-- Additive: one new table; existing GitHub OAuth connections are untouched. Idempotent.

CREATE TABLE IF NOT EXISTS "OrgGithubAppInstallation" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "installationId" BIGINT NOT NULL,
  "accountLogin" TEXT NOT NULL,
  "accountType" TEXT NOT NULL,
  "repositorySelection" TEXT NOT NULL,
  "suspendedAt" TIMESTAMP(3),
  "createdBy" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "OrgGithubAppInstallation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "OrgGithubAppInstallation_installationId_key" ON "OrgGithubAppInstallation"("installationId");
CREATE INDEX IF NOT EXISTS "OrgGithubAppInstallation_organizationId_idx" ON "OrgGithubAppInstallation"("organizationId");

DO $$ BEGIN
  ALTER TABLE "OrgGithubAppInstallation" ADD CONSTRAINT "OrgGithubAppInstallation_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
