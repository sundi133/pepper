-- Pepper Bitbucket Cloud integration
-- Idempotent: safe to re-run against a DB that may have been synced via
-- `prisma db push`. Every CREATE / ALTER uses IF NOT EXISTS.

-- ─── Project columns ────────────────────────────────────────────────

ALTER TABLE "Project"
  ADD COLUMN IF NOT EXISTS "bitbucketWorkspace"    TEXT,
  ADD COLUMN IF NOT EXISTS "bitbucketRepoSlug"     TEXT,
  ADD COLUMN IF NOT EXISTS "bitbucketRepoUuid"     TEXT,
  ADD COLUMN IF NOT EXISTS "connectedViaBitbucket" BOOLEAN NOT NULL DEFAULT FALSE;

-- Unique per-org for the Bitbucket repo UUID (mirrors the GitHub repo id constraint).
CREATE UNIQUE INDEX IF NOT EXISTS "Project_organizationId_bitbucketRepoUuid_key"
  ON "Project" ("organizationId", "bitbucketRepoUuid");

-- ─── OrgBitbucketConnection ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS "OrgBitbucketConnection" (
  "id"             TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "workspace"      TEXT,
  "username"       TEXT NOT NULL,
  "appPasswordEnc" TEXT NOT NULL,
  "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"      TIMESTAMP(3) NOT NULL,
  CONSTRAINT "OrgBitbucketConnection_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "OrgBitbucketConnection_organizationId_key"
  ON "OrgBitbucketConnection" ("organizationId");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'OrgBitbucketConnection_organizationId_fkey'
  ) THEN
    ALTER TABLE "OrgBitbucketConnection"
      ADD CONSTRAINT "OrgBitbucketConnection_organizationId_fkey"
      FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
      ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;
