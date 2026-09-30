-- Developer pre-push scan support.
--
-- ScanOrigin distinguishes where a scan was triggered from, independent of how
-- the source arrived (sourceType). Project.ephemeral segregates throwaway dev
-- scans so a local scan never clobbers a canonical project's scan.
--
-- Both columns are additive and nullable/defaulted, so existing rows are
-- untouched. IF NOT EXISTS keeps this idempotent for db-push environments.

DO $$ BEGIN
  CREATE TYPE "ScanOrigin" AS ENUM ('WEB', 'LOCAL', 'CICD', 'WEBHOOK');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

ALTER TABLE "Scan" ADD COLUMN IF NOT EXISTS "origin" "ScanOrigin";
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "ephemeral" BOOLEAN NOT NULL DEFAULT false;
