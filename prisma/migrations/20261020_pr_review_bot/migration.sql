-- PR review bot (docs/PR_REVIEW_BOT_SPEC.md): per-PR pause state and the
-- organization policy for personal GitHub connections. Additive. Idempotent.

ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "allowPersonalGithub" BOOLEAN NOT NULL DEFAULT true;

CREATE TABLE IF NOT EXISTS "PrReviewState" (
  "id" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "prNumber" INTEGER NOT NULL,
  "paused" BOOLEAN NOT NULL DEFAULT false,
  "pausedBy" TEXT,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PrReviewState_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PrReviewState_projectId_prNumber_key" ON "PrReviewState"("projectId", "prNumber");

DO $$ BEGIN
  ALTER TABLE "PrReviewState" ADD CONSTRAINT "PrReviewState_projectId_fkey"
    FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
