-- GitLab merge-request reviews (docs/PR_REVIEW_PROVIDERS_SPEC.md §2). Additive and idempotent.

ALTER TABLE "OrgGitLabConnection" ADD COLUMN IF NOT EXISTS "tokenKind" TEXT;
ALTER TABLE "OrgGitLabConnection" ADD COLUMN IF NOT EXISTS "tokenScopes" TEXT;
ALTER TABLE "OrgGitLabConnection" ADD COLUMN IF NOT EXISTS "tokenExpiresAt" TIMESTAMP(3);
ALTER TABLE "OrgGitLabConnection" ADD COLUMN IF NOT EXISTS "commitStatuses" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "connectedViaGitlab" BOOLEAN NOT NULL DEFAULT false;
