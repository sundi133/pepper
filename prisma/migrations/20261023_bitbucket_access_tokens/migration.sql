-- Bitbucket access tokens and API tokens (docs/PR_REVIEW_PROVIDERS_SPEC.md §3.2).
-- Additive: existing rows stay app-password connections. Idempotent.

ALTER TABLE "OrgBitbucketConnection" ADD COLUMN IF NOT EXISTS "authType" TEXT NOT NULL DEFAULT 'app_password';
ALTER TABLE "OrgBitbucketConnection" ADD COLUMN IF NOT EXISTS "tokenEnc" TEXT;
ALTER TABLE "OrgBitbucketConnection" ALTER COLUMN "appPasswordEnc" DROP NOT NULL;
