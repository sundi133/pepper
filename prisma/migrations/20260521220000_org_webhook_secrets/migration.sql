-- Per-organization inbound webhook secrets (encrypted at rest). Env vars remain as fallback.
ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "githubWebhookSecretEnc" TEXT;
ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "gitlabWebhookSecretEnc" TEXT;
ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "bitbucketWebhookSecretEnc" TEXT;
ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "azureDevOpsWebhookSecretEnc" TEXT;
