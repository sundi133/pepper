-- Azure DevOps: Entra ID service principal connections (docs/PR_REVIEW_PROVIDERS_SPEC.md §1.2).
-- Additive: existing rows stay PAT connections. Idempotent.

ALTER TABLE "OrgAzureDevOpsConnection" ADD COLUMN IF NOT EXISTS "authType" TEXT NOT NULL DEFAULT 'pat';
ALTER TABLE "OrgAzureDevOpsConnection" ADD COLUMN IF NOT EXISTS "tenantId" TEXT;
ALTER TABLE "OrgAzureDevOpsConnection" ADD COLUMN IF NOT EXISTS "clientId" TEXT;
ALTER TABLE "OrgAzureDevOpsConnection" ADD COLUMN IF NOT EXISTS "clientSecretEnc" TEXT;
ALTER TABLE "OrgAzureDevOpsConnection" ALTER COLUMN "patEnc" DROP NOT NULL;
