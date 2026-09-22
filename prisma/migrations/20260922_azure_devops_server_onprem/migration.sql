-- Azure DevOps Server (on-prem) support: store the self-hosted server base URL
-- alongside the collection. Null = hosted service (dev.azure.com). Idempotent.

ALTER TABLE "OrgAzureDevOpsConnection"
  ADD COLUMN IF NOT EXISTS "azureServerUrl" TEXT;
