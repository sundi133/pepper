-- Add encrypted DAST config YAML storage for org-scoped local Dapper orchestration.
ALTER TABLE "OrgSettings"
ADD COLUMN IF NOT EXISTS "dastConfigYamlEnc" TEXT;
