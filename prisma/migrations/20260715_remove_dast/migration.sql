-- Drop DAST-related fields from Project
ALTER TABLE "Project" DROP COLUMN IF EXISTS "dastTargetUrl";

-- Drop DAST-related fields from OrgSettings
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastEnabled";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastEndpoint";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastApiKeyEnc";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastConfigYamlEnc";

-- Remove DAST from Scanner enum
-- Note: This requires PostgreSQL migration that alters the enum type
-- First, we need to handle any existing DAST findings before removing the enum value
DELETE FROM "Finding" WHERE scanner = 'DAST';

-- Drop and recreate the Scanner enum without DAST
ALTER TYPE "Scanner" RENAME TO "Scanner_old";

CREATE TYPE "Scanner" AS ENUM (
  'SAST_PATTERN',
  'SAST_LLM',
  'SCA',
  'SECRETS_PATTERN',
  'SECRETS_LLM',
  'IAC',
  'MALICIOUS_PKG',
  'ZERO_DAY',
  'CONTAINER'
);

ALTER TABLE "Finding" ALTER COLUMN scanner TYPE "Scanner" USING scanner::"text"::"Scanner";
DROP TYPE "Scanner_old";

-- Remove DAST from ScanType enum
DELETE FROM "Scan" WHERE "scanType" = 'DAST_ONLY';

ALTER TYPE "ScanType" RENAME TO "ScanType_old";

CREATE TYPE "ScanType" AS ENUM (
  'FULL',
  'INCREMENTAL',
  'SAST_ONLY',
  'SCA_ONLY',
  'SECRETS_ONLY',
  'IAC_ONLY',
  'ZERO_DAY_ONLY',
  'CONTAINER_ONLY'
);

ALTER TABLE "Scan" ALTER COLUMN "scanType" TYPE "ScanType" USING "scanType"::"text"::"ScanType";
DROP TYPE "ScanType_old";

-- Remove DAST from SourceType enum
-- First, clean up any Scan records with DAST_TARGET sourceType (which no longer exists)
DELETE FROM "Scan" WHERE "sourceType" = 'DAST_TARGET';

ALTER TYPE "SourceType" RENAME TO "SourceType_old";

CREATE TYPE "SourceType" AS ENUM (
  'UPLOAD',
  'GIT_CLONE',
  'SVN_CHECKOUT',
  'WEBHOOK',
  'CONTAINER_IMAGE',
  'PRECOMMIT'
);

ALTER TABLE "Scan" ALTER COLUMN "sourceType" TYPE "SourceType" USING "sourceType"::"text"::"SourceType";
DROP TYPE "SourceType_old";

-- Remove DAST from ArtifactType enum
DELETE FROM "ScanArtifact" WHERE type = 'DAST_REPORT';

ALTER TYPE "ArtifactType" RENAME TO "ArtifactType_old";

CREATE TYPE "ArtifactType" AS ENUM (
  'SARIF',
  'SBOM_CYCLONEDX',
  'SBOM_SPDX',
  'SCAN_LOG',
  'CONTAINER_REPORT',
  'SIGNATURE'
);

ALTER TABLE "ScanArtifact" ALTER COLUMN type TYPE "ArtifactType" USING type::"text"::"ArtifactType";
DROP TYPE "ArtifactType_old";

-- Remove DAST from IntegrationKind enum
DELETE FROM "IntegrationConfig" WHERE kind = 'DAST';

ALTER TYPE "IntegrationKind" RENAME TO "IntegrationKind_old";

CREATE TYPE "IntegrationKind" AS ENUM (
  'JIRA',
  'SLACK',
  'SIEM',
  'CODE_SIGNING',
  'WEBHOOK'
);

ALTER TABLE "IntegrationConfig" ALTER COLUMN kind TYPE "IntegrationKind" USING kind::"text"::"IntegrationKind";
DROP TYPE "IntegrationKind_old";
