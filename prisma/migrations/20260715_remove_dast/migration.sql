-- Drop DAST-related fields from Project
ALTER TABLE "Project" DROP COLUMN IF EXISTS "dastTargetUrl";

-- Drop DAST-related fields from OrgSettings
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastEnabled";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastEndpoint";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastApiKeyEnc";
ALTER TABLE "OrgSettings" DROP COLUMN IF EXISTS "dastConfigYamlEnc";

-- Drop all defaults that depend on enums before dropping the types
ALTER TABLE "Scan" ALTER COLUMN "scanType" DROP DEFAULT;
ALTER TABLE "ScanSchedule" ALTER COLUMN "scanType" DROP DEFAULT;
ALTER TABLE "Scan" ALTER COLUMN "sourceType" DROP DEFAULT;

-- Remove DAST from Scanner enum
ALTER TABLE "Finding" ALTER COLUMN scanner TYPE text;
DELETE FROM "Finding" WHERE scanner = 'DAST';
DROP TYPE "Scanner";
CREATE TYPE "Scanner" AS ENUM (
  'SAST_PATTERN',
  'SAST_LLM',
  'SCA',
  'SECRETS_PATTERN',
  'SECRETS_LLM',
  'IAC',
  'MALICIOUS_PKG',
  'ZERO_DAY',
  'CONTAINER',
  'K8S'
);
ALTER TABLE "Finding" ALTER COLUMN scanner TYPE "Scanner" USING (scanner::"Scanner");

-- Remove DAST from ScanType enum
ALTER TABLE "Scan" ALTER COLUMN "scanType" TYPE text;
ALTER TABLE "ScanSchedule" ALTER COLUMN "scanType" TYPE text;
DELETE FROM "Scan" WHERE "scanType" = 'DAST_ONLY';
DROP TYPE "ScanType";
CREATE TYPE "ScanType" AS ENUM (
  'FULL',
  'INCREMENTAL',
  'SAST_ONLY',
  'SCA_ONLY',
  'SECRETS_ONLY',
  'IAC_ONLY',
  'ZERO_DAY_ONLY',
  'CONTAINER_ONLY',
  'K8S_ONLY'
);
ALTER TABLE "Scan" ALTER COLUMN "scanType" TYPE "ScanType" USING ("scanType"::"ScanType");
ALTER TABLE "Scan" ALTER COLUMN "scanType" SET DEFAULT 'FULL'::"ScanType";
ALTER TABLE "ScanSchedule" ALTER COLUMN "scanType" TYPE "ScanType" USING ("scanType"::"ScanType");
ALTER TABLE "ScanSchedule" ALTER COLUMN "scanType" SET DEFAULT 'FULL'::"ScanType";

-- Remove DAST from SourceType enum
ALTER TABLE "Scan" ALTER COLUMN "sourceType" TYPE text;
DELETE FROM "Scan" WHERE "sourceType" = 'DAST_TARGET';
DROP TYPE "SourceType";
CREATE TYPE "SourceType" AS ENUM (
  'UPLOAD',
  'GIT_CLONE',
  'SVN_CHECKOUT',
  'WEBHOOK',
  'CONTAINER_IMAGE',
  'PRECOMMIT'
);
ALTER TABLE "Scan" ALTER COLUMN "sourceType" TYPE "SourceType" USING ("sourceType"::"SourceType");
ALTER TABLE "Scan" ALTER COLUMN "sourceType" SET DEFAULT 'UPLOAD'::"SourceType";

-- Remove DAST from ArtifactType enum
ALTER TABLE "ScanArtifact" ALTER COLUMN type TYPE text;
DELETE FROM "ScanArtifact" WHERE type = 'DAST_REPORT';
DROP TYPE "ArtifactType";
CREATE TYPE "ArtifactType" AS ENUM (
  'SARIF',
  'SBOM_CYCLONEDX',
  'SBOM_SPDX',
  'SCAN_LOG',
  'CONTAINER_REPORT',
  'SIGNATURE'
);
ALTER TABLE "ScanArtifact" ALTER COLUMN type TYPE "ArtifactType" USING (type::"ArtifactType");

-- Remove DAST from IntegrationKind enum
ALTER TABLE "IntegrationConfig" ALTER COLUMN kind TYPE text;
DELETE FROM "IntegrationConfig" WHERE kind = 'DAST';
DROP TYPE "IntegrationKind";
CREATE TYPE "IntegrationKind" AS ENUM (
  'JIRA',
  'SLACK',
  'SIEM',
  'CODE_SIGNING',
  'WEBHOOK'
);
ALTER TABLE "IntegrationConfig" ALTER COLUMN kind TYPE "IntegrationKind" USING (kind::"IntegrationKind");
