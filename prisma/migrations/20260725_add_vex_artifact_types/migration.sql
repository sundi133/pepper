-- Add VEX document artifact types.
--
-- A VEX accompanies an SBOM and states whether the vulnerabilities in the
-- listed components actually affect the product. ALTER TYPE ... ADD VALUE is
-- used rather than recreating the enum so existing ScanArtifact rows are
-- untouched. IF NOT EXISTS keeps the migration idempotent for environments
-- that were previously synced with `prisma db push`.

ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'VEX_OPENVEX';
ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'VEX_CYCLONEDX';
