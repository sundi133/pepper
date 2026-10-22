-- Add the AI_REASONING artifact type.
--
-- The worker aggregates every AI scanner's full model-reasoning trace into one
-- ScanArtifact of this type, so developers can read how the AI reached its
-- findings. ALTER TYPE ... ADD VALUE is used rather than recreating the enum so
-- existing ScanArtifact rows are untouched. IF NOT EXISTS keeps the migration
-- idempotent for environments previously synced with `prisma db push`.

ALTER TYPE "ArtifactType" ADD VALUE IF NOT EXISTS 'AI_REASONING';
