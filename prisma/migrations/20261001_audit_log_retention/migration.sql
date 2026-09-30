-- Audit log retention: per-organization retention window and archive-before-
-- delete switch. Existing organizations keep every entry (NULL = instance
-- default, which is "keep forever" unless AUDIT_LOG_RETENTION_DAYS is set).
-- Idempotent.

ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "auditLogRetentionDays" INTEGER;
ALTER TABLE "OrgSettings" ADD COLUMN IF NOT EXISTS "auditLogArchive" BOOLEAN NOT NULL DEFAULT true;
