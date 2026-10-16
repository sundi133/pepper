-- Custom reports: organization report templates, and AI-generated reports that
-- fill a template with one scan's data (run in the worker). Idempotent.

DO $$ BEGIN
  CREATE TYPE "CustomReportStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS "ReportTemplate" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "description" TEXT,
  "format" TEXT NOT NULL DEFAULT 'markdown',
  "body" TEXT NOT NULL,
  "instructions" TEXT,
  "sourceFileName" TEXT,
  "createdBy" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ReportTemplate_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "CustomReport" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "templateId" TEXT,
  "templateName" TEXT NOT NULL,
  "templateSnapshot" JSONB NOT NULL,
  "extraInstructions" TEXT,
  "createdBy" TEXT,
  "status" "CustomReportStatus" NOT NULL DEFAULT 'QUEUED',
  "progress" INTEGER NOT NULL DEFAULT 0,
  "stage" TEXT,
  "steps" JSONB,
  "provider" TEXT,
  "model" TEXT,
  "llmCalls" INTEGER NOT NULL DEFAULT 0,
  "title" TEXT,
  "markdown" TEXT,
  "html" TEXT,
  "grounding" JSONB,
  "errorMessage" TEXT,
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "CustomReport_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "ReportTemplate_organizationId_name_key" ON "ReportTemplate"("organizationId", "name");
CREATE INDEX IF NOT EXISTS "CustomReport_scanId_createdAt_idx" ON "CustomReport"("scanId", "createdAt");
CREATE INDEX IF NOT EXISTS "CustomReport_organizationId_createdAt_idx" ON "CustomReport"("organizationId", "createdAt");

DO $$ BEGIN
  ALTER TABLE "ReportTemplate" ADD CONSTRAINT "ReportTemplate_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "CustomReport" ADD CONSTRAINT "CustomReport_scanId_fkey"
    FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "CustomReport" ADD CONSTRAINT "CustomReport_templateId_fkey"
    FOREIGN KEY ("templateId") REFERENCES "ReportTemplate"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
