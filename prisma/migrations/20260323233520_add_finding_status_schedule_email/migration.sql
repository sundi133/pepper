-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED');

-- CreateEnum
CREATE TYPE "ScheduleFreq" AS ENUM ('DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'CUSTOM');

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
ADD COLUMN     "statusNote" TEXT,
ADD COLUMN     "statusUpdatedAt" TIMESTAMP(3),
ADD COLUMN     "statusUpdatedBy" TEXT;

-- AlterTable
ALTER TABLE "OrgMember" ADD COLUMN     "emailOnCritical" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "emailOnGateFail" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "emailOnScanComplete" BOOLEAN NOT NULL DEFAULT true;

-- AlterTable
ALTER TABLE "OrgSettings" ADD COLUMN     "smtpFromAddress" TEXT DEFAULT 'noreply@pepper-sast.local',
ADD COLUMN     "smtpHost" TEXT,
ADD COLUMN     "smtpPassword" TEXT,
ADD COLUMN     "smtpPort" INTEGER DEFAULT 587,
ADD COLUMN     "smtpUseTls" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "smtpUser" TEXT;

-- CreateTable
CREATE TABLE "ScanSchedule" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "frequency" "ScheduleFreq" NOT NULL,
    "cronExpr" TEXT,
    "scanType" "ScanType" NOT NULL DEFAULT 'FULL',
    "branch" TEXT,
    "lastRunAt" TIMESTAMP(3),
    "nextRunAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ScanSchedule_projectId_key" ON "ScanSchedule"("projectId");

-- CreateIndex
CREATE INDEX "Finding_scanId_status_idx" ON "Finding"("scanId", "status");

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
