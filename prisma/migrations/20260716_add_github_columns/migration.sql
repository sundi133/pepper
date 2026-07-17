-- Add missing GitHub columns to Project
ALTER TABLE "Project" ADD COLUMN "githubRepoId" INTEGER;
ALTER TABLE "Project" ADD COLUMN "githubOwner" TEXT;
ALTER TABLE "Project" ADD COLUMN "githubRepoName" TEXT;
ALTER TABLE "Project" ADD COLUMN "primaryLanguage" TEXT;
ALTER TABLE "Project" ADD COLUMN "connectedViaGithub" BOOLEAN NOT NULL DEFAULT false;

-- Add unique constraint for GitHub repos
ALTER TABLE "Project" ADD CONSTRAINT "Project_organizationId_githubRepoId_key" UNIQUE ("organizationId", "githubRepoId");
