-- OrgGitLabConnection table
CREATE TABLE IF NOT EXISTS "OrgGitLabConnection" (
    "id"             TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "hostUrl"        TEXT NOT NULL DEFAULT 'https://gitlab.com',
    "gitlabUserId"   INTEGER,
    "gitlabUsername" TEXT,
    "accessTokenEnc" TEXT NOT NULL,
    "createdAt"      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"      TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrgGitLabConnection_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "OrgGitLabConnection_organizationId_key"
    ON "OrgGitLabConnection"("organizationId");

ALTER TABLE "OrgGitLabConnection"
    ADD CONSTRAINT "OrgGitLabConnection_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

-- GitLab project identity on Project
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "gitlabProjectId" INTEGER;
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "gitlabNamespace" TEXT;
