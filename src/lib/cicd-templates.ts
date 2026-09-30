/**
 * CI/CD pipeline templates. Every template embeds the same scan script
 * (public/ci/pepper-scan.sh, or pepper-scan.ps1 for Windows agents) verbatim,
 * so pipelines are self-contained and reviewable, and all platforms share one
 * tested implementation: upload → wait → fail the job when the gate fails.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

function script(name: "pepper-scan.sh" | "pepper-scan.ps1"): string {
  return readFileSync(path.join(process.cwd(), "public", "ci", name), "utf8").trimEnd();
}

/** Indent every line (blank lines stay blank) for a YAML block scalar. */
export function indentBlock(text: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => (line.length ? pad + line : line))
    .join("\n");
}

/** Body for a Groovy ''' string: backslashes are escape characters there. */
export function groovySingleQuoted(text: string): string {
  if (text.includes("'''")) throw new Error("script must not contain '''");
  return text.replace(/\\/g, "\\\\");
}

function githubActions(): string {
  return `# .github/workflows/pepper.yml
# Pepper security scan: fails the job when the Pepper build gate fails and
# uploads the SBOMs. Repository secrets: PEPPER_API_URL, PEPPER_API_KEY
# (Pepper → Settings → API Keys).

name: Pepper Security Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write   # cosign keyless signing of the SBOM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Pepper scan
        env:
          PEPPER_API_URL: \${{ secrets.PEPPER_API_URL }}
          PEPPER_API_KEY: \${{ secrets.PEPPER_API_KEY }}
          PEPPER_PROJECT: \${{ github.event.repository.name }}
          PEPPER_BRANCH: \${{ github.head_ref || github.ref_name }}
          PEPPER_COMMIT: \${{ github.sha }}
          PEPPER_ERROR_PREFIX: "::error::"
        run: |
${indentBlock(script("pepper-scan.sh"), 10)}

      - name: Download SBOM
        if: always()
        env:
          PEPPER_API_URL: \${{ secrets.PEPPER_API_URL }}
          PEPPER_API_KEY: \${{ secrets.PEPPER_API_KEY }}
        run: |
          [ -f .pepper-scan-id ] || exit 0
          id=$(cat .pepper-scan-id)
          for f in cyclonedx spdx; do
            curl -fsS -H "Authorization: Bearer $PEPPER_API_KEY" \\
              "\${PEPPER_API_URL%/}/api/scans/$id/artifacts/$f" -o "sbom.$f.json" || true
          done

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pepper-sbom
          path: sbom.*.json
          if-no-files-found: ignore

      - uses: sigstore/cosign-installer@v3
        if: success()

      - name: Sign SBOM (keyless via Fulcio + Rekor)
        if: success()
        run: |
          for f in sbom.*.json; do
            [ -f "$f" ] && cosign sign-blob --yes --output-signature "$f.sig" "$f" || true
          done
`;
}

function gitlabCi(): string {
  return `# .gitlab-ci.yml fragment — add to your pipeline.
# CI/CD variables: PEPPER_API_URL, PEPPER_API_KEY (masked).

pepper_security:
  stage: test
  image: alpine:3.20
  variables:
    PEPPER_PROJECT: $CI_PROJECT_NAME
    PEPPER_BRANCH: $CI_COMMIT_REF_NAME
    PEPPER_COMMIT: $CI_COMMIT_SHA
  before_script:
    - apk add --no-cache curl jq tar
  script:
    - |
${indentBlock(script("pepper-scan.sh"), 6)}
  after_script:
    - |
      [ -f .pepper-scan-id ] && curl -fsS -H "Authorization: Bearer $PEPPER_API_KEY" \\
        "\${PEPPER_API_URL%/}/api/scans/$(cat .pepper-scan-id)/artifacts/cyclonedx" -o sbom.cyclonedx.json || true
  artifacts:
    when: always
    paths:
      - sbom.cyclonedx.json
`;
}

function jenkins(): string {
  return `// Jenkinsfile — Pepper security scan.
// Credentials (Secret text): PEPPER_API_URL, PEPPER_API_KEY. The agent needs curl, jq and tar.
pipeline {
  agent any
  environment {
    PEPPER_API_URL = credentials('PEPPER_API_URL')
    PEPPER_API_KEY = credentials('PEPPER_API_KEY')
  }
  stages {
    stage('Pepper Scan') {
      steps {
        withEnv(["PEPPER_PROJECT=\${env.JOB_BASE_NAME}", "PEPPER_BRANCH=\${env.BRANCH_NAME ?: ''}", "PEPPER_COMMIT=\${env.GIT_COMMIT ?: ''}"]) {
          sh '''
${indentBlock(groovySingleQuoted(script("pepper-scan.sh")), 12)}
          '''
        }
      }
    }
  }
}
`;
}

const ADO_HEADER = `# Azure DevOps Server / Services — Pepper security scan.
#
# 1. Pipelines → Library → variable group "pepper" with PEPPER_API_URL and
#    PEPPER_API_KEY (mark the key secret; Pepper → Settings → API Keys).
# 2. Create a pipeline from this file.
# 3. To gate pull requests: Repos → Branches → <main> → Branch policies →
#    Build validation → add this pipeline (Required). Pepper's own PR status
#    ("pepper/security") can also be added as a required status check.
# Behind a proxy: add HTTPS_PROXY / NO_PROXY to the variable group.
# Internal certificate: set PEPPER_CA_CERT to the CA bundle path on the agent.

trigger:
  branches:
    include: [main]

variables:
  - group: pepper
`;

function azureDevOpsLinux(): string {
  return `${ADO_HEADER}
pool:
  vmImage: ubuntu-latest   # on Azure DevOps Server use your agent pool, e.g. "name: Default"

steps:
  - checkout: self

  - task: Bash@3
    displayName: Pepper security scan
    inputs:
      targetType: inline
      script: |
${indentBlock(script("pepper-scan.sh"), 8)}
    env:
      PEPPER_API_URL: $(PEPPER_API_URL)
      PEPPER_API_KEY: $(PEPPER_API_KEY)   # secrets must be mapped explicitly
      PEPPER_PROJECT: $(Build.Repository.Name)
      PEPPER_BRANCH: $(Build.SourceBranchName)
      PEPPER_COMMIT: $(Build.SourceVersion)
      PEPPER_ERROR_PREFIX: "##vso[task.logissue type=error]"

  - task: Bash@3
    displayName: Download SBOM
    condition: always()
    inputs:
      targetType: inline
      script: |
        [ -f .pepper-scan-id ] || exit 0
        curl -fsS -H "Authorization: Bearer $PEPPER_API_KEY" \\
          "\${PEPPER_API_URL%/}/api/scans/$(cat .pepper-scan-id)/artifacts/cyclonedx" \\
          -o "$BUILD_ARTIFACTSTAGINGDIRECTORY/sbom.cyclonedx.json" || true
    env:
      PEPPER_API_URL: $(PEPPER_API_URL)
      PEPPER_API_KEY: $(PEPPER_API_KEY)

  - task: PublishBuildArtifacts@1
    displayName: Publish SBOM
    condition: always()
    inputs:
      PathtoPublish: $(Build.ArtifactStagingDirectory)
      ArtifactName: pepper-sbom
`;
}

function azureDevOpsWindows(): string {
  return `${ADO_HEADER}
pool:
  name: Default   # your Windows agent pool

steps:
  - checkout: self

  - task: PowerShell@2
    displayName: Pepper security scan
    inputs:
      targetType: inline
      pwsh: false   # Windows PowerShell 5.1 works; set true to use PowerShell 7
      script: |
${indentBlock(script("pepper-scan.ps1"), 8)}
    env:
      PEPPER_API_URL: $(PEPPER_API_URL)
      PEPPER_API_KEY: $(PEPPER_API_KEY)   # secrets must be mapped explicitly
      PEPPER_PROJECT: $(Build.Repository.Name)
      PEPPER_BRANCH: $(Build.SourceBranchName)
      PEPPER_COMMIT: $(Build.SourceVersion)
      PEPPER_ERROR_PREFIX: "##vso[task.logissue type=error]"
`;
}

export interface CiTemplate {
  body: string;
  contentType: string;
  filename: string;
}

export function buildCiTemplates(): Record<string, CiTemplate> {
  const yaml = "text/yaml";
  const github = { body: githubActions(), contentType: yaml, filename: "pepper.yml" };
  const adoLinux = { body: azureDevOpsLinux(), contentType: yaml, filename: "azure-pipelines.pepper.yml" };
  return {
    github,
    "github-actions": github,
    gitlab: { body: gitlabCi(), contentType: yaml, filename: ".gitlab-ci.pepper.yml" },
    jenkins: { body: jenkins(), contentType: "text/plain", filename: "Jenkinsfile" },
    "azure-devops": adoLinux,
    "azure-pipelines": adoLinux,
    "azure-devops-windows": {
      body: azureDevOpsWindows(),
      contentType: yaml,
      filename: "azure-pipelines.pepper.windows.yml",
    },
  };
}
