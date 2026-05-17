import { NextRequest, NextResponse } from "next/server";

const GITHUB_ACTIONS = `# .github/workflows/pepper.yml
# Pepper security scan with fail-build policy, SBOM upload, and optional cosign signing.
#
# Required secrets:
#   PEPPER_API_URL  — base URL of your Pepper instance
#   PEPPER_API_KEY  — API key with scan permissions (Settings → API Keys)
# Optional:
#   COSIGN_EXPERIMENTAL=1 enables keyless cosign signing.

name: Pepper Security Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write   # required for cosign keyless signing
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Pepper scan
        id: pepper
        env:
          PEPPER_API_URL: \${{ secrets.PEPPER_API_URL }}
          PEPPER_API_KEY: \${{ secrets.PEPPER_API_KEY }}
        run: |
          set -euo pipefail
          tarball=\$(mktemp -u).tar.gz
          tar --exclude-vcs --exclude=node_modules --exclude=dist -czf "\$tarball" .
          resp=\$(curl -fsSL -X POST \\
            -H "Authorization: Bearer \$PEPPER_API_KEY" \\
            -F "source=@\$tarball" \\
            -F "scanType=FULL" \\
            -F "branch=\${GITHUB_REF_NAME}" \\
            -F "commitSha=\${GITHUB_SHA}" \\
            "\$PEPPER_API_URL/api/scans")
          scan_id=\$(echo "\$resp" | jq -r '.scanId')
          echo "scan_id=\$scan_id" >> "\$GITHUB_OUTPUT"

          # Poll for completion (up to 30m)
          for i in \$(seq 1 180); do
            scan=\$(curl -fsSL -H "Authorization: Bearer \$PEPPER_API_KEY" \\
              "\$PEPPER_API_URL/api/scans/\$scan_id")
            status=\$(echo "\$scan" | jq -r .status)
            [[ "\$status" == "COMPLETED" || "\$status" == "FAILED" ]] && break
            sleep 10
          done

          gate=\$(echo "\$scan" | jq -r .gateResult)
          echo "Scan \$scan_id status=\$status gate=\$gate"
          if [[ "\$gate" == "FAILED" ]]; then
            echo "::error::Pepper build gate failed"
            exit 1
          fi

      - name: Download SBOM
        if: always()
        env:
          PEPPER_API_URL: \${{ secrets.PEPPER_API_URL }}
          PEPPER_API_KEY: \${{ secrets.PEPPER_API_KEY }}
        run: |
          curl -fsSL -H "Authorization: Bearer \$PEPPER_API_KEY" \\
            "\$PEPPER_API_URL/api/scans/\${{ steps.pepper.outputs.scan_id }}/artifacts/cyclonedx" \\
            -o sbom.cyclonedx.json || true
          curl -fsSL -H "Authorization: Bearer \$PEPPER_API_KEY" \\
            "\$PEPPER_API_URL/api/scans/\${{ steps.pepper.outputs.scan_id }}/artifacts/spdx" \\
            -o sbom.spdx.json || true

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pepper-sbom
          path: |
            sbom.cyclonedx.json
            sbom.spdx.json

      - uses: sigstore/cosign-installer@v3
        if: success()

      - name: Sign SBOM (keyless via Fulcio + Rekor)
        if: success()
        run: |
          COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \\
            --output-signature sbom.cyclonedx.json.sig \\
            sbom.cyclonedx.json || true
          COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \\
            --output-signature sbom.spdx.json.sig \\
            sbom.spdx.json || true

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: pepper-sbom-signatures
          path: |
            sbom.cyclonedx.json.sig
            sbom.spdx.json.sig
`;

const GITLAB_CI = `# .gitlab-ci.yml fragment
# Add to your existing pipeline. Requires CI variables PEPPER_API_URL and PEPPER_API_KEY.

pepper_security:
  stage: test
  image: alpine:3
  before_script:
    - apk add --no-cache curl jq tar
  script:
    - tar --exclude=node_modules --exclude=.git -czf /tmp/src.tar.gz .
    - |
      resp=\$(curl -fsSL -X POST \\
        -H "Authorization: Bearer \$PEPPER_API_KEY" \\
        -F "source=@/tmp/src.tar.gz" \\
        -F "scanType=FULL" \\
        -F "branch=\$CI_COMMIT_REF_NAME" \\
        -F "commitSha=\$CI_COMMIT_SHA" \\
        "\$PEPPER_API_URL/api/scans")
      scan_id=\$(echo "\$resp" | jq -r '.scanId')
      echo "scan_id=\$scan_id"
      for i in \$(seq 1 180); do
        scan=\$(curl -fsSL -H "Authorization: Bearer \$PEPPER_API_KEY" \\
          "\$PEPPER_API_URL/api/scans/\$scan_id")
        status=\$(echo "\$scan" | jq -r .status)
        [ "\$status" = "COMPLETED" ] || [ "\$status" = "FAILED" ] && break
        sleep 10
      done
      gate=\$(echo "\$scan" | jq -r .gateResult)
      echo "Pepper status=\$status gate=\$gate"
      curl -fsSL -H "Authorization: Bearer \$PEPPER_API_KEY" \\
        "\$PEPPER_API_URL/api/scans/\$scan_id/artifacts/cyclonedx" -o sbom.cyclonedx.json || true
      if [ "\$gate" = "FAILED" ]; then exit 1; fi
  artifacts:
    when: always
    paths:
      - sbom.cyclonedx.json
`;

const JENKINS = `// Jenkinsfile
pipeline {
  agent any
  environment {
    PEPPER_API_URL = credentials('PEPPER_API_URL')
    PEPPER_API_KEY = credentials('PEPPER_API_KEY')
  }
  stages {
    stage('Pepper Scan') {
      steps {
        sh '''
          set -e
          tar --exclude=node_modules --exclude=.git -czf /tmp/src.tar.gz .
          resp=\$(curl -fsSL -X POST \\
            -H "Authorization: Bearer $PEPPER_API_KEY" \\
            -F "source=@/tmp/src.tar.gz" \\
            -F "scanType=FULL" \\
            -F "branch=\${BRANCH_NAME:-main}" \\
            "$PEPPER_API_URL/api/scans")
          scan_id=\$(echo "$resp" | jq -r '.scanId')
          for i in \$(seq 1 180); do
            scan=\$(curl -fsSL -H "Authorization: Bearer $PEPPER_API_KEY" \\
              "$PEPPER_API_URL/api/scans/$scan_id")
            status=\$(echo "$scan" | jq -r .status)
            [ "$status" = "COMPLETED" ] && break
            sleep 10
          done
          gate=\$(echo "$scan" | jq -r .gateResult)
          if [ "$gate" = "FAILED" ]; then exit 1; fi
        '''
      }
    }
  }
}
`;

const TEMPLATES: Record<string, { body: string; contentType: string; filename: string }> = {
  github: {
    body: GITHUB_ACTIONS,
    contentType: "text/yaml",
    filename: "pepper.yml",
  },
  "github-actions": {
    body: GITHUB_ACTIONS,
    contentType: "text/yaml",
    filename: "pepper.yml",
  },
  gitlab: { body: GITLAB_CI, contentType: "text/yaml", filename: ".gitlab-ci.pepper.yml" },
  jenkins: { body: JENKINS, contentType: "text/plain", filename: "Jenkinsfile" },
};

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ platform: string }> },
) {
  const { platform } = await params;
  const t = TEMPLATES[platform.toLowerCase()];
  if (!t) {
    return NextResponse.json(
      {
        error: "Unknown platform",
        availablePlatforms: Object.keys(TEMPLATES),
      },
      { status: 404 },
    );
  }
  return new NextResponse(t.body, {
    headers: {
      "Content-Type": `${t.contentType}; charset=utf-8`,
      "Content-Disposition": `attachment; filename="${t.filename}"`,
    },
  });
}
