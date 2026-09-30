#!/bin/sh
# Download the upstream sources used by build-frameworks.mjs into <dir>.
# Needs the GitHub CLI (gh) or swap in curl against raw.githubusercontent.com.
set -eu
DIR="${1:?usage: fetch-sources.sh <dir>}"
mkdir -p "$DIR"
gh api "repos/OWASP/ASVS/contents/4.0/docs_en/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.flat.json?ref=v4.0.3" \
  -H "Accept: application/vnd.github.raw" > "$DIR/asvs-4.0.3.flat.json"
SHA=$(gh api repos/aquasecurity/trivy-checks/commits/main --jq .sha)
for f in k8s-cis-1.23 eks-cis-1.4 aws-cis-1.4; do
  gh api "repos/aquasecurity/trivy-checks/contents/pkg/compliance/$f.yaml?ref=$SHA" \
    -H "Accept: application/vnd.github.raw" > "$DIR/$f.yaml"
done
echo "$SHA" > "$DIR/trivy-checks.sha"
echo "Sources in $DIR (trivy-checks @ $SHA). Next: node scripts/compliance/build-frameworks.mjs $DIR $SHA"
