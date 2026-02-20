#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Pepper — Build & Push Docker Images
#
# Usage:
#   ./scripts/release.sh                  # builds :latest
#   ./scripts/release.sh 1.2.0            # builds :1.2.0 + :latest
#   REGISTRY=your.ecr.aws ./scripts/release.sh 1.2.0
# ──────────────────────────────────────────────────────────────────────

VERSION="${1:-latest}"
REGISTRY="${REGISTRY:-docker.io/YOURUSERNAME}"

API_IMAGE="${REGISTRY}/pepper"
WORKER_IMAGE="${REGISTRY}/pepper-worker"

echo "==> Building Pepper v${VERSION}"
echo "    API:    ${API_IMAGE}:${VERSION}"
echo "    Worker: ${WORKER_IMAGE}:${VERSION}"
echo ""

# Build API image
echo "==> Building API image..."
docker build \
  --target api \
  --tag "${API_IMAGE}:${VERSION}" \
  --tag "${API_IMAGE}:latest" \
  .

# Build Worker image
echo "==> Building Worker image..."
docker build \
  --target worker \
  --tag "${WORKER_IMAGE}:${VERSION}" \
  --tag "${WORKER_IMAGE}:latest" \
  .

echo ""
echo "==> Images built successfully"
echo ""

# Push
read -p "Push to ${REGISTRY}? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "==> Pushing API image..."
  docker push "${API_IMAGE}:${VERSION}"
  docker push "${API_IMAGE}:latest"

  echo "==> Pushing Worker image..."
  docker push "${WORKER_IMAGE}:${VERSION}"
  docker push "${WORKER_IMAGE}:latest"

  echo ""
  echo "==> Pushed successfully!"
  echo ""
  echo "Customers can pull with:"
  echo "  docker pull ${API_IMAGE}:${VERSION}"
  echo "  docker pull ${WORKER_IMAGE}:${VERSION}"
else
  echo "==> Skipping push. Images are available locally."
fi
