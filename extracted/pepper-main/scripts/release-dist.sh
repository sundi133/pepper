#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
OUT_DIR="$ROOT_DIR/release"

VERSION="${VERSION:-}"
REGISTRY="${REGISTRY:-}"
API_IMAGE_NAME="${API_IMAGE_NAME:-pepper}"
WORKER_IMAGE_NAME="${WORKER_IMAGE_NAME:-pepper-worker}"

if [ -z "$VERSION" ]; then
  echo "VERSION is required, for example: VERSION=1.2.0"
  exit 1
fi

if [ -z "$REGISTRY" ]; then
  echo "REGISTRY is required, for example: REGISTRY=registry.example.com/security"
  exit 1
fi

API_REPO="${REGISTRY}/${API_IMAGE_NAME}"
WORKER_REPO="${REGISTRY}/${WORKER_IMAGE_NAME}"
API_IMAGE="${API_REPO}:${VERSION}"
WORKER_IMAGE="${WORKER_REPO}:${VERSION}"
BUNDLE_DIR="$OUT_DIR/pepper-${VERSION}"
BUNDLE_ZIP="$OUT_DIR/pepper-${VERSION}.zip"

mkdir -p "$OUT_DIR"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

echo "Building API image: $API_IMAGE"
docker build --target api -t "$API_IMAGE" "$ROOT_DIR"

echo "Building worker image: $WORKER_IMAGE"
docker build --target worker -t "$WORKER_IMAGE" "$ROOT_DIR"

echo "Pushing images"
docker push "$API_IMAGE"
docker push "$WORKER_IMAGE"

cp "$DIST_DIR/docker-compose.yml" "$BUNDLE_DIR/"
cp "$DIST_DIR/.env.example" "$BUNDLE_DIR/"
cp "$DIST_DIR/setup.sh" "$BUNDLE_DIR/"
cp "$DIST_DIR/INSTALL.md" "$BUNDLE_DIR/"

if command -v python >/dev/null 2>&1; then
  python - <<PY
from pathlib import Path
bundle = Path(r"$BUNDLE_DIR")
env_file = bundle / ".env.example"

env_text = env_file.read_text()
env_text = env_text.replace(
    '# PEPPER_API_IMAGE="registry.example.com/pepper"',
    'PEPPER_API_IMAGE="$API_REPO"',
)
env_text = env_text.replace(
    '# PEPPER_WORKER_IMAGE="registry.example.com/pepper-worker"',
    'PEPPER_WORKER_IMAGE="$WORKER_REPO"',
)
env_text = env_text.replace(
    '# PEPPER_VERSION="1.2.0"',
    f'PEPPER_VERSION="$VERSION"',
)
env_file.write_text(env_text)
PY
else
  echo "python not found; bundle templating skipped"
fi

rm -f "$BUNDLE_ZIP"
powershell -NoProfile -Command "Compress-Archive -Path '$BUNDLE_DIR\\*' -DestinationPath '$BUNDLE_ZIP' -Force"

echo ""
echo "Release complete"
echo "API image:    $API_IMAGE"
echo "Worker image: $WORKER_IMAGE"
echo "Bundle:       $BUNDLE_ZIP"
