#!/bin/sh
# Package the customer install bundle (no source code) for one Pepper version.
#
#   scripts/package-install-bundle.sh sha-a0c538e     # or 1.5.0 after a v1.5.0 tag
#
# Produces release/pepper-install-<version>.tar.gz and .zip containing
# docker-compose.yml, .env.example (version prefilled), setup.sh, INSTALL.md and
# RUNBOOK.html (the step-by-step runbook for the customer's team).
# Optionally set IMAGES=1 to also write the offline image archive
# (release/pepper-images-<version>.tar, ~3 GB) for air-gapped customers.
set -eu
VERSION="${1:?usage: package-install-bundle.sh <image-tag>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/release"
NAME="pepper-install-$VERSION"
STAGE="$OUT/$NAME"
API="docker.io/sundi133/pepper-api:$VERSION"
WORKER="docker.io/sundi133/pepper-worker:$VERSION"

rm -rf "$STAGE" && mkdir -p "$STAGE/certs"
cp "$ROOT/dist/docker-compose.yml" "$ROOT/dist/INSTALL.md" "$ROOT/dist/setup.sh" "$STAGE/"
sed "s/^PEPPER_VERSION=.*/PEPPER_VERSION=\"$VERSION\"/" "$ROOT/dist/.env.example" > "$STAGE/.env.example"
sed -i.bak "s/sha-a0c538e/$VERSION/g" "$STAGE/INSTALL.md" && rm -f "$STAGE/INSTALL.md.bak"
# Drop the template comment and fill in the version.
sed -e '/^<!-- Customer install runbook/,/-->$/d' -e "s/__PEPPER_VERSION__/$VERSION/g" \
  "$ROOT/dist/RUNBOOK.html" > "$STAGE/RUNBOOK.html"
chmod +x "$STAGE/setup.sh"
touch "$STAGE/certs/.keep"

(cd "$OUT" && tar -czf "$NAME.tar.gz" "$NAME")
if command -v zip >/dev/null 2>&1; then (cd "$OUT" && rm -f "$NAME.zip" && zip -qr "$NAME.zip" "$NAME"); fi
echo "Bundle: $OUT/$NAME.tar.gz"

if [ "${IMAGES:-0}" = "1" ]; then
  for img in "$API" "$WORKER"; do docker pull --platform linux/amd64 "$img"; done
  for img in postgres:16-alpine redis:7-alpine docker.io/chainguard/minio:latest; do docker pull --platform linux/amd64 "$img"; done
  docker save -o "$OUT/pepper-images-$VERSION.tar" "$API" "$WORKER" postgres:16-alpine redis:7-alpine docker.io/chainguard/minio:latest
  (cd "$OUT" && sha256sum "pepper-images-$VERSION.tar" > "pepper-images-$VERSION.tar.sha256" 2>/dev/null || shasum -a 256 "pepper-images-$VERSION.tar" > "pepper-images-$VERSION.tar.sha256")
  echo "Images: $OUT/pepper-images-$VERSION.tar"
fi
