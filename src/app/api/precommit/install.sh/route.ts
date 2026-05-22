import { NextResponse } from "next/server";
import { PEPPER_PRECOMMIT_HOOK_SCRIPT } from "@/lib/pepper-precommit-hook";

/**
 * Serves the Pepper pre-commit installer. Hook body is bundled in the app so
 * production images do not need scripts/pepper-precommit.sh on disk.
 *
 *   curl -fsSL $PEPPER_API_URL/api/precommit/install.sh \
 *     | bash -s -- $PEPPER_API_URL $PEPPER_API_KEY
 */
export async function GET() {
  const installer = `#!/usr/bin/env bash
set -euo pipefail
API_URL="\${1:-\${PEPPER_API_URL:-}}"
API_KEY="\${2:-\${PEPPER_API_KEY:-}}"
if [[ -z "$API_URL" || -z "$API_KEY" ]]; then
  echo "Usage: install.sh <PEPPER_API_URL> <PEPPER_API_KEY>" >&2
  exit 2
fi
GIT_DIR="\$(git rev-parse --git-dir 2>/dev/null || true)"
if [[ -z "$GIT_DIR" ]]; then
  echo "Not inside a git repository." >&2
  exit 1
fi
mkdir -p "$GIT_DIR/hooks"
cat > "$GIT_DIR/hooks/pre-commit" <<'PEPPER_HOOK_EOF'
${PEPPER_PRECOMMIT_HOOK_SCRIPT}
PEPPER_HOOK_EOF
chmod +x "$GIT_DIR/hooks/pre-commit"

ENV_FILE=".pepper.env"
if ! grep -q PEPPER_API_URL "$ENV_FILE" 2>/dev/null; then
  printf 'PEPPER_API_URL=%s\\nPEPPER_API_KEY=%s\\n' "$API_URL" "$API_KEY" >> "$ENV_FILE"
fi
if [[ -f .gitignore ]] && ! grep -q '^.pepper.env$' .gitignore; then
  printf '\\n.pepper.env\\n' >> .gitignore
fi
if ! grep -q 'pepper.env' "$GIT_DIR/hooks/pre-commit"; then
  sed -i.bak '1a\\
[ -f .pepper.env ] && set -a && . ./.pepper.env && set +a
' "$GIT_DIR/hooks/pre-commit" || true
  rm -f "$GIT_DIR/hooks/pre-commit.bak"
fi
echo "[pepper] pre-commit hook installed at $GIT_DIR/hooks/pre-commit"
`;

  return new NextResponse(installer, {
    headers: {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
