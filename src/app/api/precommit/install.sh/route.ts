import { NextResponse } from "next/server";
import * as fs from "fs";
import * as path from "path";

/**
 * Serves the canonical Pepper pre-commit hook script so users can install it
 * with a single command:
 *
 *   curl -fsSL $PEPPER_API_URL/api/precommit/install.sh \
 *     | bash -s -- $PEPPER_API_URL $PEPPER_API_KEY
 *
 * The installer drops `scripts/pepper-precommit.sh` into `.git/hooks/pre-commit`
 * of the current repo, makes it executable, and writes the supplied API URL
 * and API key to a local `.pepper.env` (already gitignored by convention).
 */
export async function GET() {
  const hookPath = path.join(process.cwd(), "scripts", "pepper-precommit.sh");
  let hookBody = "";
  try {
    hookBody = fs.readFileSync(hookPath, "utf-8");
  } catch {
    return NextResponse.json(
      {
        error: "Pre-commit hook script is unavailable on this server",
        detail: `Missing ${hookPath}. Ensure scripts/pepper-precommit.sh is deployed (see Dockerfile api stage).`,
      },
      { status: 500 },
    );
  }

  const installer = `#!/usr/bin/env bash
set -euo pipefail
API_URL="\${1:-\${PEPPER_API_URL:-}}"
API_KEY="\${2:-\${PEPPER_API_KEY:-}}"
if [[ -z "\$API_URL" || -z "\$API_KEY" ]]; then
  echo "Usage: install.sh <PEPPER_API_URL> <PEPPER_API_KEY>" >&2
  exit 2
fi
GIT_DIR="\$(git rev-parse --git-dir 2>/dev/null || true)"
if [[ -z "\$GIT_DIR" ]]; then
  echo "Not inside a git repository." >&2
  exit 1
fi
mkdir -p "\$GIT_DIR/hooks"
cat > "\$GIT_DIR/hooks/pre-commit" <<'PEPPER_HOOK_EOF'
${hookBody}
PEPPER_HOOK_EOF
chmod +x "\$GIT_DIR/hooks/pre-commit"

ENV_FILE=".pepper.env"
if ! grep -q PEPPER_API_URL "\$ENV_FILE" 2>/dev/null; then
  printf 'PEPPER_API_URL=%s\\nPEPPER_API_KEY=%s\\n' "\$API_URL" "\$API_KEY" >> "\$ENV_FILE"
fi
if [[ -f .gitignore ]] && ! grep -q '^.pepper.env$' .gitignore; then
  printf '\\n.pepper.env\\n' >> .gitignore
fi
# Ensure the hook can find the env at run time
if ! grep -q 'pepper.env' "\$GIT_DIR/hooks/pre-commit"; then
  sed -i.bak '1a\\
[ -f .pepper.env ] && set -a && . ./.pepper.env && set +a
' "\$GIT_DIR/hooks/pre-commit" || true
  rm -f "\$GIT_DIR/hooks/pre-commit.bak"
fi
echo "[pepper] pre-commit hook installed at \$GIT_DIR/hooks/pre-commit"
`;

  return new NextResponse(installer, {
    headers: {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
