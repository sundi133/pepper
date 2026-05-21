/**
 * Canonical pre-commit hook body served by GET /api/precommit/install.sh.
 * Keep in sync with scripts/pepper-precommit.sh (local reference copy).
 */
export const PEPPER_PRECOMMIT_HOOK_SCRIPT = `#!/usr/bin/env bash
# Pepper pre-commit hook — scans staged files for secrets and high-severity
# SAST findings via the Pepper /api/precommit/scan endpoint and aborts the
# commit if any CRITICAL or HIGH issues are found.
#
# Install:
#   1) Save this file to .git/hooks/pre-commit and \`chmod +x\` it.
#   2) Export PEPPER_API_URL and PEPPER_API_KEY in your shell or .env.
#
#   PEPPER_API_URL=https://pepper.your-org.com  (default: http://localhost:3000)
#   PEPPER_API_KEY=ppr_xxxxxxxxxxxxxxxxxxxxxxxx
#   PEPPER_FAIL_ON="CRITICAL,HIGH"   (override severities that block commit)
#
# Skip hook for a single commit with: git commit --no-verify
set -euo pipefail

API_URL="\${PEPPER_API_URL:-http://localhost:3000}"
API_KEY="\${PEPPER_API_KEY:-}"
FAIL_ON="\${PEPPER_FAIL_ON:-CRITICAL,HIGH}"

if [[ -z "$API_KEY" ]]; then
  echo "[pepper] PEPPER_API_KEY not set; skipping pre-commit scan." >&2
  exit 0
fi

mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM)
if [[ \${#STAGED[@]} -eq 0 ]]; then
  exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$TMP" "\${STAGED[@]}" <<'PY' || { echo "[pepper] could not build payload" >&2; exit 0; }
import json, sys, os
out_path = sys.argv[1]
files = []
for path in sys.argv[2:]:
    if not os.path.isfile(path):
        continue
    if os.path.getsize(path) > 2_000_000:
        continue
    try:
        with open(path, "rb") as f:
            data = f.read()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        files.append({"path": path, "content": text})
    except OSError:
        continue
with open(out_path, "w") as out:
    json.dump({"files": files, "failOn": os.environ.get("PEPPER_FAIL_ON", "CRITICAL,HIGH").split(",")}, out)
PY

HTTP_STATUS="$(curl -sS -o /tmp/pepper-precommit-resp.json -w "%{http_code}" \\
  -X POST \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  --data-binary "@$TMP" \\
  "$API_URL/api/precommit/scan" || echo 000)"

if [[ "$HTTP_STATUS" != "200" ]]; then
  echo "[pepper] pre-commit endpoint returned $HTTP_STATUS (skipping)" >&2
  cat /tmp/pepper-precommit-resp.json >&2 || true
  exit 0
fi

BLOCK="$(python3 -c "import json; d=json.load(open('/tmp/pepper-precommit-resp.json')); print('1' if d.get('block') else '0')")"

if [[ "$BLOCK" == "1" ]]; then
  echo "" >&2
  echo "[pepper] commit blocked — security findings detected:" >&2
  python3 - <<'PY' >&2
import json
d = json.load(open('/tmp/pepper-precommit-resp.json'))
for f in d.get('findings', []):
    if f['severity'] in ('CRITICAL', 'HIGH'):
        print(f"  {f['severity']:>8}  {f['filePath']}:{f['line']}  {f['ruleId']}  {f['title']}")
PY
  echo "" >&2
  echo "Use \\\`git commit --no-verify\\\` to bypass (not recommended)." >&2
  exit 1
fi

echo "[pepper] pre-commit scan ok ($(python3 -c "import json; print(json.load(open('/tmp/pepper-precommit-resp.json'))['summary']['total'])") finding(s))"
`;
