#!/bin/sh
# Pepper CI scan: upload the checked-out source, wait for the scan, and fail
# the job when the Pepper build gate fails.
#
# Required env:  PEPPER_API_URL, PEPPER_API_KEY (Settings → API Keys)
# Optional env:  PEPPER_PROJECT        project name to reuse (default: current dir name)
#                PEPPER_SCAN_TYPE      FULL | SAST_ONLY | SCA_ONLY | SECRETS_ONLY | IAC_ONLY (default FULL)
#                PEPPER_BRANCH, PEPPER_COMMIT   shown on the scan
#                PEPPER_TIMEOUT_MINUTES          default 30
#                PEPPER_FAIL_ON_ERROR  1 (default) fails the job if the scan errors or times out
#                PEPPER_CA_CERT        CA bundle for a Pepper server with an internal certificate
#                PEPPER_ERROR_PREFIX   CI annotation prefix, e.g. "::error::" or "##vso[task.logissue type=error]"
# Needs: sh, tar, curl, jq. Honours HTTPS_PROXY / NO_PROXY via curl.
# Exit codes: 0 gate passed · 1 gate failed · 2 bad config/upload · 3 scan error/timeout
set -eu

err() { printf '%s%s\n' "${PEPPER_ERROR_PREFIX:-}" "$*" >&2; }

: "${PEPPER_API_URL:?PEPPER_API_URL is not set}"
: "${PEPPER_API_KEY:?PEPPER_API_KEY is not set}"
for bin in tar curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { err "Pepper: '$bin' is required on the build agent"; exit 2; }
done

API="${PEPPER_API_URL%/}"
PROJECT="${PEPPER_PROJECT:-$(basename "$(pwd)")}"
SCAN_TYPE="${PEPPER_SCAN_TYPE:-FULL}"
TIMEOUT_MINUTES="${PEPPER_TIMEOUT_MINUTES:-30}"
FAIL_ON_ERROR="${PEPPER_FAIL_ON_ERROR:-1}"

set -- -sS --retry 3 --retry-delay 5 -H "Authorization: Bearer ${PEPPER_API_KEY}"
[ -n "${PEPPER_CA_CERT:-}" ] && set -- "$@" --cacert "$PEPPER_CA_CERT"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
tarball="$workdir/source.tar.gz"
tar --exclude=.git --exclude=node_modules --exclude=dist --exclude=build \
    --exclude=target --exclude=.venv --exclude=.pepper-scan-id -czf "$tarball" .

data="$(jq -nc \
  --arg p "$PROJECT" --arg t "$SCAN_TYPE" \
  --arg b "${PEPPER_BRANCH:-}" --arg c "${PEPPER_COMMIT:-}" \
  '{projectName: $p, scanType: $t}
   + (if $b != "" then {branch: $b} else {} end)
   + (if $c != "" then {commitSha: $c} else {} end)')"

echo "Pepper: uploading $(du -h "$tarball" | cut -f1) for project '$PROJECT' ($SCAN_TYPE)"
resp="$(curl "$@" -X POST \
  -F "file=@${tarball};type=application/gzip;filename=source.tar.gz" \
  --form-string "data=${data}" \
  -w '\n%{http_code}' "$API/api/scans")" || { err "Pepper: could not reach $API"; exit 2; }
code="$(printf '%s\n' "$resp" | tail -n 1)"
body="$(printf '%s\n' "$resp" | sed '$d')"
if [ "$code" != "201" ]; then
  err "Pepper: scan request failed (HTTP $code): $(printf '%s' "$body" | jq -r '.error // .' 2>/dev/null || printf '%s' "$body")"
  exit 2
fi
scan_id="$(printf '%s' "$body" | jq -r '.scanId')"
echo "Pepper: scan $scan_id queued — $API/scans/$scan_id"
printf '%s\n' "$scan_id" > .pepper-scan-id

deadline=$(( $(date +%s) + TIMEOUT_MINUTES * 60 ))
status="UNKNOWN"
scan="{}"
while :; do
  if scan="$(curl "$@" -f "$API/api/scans/$scan_id")"; then
    status="$(printf '%s' "$scan" | jq -r '.status // "UNKNOWN"')"
  fi
  case "$status" in COMPLETED|FAILED|CANCELLED|STOPPED) break ;; esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    err "Pepper: scan $scan_id still $status after ${TIMEOUT_MINUTES} minutes"
    [ "$FAIL_ON_ERROR" = "1" ] && exit 3 || exit 0
  fi
  sleep 10
done

gate="$(printf '%s' "$scan" | jq -r '.gateResult // "PENDING"')"
summary="$(printf '%s' "$scan" | jq -r '"critical=\(.criticalCount // 0) high=\(.highCount // 0) medium=\(.mediumCount // 0) low=\(.lowCount // 0)"')"
echo "Pepper: status=$status gate=$gate $summary"
echo "Pepper: results — $API/scans/$scan_id"

if [ "$status" != "COMPLETED" ]; then
  err "Pepper: scan $scan_id ended with status $status: $(printf '%s' "$scan" | jq -r '.errorMessage // ""')"
  [ "$FAIL_ON_ERROR" = "1" ] && exit 3 || exit 0
fi
if [ "$gate" = "FAILED" ]; then
  err "Pepper: build gate FAILED ($summary)"
  exit 1
fi
echo "Pepper: build gate passed"
