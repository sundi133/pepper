#!/usr/bin/env bash
#
# Provision Azure DevOps Server 2022 on a GCP Windows VM for testing Pepper's
# on-prem Azure DevOps integration.
#
#   ADO_INSTALLER=~/Downloads/azuredevopsserver2022.2.iso \
#   PROJECT=my-gcp-project ./scripts/ado-server-gcp.sh up
#
#   ./scripts/ado-server-gcp.sh seed     # test project + vulnerable repo + open PR
#   ./scripts/ado-server-gcp.sh status   # install progress (serial console)
#   ./scripts/ado-server-gcp.sh rdp      # RDP via IAP → localhost:13389
#   ./scripts/ado-server-gcp.sh stop | start | down
#
# What "up" does (reliable GCP parts are fully automated):
#   1. Enables the compute API and creates a GCS bucket for the ISO.
#   2. Uploads $ADO_INSTALLER to the bucket.
#   3. Creates firewall rules: RDP over IAP (35.235.240.0/20) and internal 8080.
#   4. Creates a Windows Server 2022 VM whose startup script downloads + mounts
#      the ISO, installs SQL Server Express, then runs the ADO Server installer
#      and an unattended "Basic" configuration — writing progress markers to the
#      serial console (read them with `status`).
#
# The ADO unattended configuration is inherently version-specific; if it stalls,
# `rdp` in and finish the one-screen wizard (the installer bits are already
# laid down). Everything else here is deterministic.
#
set -euo pipefail

# ── Config (override via env) ────────────────────────────────────────────────
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
ZONE="${ZONE:-us-central1-a}"
REGION="${REGION:-${ZONE%-*}}"
VM_NAME="${VM_NAME:-ado-server}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-4}"
DISK_SIZE="${DISK_SIZE:-128GB}"
ADO_USER="${ADO_USER:-adoadmin}"
ADO_PORT="${ADO_PORT:-8080}"
COLLECTION="${COLLECTION:-DefaultCollection}"
BUCKET="${BUCKET:-gs://${PROJECT}-ado-installer}"
NETWORK_TAG="ado-server"
ISO_OBJECT="ado-server.iso"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH"; }
gc() { gcloud --project="$PROJECT" "$@"; }

require_project() {
  [ -n "$PROJECT" ] || die "set PROJECT=<gcp-project> (or 'gcloud config set project')"
}

vm_exists() { gc compute instances describe "$VM_NAME" --zone="$ZONE" >/dev/null 2>&1; }
require_vm() {
  vm_exists || die "VM '$VM_NAME' not found in $PROJECT/$ZONE.
  Create it first:  ADO_INSTALLER=<iso> PROJECT=$PROJECT $0 up
  (or set ZONE=<zone> if you created it in a different zone)"
}

# ── Windows startup script (PowerShell) ──────────────────────────────────────
# Runs on first boot. Emits [ADO-SETUP] markers to the serial console so
# `status` can report progress. Idempotent-ish: skips steps already done.
startup_ps1() {
  cat <<PS1
\$ErrorActionPreference = "Stop"
function Mark(\$m) { Write-Host "[ADO-SETUP] \$m"; Add-Content C:\\ado-setup.log "\$(Get-Date -Format o)  \$m" }
New-Item -ItemType Directory -Force -Path C:\\ado | Out-Null
if (Test-Path C:\\ado\\DONE) { Mark "already configured; nothing to do"; exit 0 }

try {
  Mark "downloading installer from ${BUCKET}/${ISO_OBJECT}"
  & gsutil cp "${BUCKET}/${ISO_OBJECT}" C:\\ado\\ado.iso
  Mark "mounting ISO"
  \$vol = (Mount-DiskImage -ImagePath C:\\ado\\ado.iso -PassThru | Get-Volume).DriveLetter
  \$setup = Get-ChildItem "\${vol}:\\" -Filter *.exe | Select-Object -First 1
  if (-not \$setup) { throw "no installer .exe found on the ISO" }

  Mark "installing SQL Server Express (LocalDB is insufficient for ADO)"
  # ADO Server 2022 needs SQL Server 2019+. Install Express unattended.
  \$sqlUrl = "https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLEXPR_x64_ENU.exe"
  Invoke-WebRequest -Uri \$sqlUrl -OutFile C:\\ado\\sqlexpr.exe
  Start-Process C:\\ado\\sqlexpr.exe -ArgumentList "/qs","/x:C:\\ado\\sqlx" -Wait
  Start-Process C:\\ado\\sqlx\\setup.exe -ArgumentList "/q","/ACTION=Install","/FEATURES=SQLEngine","/INSTANCENAME=MSSQLSERVER","/SQLSYSADMINACCOUNTS=BUILTIN\\Administrators","/IACCEPTSQLSERVERLICENSETERMS","/TCPENABLED=1" -Wait
  Mark "SQL Express installed"

  Mark "running ADO Server installer (quiet)"
  Start-Process \$setup.FullName -ArgumentList "/quiet" -Wait
  \$tfsConfig = Get-ChildItem "C:\\Program Files\\Azure DevOps Server 2022\\Tools\\TfsConfig.exe" -ErrorAction SilentlyContinue
  if (-not \$tfsConfig) { \$tfsConfig = Get-ChildItem "C:\\Program Files\\Azure DevOps Server *\\Tools\\TfsConfig.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 }
  if (-not \$tfsConfig) { throw "TfsConfig.exe not found after install" }

  Mark "configuring Basic deployment (this can take 10-20 min)"
  & \$tfsConfig.FullName unattend /configure /type:NewServerBasic /continue 2>&1 | Tee-Object -Append C:\\ado-setup.log
  Mark "ADO configuration finished"

  # Ensure the site answers on the expected port and open the firewall.
  New-NetFirewallRule -DisplayName "ADO ${ADO_PORT}" -Direction Inbound -Protocol TCP -LocalPort ${ADO_PORT} -Action Allow -ErrorAction SilentlyContinue | Out-Null
  Set-Content C:\\ado\\DONE "ok"
  Mark "READY  http://<vm>:${ADO_PORT}/${COLLECTION}"
}
catch {
  Mark "FAILED: \$(\$_.Exception.Message)  — RDP in and finish the ADO config wizard"
  exit 1
}
PS1
}

# ── Commands ─────────────────────────────────────────────────────────────────
cmd_up() {
  require_project
  need gcloud; need gsutil
  [ -n "${ADO_INSTALLER:-}" ] || die "set ADO_INSTALLER=/path/to/azuredevopsserver2022.iso"
  [ -f "$ADO_INSTALLER" ]     || die "installer not found: $ADO_INSTALLER"

  echo "→ enabling compute API"
  gc services enable compute.googleapis.com >/dev/null

  echo "→ ensuring bucket $BUCKET"
  gsutil ls -b "$BUCKET" >/dev/null 2>&1 || gsutil mb -p "$PROJECT" -l "$REGION" "$BUCKET"

  echo "→ uploading installer (this can take a while)"
  gsutil cp "$ADO_INSTALLER" "$BUCKET/$ISO_OBJECT"

  echo "→ firewall: RDP over IAP + internal $ADO_PORT"
  gc compute firewall-rules describe ado-iap-rdp >/dev/null 2>&1 || \
    gc compute firewall-rules create ado-iap-rdp \
      --direction=INGRESS --action=ALLOW --rules=tcp:3389 \
      --source-ranges=35.235.240.0/20 --target-tags="$NETWORK_TAG"
  gc compute firewall-rules describe ado-internal >/dev/null 2>&1 || \
    gc compute firewall-rules create ado-internal \
      --direction=INGRESS --action=ALLOW --rules="tcp:${ADO_PORT}" \
      --source-ranges=10.0.0.0/8 --target-tags="$NETWORK_TAG"

  echo "→ creating VM $VM_NAME ($MACHINE_TYPE, Windows Server 2022)"
  local tmp; tmp="$(mktemp)"; startup_ps1 > "$tmp"
  gc compute instances create "$VM_NAME" \
    --zone="$ZONE" --machine-type="$MACHINE_TYPE" \
    --image-family=windows-2022 --image-project=windows-cloud \
    --boot-disk-size="$DISK_SIZE" --boot-disk-type=pd-ssd \
    --tags="$NETWORK_TAG" --scopes=cloud-platform \
    --metadata-from-file=windows-startup-script-ps1="$tmp"
  rm -f "$tmp"

  cat <<EOF

✓ VM created. The startup script is installing SQL Express + ADO Server now.
  Track it:   ./scripts/ado-server-gcp.sh status
  RDP:        ./scripts/ado-server-gcp.sh rdp
  Internal IP (use as Pepper Server URL, http://<ip>:${ADO_PORT}):
$(gc compute instances describe "$VM_NAME" --zone="$ZONE" \
    --format='value(networkInterfaces[0].networkIP)' 2>/dev/null | sed 's/^/    /')
EOF
}

cmd_status() {
  require_project; require_vm
  echo "→ recent [ADO-SETUP] markers from the serial console:"
  gc compute instances get-serial-port-output "$VM_NAME" --zone="$ZONE" 2>/dev/null \
    | grep "\[ADO-SETUP\]" | tail -20 || echo "  (no markers yet — boot/serial not ready)"
}

cmd_rdp() {
  require_project; need gcloud; require_vm
  echo "→ resetting Windows password for '$ADO_USER' (save it):"
  gc compute reset-windows-password "$VM_NAME" --zone="$ZONE" --user="$ADO_USER" || true
  echo "→ opening IAP tunnel; RDP to localhost:13389 (Ctrl-C to close)"
  # Note: 'gc' is a shell function, so it cannot be exec'd — call it directly.
  gc compute start-iap-tunnel "$VM_NAME" 3389 \
    --local-host-port=localhost:13389 --zone="$ZONE"
}

# seed needs the ADO server reachable and a PAT.
#   ADO_URL=http://localhost:8080  (e.g. through an IAP tunnel to :8080)
#   ADO_PAT=<pat from the ADO web UI>
cmd_seed() {
  need curl
  local url="${ADO_URL:?set ADO_URL=http://<ado-host>:${ADO_PORT}}"
  local pat="${ADO_PAT:?set ADO_PAT=<personal access token>}"
  local proj="${SEED_PROJECT:-PepperTest}"
  local repo="${SEED_REPO:-vuln-app}"
  local base="${url%/}/${COLLECTION}"
  local auth=(-u ":${pat}" -H "Content-Type: application/json")

  echo "→ creating project $proj"
  curl -s "${auth[@]}" -X POST "${base}/_apis/projects?api-version=7.1" -d "{
    \"name\":\"${proj}\",
    \"capabilities\":{\"versioncontrol\":{\"sourceControlType\":\"Git\"},
      \"processTemplate\":{\"templateTypeId\":\"adcc42ab-9882-485e-a3ed-7678f01f66bc\"}}
  }" >/dev/null || true
  sleep 15  # project creation is async

  echo "→ creating repo $repo"
  local repoId
  repoId=$(curl -s "${auth[@]}" -X POST \
    "${base}/${proj}/_apis/git/repositories?api-version=7.1" \
    -d "{\"name\":\"${repo}\"}" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$repoId" ] || die "repo creation failed (check ADO_URL/ADO_PAT and that $proj exists)"

  echo "→ pushing a vulnerable file to main"
  local content
  content=$(printf '%s' 'function login(req){ const q="SELECT * FROM users WHERE u='"'"'"+req.query.u+"'"'"'"; db.query(q); eval(req.query.x); }' | base64)
  curl -s "${auth[@]}" -X POST \
    "${base}/${proj}/_apis/git/repositories/${repoId}/pushes?api-version=7.1" -d "{
      \"refUpdates\":[{\"name\":\"refs/heads/main\",\"oldObjectId\":\"0000000000000000000000000000000000000000\"}],
      \"commits\":[{\"comment\":\"seed: vulnerable sample\",\"changes\":[{\"changeType\":\"add\",
        \"item\":{\"path\":\"/src/login.js\"},
        \"newContent\":{\"content\":\"${content}\",\"contentType\":\"base64encoded\"}}]}]
    }" >/dev/null

  echo "→ opening a PR (feature/login → main)"
  curl -s "${auth[@]}" -X POST \
    "${base}/${proj}/_apis/git/repositories/${repoId}/pushes?api-version=7.1" -d "{
      \"refUpdates\":[{\"name\":\"refs/heads/feature/login\",\"oldObjectId\":\"0000000000000000000000000000000000000000\"}],
      \"commits\":[{\"comment\":\"tweak\",\"changes\":[{\"changeType\":\"edit\",
        \"item\":{\"path\":\"/src/login.js\"},
        \"newContent\":{\"content\":\"${content}\",\"contentType\":\"base64encoded\"}}]}]
    }" >/dev/null || true
  curl -s "${auth[@]}" -X POST \
    "${base}/${proj}/_apis/git/repositories/${repoId}/pullrequests?api-version=7.1" -d "{
      \"sourceRefName\":\"refs/heads/feature/login\",
      \"targetRefName\":\"refs/heads/main\",
      \"title\":\"Add login (seed)\"
    }" >/dev/null || true

  echo "✓ seeded ${proj}/${repo} (repoId ${repoId}). Connect Pepper to Server URL ${url}, collection ${COLLECTION}."
}

cmd_stop()  { require_project; require_vm; gc compute instances stop  "$VM_NAME" --zone="$ZONE"; }
cmd_start() { require_project; require_vm; gc compute instances start "$VM_NAME" --zone="$ZONE"; }

cmd_down() {
  require_project
  read -r -p "Delete VM '$VM_NAME', firewall rules, and bucket $BUCKET? [y/N] " a
  [ "$a" = "y" ] || { echo "aborted"; return; }
  gc compute instances delete "$VM_NAME" --zone="$ZONE" --quiet || true
  gc compute firewall-rules delete ado-iap-rdp ado-internal --quiet || true
  gsutil -m rm -r "$BUCKET" 2>/dev/null || true
  echo "✓ torn down"
}

case "${1:-}" in
  up)     cmd_up ;;
  status) cmd_status ;;
  rdp)    cmd_rdp ;;
  seed)   cmd_seed ;;
  stop)   cmd_stop ;;
  start)  cmd_start ;;
  down)   cmd_down ;;
  *) cat <<EOF
usage: ADO_INSTALLER=<iso> PROJECT=<gcp-project> $0 <command>

  up      create VM + deliver ISO + install/configure ADO Server 2022
  status  show install progress (serial console markers)
  rdp     reset password + IAP tunnel → localhost:13389
  seed    ADO_URL=<url> ADO_PAT=<pat> — create test project + vulnerable repo + PR
  stop    stop the VM (keeps disk)
  start   start the VM
  down    delete VM, firewall rules, and installer bucket

env: PROJECT ZONE(=$ZONE) MACHINE_TYPE(=$MACHINE_TYPE) DISK_SIZE(=$DISK_SIZE)
     ADO_USER(=$ADO_USER) ADO_PORT(=$ADO_PORT) COLLECTION(=$COLLECTION) BUCKET
EOF
     [ "${1:-}" = "" ] && exit 1 || exit 0 ;;
esac
