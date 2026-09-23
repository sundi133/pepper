#!/usr/bin/env bash
#
# Spin up a throwaway Azure DevOps Server 2022 on Google Compute Engine for
# testing Pepper's Azure DevOps integration against an on-prem server.
#
# What `up` does, end to end (~45-75 min, mostly Windows + ADO install time):
#   1. Enables the Compute API, reserves a static IP, creates firewall rules
#      (RDP only via IAP; HTTP/HTTPS only from ALLOWED_CIDRS).
#   2. Uploads your Azure DevOps Server 2022 installer (.exe or .iso) to a GCS
#      bucket, or hands the VM a download URL.
#   3. Creates a Windows Server 2022 VM whose startup script, unattended:
#        - installs Azure DevOps Server (reboots if the installer asks),
#        - configures it with TfsConfig "NewServerBasic" (SQL Server Express,
#          IIS, DefaultCollection; code search disabled to skip Elasticsearch),
#        - adds an HTTPS binding with a self-signed cert for the static IP,
#        - sets the public URL to https://<ip>/,
#        - reports progress + the cert via GCE guest attributes.
#   4. Waits for "ready", saves the cert locally, resets a Windows admin
#      password, and prints URLs / next steps.
#
# `seed` then creates a project + Git repo with deliberately vulnerable code
# and an open PR, so Pepper has something to scan and comment on.
#
# Prereqs (on your machine): gcloud (authenticated), curl, git, python3.
# Get the installer from Microsoft's "Azure DevOps Server" download page
# (Azure DevOps Server 2022, latest update, .exe or .iso).
#
# Usage:
#   ADO_INSTALLER=~/Downloads/azuredevopsserver2022.2.iso \
#   PROJECT=my-gcp-project ./scripts/ado-server-gcp.sh up
#   ./scripts/ado-server-gcp.sh status   # progress while installing
#   ./scripts/ado-server-gcp.sh seed     # test project, repo, PR
#   ./scripts/ado-server-gcp.sh rdp      # IAP tunnel -> localhost:13389
#   ./scripts/ado-server-gcp.sh stop | start | down
#
# Config (env vars):
#   PROJECT         GCP project (default: gcloud config project)
#   ZONE            default us-central1-a
#   INSTANCE        default ado-server
#   MACHINE_TYPE    default e2-standard-4 (4 vCPU / 16 GB)
#   DISK_GB         default 128
#   ADMIN_USER      Windows admin (also ADO admin), default adoadmin
#   ADO_INSTALLER   local path to the .exe/.iso   } one of these
#   ADO_INSTALLER_URL  direct download URL        } is required for `up`
#   BUCKET          GCS bucket for the installer (default: <project>-ado-installer)
#   ALLOWED_CIDRS   comma-separated CIDRs allowed to reach 80/443
#                   (default: your current public IP /32). Add Pepper's egress IP.
#   STATE_DIR       default ~/.ado-gcp  (password, cert, URLs are saved here)
#
# Cost: roughly $0.30/hr running (VM + Windows license); stop it when idle.
# Licensing: Azure DevOps Server installs without a product key as a trial;
# that is fine for integration testing.

set -euo pipefail

CMD="${1:-up}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
ZONE="${ZONE:-us-central1-a}"
REGION="${ZONE%-*}"
INSTANCE="${INSTANCE:-ado-server}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-4}"
DISK_GB="${DISK_GB:-128}"
ADMIN_USER="${ADMIN_USER:-adoadmin}"
BUCKET="${BUCKET:-${PROJECT}-ado-installer}"
STATE_DIR="${STATE_DIR:-$HOME/.ado-gcp}"
STATE_FILE="$STATE_DIR/$INSTANCE.env"
CERT_FILE="$STATE_DIR/$INSTANCE.crt"
TAG="ado-server"
IP_NAME="$INSTANCE-ip"
FW_RDP="$INSTANCE-allow-iap-rdp"
FW_WEB="$INSTANCE-allow-web"
SEED_PROJECT="${SEED_PROJECT:-PepperTest}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "$PROJECT" ]] || die "Set PROJECT or run: gcloud config set project <id>"
command -v gcloud >/dev/null || die "gcloud CLI not found"
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"

G=(--project="$PROJECT")
GZ=(--project="$PROJECT" --zone="$ZONE")

guest_attr() {
  gcloud compute instances get-guest-attributes "$INSTANCE" "${GZ[@]}" \
    --query-path="ado/$1" --format='value(value)' 2>/dev/null || true
}

static_ip() {
  gcloud compute addresses describe "$IP_NAME" "${G[@]}" --region="$REGION" \
    --format='value(address)' 2>/dev/null || true
}

load_state() {
  [[ -f "$STATE_FILE" ]] || die "No state at $STATE_FILE — run '$0 up' first"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
}

# ─── Windows startup script (runs as SYSTEM on every boot; idempotent) ───────
write_startup_script() {
  cat >"$1" <<'PS1'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Work = 'C:\ado'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
Start-Transcript -Path "$Work\startup-$(Get-Date -Format yyyyMMdd-HHmmss).log" -Append | Out-Null

$MD = 'http://metadata.google.internal/computeMetadata/v1/instance'
$H  = @{ 'Metadata-Flavor' = 'Google' }
function Get-Attr($name) {
  try { Invoke-RestMethod -Headers $H -Uri "$MD/attributes/$name" } catch { $null }
}
function Set-Status($key, $value) {
  Write-Host "[ado] $key = $value"
  try { Invoke-RestMethod -Method Put -Headers $H -Body $value -Uri "$MD/guest-attributes/ado/$key" | Out-Null } catch {}
}
function Done($stage) { Test-Path "$Work\$stage.done" }
function Mark($stage) { New-Item -ItemType File -Force -Path "$Work\$stage.done" | Out-Null }

try {
  # 1. Windows features ADO Server needs (TfsConfig would add most; do it up front).
  if (-not (Done 'features')) {
    Set-Status status 'installing-windows-features'
    Install-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth, Web-Mgmt-Console, `
      Web-Stat-Compression, Web-Dyn-Compression, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45 `
      -IncludeManagementTools | Out-Null
    New-NetFirewallRule -DisplayName 'ADO HTTP/HTTPS' -Direction Inbound -Protocol TCP `
      -LocalPort 80,443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Mark 'features'
  }

  # 2. Fetch the installer.
  $installer = Get-ChildItem $Work -Filter 'installer.*' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (Done 'installed') -and -not $installer) {
    Set-Status status 'downloading-installer'
    $gcs = Get-Attr 'ado-installer-gcs'
    $url = Get-Attr 'ado-installer-url'
    if ($gcs) {
      $ext = [IO.Path]::GetExtension($gcs)
      & gcloud storage cp $gcs "$Work\installer$ext"
      if ($LASTEXITCODE -ne 0) { & gsutil cp $gcs "$Work\installer$ext" }
    } elseif ($url) {
      $ext = if ($url -match '\.iso($|\?)') { '.iso' } else { '.exe' }
      Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile "$Work\installer$ext"
    } else { throw 'No ado-installer-gcs or ado-installer-url metadata set' }
    $installer = Get-ChildItem $Work -Filter 'installer.*' | Select-Object -First 1
  }

  # 3. Install binaries (silent Burn bundle). 3010 = reboot required.
  if (-not (Done 'installed')) {
    Set-Status status 'installing-ado-server'
    $exe = $installer.FullName
    if ($installer.Extension -eq '.iso') {
      $img = Mount-DiskImage -ImagePath $installer.FullName -PassThru
      $drive = ($img | Get-Volume).DriveLetter + ':\'
      $exe = (Get-ChildItem $drive -Filter '*.exe' | Sort-Object Length -Descending | Select-Object -First 1).FullName
    }
    $p = Start-Process -FilePath $exe -ArgumentList '/quiet', '/norestart', '/log', "$Work\ado-install.log" -Wait -PassThru
    Write-Host "[ado] installer exit code $($p.ExitCode)"
    if ($p.ExitCode -notin 0, 3010) { throw "ADO installer failed with exit code $($p.ExitCode); see $Work\ado-install.log" }
    Mark 'installed'
    if ($p.ExitCode -eq 3010) {
      Set-Status status 'rebooting-after-install'
      Stop-Transcript | Out-Null
      Restart-Computer -Force
      exit 0
    }
  }

  $tfsConfig = (Get-ChildItem 'C:\Program Files\Azure DevOps Server*\Tools\TfsConfig.exe' | Select-Object -First 1).FullName
  if (-not $tfsConfig) { throw 'TfsConfig.exe not found after install' }

  # 4. Configure: Basic (SQL Express + app tier + DefaultCollection), no search.
  if (-not (Done 'configured')) {
    Set-Status status 'configuring-ado-server'
    $ini = "$Work\basic.ini"
    & $tfsConfig unattend /create /type:NewServerBasic /unattendfile:$ini
    if ($LASTEXITCODE -ne 0) { throw "TfsConfig unattend /create failed ($LASTEXITCODE)" }
    (Get-Content $ini) `
      -replace '^(ConfigureSearch)=.*', '$1=False' `
      -replace '^(InstallSqlExpress)=.*', '$1=True' `
      -replace '^(SendFeedback)=.*', '$1=False' | Set-Content $ini
    Write-Host '[ado] unattend file:'; Get-Content $ini | Write-Host
    & $tfsConfig unattend /configure /unattendfile:$ini /continue
    if ($LASTEXITCODE -ne 0) { throw "TfsConfig unattend /configure failed ($LASTEXITCODE); logs in C:\ProgramData\Microsoft\Azure DevOps\Server Configuration\Logs" }
    Mark 'configured'
  }

  # 5. HTTPS with a self-signed cert for the static external IP + public URL.
  $ip = Invoke-RestMethod -Headers $H -Uri "$MD/network-interfaces/0/access-configs/0/external-ip"
  if (-not (Done 'https')) {
    Set-Status status 'configuring-https'
    Import-Module WebAdministration
    $cert = New-SelfSignedCertificate -Subject "CN=$ip" `
      -TextExtension @("2.5.29.17={text}IPAddress=$ip&DNS=$env:COMPUTERNAME") `
      -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable `
      -NotAfter (Get-Date).AddYears(2)
    # Trust it locally so server-side calls to the public URL succeed.
    $tmp = "$Work\ado-server.cer"
    Export-Certificate -Cert $cert -FilePath $tmp | Out-Null
    Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    $site = (Get-Website | Where-Object { $_.Name -like 'Azure DevOps Server*' } | Select-Object -First 1).Name
    if (-not $site) { throw 'Azure DevOps Server IIS site not found' }
    if (-not (Get-WebBinding -Name $site -Protocol https -Port 443)) {
      New-WebBinding -Name $site -Protocol https -Port 443
    }
    (Get-WebBinding -Name $site -Protocol https -Port 443).AddSslCertificate($cert.Thumbprint, 'My')
    & $tfsConfig settings /publicUrl:"https://$ip/"
    if ($LASTEXITCODE -ne 0) { throw "TfsConfig settings /publicUrl failed ($LASTEXITCODE)" }
    # Single-line base64 (guest attributes); the local side re-wraps it as PEM.
    Set-Content -Path "$Work\ado-server.b64" -Value ([Convert]::ToBase64String($cert.RawData)) -NoNewline
    Mark 'https'
  }
  Set-Status cert (Get-Content "$Work\ado-server.b64" -Raw)

  # 6. Find the collection URL (root vdir on new 2019+ installs, /tfs on some).
  Set-Status status 'waiting-for-web'
  $collection = $null
  for ($i = 0; $i -lt 60 -and -not $collection; $i++) {
    foreach ($path in '/DefaultCollection', '/tfs/DefaultCollection') {
      try {
        Invoke-WebRequest -UseBasicParsing -Uri "http://localhost$path/_apis/connectionData" | Out-Null
        $collection = $path
      } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 401 -or $code -eq 203) { $collection = $path }
      }
      if ($collection) { break }
    }
    if (-not $collection) { Start-Sleep -Seconds 10 }
  }
  if (-not $collection) { throw 'ADO web app did not come up on /DefaultCollection or /tfs/DefaultCollection' }
  Set-Status collection_url "https://$ip$collection"
  Set-Status status 'ready'
} catch {
  Set-Status error ($_ | Out-String)
  Set-Status status 'error'
  throw
} finally {
  try { Stop-Transcript | Out-Null } catch {}
}
PS1
}

# ─── Commands ────────────────────────────────────────────────────────────────
cmd_up() {
  [[ -n "${ADO_INSTALLER:-}" || -n "${ADO_INSTALLER_URL:-}" ]] || die \
    "Set ADO_INSTALLER=/path/to/azuredevopsserver2022*.{exe,iso} (or ADO_INSTALLER_URL). Download it from Microsoft's Azure DevOps Server download page."
  if [[ -n "${ADO_INSTALLER:-}" ]]; then
    [[ -f "$ADO_INSTALLER" ]] || die "ADO_INSTALLER not found: $ADO_INSTALLER"
    case "$ADO_INSTALLER" in *.exe|*.iso) ;; *) die "ADO_INSTALLER must be .exe or .iso" ;; esac
  fi

  local cidrs="${ALLOWED_CIDRS:-}"
  if [[ -z "$cidrs" ]]; then
    local myip; myip="$(curl -fsS -m 10 https://ifconfig.me || true)"
    [[ -n "$myip" ]] || die "Could not detect your public IP; set ALLOWED_CIDRS"
    cidrs="$myip/32"
  fi

  log "Project $PROJECT, zone $ZONE, instance $INSTANCE"
  gcloud services enable compute.googleapis.com storage.googleapis.com "${G[@]}"

  if [[ -z "$(static_ip)" ]]; then
    log "Reserving static IP $IP_NAME"
    gcloud compute addresses create "$IP_NAME" "${G[@]}" --region="$REGION"
  fi
  local ip; ip="$(static_ip)"
  log "Static IP: $ip"

  if ! gcloud compute firewall-rules describe "$FW_RDP" "${G[@]}" >/dev/null 2>&1; then
    log "Firewall: RDP from IAP only"
    gcloud compute firewall-rules create "$FW_RDP" "${G[@]}" --allow=tcp:3389 \
      --source-ranges=35.235.240.0/20 --target-tags="$TAG"
  fi
  if gcloud compute firewall-rules describe "$FW_WEB" "${G[@]}" >/dev/null 2>&1; then
    gcloud compute firewall-rules update "$FW_WEB" "${G[@]}" --source-ranges="$cidrs"
  else
    log "Firewall: 80/443 from $cidrs"
    gcloud compute firewall-rules create "$FW_WEB" "${G[@]}" --allow=tcp:80,tcp:443 \
      --source-ranges="$cidrs" --target-tags="$TAG"
  fi

  local md_installer
  if [[ -n "${ADO_INSTALLER:-}" ]]; then
    if ! gcloud storage buckets describe "gs://$BUCKET" "${G[@]}" >/dev/null 2>&1; then
      log "Creating bucket gs://$BUCKET"
      gcloud storage buckets create "gs://$BUCKET" "${G[@]}" --location="$REGION" \
        --uniform-bucket-level-access
    fi
    local obj="gs://$BUCKET/$(basename "$ADO_INSTALLER")"
    if ! gcloud storage objects describe "$obj" "${G[@]}" >/dev/null 2>&1; then
      log "Uploading installer to $obj"
      gcloud storage cp "$ADO_INSTALLER" "$obj" "${G[@]}"
    fi
    md_installer="ado-installer-gcs=$obj"
  else
    md_installer="ado-installer-url=$ADO_INSTALLER_URL"
  fi

  if gcloud compute instances describe "$INSTANCE" "${GZ[@]}" >/dev/null 2>&1; then
    warn "Instance $INSTANCE already exists; skipping create"
  else
    local ps1; ps1="$(mktemp -t ado-startup-XXXX.ps1)"
    write_startup_script "$ps1"
    log "Creating Windows Server 2022 VM ($MACHINE_TYPE, ${DISK_GB}GB)"
    gcloud compute instances create "$INSTANCE" "${GZ[@]}" \
      --machine-type="$MACHINE_TYPE" \
      --image-project=windows-cloud --image-family=windows-2022 \
      --boot-disk-size="${DISK_GB}GB" --boot-disk-type=pd-balanced \
      --address="$ip" --tags="$TAG" \
      --scopes=cloud-platform \
      --metadata=enable-guest-attributes=TRUE,"$md_installer" \
      --metadata-from-file=windows-startup-script-ps1="$ps1"
    rm -f "$ps1"
  fi

  wait_ready
  finish_up "$ip"
}

wait_ready() {
  log "Waiting for install/config (typically 45-75 min). Ctrl-C is safe; re-run '$0 status' later."
  local last="" status deadline=$(( $(date +%s) + 120*60 ))
  while (( $(date +%s) < deadline )); do
    status="$(guest_attr status)"
    if [[ "$status" != "$last" && -n "$status" ]]; then
      log "VM status: $status"; last="$status"
    fi
    case "$status" in
      ready) return 0 ;;
      error)
        warn "Setup failed on the VM:"
        guest_attr error >&2
        die "Inspect with: gcloud compute instances get-serial-port-output $INSTANCE --zone $ZONE --project $PROJECT (or RDP and read C:\\ado\\*.log)"
        ;;
    esac
    sleep 30
  done
  die "Timed out waiting for the VM; check '$0 status' and the serial port output"
}

finish_up() {
  local ip="$1"
  local b64; b64="$(guest_attr cert | tr -d '[:space:]')"
  if [[ -n "$b64" ]]; then
    { echo "-----BEGIN CERTIFICATE-----"; fold -w 64 <<<"$b64"; echo "-----END CERTIFICATE-----"; } >"$CERT_FILE"
  fi
  [[ -s "$CERT_FILE" ]] || warn "Could not read cert from guest attributes"
  local coll; coll="$(guest_attr collection_url)"

  local pass=""
  if [[ -f "$STATE_FILE" ]] && grep -q '^ADMIN_PASS=' "$STATE_FILE"; then
    # shellcheck disable=SC1090
    pass="$(source "$STATE_FILE"; echo "$ADMIN_PASS")"
  else
    log "Creating Windows admin $ADMIN_USER"
    pass="$(gcloud compute reset-windows-password "$INSTANCE" "${GZ[@]}" \
      --user="$ADMIN_USER" --quiet --format='value(password)')"
  fi

  umask 077
  cat >"$STATE_FILE" <<EOF
ADO_IP=$(printf %q "$ip")
ADO_URL=$(printf %q "https://$ip")
ADO_COLLECTION_URL=$(printf %q "$coll")
ADMIN_USER=$(printf %q "$ADMIN_USER")
ADMIN_PASS=$(printf %q "$pass")
ADO_CERT=$(printf %q "$CERT_FILE")
EOF

  cat <<EOF

────────────────────────────────────────────────────────────────────────────
 Azure DevOps Server is ready
────────────────────────────────────────────────────────────────────────────
 Collection URL : $coll
 Admin login    : $ADMIN_USER / (saved in $STATE_FILE)
 Server cert    : $CERT_FILE   (self-signed; trust it in your browser/OS)

 Check the API (Windows auth):
   curl --cacert $CERT_FILE --ntlm -u '$ADMIN_USER' "$coll/_apis/connectionData?api-version=7.0"

 Next:
   1. $0 seed     # project "$SEED_PROJECT", vulnerable repo, open PR
   2. In the browser: $coll/_usersSettings/tokens  → create a PAT
      (scopes: Code Read & Write, Code Status, Project and Team Read)
   3. PAT check:
      curl --cacert $CERT_FILE -u ":\$PAT" "$coll/_apis/connectionData?api-version=7.0"
   4. Pepper (web + worker containers) must trust the cert:
      NODE_EXTRA_CA_CERTS=$CERT_FILE   GIT_SSL_CAINFO=$CERT_FILE
   5. RDP if needed: $0 rdp   → connect to localhost:13389

 Stop when idle: $0 stop     Tear down: $0 down
────────────────────────────────────────────────────────────────────────────
EOF
}

cmd_status() {
  local s; s="$(guest_attr status)"
  echo "status: ${s:-<no status yet — VM may still be booting>}"
  local c; c="$(guest_attr collection_url)"; [[ -n "$c" ]] && echo "collection: $c"
  [[ "$s" == error ]] && { echo "error:"; guest_attr error; }
  if [[ "$s" == ready && ! -f "$STATE_FILE" ]]; then finish_up "$(static_ip)"; fi
}

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

cmd_seed() {
  load_state
  command -v git >/dev/null || die "git not found"
  command -v python3 >/dev/null || die "python3 not found"
  local coll="$ADO_COLLECTION_URL"
  local c=(curl -fsS --cacert "$ADO_CERT" --ntlm -u "$ADMIN_USER:$ADMIN_PASS" -H 'Content-Type: application/json')

  if "${c[@]}" "$coll/_apis/projects/$SEED_PROJECT?api-version=7.0" >/dev/null 2>&1; then
    log "Project $SEED_PROJECT already exists"
  else
    log "Creating project $SEED_PROJECT (Git, Agile)"
    local op
    op="$("${c[@]}" -X POST "$coll/_apis/projects?api-version=7.0" -d "{
      \"name\": \"$SEED_PROJECT\", \"description\": \"Pepper integration test\",
      \"capabilities\": {
        \"versioncontrol\": {\"sourceControlType\": \"Git\"},
        \"processTemplate\": {\"templateTypeId\": \"adcc42ab-9882-485e-a3ed-7678f01f66bc\"}
      }}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["url"])')"
    for _ in $(seq 1 60); do
      local st; st="$("${c[@]}" "$op" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')"
      [[ "$st" == succeeded ]] && break
      [[ "$st" == failed || "$st" == cancelled ]] && die "Project creation $st"
      sleep 5
    done
  fi

  local work; work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  local remote="${coll/https:\/\//https://$(urlenc "$ADMIN_USER"):$(urlenc "$ADMIN_PASS")@}/$SEED_PROJECT/_git/$SEED_PROJECT"
  local g=(git -c http.sslCAInfo="$ADO_CERT" -c user.name="Pepper Seed" -c user.email="seed@example.com")

  log "Pushing vulnerable sample code to $SEED_PROJECT"
  mkdir -p "$work/repo/k8s" && cd "$work/repo"
  "${g[@]}" init -q -b main
  cat >package.json <<'EOF'
{
  "name": "pepper-ado-sample",
  "version": "1.0.0",
  "main": "app.js",
  "dependencies": { "express": "4.16.0", "lodash": "4.17.15", "mysql": "2.18.1" }
}
EOF
  cat >app.js <<'EOF'
const express = require("express");
const mysql = require("mysql");
const { exec } = require("child_process");
const app = express();

// Intentionally vulnerable test fixture — do not deploy.
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const db = mysql.createConnection({ host: "db", user: "root", password: "hunter2" });

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.listen(3000);
EOF
  cat >Dockerfile <<'EOF'
FROM node:10
USER root
COPY . /app
WORKDIR /app
RUN npm install
CMD ["node", "app.js"]
EOF
  cat >k8s/deployment.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: sample }
spec:
  selector: { matchLabels: { app: sample } }
  template:
    metadata: { labels: { app: sample } }
    spec:
      containers:
        - name: app
          image: sample:latest
          securityContext: { privileged: true, runAsUser: 0 }
EOF
  "${g[@]}" add -A && "${g[@]}" commit -qm "Initial vulnerable sample"
  "${g[@]}" push -q --force "$remote" main

  "${g[@]}" checkout -q -b feature/path-traversal
  cat >>app.js <<'EOF'

const fs = require("fs");
app.get("/file", (req, res) => {
  res.send(fs.readFileSync("/srv/files/" + req.query.name, "utf8"));
});
EOF
  "${g[@]}" commit -qam "Add file download endpoint"
  "${g[@]}" push -q --force "$remote" feature/path-traversal

  log "Opening PR feature/path-traversal -> main"
  local repo_api="$coll/$SEED_PROJECT/_apis/git/repositories/$SEED_PROJECT"
  "${c[@]}" -X POST "$repo_api/pullrequests?api-version=7.0" -d '{
      "sourceRefName": "refs/heads/feature/path-traversal",
      "targetRefName": "refs/heads/main",
      "title": "Add file download endpoint",
      "description": "Seeded by ado-server-gcp.sh for Pepper PR scanning tests."
    }' >/dev/null || warn "PR create failed (it may already exist)"
  cd - >/dev/null

  cat <<EOF

Seeded:
  Repo : $coll/$SEED_PROJECT/_git/$SEED_PROJECT
  PRs  : $coll/$SEED_PROJECT/_git/$SEED_PROJECT/pullrequests
Service hook for Pepper: Project settings → Service hooks → Web Hooks →
  "Code pushed" and "Pull request created/updated" → https://<pepper>/api/webhooks/azure-devops
EOF
}

cmd_rdp() {
  load_state
  echo "RDP to localhost:13389 as $ADMIN_USER (password in $STATE_FILE). Ctrl-C to close."
  gcloud compute start-iap-tunnel "$INSTANCE" 3389 --local-host-port=localhost:13389 "${GZ[@]}"
}

cmd_stop()  { gcloud compute instances stop "$INSTANCE" "${GZ[@]}"; }
cmd_start() { gcloud compute instances start "$INSTANCE" "${GZ[@]}"; }

cmd_down() {
  read -r -p "Delete VM $INSTANCE, IP $IP_NAME, firewall rules and state in $STATE_DIR? [y/N] " a
  [[ "$a" == [yY]* ]] || exit 1
  gcloud compute instances delete "$INSTANCE" "${GZ[@]}" --quiet || true
  gcloud compute addresses delete "$IP_NAME" "${G[@]}" --region="$REGION" --quiet || true
  gcloud compute firewall-rules delete "$FW_RDP" "$FW_WEB" "${G[@]}" --quiet || true
  rm -f "$STATE_FILE" "$CERT_FILE"
  log "Done. The installer is kept in gs://$BUCKET (delete with: gcloud storage rm -r gs://$BUCKET)"
}

case "$CMD" in
  up) cmd_up ;;
  status) cmd_status ;;
  seed) cmd_seed ;;
  rdp) cmd_rdp ;;
  stop) cmd_stop ;;
  start) cmd_start ;;
  down) cmd_down ;;
  *) die "Unknown command '$CMD' (up|status|seed|rdp|stop|start|down)" ;;
esac
