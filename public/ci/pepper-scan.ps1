# Pepper CI scan for Windows build agents (Windows PowerShell 5.1+ or PowerShell 7).
# Uploads the checked-out source, waits for the scan, and fails the job when
# the Pepper build gate fails. Same settings and exit codes as pepper-scan.sh:
#
#   Required env: PEPPER_API_URL, PEPPER_API_KEY
#   Optional env: PEPPER_PROJECT, PEPPER_SCAN_TYPE (FULL), PEPPER_BRANCH, PEPPER_COMMIT,
#                 PEPPER_TIMEOUT_MINUTES (30), PEPPER_FAIL_ON_ERROR (1), PEPPER_CA_CERT,
#                 PEPPER_ERROR_PREFIX (e.g. "##vso[task.logissue type=error]")
#   Exit codes:   0 gate passed · 1 gate failed · 2 bad config/upload · 3 scan error/timeout
$ErrorActionPreference = 'Stop'

function Write-PepperError([string]$Message) {
  $prefix = if ($env:PEPPER_ERROR_PREFIX) { $env:PEPPER_ERROR_PREFIX } else { '' }
  [Console]::Error.WriteLine("$prefix$Message")
}
function Get-Setting([string]$Name, [string]$Default) {
  $v = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($v)) { return $Default } else { return $v }
}

if (-not $env:PEPPER_API_URL) { Write-PepperError 'Pepper: PEPPER_API_URL is not set'; exit 2 }
if (-not $env:PEPPER_API_KEY) { Write-PepperError 'Pepper: PEPPER_API_KEY is not set'; exit 2 }

$api = $env:PEPPER_API_URL.TrimEnd('/')
$project = Get-Setting 'PEPPER_PROJECT' (Split-Path -Leaf (Get-Location))
$scanType = Get-Setting 'PEPPER_SCAN_TYPE' 'FULL'
$timeoutMinutes = [int](Get-Setting 'PEPPER_TIMEOUT_MINUTES' '30')
$failOnError = (Get-Setting 'PEPPER_FAIL_ON_ERROR' '1') -eq '1'
# curl.exe ships with Windows 10 1803+ / Server 2019+; on Linux/macOS pwsh it is "curl".
$curl = if ($IsLinux -or $IsMacOS) { 'curl' } else { 'curl.exe' }
$curlTls = @()
if ($env:PEPPER_CA_CERT) { $curlTls = @('--cacert', $env:PEPPER_CA_CERT) }
$headers = @{ Authorization = "Bearer $($env:PEPPER_API_KEY)" }

$work = Join-Path ([IO.Path]::GetTempPath()) ("pepper-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $zip = Join-Path $work 'source.zip'
  $exclude = @('.git', 'node_modules', 'dist', 'build', 'target', '.venv', 'bin', 'obj', '.pepper-scan-id')
  $items = Get-ChildItem -Force | Where-Object { $exclude -notcontains $_.Name }
  if (-not $items) { Write-PepperError 'Pepper: nothing to scan in the current directory'; exit 2 }
  $items | Compress-Archive -DestinationPath $zip -CompressionLevel Optimal

  $data = @{ projectName = $project; scanType = $scanType }
  if ($env:PEPPER_BRANCH) { $data.branch = $env:PEPPER_BRANCH }
  if ($env:PEPPER_COMMIT) { $data.commitSha = $env:PEPPER_COMMIT }
  $dataFile = Join-Path $work 'data.json'
  [IO.File]::WriteAllText($dataFile, ($data | ConvertTo-Json -Compress))

  $sizeMb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
  Write-Host "Pepper: uploading $sizeMb MB for project '$project' ($scanType)"
  $out = Join-Path $work 'response.json'
  $code = & $curl -sS --retry 3 --retry-delay 5 @curlTls -o $out -w '%{http_code}' -X POST `
    -H "Authorization: Bearer $($env:PEPPER_API_KEY)" `
    -F "file=@$zip;type=application/zip;filename=source.zip" `
    -F "data=<$dataFile" `
    "$api/api/scans"
  if ($LASTEXITCODE -ne 0) { Write-PepperError "Pepper: could not reach $api"; exit 2 }
  $body = if (Test-Path $out) { Get-Content $out -Raw } else { '' }
  if ($code -ne '201') {
    $msg = try { ($body | ConvertFrom-Json).error } catch { $body }
    Write-PepperError "Pepper: scan request failed (HTTP $code): $msg"
    exit 2
  }
  $scanId = ($body | ConvertFrom-Json).scanId
  Write-Host "Pepper: scan $scanId queued - $api/scans/$scanId"
  Set-Content -Path '.pepper-scan-id' -Value $scanId

  $invokeArgs = @{ Uri = "$api/api/scans/$scanId"; Headers = $headers; Method = 'Get' }
  if ($env:PEPPER_CA_CERT -and $PSVersionTable.PSVersion.Major -lt 6) {
    Write-Host 'Pepper: PEPPER_CA_CERT is used for the upload; for polling on Windows PowerShell 5.1 import the CA into the machine trust store.'
  }
  $deadline = (Get-Date).AddMinutes($timeoutMinutes)
  $status = 'UNKNOWN'
  $scan = $null
  while ($true) {
    try {
      $scan = Invoke-RestMethod @invokeArgs
      $status = $scan.status
    } catch {
      Write-Host "Pepper: status check failed ($($_.Exception.Message)); retrying"
    }
    if (@('COMPLETED', 'FAILED', 'CANCELLED', 'STOPPED') -contains $status) { break }
    if ((Get-Date) -ge $deadline) {
      Write-PepperError "Pepper: scan $scanId still $status after $timeoutMinutes minutes"
      if ($failOnError) { exit 3 } else { exit 0 }
    }
    Start-Sleep -Seconds 10
  }

  $gate = if ($scan.gateResult) { $scan.gateResult } else { 'PENDING' }
  $summary = "critical=$([int]$scan.criticalCount) high=$([int]$scan.highCount) medium=$([int]$scan.mediumCount) low=$([int]$scan.lowCount)"
  Write-Host "Pepper: status=$status gate=$gate $summary"
  Write-Host "Pepper: results - $api/scans/$scanId"

  if ($status -ne 'COMPLETED') {
    Write-PepperError "Pepper: scan $scanId ended with status $status $($scan.errorMessage)"
    if ($failOnError) { exit 3 } else { exit 0 }
  }
  if ($gate -eq 'FAILED') {
    Write-PepperError "Pepper: build gate FAILED ($summary)"
    exit 1
  }
  Write-Host 'Pepper: build gate passed'
  exit 0
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
