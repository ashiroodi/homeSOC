<#  HomeSOC agent installer for Windows.

    Usage (elevated PowerShell):
      .\install.ps1 -Server "http://192.168.1.10:8080" -Key "yourkey"
      .\install.ps1 -Server "http://192.168.1.10:8080" -Key "yourkey" -Service

    -Server  base URL of the HomeSOC server (a bare host/IP is accepted and
             gets http:// added automatically).
    -Key     enroll key; must match HOMESOC_ENROLL_KEY on the server.
    -Service register + start a Scheduled Task (runs as SYSTEM at startup).

    Reading the Security event log (auth telemetry) needs Administrator, so run
    this from an elevated PowerShell.
#>
param(
  [string]$Server = "",
  [string]$Key = "",
  [switch]$Service
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Good($m){ Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Bad ($m){ Write-Host "[x] $m" -ForegroundColor Red }

$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue) }
if (-not $py) { Bad "Python not found on PATH. Install Python 3 and re-run."; exit 1 }

$venv  = Join-Path $Here ".venv"
$pyexe = Join-Path $venv "Scripts\python.exe"
$agent = Join-Path $Here "homesoc_agent.py"
$cfg   = Join-Path $Here "config.yaml"

Info "Creating virtualenv in $venv"
& $py.Source -m venv $venv

# Upgrade pip the supported way (python -m pip), and don't let a pip hiccup abort us.
Info "Upgrading pip and installing dependencies"
try { & $pyexe -m pip install --quiet --upgrade pip } catch { Warn "pip self-upgrade skipped: $($_.Exception.Message)" }
& $pyexe -m pip install --quiet -r (Join-Path $Here "requirements.txt")
if ($LASTEXITCODE -ne 0) { Bad "Dependency install failed (see pip output above)."; exit 1 }

if (-not $Server) { $Server = Read-Host "Server URL (e.g. http://192.168.1.10:8080)" }
if (-not $Key)    { $Key    = Read-Host "Enroll key" }

# Normalize the server URL so a bare host/IP can't produce a schemeless URL.
if ($Server -and $Server -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $Server = "http://$Server" }
$Server = $Server.TrimEnd('/')
if (-not $Server -or -not $Key) { Bad "Server and key are required."; exit 1 }
if ($Server -notmatch ':\d+') { Warn "No port in '$Server' — if the server listens on 8080, use http://<host>:8080" }

# Write config as ASCII (no BOM) so YAML parses cleanly.
@"
server: "$Server"
enroll_key: "$Key"
"@ | Set-Content -Encoding ascii $cfg
Good "Wrote $cfg"
Info "  server: $Server"

# Verify connectivity + key before we declare anything 'installed'.
Info "Verifying connection to the server..."
$checkOut = & $pyexe $agent --config $cfg --check 2>&1
$checkCode = $LASTEXITCODE
$checkOut | ForEach-Object { Write-Host "    $_" }

if ($checkCode -ne 0) {
  Bad  "Agent is NOT live. Fix the issue above, then re-run this script."
  if ($checkCode -eq 2) { Warn "Key mismatch: make config.yaml's enroll_key equal the server's HOMESOC_ENROLL_KEY." }
  if ($checkCode -eq 1) { Warn "Server unreachable: check the URL/port, that the container is up, and the server firewall." }
  exit $checkCode
}
Good "Connection OK — server reachable and key accepted."

if ($Service) {
  Info "Registering scheduled task 'HomeSOC Agent' (SYSTEM, at startup)"
  $action  = New-ScheduledTaskAction -Execute $pyexe -Argument "`"$agent`" --config `"$cfg`" --no-prompt"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "HomeSOC Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName "HomeSOC Agent"
  Start-Sleep -Seconds 2
  $state = (Get-ScheduledTask -TaskName "HomeSOC Agent").State
  Good "Scheduled task registered and started (State: $state, runs as SYSTEM)."
  Good "Going live — this host should appear in the dashboard within ~30s."
} else {
  Good "Agent verified. To keep it running in the background, re-run with -Service:"
  Write-Host "    .\install.ps1 -Server `"$Server`" -Key `"<key>`" -Service"
  Write-Host ""
  Info "Or run it in the foreground now (Ctrl+C to stop):"
  Write-Host "    & `"$pyexe`" `"$agent`" --config `"$cfg`""
}
