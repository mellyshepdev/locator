# ─────────────────────────────────────────────────────────────
#  Lokey Client — Windows Installer
#  Downloaded and run from the Locator's own /register-device page.
#  Usage:
#    powershell -ExecutionPolicy Bypass -File install-windows.ps1 -LocatorUrl "https://tobsco-locator.fly.dev" -UnitName "unit5"
# ─────────────────────────────────────────────────────────────
param(
    [Parameter(Mandatory=$true)] [string]$LocatorUrl,
    [Parameter(Mandatory=$true)] [string]$UnitName,
    [string]$TickRate = "60"
)

$ErrorActionPreference = "Stop"
$LocatorUrl = $LocatorUrl.TrimEnd('/')
$InstallDir = Join-Path $env:LOCALAPPDATA "Lokey"
$TaskName   = "Lokey Client ($UnitName)"

Write-Host "==============================================="
Write-Host "  Lokey Client - Windows Installer ($UnitName)"
Write-Host "==============================================="

# ── 1. Python present? ──────────────────────────────────────
Write-Host ""
Write-Host "[1/4] Checking for Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  Python not found on PATH. Install it from https://python.org/downloads/"
    Write-Host "  (check 'Add python.exe to PATH' during setup), then re-run this installer."
    exit 1
}
Write-Host "  Found: $($python.Source)"

# ── 2. Fetch hard-stats.py from the Locator itself ──────────
Write-Host ""
Write-Host "[2/4] Downloading Lokey client to $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "$LocatorUrl/static/lokey-native/hard-stats.py" -OutFile (Join-Path $InstallDir "hard-stats.py")
Write-Host "  Done."

# ── 3. Python deps ───────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Installing Python dependencies (psutil, requests)..."
& python -m pip install --quiet --user psutil requests
Write-Host "  Done."

# ── 4. Persist config + register a logon Scheduled Task ─────
Write-Host ""
Write-Host "[4/4] Registering Scheduled Task (runs at logon, and now)..."

[Environment]::SetEnvironmentVariable("UNIT_NAME", $UnitName, "User")
[Environment]::SetEnvironmentVariable("LOCATOR_URL", $LocatorUrl, "User")
[Environment]::SetEnvironmentVariable("TICK_RATE", $TickRate, "User")

$pythonw = Join-Path (Split-Path $python.Source) "pythonw.exe"
if (-not (Test-Path $pythonw)) { $pythonw = $python.Source }

$action  = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$InstallDir\hard-stats.py`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 0)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Lokey heartbeat agent for $UnitName" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "  Task '$TaskName' registered and started."
Write-Host ""
Write-Host "==============================================="
Write-Host "  Install complete."
Write-Host "  Check the Tactical Grid in ~60s for $UnitName."
Write-Host ""
Write-Host "  Manage it with:"
Write-Host "    Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "    Stop-ScheduledTask -TaskName '$TaskName'"
Write-Host "    Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "==============================================="
