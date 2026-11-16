# Starts everything CyberGuard AI needs with one command:
#   1. the PostgreSQL Windows service (if it is installed locally and stopped),
#   2. the backend, in its own window (applies pending database migrations first),
#   3. the frontend, in its own window,
# then waits until both answer and opens the website in the default browser.
#
# Run it from any folder:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start.ps1
# or double-click start.cmd in the project folder.
#
# Safe to run again: parts that are already running are left alone.
# To stop the application, close the two windows it opened (or press Ctrl+C in them).
param(
    # Do not open the browser at the end.
    [switch]$NoBrowser,
    # Seconds to wait for the backend. The first start compiles it and can take a while.
    [int]$BackendTimeout = 240,
    [int]$FrontendTimeout = 90
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$localConfig = Join-Path $projectRoot '.env.local'

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Stop-WithHelp([string]$Text) {
    Write-Host ''
    Write-Host $Text -ForegroundColor Red
    Write-Host 'Full guide: docs\local-windows.md'
    exit 1
}

# Reads one value from .env.local as plain text. The file is never executed.
function Get-LocalValue([string]$Name, [string]$Default) {
    $fromProcess = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ($fromProcess) { return $fromProcess }
    if (Test-Path -LiteralPath $localConfig) {
        foreach ($line in [IO.File]::ReadAllLines($localConfig)) {
            $text = $line.Trim().TrimStart([char]0xFEFF)
            if ($text.StartsWith("$Name=")) {
                $value = $text.Substring($Name.Length + 1).Trim().Trim('"').Trim("'")
                if ($value) { return $value }
            }
        }
    }
    return $Default
}

function Test-Port([string]$HostName, [int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $attempt = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $attempt.AsyncWaitHandle.WaitOne(700)) { return $false }
        $client.EndConnect($attempt)
        return $true
    } catch { return $false } finally { $client.Close() }
}

function Test-Url([string]$Url) {
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4
        return $response.StatusCode -eq 200
    } catch { return $false }
}

# Opens a script in a new PowerShell window that stays open, so its messages
# remain readable. Bypass applies to that one process only.
function Start-Window([string]$Title, [string]$Script) {
    $command = "`$Host.UI.RawUI.WindowTitle = '$Title'; & '$($Script.Replace("'", "''"))'"
    return Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -WorkingDirectory $projectRoot -PassThru
}

# ---- 1. Prerequisites -------------------------------------------------------
Write-Step 'Checking prerequisites'
$missing = @()
foreach ($tool in @(@('go', 'Go  https://go.dev/dl/'), @('node', 'Node.js LTS  https://nodejs.org/'), @('npm.cmd', 'npm (comes with Node.js)'))) {
    if (-not (Get-Command $tool[0] -ErrorAction SilentlyContinue)) { $missing += $tool[1] }
}
if ($missing.Count -gt 0) { Stop-WithHelp ("Not installed or not on PATH: " + ($missing -join '; ') + "`nInstall it, open a NEW PowerShell window and run this script again.") }
if (-not (Test-Path -LiteralPath $localConfig)) {
    Stop-WithHelp "The application is not set up yet (.env.local is missing). Run these two commands once, then start again:`n  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-postgres.ps1`n  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1"
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'frontend\node_modules'))) {
    Stop-WithHelp "Frontend dependencies are not installed. Run once:`n  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1"
}
Write-Host 'Go, Node.js, npm and the local configuration are present.'

$address = Get-LocalValue 'APP_ADDRESS' '127.0.0.1:8080'
$origin = (Get-LocalValue 'APP_ORIGIN' 'http://localhost:3000').TrimEnd('/')
$backendHost, $backendPort = $address.Split(':')[0], [int]$address.Split(':')[-1]
if (-not $backendHost -or $backendHost -eq '0.0.0.0') { $backendHost = '127.0.0.1' }
$frontendUri = [Uri]$origin
$healthUrl = "http://${backendHost}:${backendPort}/api/v1/health"

# ---- 2. PostgreSQL ----------------------------------------------------------
Write-Step 'PostgreSQL'
$services = @(Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue)
if ($services.Count -eq 0) {
    Write-Host 'No local PostgreSQL service found. Continuing: the database in .env.local may run elsewhere.' -ForegroundColor Yellow
} elseif ($services | Where-Object Status -eq 'Running') {
    Write-Host ("Running: " + (($services | Where-Object Status -eq 'Running' | ForEach-Object Name) -join ', '))
} else {
    # Newest installed version first.
    $service = $services | Sort-Object Name -Descending | Select-Object -First 1
    Write-Host "Starting service $($service.Name)..."
    try {
        Start-Service -Name $service.Name
    } catch {
        # Starting a service needs administrator rights. Ask Windows for them
        # for this single action; you will see the usual confirmation prompt.
        Write-Host 'Administrator permission is needed to start the service. Confirm the Windows prompt.' -ForegroundColor Yellow
        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList @('-NoProfile', '-Command', "Start-Service -Name '$($service.Name)'")
        } catch { }
    }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service -Name $service.Name).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if ((Get-Service -Name $service.Name).Status -ne 'Running') {
        Stop-WithHelp "PostgreSQL service '$($service.Name)' could not be started. Start it in the Windows 'Services' application and run this script again."
    }
    Write-Host "Started: $($service.Name)"
}

# ---- 3. Backend -------------------------------------------------------------
Write-Step 'Backend'
if (Test-Url $healthUrl) {
    Write-Host "Already running at http://${backendHost}:${backendPort}"
} elseif (Test-Port $backendHost $backendPort) {
    Stop-WithHelp "Port $backendPort is used by another program, or the backend there is not healthy.`nOpen $healthUrl in a browser to see its message, close the program using the port and run this script again."
} else {
    $backendWindow = Start-Window 'CyberGuard AI - backend' (Join-Path $PSScriptRoot 'start-backend.ps1')
    Write-Host 'Opened the backend window. Applying database migrations and starting (the first start compiles the program)...'
    $deadline = (Get-Date).AddSeconds($BackendTimeout)
    while (-not (Test-Url $healthUrl)) {
        if ($backendWindow.HasExited) { Stop-WithHelp 'The backend window was closed before the backend became ready.' }
        if ((Get-Date) -ge $deadline) {
            Stop-WithHelp "The backend did not become ready within $BackendTimeout seconds. Read the message in the backend window.`nCommon causes: PostgreSQL is not running, DATABASE_URL in .env.local is wrong, or setup.ps1 has not been run."
        }
        Start-Sleep -Seconds 2
        Write-Host '.' -NoNewline
    }
    Write-Host ''
    Write-Host "Ready at http://${backendHost}:${backendPort}"
}

# ---- 4. Frontend ------------------------------------------------------------
Write-Step 'Frontend'
if (Test-Url $origin) {
    Write-Host "Already running at $origin"
} elseif (Test-Port $frontendUri.Host $frontendUri.Port) {
    Stop-WithHelp "Port $($frontendUri.Port) is used by another program. Close it and run this script again."
} else {
    $frontendWindow = Start-Window 'CyberGuard AI - frontend' (Join-Path $PSScriptRoot 'start-frontend.ps1')
    Write-Host 'Opened the frontend window. Starting...'
    $deadline = (Get-Date).AddSeconds($FrontendTimeout)
    while (-not (Test-Url $origin)) {
        if ($frontendWindow.HasExited) { Stop-WithHelp 'The frontend window was closed before the frontend became ready.' }
        if ((Get-Date) -ge $deadline) { Stop-WithHelp "The frontend did not become ready within $FrontendTimeout seconds. Read the message in the frontend window." }
        Start-Sleep -Seconds 1
        Write-Host '.' -NoNewline
    }
    Write-Host ''
    Write-Host "Ready at $origin"
}

# ---- 5. Done ----------------------------------------------------------------
Write-Host ''
Write-Host "CyberGuard AI is running: $origin" -ForegroundColor Green
Write-Host 'Use exactly this address. To stop the application, close the backend and frontend windows.'
if (-not $NoBrowser) { Start-Process $origin }
