# First-time and update setup for CyberGuard AI on Windows 10/11.
# Safe to run again at any time: it never deletes data, never recreates a
# database and never replaces an existing provider encryption key.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$localConfig = Join-Path $projectRoot '.env.local'

$missing = @()
foreach ($tool in @(@('go','Go (https://go.dev/dl/)'), @('node','Node.js LTS (https://nodejs.org/)'), @('npm.cmd','npm (installed with Node.js)'))) {
    if (-not (Get-Command $tool[0] -ErrorAction SilentlyContinue)) { $missing += $tool[1] }
}
if ($missing.Count -gt 0) { throw ("Missing prerequisites: " + ($missing -join '; ') + ". Install them and open a new PowerShell window.") }
Write-Host ("Go:      " + (& go version))
Write-Host ("Node.js: " + (& node --version))
Write-Host ("npm:     " + (& npm.cmd --version))

$postgres = Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue
if (-not $postgres) {
    Write-Warning 'No PostgreSQL Windows service was found. Install PostgreSQL (https://www.postgresql.org/download/windows/) unless your database runs on another computer.'
} elseif (-not ($postgres | Where-Object Status -eq 'Running')) {
    Write-Warning ("PostgreSQL service is not running: " + (($postgres | ForEach-Object Name) -join ', ') + ". Start it in the Services application.")
}

if (-not (Test-Path -LiteralPath $localConfig)) {
    Write-Host ''
    Write-Host 'No .env.local yet. Choose one:'
    Write-Host '  A) Let CyberGuard create the PostgreSQL role, databases and .env.local:'
    Write-Host '       powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup-postgres.ps1'
    Write-Host '  B) Use an existing database: copy .env.example to .env.local and set DATABASE_URL.'
    Write-Host 'Then run this script again.'
    exit 1
}
$databaseLine = [IO.File]::ReadAllLines($localConfig) | Where-Object { $_ -match '^\s*DATABASE_URL=' } | Select-Object -First 1
if (-not $env:DATABASE_URL -and (-not $databaseLine -or $databaseLine -match 'USER:PASSWORD@' -or $databaseLine -match '^\s*DATABASE_URL=\s*$')) {
    throw 'DATABASE_URL in .env.local still contains the template value. Set it to your PostgreSQL connection string (percent-encode special characters in the password) and run setup again.'
}

& (Join-Path $PSScriptRoot 'initialize-provider-key.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Provider encryption key initialization failed.' }

Write-Host 'Applying database migrations (existing data is kept)...'
& (Join-Path $PSScriptRoot 'backend.ps1') -Mode migrate
& (Join-Path $PSScriptRoot 'backend.ps1') -Mode status

Write-Host 'Installing frontend dependencies...'
Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed. Check the internet connection and run setup again.' }
} finally { Pop-Location }

Write-Host ''
Write-Host 'Setup complete. Start the application in two PowerShell windows:'
Write-Host '  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-backend.ps1'
Write-Host '  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-frontend.ps1'
Write-Host 'Then open http://localhost:3000'
