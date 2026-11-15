$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
foreach ($tool in @('go','node','npm.cmd')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Missing prerequisite: $tool. Install it and reopen PowerShell." }
}
$localConfig = Join-Path $projectRoot '.env.local'
if (-not (Test-Path -LiteralPath $localConfig)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot '.env.example') -Destination $localConfig
    Write-Host 'Created .env.local. Set DATABASE_URL for your existing application database, then rerun setup. See docs/local-windows.md.'
    exit 0
}
& (Join-Path $PSScriptRoot 'initialize-provider-key.ps1')
Push-Location -LiteralPath (Join-Path $projectRoot 'backend')
try {
    & go run ./cmd/cyberguardctl migrate
    if ($LASTEXITCODE -ne 0) { throw 'Database connection/migration failed. Check .env.local and PostgreSQL; no database was recreated.' }
} finally { Pop-Location }
Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
} finally { Pop-Location }
Write-Host 'Setup complete. Start scripts/start-backend.ps1 and scripts/start-frontend.ps1 in separate terminals.'
