param([ValidateSet('migrate','start','status','test')][string]$Mode='start')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $projectRoot 'backend'
$localConfig = Join-Path $projectRoot '.env.local'

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Go is not installed or not on PATH. Install Go and open a new PowerShell window.' }
if ($Mode -ne 'test' -and -not $env:DATABASE_URL -and -not (Test-Path -LiteralPath $localConfig)) {
    throw '.env.local was not found. Run scripts\setup.ps1 first (see docs\local-windows.md).'
}

# Reads one value from .env.local as literal text. The file is never executed.
function Get-LocalValue([string]$Name) {
    if (-not (Test-Path -LiteralPath $localConfig)) { return $null }
    foreach ($line in [IO.File]::ReadAllLines($localConfig)) {
        $text = $line.Trim().TrimStart([char]0xFEFF)
        if ($text.StartsWith("$Name=")) {
            $value = $text.Substring($Name.Length + 1).Trim()
            if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) { $value = $value.Substring(1, $value.Length - 2) }
            return $value
        }
    }
    return $null
}

function Invoke-Go([string[]]$Arguments, [string]$Failure) {
    & go @Arguments
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

Push-Location -LiteralPath $backend
try {
    switch ($Mode) {
        'migrate' { Invoke-Go @('run','./cmd/cyberguardctl','migrate') 'Migration failed. Check DATABASE_URL in .env.local and that the PostgreSQL service is running. No data was deleted.' }
        'status'  { Invoke-Go @('run','./cmd/cyberguardctl','status') 'The database is not ready. See the message above.' }
        'start' {
            # Migrations are additive and idempotent. Applying them on every start
            # keeps the database in step with the code after an update; a backend
            # running against an older schema cannot save provider settings.
            Invoke-Go @('run','./cmd/cyberguardctl','migrate') 'Migration failed. Check DATABASE_URL in .env.local and that the PostgreSQL service is running. No data was deleted.'
            Write-Host 'Starting CyberGuard AI backend. Press Ctrl+C to stop.'
            Invoke-Go @('run','./cmd/server') 'The backend stopped with an error. See the message above.'
        }
        'test' {
            if (-not $env:TEST_DATABASE_URL) {
                $value = Get-LocalValue 'TEST_DATABASE_URL'
                if ($value) { $env:TEST_DATABASE_URL = $value }
            }
            if (-not $env:TEST_DATABASE_URL) { throw 'TEST_DATABASE_URL is required for integration tests (isolated cyberguard_test database).' }
            $testUri = [Uri]$env:TEST_DATABASE_URL
            if ($testUri.AbsolutePath -ne '/cyberguard_test') { throw 'Integration tests only run against the isolated cyberguard_test database.' }
            $savedDatabase = $env:DATABASE_URL
            try {
                $env:DATABASE_URL = $env:TEST_DATABASE_URL
                Invoke-Go @('run','./cmd/cyberguardctl','migrate') 'Test database migration failed.'
            } finally { $env:DATABASE_URL = $savedDatabase }
            Invoke-Go @('test','-count=1','./...') 'Backend tests failed.'
        }
    }
} finally { Pop-Location }
