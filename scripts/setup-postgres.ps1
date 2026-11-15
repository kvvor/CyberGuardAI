param([string]$PsqlPath = 'psql.exe')
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot) -ErrorAction Stop
$ErrorActionPreference = 'Stop'
if (-not (Get-Command $PsqlPath -ErrorAction SilentlyContinue)) {
    # psql.exe is not on PATH. First ask Windows where the installed PostgreSQL
    # service keeps its programs (works for any drive, folder and version), then
    # fall back to the standard installer locations.
    $candidates = @()
    foreach ($service in @(Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" -ErrorAction SilentlyContinue)) {
        if ($service.PathName -match '^"?(?<exe>[^"]+?pg_ctl\.exe)') {
            $beside = Join-Path (Split-Path -Parent $Matches['exe']) 'psql.exe'
            if (Test-Path -LiteralPath $beside) { $candidates += Get-Item -LiteralPath $beside }
        }
    }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }) {
        $candidates += Get-ChildItem -Path (Join-Path $base 'PostgreSQL\*\bin\psql.exe') -ErrorAction SilentlyContinue
    }
    $found = $candidates | Sort-Object { [version]($_.VersionInfo.ProductVersion -replace '[^0-9.].*$','') } -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { throw 'psql.exe not found. Install PostgreSQL, or pass the location of psql.exe with -PsqlPath.' }
    $PsqlPath = $found.FullName
    Write-Host "Using $PsqlPath"
}
if (Test-Path -LiteralPath '.env.local') { throw '.env.local already exists; existing configuration was not changed' }
$adminSecret = Read-Host 'PostgreSQL postgres password (local input only)' -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential('postgres', $adminSecret)
$previousPassword = $env:PGPASSWORD
try {
    $env:PGPASSWORD = $credential.GetNetworkCredential().Password
    $roleExists = & $psqlPath -X -w -h 127.0.0.1 -U postgres -d postgres -Atc "SELECT count(*) FROM pg_roles WHERE rolname='cyberguard_app'"
    if ($LASTEXITCODE -ne 0) { throw 'Administrator authentication failed' }
    if ($roleExists.Trim() -eq '0') {
        $randomBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($randomBytes)
        $rng.Dispose()
        $appPassword = [Convert]::ToBase64String($randomBytes)
        "CREATE ROLE cyberguard_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$appPassword';" | & $psqlPath -X -w -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -q
        if ($LASTEXITCODE -ne 0) { throw 'Role creation failed' }
    } else {
        $appSecret = Read-Host 'Existing cyberguard_app password (will not reset it)' -AsSecureString
        $appPassword = (New-Object System.Management.Automation.PSCredential('cyberguard_app', $appSecret)).GetNetworkCredential().Password
    }
    $unsafeRole = & $psqlPath -X -w -h 127.0.0.1 -U postgres -d postgres -Atc "SELECT count(*) FROM pg_roles WHERE rolname='cyberguard_app' AND (rolsuper OR rolcreaterole OR rolcreatedb)"
    if ($LASTEXITCODE -ne 0 -or $unsafeRole.Trim() -ne '0') { throw 'Existing application role has elevated privileges; no privileges were changed' }
    foreach ($databaseName in @('cyberguard', 'cyberguard_test')) {
        $exists = & $psqlPath -X -w -h 127.0.0.1 -U postgres -d postgres -Atc "SELECT count(*) FROM pg_database WHERE datname='$databaseName'"
        if ($LASTEXITCODE -ne 0) { throw 'Database inspection failed' }
        if ($exists.Trim() -eq '0') {
            & $psqlPath -X -w -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -qc "CREATE DATABASE $databaseName OWNER cyberguard_app"
            if ($LASTEXITCODE -ne 0) { throw 'Database creation failed' }
        }
    }
    $env:PGPASSWORD = $appPassword
    foreach ($databaseName in @('cyberguard', 'cyberguard_test')) {
        & $psqlPath -X -w -h 127.0.0.1 -U cyberguard_app -d $databaseName -v ON_ERROR_STOP=1 -qc 'SELECT 1' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Application connection failed; existing privileges were not changed' }
    }
    if (Test-Path -LiteralPath '.env.local') { throw '.env.local already exists; not overwriting existing configuration' }
    $encodedPassword = [Uri]::EscapeDataString($appPassword)
    $lines = @(
        '# Local CyberGuard AI configuration. Never commit or share this file.',
        "DATABASE_URL=postgres://cyberguard_app:${encodedPassword}@127.0.0.1:5432/cyberguard?sslmode=disable",
        "TEST_DATABASE_URL=postgres://cyberguard_app:${encodedPassword}@127.0.0.1:5432/cyberguard_test?sslmode=disable",
        '# Lets you create your account on the sign-in page of this local installation.',
        '# Set to false after registering if other people can reach this computer.',
        'PUBLIC_REGISTRATION_ENABLED=true'
    )
    [IO.File]::WriteAllLines((Join-Path (Get-Location).Path '.env.local'), $lines)
    Write-Host 'Local database configuration saved to .env.local (ignored by Git). No existing database was reset. Next: run scripts\setup.ps1'
} finally {
    $env:PGPASSWORD = $previousPassword
    $appPassword = $null
    $encodedPassword = $null
    $credential = $null
}
