Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
$ErrorActionPreference = 'Stop'
$psqlPath = 'D:\Programs\PostgreSQL\bin\psql.exe'
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
    $lines = @("DATABASE_URL=postgres://cyberguard_app:${encodedPassword}@127.0.0.1:5432/cyberguard?sslmode=disable", "TEST_DATABASE_URL=postgres://cyberguard_app:${encodedPassword}@127.0.0.1:5432/cyberguard_test?sslmode=disable")
    [IO.File]::WriteAllLines((Join-Path (Get-Location).Path '.env.local'), $lines)
    Write-Host 'Local database configuration saved to ignored .env.local. No existing database was reset.'
} finally {
    $env:PGPASSWORD = $previousPassword
    $appPassword = $null
    $encodedPassword = $null
    $credential = $null
}
