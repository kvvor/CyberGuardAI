param([ValidateSet('migrate','start','test')][string]$Mode='start')
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath '.env.local') {
    foreach ($line in Get-Content -LiteralPath '.env.local') {
        if ($line -match '^(DATABASE_URL|TEST_DATABASE_URL|PROVIDER_MASTER_KEY)=(.+)$') {
            [Environment]::SetEnvironmentVariable($Matches[1],$Matches[2],'Process')
        }
    }
}
Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend\backend" -ErrorAction Stop
switch ($Mode) {
    'migrate' { go run ./cmd/cyberguardctl migrate }
    'start' { go run ./cmd/server }
    'test' {
        if (-not $env:TEST_DATABASE_URL) { throw 'TEST_DATABASE_URL is required for integration validation' }
        $testUri = [Uri]$env:TEST_DATABASE_URL
        if ($testUri.AbsolutePath -ne '/cyberguard_test') { throw 'Tests require the isolated cyberguard_test database' }
        $savedDatabase = $env:DATABASE_URL
        try {
            $env:DATABASE_URL = $env:TEST_DATABASE_URL
            go run ./cmd/cyberguardctl migrate
            if ($LASTEXITCODE -ne 0) { throw 'Test migrations failed' }
        } finally { $env:DATABASE_URL = $savedDatabase }
        go test -count=1 ./...
    }
}
if ($LASTEXITCODE -ne 0) { throw 'Backend command failed' }
