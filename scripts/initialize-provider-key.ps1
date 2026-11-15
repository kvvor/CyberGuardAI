Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot) -ErrorAction Stop
$ErrorActionPreference='Stop'
if (-not (Test-Path -LiteralPath '.env.local')) { throw 'Configure the local database first' }
if (Select-String -LiteralPath '.env.local' -Pattern '^PROVIDER_MASTER_KEY=.+$' -Quiet) { Write-Host 'Provider encryption key already configured'; exit 0 }
$providerBytes=New-Object byte[] 32
$providerRng=[Security.Cryptography.RandomNumberGenerator]::Create()
try { $providerRng.GetBytes($providerBytes) } finally { $providerRng.Dispose() }
$keyLine = "PROVIDER_MASTER_KEY="+[Convert]::ToBase64String($providerBytes)
$configText = [IO.File]::ReadAllText((Join-Path (Get-Location) '.env.local'))
if ($configText -match '(?m)^PROVIDER_MASTER_KEY=\s*$') {
    $configText = [regex]::Replace($configText, '(?m)^PROVIDER_MASTER_KEY=[ \t]*\r?$', $keyLine)
} else { $configText = $configText.TrimEnd()+[Environment]::NewLine+$keyLine+[Environment]::NewLine }
[IO.File]::WriteAllText((Join-Path (Get-Location) '.env.local'), $configText)
Write-Host 'Provider encryption key saved to ignored .env.local. Back up this file securely; changing the key makes existing provider credentials unreadable.'
