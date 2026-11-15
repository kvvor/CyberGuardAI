Set-Location -LiteralPath "D:\AI\CyberGuardAI-backend" -ErrorAction Stop
$ErrorActionPreference='Stop'
if (-not (Test-Path -LiteralPath '.env.local')) { throw 'Configure the local database first' }
if (Select-String -LiteralPath '.env.local' -Pattern '^PROVIDER_MASTER_KEY=.+$' -Quiet) { Write-Host 'Provider encryption key already configured'; exit 0 }
$providerBytes=New-Object byte[] 32
$providerRng=[Security.Cryptography.RandomNumberGenerator]::Create()
try { $providerRng.GetBytes($providerBytes) } finally { $providerRng.Dispose() }
Add-Content -LiteralPath '.env.local' -Value ("PROVIDER_MASTER_KEY="+[Convert]::ToBase64String($providerBytes))
Write-Host 'Provider encryption key saved to ignored .env.local. Back up this file securely; changing the key makes existing provider credentials unreadable.'
