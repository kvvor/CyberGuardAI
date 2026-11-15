$ErrorActionPreference = 'Stop'
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw 'Node.js is not installed or not on PATH. Install Node.js and open a new PowerShell window.' }
$frontend = Join-Path (Split-Path -Parent $PSScriptRoot) 'frontend'
if (-not (Test-Path -LiteralPath (Join-Path $frontend 'node_modules'))) { throw 'Frontend dependencies are not installed. Run scripts\setup.ps1 first.' }
Push-Location -LiteralPath $frontend
try {
    Write-Host 'Starting CyberGuard AI frontend on http://localhost:3000 (use exactly this address). Press Ctrl+C to stop.'
    # npm.cmd avoids the npm.ps1 shim that PowerShell execution policy can block.
    & npm.cmd run dev
    if ($LASTEXITCODE -ne 0) { throw 'Frontend stopped with an error. If port 3000 is in use, close the other program and retry.' }
} finally { Pop-Location }
