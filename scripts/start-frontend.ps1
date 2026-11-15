$ErrorActionPreference = 'Stop'
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw 'Install Node.js and reopen PowerShell.' }
Push-Location -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'frontend')
try {
    & npm.cmd run dev
    if ($LASTEXITCODE -ne 0) { throw 'Frontend startup failed. Run setup.ps1 first.' }
} finally { Pop-Location }
