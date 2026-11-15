$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'backend.ps1') -Mode start
