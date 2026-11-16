@echo off
rem Double-click to start CyberGuard AI (PostgreSQL service, backend, frontend, browser).
rem Runs scripts\start.ps1; the execution-policy bypass applies to this one run only.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start.ps1" %*
echo.
pause
