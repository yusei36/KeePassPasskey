@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must run as Administrator.
    pause
    exit /b 1
)

for %%f in ("%~dp0*.cer")  do set "CER=%%f"
for %%f in ("%~dp0*.msix") do set "MSIX=%%f"

certutil -addstore "TrustedPeople" "%CER%"
PowerShell -ExecutionPolicy Bypass -Command "Stop-Process -Name KeePassPasskeyProvider -Force -ErrorAction SilentlyContinue"
PowerShell -ExecutionPolicy Bypass -Command "Add-AppxPackage '%MSIX%'"
start "" KeePassPasskeyProvider.exe
