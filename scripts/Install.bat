@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must run as Administrator.
    pause
    exit /b 1
)

for %%f in ("%~dp0*.cer")  do set "CER=%%f"
for %%f in ("%~dp0*.msix") do set "MSIX=%%f"

echo Installing certificate...
certutil -addstore "TrustedPeople" "%CER%"

echo Stopping existing KeePassPasskeyProvider process...
PowerShell -ExecutionPolicy Bypass -Command "Stop-Process -Name KeePassPasskeyProvider -Force -ErrorAction SilentlyContinue"

echo Installing MSIX package...
PowerShell -ExecutionPolicy Bypass -Command "Start-Process PowerShell -Verb RunAsCurrentUser -Wait -WindowStyle Hidden -ArgumentList '-ExecutionPolicy Bypass -Command \"Add-AppxPackage ''''%MSIX%''''\"'"

echo Starting KeePassPasskeyProvider...
PowerShell -ExecutionPolicy Bypass -Command "Start-Process KeePassPasskeyProvider.exe -Verb RunAsCurrentUser"

echo Done.
timeout /t 5