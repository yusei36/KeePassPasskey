REM SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
REM SPDX-License-Identifier: GPL-3.0-or-later
@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must run as Administrator.
    pause
    exit /b 1
)

set "LOG=%~dp0install_user.log"
if "%1"=="logged" goto :main
call "%~f0" logged >> "%LOG%" 2>&1
exit /b

:main
echo Install started at %DATE% %TIME%
for %%f in ("%~dp0*.cer")  do set "CER=%%f"
for %%f in ("%~dp0*.msix") do set "MSIX=%%f"

for /f "tokens=1" %%u in ('query user ^| findstr "^>"') do set "ACTUAL_USER=%%u"
set "ACTUAL_USER=%ACTUAL_USER:>=%"
echo Found active user: %ACTUAL_USER%

echo Installing certificate...
certutil -addstore "TrustedPeople" "%CER%"

echo Stopping existing KeePassPasskeyProvider process...
PowerShell -ExecutionPolicy Bypass -Command "Stop-Process -Name KeePassPasskeyProvider -Force -ErrorAction SilentlyContinue"

echo Writing user install script...
set "PS1=%~dp0install_user.ps1"

(
    echo $log = '%~dp0install_user.log'
    echo "Installing MSIX package..." ^| Tee-Object -FilePath $log -Append
    echo Add-AppxPackage -Path '%MSIX%' 2^>^&1 ^| Tee-Object -FilePath $log -Append
    echo "Starting KeePassPasskeyProvider..." ^| Tee-Object -FilePath $log -Append
    echo Start-Process KeePassPasskeyProvider.exe
    echo "Done." ^| Tee-Object -FilePath $log -Append
    echo Remove-Item $PSCommandPath
    echo Start-Sleep -Seconds 10
) > "%PS1%"

echo Creating and running scheduled task...
PowerShell -ExecutionPolicy Bypass -Command "Register-ScheduledTask -TaskName 'InstallKeePassPasskeyMSIX' -Action (New-ScheduledTaskAction -Execute 'PowerShell' -Argument '-ExecutionPolicy Bypass -File \"%PS1%\"') -Principal (New-ScheduledTaskPrincipal -UserId '%ACTUAL_USER%') -Force | Out-Null; Start-ScheduledTask -TaskName 'InstallKeePassPasskeyMSIX'"