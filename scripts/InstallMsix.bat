REM SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
REM SPDX-License-Identifier: GPL-3.0-or-later
@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    PowerShell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "LOG=%~dp0install_user.log"
if "%1"=="logged" goto :main
call "%~f0" logged >> "%LOG%" 2>&1
exit /b

:main
echo Install started at %DATE% %TIME%
for %%f in ("%~dp0*.cer")  do set "CER=%%f"
for %%f in ("%~dp0*.msix") do set "MSIX=%%f"

for /f "usebackq delims=" %%u in (`PowerShell -ExecutionPolicy Bypass -Command "$user = (Get-CimInstance Win32_ComputerSystem).UserName; if (-not $user) { $user = \"$env:USERDOMAIN\$env:USERNAME\" }; Write-Output $user"`) do set "ACTUAL_USER=%%u"
echo Found active user: %ACTUAL_USER%

echo Installing certificate...
certutil -addstore "TrustedPeople" "%CER%"

echo Stopping existing KeePassPasskeyProvider process...
PowerShell -ExecutionPolicy Bypass -Command "Stop-Process -Name KeePassPasskeyProvider -Force -ErrorAction SilentlyContinue"

echo Writing user install script...
set "PS1=%~dp0install_user.ps1"

(
    echo $log = '%~dp0install_user.log'
    echo function Log { process { Write-Host $_; $_ ^| Out-File -FilePath $log -Append -Encoding ASCII } }
    echo function LogError { process { Write-Host $_ -ForegroundColor Red; $_ ^| Out-File -FilePath $log -Append -Encoding ASCII } }
    echo "Installing MSIX package..." ^| Log
    echo try {
    echo     Add-AppxPackage -Path '%MSIX%' -ErrorAction Stop 2^>^&1 ^| Log
    echo } catch {
    echo     "ERROR: Install failed: $_" ^| LogError
    echo     Read-Host "Press Enter to exit"
    echo     exit 1
    echo }
    echo "Starting KeePassPasskeyProvider..." ^| Log
    echo Start-Process KeePassPasskeyProvider.exe
    echo "Done." ^| Log
    echo Remove-Item $PSCommandPath
    echo Start-Sleep -Seconds 10
) > "%PS1%"

echo Creating and running scheduled task...
PowerShell -ExecutionPolicy Bypass -Command "$action = New-ScheduledTaskAction -Execute 'PowerShell' -Argument '-ExecutionPolicy Bypass -File \"%PS1%\"'; $principal = New-ScheduledTaskPrincipal -UserId '%ACTUAL_USER%'; try { Register-ScheduledTask -TaskName 'InstallKeePassPasskeyMSIX' -Action $action -Principal $principal -Force | Out-Null; Start-ScheduledTask -TaskName 'InstallKeePassPasskeyMSIX' } catch { Write-Host \"ERROR: Could not create scheduled task for user %ACTUAL_USER%: $_\" -ForegroundColor Red; exit 1 }"