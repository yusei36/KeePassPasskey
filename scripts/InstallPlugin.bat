@echo off
rem Elevated half of installing the KeePass plugin: cmd.exe /c "InstallPlugin.bat <install|remove> <pluginsFolder>"
rem Exists because Windows cannot run a packaged executable elevated; see PluginInstallLauncher.
rem Exit codes match PluginInstallResult: 0 ok, 2 access denied, 3 source missing, 4 target invalid.
setlocal

set "ACTION=%~1"
set "TARGET=%~2"
set "SRC=%~dp0..\KeePassPasskeyPlugin\KeePassPasskey.dll"
set "DST=%TARGET%\KeePassPasskey.dll"

if not defined TARGET exit /b 4

rem Elevated, so the target is re-derived rather than trusted: cut the path at its \Plugins\ segment
rem and the remainder must hold KeePass.exe. '|' is safe as the marker, paths cannot contain it.
if exist "%TARGET%\KeePass.exe" goto validated
set "ROOT=%TARGET%\"
set "ROOT=%ROOT:\Plugins\=|%"
for /f "tokens=1 delims=|" %%I in ("%ROOT%") do set "ROOT=%%I"
if not exist "%ROOT%\KeePass.exe" exit /b 4
:validated

if /i "%ACTION%"=="remove" goto remove
if /i not "%ACTION%"=="install" exit /b 4

if not exist "%SRC%" exit /b 3

if not exist "%TARGET%\" mkdir "%TARGET%"
if not exist "%TARGET%\" exit /b 4

if exist "%DST%.old" del /f /q "%DST%.old" >nul 2>nul

rem A loaded DLL cannot be deleted but can be renamed, so move it aside and write over the name.
if exist "%DST%" (
	move /y "%DST%" "%DST%.old" >nul
	if errorlevel 1 exit /b 2
)

copy /y "%SRC%" "%DST%" >nul
if errorlevel 1 exit /b 2

rem Only chance to drop the backup; it survives just while a running KeePass still maps it.
if exist "%DST%.old" del /f /q "%DST%.old" >nul 2>nul
exit /b 0

:remove
if exist "%DST%" (
	del /f /q "%DST%" >nul 2>nul
	if exist "%DST%" (
		move /y "%DST%" "%DST%.old" >nul
		if errorlevel 1 exit /b 2
	)
)
if exist "%DST%.old" del /f /q "%DST%.old" >nul 2>nul
exit /b 0
