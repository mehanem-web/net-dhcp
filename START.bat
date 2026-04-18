@echo off
setlocal

:: Self-elevate if not admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/d /c \"%~f0\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: Check Node
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Node.js not found. Download from https://nodejs.org
    pause
    exit /b 1
)

:: Install deps if needed
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
    if %errorlevel% neq 0 (
        echo npm install failed.
        pause
        exit /b 1
    )
)

:: Launch Electron
set "ELECTRON=%~dp0node_modules\electron\dist\electron.exe"
set "APPDIR=%~dp0"

if not exist "%ELECTRON%" (
    echo electron.exe not found at: %ELECTRON%
    pause
    exit /b 1
)

powershell -NoProfile -WindowStyle Hidden -Command "Start-Process '%ELECTRON%' -ArgumentList '%APPDIR%' -WindowStyle Normal"

endlocal
