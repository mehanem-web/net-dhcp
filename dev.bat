@echo off
cd /d "%~dp0"
echo.
echo  ==========================================
echo   NET//DHCP -- DEV MODE
echo   Broman Enterprises
echo  ==========================================
echo.
if not exist "node_modules" (
    echo [1/2] Installing dependencies...
    call npm install
    if errorlevel 1 ( echo  ERROR: npm install failed. & pause & exit /b 1 )
    echo  Done.
    echo.
    echo [2/2] Launching...
) else (
    echo [1/1] Launching...
)
echo.
npx electron . --dev
