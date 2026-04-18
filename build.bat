@echo off
cd /d "%~dp0"

echo.
echo  ================================================
echo   NET//DHCP — BUILD (NSIS + PORTABLE)
echo  ================================================
echo.

echo [1/2] Installing modules...
call npm install > build.log 2>&1
if errorlevel 1 (
    echo  ERROR: npm install failed. Check build.log for details.
    type build.log
    exit /b 1
)
echo  Done.
echo.

echo [2/2] Building NSIS installer + portable .exe...
set CSC_IDENTITY_AUTO_DISCOVERY=false
call npx electron-builder --win nsis portable >> build.log 2>&1
if errorlevel 1 (
    echo  ERROR: Build failed. Check build.log for details.
    echo.
    type build.log
    echo.
    exit /b 1
)
echo  Done.
echo.

if exist "dist" (
    echo  Opening dist folder...
    start "" "%~dp0dist"
) else (
    echo  WARNING: dist folder not found after build.
    type build.log
    exit /b 1
)
exit /b 0
