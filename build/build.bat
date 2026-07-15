@echo off
setlocal

rem Ensure we start in the directory where the batch file is located
cd /d "%~dp0"

echo ===================================================
echo             Trels Build Script (Windows)           
echo ===================================================
echo.

echo [INFO] Step 1: Checking for Go compiler...
where go >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] 'go' is not recognized as an internal or external command.
    echo [ERROR] Please ensure Go is installed and added to your system PATH.
    echo [ERROR] Download from: https://go.dev/dl/
    echo.
    pause
    exit /b 1
)
echo [OK] Go compiler found.
echo.

echo [INFO] Step 2: Preparing output directory...
if not exist "bin" (
    echo [INFO] Creating 'build\bin\' directory...
    mkdir bin
) else (
    echo [OK] 'build\bin\' directory already exists.
)
echo.

echo [INFO] Step 3: Navigating to backend source...
cd ..\backend
echo [OK] Current directory: %CD%
echo.

echo [INFO] Step 4: Resolving Go dependencies...
go mod tidy
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Dependency resolution encountered an issue, but compilation will proceed.
) else (
    echo [OK] Dependencies resolved.
)
echo.

echo [INFO] Step 5: Preparing frontend assets for embed...
xcopy /E /I /Y ..\frontend\admin admin_dist >nul
echo [OK] Assets copied to backend\admin_dist.
echo.

echo [INFO] Step 5.5: Embedding App Icon...
go install github.com/akavel/rsrc@latest >nul 2>nul
for /f %%i in ('go env GOPATH') do set GOPATH=%%i
if exist "%GOPATH%\bin\rsrc.exe" (
    "%GOPATH%\bin\rsrc.exe" -manifest trels.manifest -ico ..\trels.ico -o rsrc_windows_amd64.syso >nul 2>nul
    echo [OK] App icon and Admin manifest embedded.
) else (
    echo [WARNING] Could not install rsrc. Icon and manifest will not be embedded.
)
echo.

echo [INFO] Step 6: Compiling Go binary...
echo [INFO] Executing: go build -ldflags "-s -w -H=windowsgui" -v -o ..\build\bin\trels.exe .
go build -ldflags "-s -w -H=windowsgui" -v -o ..\build\bin\trels.exe .

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===================================================
    echo [SUCCESS] Build completed successfully!
    echo [SUCCESS] The executable is located at: build\bin\trels.exe
    echo [SUCCESS] Remember to run the binary as Administrator to enable hosts file sync!
    echo ===================================================
) else (
    echo.
    echo [ERROR] Compilation failed! See the error output above for details.
)

cd ..\build
echo.
pause
endlocal
