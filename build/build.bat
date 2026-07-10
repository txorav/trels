@echo off
setlocal

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

echo [INFO] Step 5: Compiling Go binary...
echo [INFO] Executing: go build -ldflags "-s -w" -v -o ..\build\bin\trels.exe main.go
go build -ldflags "-s -w" -v -o ..\build\bin\trels.exe main.go

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
