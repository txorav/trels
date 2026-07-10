@echo off
echo Building Trels for Windows...

if not exist "bin" (
    mkdir bin
)

cd ..\backend
go build -ldflags "-s -w" -o ..\build\bin\trels.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo Build successful! The executable is located at build\bin\trels.exe
    echo Remember to run it as Administrator!
) else (
    echo Build failed! Please ensure you have Go installed.
)
cd ..\build
pause
