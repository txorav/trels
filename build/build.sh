#!/bin/bash

echo "==================================================="
echo "            Trels Build Script (Linux/macOS)       "
echo "==================================================="
echo ""

echo "[INFO] Step 1: Checking for Go compiler..."
if ! command -v go &> /dev/null; then
    echo "[ERROR] 'go' could not be found in your PATH."
    echo "[ERROR] Please ensure Go is installed and configured correctly."
    echo "[ERROR] Download from: https://go.dev/dl/"
    echo ""
    exit 1
fi
echo "[OK] Go compiler found."
echo ""

echo "[INFO] Step 2: Preparing output directory..."
if [ ! -d "bin" ]; then
    echo "[INFO] Creating 'build/bin/' directory..."
    mkdir -p bin
else
    echo "[OK] 'build/bin/' directory already exists."
fi
echo ""

echo "[INFO] Step 3: Navigating to backend source..."
cd ../backend
echo "[OK] Current directory: $(pwd)"
echo ""

echo "[INFO] Step 4: Resolving Go dependencies..."
go mod tidy
if [ $? -ne 0 ]; then
    echo "[WARNING] Dependency resolution encountered an issue, but compilation will proceed."
else
    echo "[OK] Dependencies resolved."
fi
echo ""

echo "[INFO] Step 5: Preparing frontend assets for embed..."
rm -rf admin_dist
cp -r ../frontend/admin admin_dist
echo "[OK] Assets copied to backend/admin_dist."
echo ""

echo "[INFO] Step 6: Compiling Go binary..."
echo "[INFO] Executing: go build -ldflags \"-s -w\" -v -o ../build/bin/trels main.go"
go build -ldflags "-s -w" -v -o ../build/bin/trels main.go

if [ $? -eq 0 ]; then
    echo ""
    echo "==================================================="
    echo "[SUCCESS] Build completed successfully!"
    echo "[SUCCESS] The executable is located at: build/bin/trels"
    echo "[SUCCESS] Remember to run the binary with 'sudo' privileges to enable hosts file sync!"
    echo "==================================================="
else
    echo ""
    echo "[ERROR] Compilation failed! See the error output above for details."
fi

cd ../build
echo ""
