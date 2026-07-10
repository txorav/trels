#!/bin/bash

echo "Building Trels for Linux/macOS..."

mkdir -p bin
cd ../backend

# Build for current OS
go build -ldflags "-s -w" -o ../build/bin/trels main.go

if [ $? -eq 0 ]; then
    echo "Build successful! The executable is located at build/bin/trels"
    echo "Remember to run it with 'sudo' privileges!"
else
    echo "Build failed! Please ensure you have Go installed."
fi

cd ../build
