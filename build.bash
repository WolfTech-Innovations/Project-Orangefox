#!/bin/bash

echo "================================"
echo "Core Wrapper Setup"
echo "================================"
echo ""
echo "This script assumes binaries are already built:"
echo "  - WolfEther/wolfether"
echo "  - ATR-NET/atr-net"
echo "  - Digitz/output/digitz"
echo ""
read -p "Do you want to build them first? (y/N): " build_choice

if [[ "$build_choice" =~ ^[Yy]$ ]]; then
    echo "Building programs..."
    
    # Build WolfEther
    cd WolfEther
    go mod tidy
    go build -o wolfether cmd/node/main.go
    cd ..
    
    # Build ATR-NET
    cd ATR-NET
    go build -o atr-net src/main.go
    cd ..
    
    # Build Digitz
    cd Digitz
    make
    cd ..
    
    echo "✓ Programs built"
else
    echo "Using pre-built binaries..."
fi

# Setup core wrapper
mkdir -p core-wrapper/embedded

# Copy binaries to wrapper
echo "Copying binaries..."
cp WolfEther/wolfether core-wrapper/embedded/
cp ATR-NET/atr-net core-wrapper/embedded/
cp Digitz/output/digitz core-wrapper/embedded/

# Build the core wrapper
cd core-wrapper

# Initialize module if needed
if [ ! -f "go.mod" ]; then
    go mod init core-wrapper
fi

# Get dependencies
go get github.com/rivo/tview@latest
go get github.com/gdamore/tcell/v2@latest
go mod tidy

# Build wrapper
echo "Building core wrapper..."
go build -o core

cd ..

echo ""
echo "================================"
echo "✓ Core wrapper ready at: ./core-wrapper/core"
echo ""
echo "Run with: ./core-wrapper/core"
echo "================================"
