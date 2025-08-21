#!/bin/bash

# CMake build script for Unix/Linux/macOS
echo "Building assembler project with CMake..."

# Check if cmake is available
if ! command -v cmake &> /dev/null; then
    echo "Error: CMake not found. Please install it:"
    echo "  Ubuntu/Debian: sudo apt install cmake"
    echo "  CentOS/RHEL: sudo yum install cmake"
    echo "  macOS: brew install cmake"
    exit 1
fi

# Create directories
mkdir -p build
mkdir -p bin

# Configure the project
echo "Configuring project..."
cd build
cmake ..
if [ $? -ne 0 ]; then
    echo "Error: CMake configuration failed"
    cd ..
    exit 1
fi

# Build the project
echo "Building project..."
cmake --build .
if [ $? -ne 0 ]; then
    echo "Error: Build failed"
    cd ..
    exit 1
fi

cd ..

echo ""
echo "CMake build completed successfully!"
echo "Executable created: bin/assembler"
echo ""