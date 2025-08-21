#!/bin/bash

# Build script for Unix/Linux/macOS
echo "Building assembler project..."

# Check if g++ is available
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ compiler not found. Please install it:"
    echo "  Ubuntu/Debian: sudo apt install g++"
    echo "  CentOS/RHEL: sudo yum install gcc-c++"
    echo "  macOS: xcode-select --install"
    exit 1
fi

# Create bin directory if it doesn't exist
mkdir -p bin

# Clean previous build
rm -f bin/assembler bin/test_assembler

# Compile the main assembler executable
echo "Compiling main assembler..."
g++ -std=c++17 -Wall -Wextra -O2 -o bin/assembler main.cpp assembler.cpp elf.cpp pe.cpp
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile main assembler"
    exit 1
fi

# Compile the test executable
echo "Compiling test assembler..."
g++ -std=c++17 -Wall -Wextra -O2 -o bin/test_assembler test_assembler.cpp assembler.cpp elf.cpp pe.cpp
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile test assembler"
    exit 1
fi

# Make executables executable (in case umask is restrictive)
chmod +x bin/assembler bin/test_assembler

echo ""
echo "Build completed successfully!"
echo "Executables created:"
echo "  - bin/assembler (main assembler)"
echo "  - bin/test_assembler (test program)"
echo ""
echo "To run the test: ./bin/test_assembler"
echo "To run the assembler: ./bin/assembler"
echo ""