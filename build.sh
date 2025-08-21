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
rm -f bin/assembler bin/test_assembler bin/test.elf bin/test.exe

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
echo "To run the assembler: ./bin/assembler"
echo ""

echo "Running end-to-end test..."

echo "Assembling test.asm into an ELF executable..."
./bin/assembler test.asm --format elf -o ./bin/test.elf
if [ $? -ne 0 ]; then
    echo "Failed to assemble test.asm to ELF."
    exit 1
fi
chmod +x ./bin/test.elf
echo "Successfully created bin/test.elf"
echo ""

echo "Running generated ELF executable ./bin/test.elf..."
./bin/test.elf
RETURN_CODE=$?
if [ $RETURN_CODE -ne 22 ]; then
    echo "Generated ELF executable failed to run or returned an error. Expected 22, got $RETURN_CODE"
    exit 1
fi
echo "ELF executable ran successfully and returned 22."
echo ""


echo "Assembling test.asm into a PE executable..."
./bin/assembler test.asm --format pe -o ./bin/test.exe
if [ $? -ne 0 ]; then
    echo "Failed to assemble test.asm to PE."
    exit 1
fi
echo "Successfully created bin/test.exe"
echo ""

if command -v wine &> /dev/null; then
    echo "Running generated PE executable bin/test.exe with Wine..."
    wine ./bin/test.exe
    RETURN_CODE=$?
    if [ $RETURN_CODE -ne 22 ]; then
        echo "Generated PE executable failed to run or returned an error. Expected 22, got $RETURN_CODE"
        exit 1
    fi
    echo "PE executable ran successfully under Wine and returned 22."
    echo ""
else
    echo "Wine not found, skipping execution test for PE executable."
    echo ""
fi


echo "End-to-end test completed successfully!"
echo ""