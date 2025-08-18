# Build Instructions

This document explains how to build the assembler project on different platforms.

## Prerequisites

### Windows
- MinGW-w64 or similar GCC compiler
- CMake (optional, for CMake builds)

### Linux/Unix/macOS
- GCC compiler (g++)
- CMake (optional, for CMake builds)

## Build Methods

### Method 1: Direct Compilation (Recommended)

#### Windows
```batch
# Run the build script
build.bat
```

#### Linux/Unix/macOS
```bash
# Make the script executable (if not already)
chmod +x build.sh

# Run the build script
./build.sh
```

### Method 2: CMake Build

#### Windows
```batch
# Run the CMake build script
build_cmake.bat
```

#### Linux/Unix/macOS
```bash
# Make the script executable (if not already)
chmod +x build_cmake.sh

# Run the CMake build script
./build_cmake.sh
```

### Method 3: Manual Compilation

If you prefer to compile manually:

```bash
# Create build directory
mkdir -p build

# Compile main assembler
g++ -std=c++17 -Wall -Wextra -O2 -o build/assembler main.cpp assembler.cpp elf.cpp pe.cpp

# Compile test program
g++ -std=c++17 -Wall -Wextra -O2 -o build/test_assembler test_assembler.cpp assembler.cpp elf.cpp pe.cpp
```

## Output

After successful compilation, you'll find the following executables in the `build/` directory:

- **assembler** (or **assembler.exe** on Windows): Main assembler program
- **test_assembler** (or **test_assembler.exe** on Windows): Test program

## Running the Programs

### Test the assembler
```bash
# Windows
build\test_assembler.exe

# Linux/Unix/macOS
./build/test_assembler
```

### Run the main assembler
```bash
# Windows
build\assembler.exe

# Linux/Unix/macOS
./build/assembler
```

## Troubleshooting

### Common Issues

1. **Compiler not found**
   - Windows: Install MinGW-w64 from https://www.mingw-w64.org/
   - Ubuntu/Debian: `sudo apt install g++`
   - CentOS/RHEL: `sudo yum install gcc-c++`
   - macOS: `xcode-select --install`

2. **CMake not found**
   - Windows: Download from https://cmake.org/
   - Ubuntu/Debian: `sudo apt install cmake`
   - CentOS/RHEL: `sudo yum install cmake`
   - macOS: `brew install cmake`

3. **Permission denied (Linux/macOS)**
   ```bash
   chmod +x build.sh
   chmod +x build_cmake.sh
   ```

### Compiler Warnings

The build may produce some warnings about unused variables or parameters. These are non-critical and don't affect functionality. The warnings are from:
- Unused parameters in function signatures
- Unused variables in some code paths
- Missing switch cases for enum values

These warnings can be safely ignored as they don't affect the core assembler functionality.

## Build Configuration

The build scripts use the following compiler flags:
- `-std=c++17`: Use C++17 standard
- `-Wall -Wextra`: Enable additional warnings
- `-O2`: Optimization level 2 for release builds

For debug builds, you can modify the scripts to use `-g -O0` instead of `-O2`.