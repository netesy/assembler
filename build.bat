@echo off
REM Build script for Windows
echo Building assembler project...

REM Check if g++ is available
where g++ >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: g++ compiler not found. Please install MinGW-w64 or similar.
    echo You can download it from: https://www.mingw-w64.org/
    pause
    exit /b 1
)

REM Create build directory if it doesn't exist
if not exist "build" mkdir build

REM Clean previous build
if exist "build\assembler.exe" del "build\assembler.exe"
if exist "build\test_assembler.exe" del "build\test_assembler.exe"

REM Compile the main assembler executable
echo Compiling main assembler...
g++ -std=c++17 -Wall -Wextra -O2 -o build\assembler.exe main.cpp assembler.cpp elf.cpp pe.cpp
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile main assembler
    pause
    exit /b 1
)

REM Compile the test executable
echo Compiling test assembler...
g++ -std=c++17 -Wall -Wextra -O2 -o build\test_assembler.exe test_assembler.cpp assembler.cpp elf.cpp pe.cpp
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile test assembler
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
echo Executables created:
echo   - build\assembler.exe (main assembler)
echo   - build\test_assembler.exe (test program)
echo.
echo To run the test: build\test_assembler.exe
echo To run the assembler: build\assembler.exe
echo.
pause