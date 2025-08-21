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

REM Create bin directory if it doesn't exist
if not exist "bin" mkdir bin

REM Clean previous build
if exist "bin\assembler.exe" del "bin\assembler.exe"
if exist "bin\test_assembler.exe" del "bin\test_assembler.exe"

REM Compile the main assembler executable
echo Compiling main assembler...
g++ -std=c++17 -Wall -Wextra -O2 -o bin\assembler.exe main.cpp assembler.cpp elf.cpp pe.cpp parser.cpp translator.cpp
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile main assembler
    pause
    exit /b 1
)

REM Compile the test executable
echo Compiling test assembler...
g++ -std=c++17 -Wall -Wextra -O2 -o bin\test_assembler.exe test_assembler.cpp assembler.cpp elf.cpp pe.cpp parser.cpp translator.cpp
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile test assembler
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
echo Executables created:
echo   - bin\assembler.exe (main assembler)
echo   - bin\test_assembler.exe (test program)
echo.
echo To run the test: bin\test_assembler.exe
echo To run the assembler: bin\assembler.exe
echo.

echo Running end-to-end test...

echo Assembling test.asm into an ELF executable...
bin\assembler.exe test.asm --format elf -o bin\test.elf
if %ERRORLEVEL% NEQ 0 (
    echo Failed to assemble test.asm to ELF.
    pause
    exit /b 1
)
echo Successfully created bin\test.elf
echo.

echo Assembling test.asm into a PE executable...
bin\assembler.exe test.asm --format pe -o bin\test.exe
if %ERRORLEVEL% NEQ 0 (
    echo Failed to assemble test.asm to PE.
    pause
    exit /b 1
)
echo Successfully created bin\test.exe
echo.

echo Running generated PE executable bin\test.exe...
bin\test.exe
if %ERRORLEVEL% NEQ 0 (
    echo Generated PE executable failed to run or returned an error.

    pause
    exit /b 1
)

echo.
echo End-to-end test completed successfully!
echo.
pause