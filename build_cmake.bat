@echo off
REM CMake build script for Windows
echo Building assembler project with CMake...

REM Check if cmake is available
where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: CMake not found. Please install CMake from https://cmake.org/
    pause
    exit /b 1
)

REM Create build directory if it doesn't exist
if not exist "build" mkdir build

REM Configure the project
echo Configuring project...
cd build
cmake .. -G "MinGW Makefiles"
if %ERRORLEVEL% NEQ 0 (
    echo Error: CMake configuration failed
    cd ..
    pause
    exit /b 1
)

REM Build the project
echo Building project...
cmake --build .
if %ERRORLEVEL% NEQ 0 (
    echo Error: Build failed
    cd ..
    pause
    exit /b 1
)

cd ..

echo.
echo CMake build completed successfully!
echo Executable created: build\assembler.exe
echo.
pause