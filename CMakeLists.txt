cmake_minimum_required(VERSION 3.16)

project(assembler LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create a static library for the assembler
add_library(assembler_lib STATIC assembler.cpp assembler.hh)

# Create a static library for ELF generation
add_library(elf_lib STATIC elf.cpp elf.hh)

# Create a static library for PE generation
add_library(pe_lib STATIC pe.cpp pe.hh)

# Add the main executable
add_executable(assembler main.cpp)

# Link the libraries to the executable
target_link_libraries(assembler PRIVATE assembler_lib elf_lib pe_lib)

include(GNUInstallDirs)
install(TARGETS assembler
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
