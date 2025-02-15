cmake_minimum_required(VERSION 3.16)

project(assember LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(assember main.cpp
    assembler.hh assembler.cpp)

include(GNUInstallDirs)
install(TARGETS assember
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
