# Project Updates and Changelog

This document outlines the major updates and refactoring efforts that transformed the project from a non-functional concept into a working x86-64 assembler and toolchain.

## Initial State

The project started with an assembler for a custom, non-standard Instruction Set Architecture (ISA). The associated ELF and PE generators were incomplete and contained numerous bugs, making it impossible to produce a valid or runnable executable. The core issue was that the machine code being generated was incompatible with any real-world CPU or operating system.

## Stage 1: Foundational Refactoring and x86-64 Assembler Rewrite

The first major effort was to fix the core architectural problem.
- **Target Architecture:** The assembler was completely rewritten to target the **x86-64** instruction set, abandoning the custom ISA.
- **Two-Pass Assembly:** A proper two-pass assembly process was implemented to handle forward-referencing of labels.
- **ELF Generator Fix:** The ELF generator was heavily refactored to produce a simple, valid, static 64-bit ELF executable. All incorrect logic related to dynamic linking was removed, and section/program header generation was fixed.
- **Build System:** The `CMakeLists.txt` was modularized, creating static libraries for each component (assembler, ELF generator, PE generator).
- **Result:** The toolchain became capable of assembling and linking a simple "Hello, World!" program that could be run on a Linux system.

## Stage 2: Core Feature Expansion

With a working baseline, the assembler's capabilities were significantly expanded.
- **Function Calls:** Support for `CALL` and `RET` was added, including the calculation of 32-bit relative displacements.
- **Conditional Jumps:** Support for `CMP` and a suite of conditional jump instructions (`JE`, `JNE`, etc.) was implemented, enabling basic control flow.
- **Stack Operations:** Support for `PUSH` and `POP` with 64-bit registers was added to allow for function arguments and saving register state.

## Stage 3: Advanced Features and Finalization

The final stage of development focused on features required for more realistic applications.
- **Memory Addressing:** The assembler's parser and encoder were overhauled to support **RIP-relative memory addressing**. This allows instructions to read from and write to variables in memory (e.g., `mov rax, [my_variable]`).
- **Atomic Operations:** Support for the `LOCK` prefix was added, enabling atomic read-modify-write operations on memory (e.g., `lock add [counter], 1`). The assembler validates its use against the list of legally lockable instructions.
- **Heap Management:** Support for the `brk` syscall was researched and verified, allowing programs to perform basic heap memory allocation.

## Final Status

The project is now a working, if simplified, assembler and toolchain for a useful subset of the x86-64 instruction set. It can produce runnable Linux ELF executables from assembly source that includes function calls, conditional logic, stack operations, memory access, and atomic operations.
