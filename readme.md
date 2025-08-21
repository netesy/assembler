# x86-64 Assembler and Executable Generator

## Description

This project is a functional, albeit simplified, toolchain for assembling and linking x86-64 assembly code into a runnable 64-bit executable for both **Linux (ELF)** and **Windows (PE)**. It was developed by incrementally refactoring a non-functional assembler into a working tool.

The core components are:
- **A two-pass Assembler:** Parses a subset of x86-64 assembly syntax and generates the corresponding machine code. It can translate Linux syscalls to Windows API calls when targeting the PE format.
- **ELF and PE Generators:** Takes the machine code and symbol information from the assembler and packages it into a valid, static executable for the target platform.

## Features

- **Architecture:** x86-64 (64-bit)
- **Output Formats:**
    - Static ELF executable for Linux
    - Static PE executable for Windows
    - Relocatable object files (`.o`)
- **Assembly Process:** Two-pass assembly to correctly handle forward-referenced labels.
- **Addressing Modes:**
    - Register-to-register (`mov rax, rbx`)
    - Immediate-to-register (`mov rax, 123`)
    - RIP-relative memory addressing (`mov rax, [my_variable]`)
- **Control Flow:**
    - Unconditional jumps (`jmp`)
    - Conditional jumps (`je`, `jne`, `jl`, `jle`, `jg`, `jge`, `jz`, `jnz`)
    - Function calls (`call`, `ret`)
- **Stack Operations:** `push` and `pop` for 64-bit registers.
- **Atomic Operations:** `lock` prefix supported for valid read-modify-write instructions.

## Supported Instructions

The assembler currently supports the following x86-64 instructions:

- **Data Transfer:** `mov`
- **Arithmetic:** `add`, `sub`
- **Comparison:** `cmp`
- **Stack:** `push`, `pop`
- **Control Flow:** `jmp`, `call`, `ret`
- **Conditional Jumps:** `je`, `jne`, `jz`, `jnz`, `jl`, `jle`, `jg`, `jge`
- **System Calls:** `syscall` (translated to Windows API calls for PE format)

## Usage

1.  **Build the Assembler:**
    -   On Linux: `./build.sh`
    -   On Windows: `build.bat` or `build_cmake.bat`

2.  **To Generate Executables (Default):**
    By default, the assembler generates executables for both ELF and PE formats.
    ```sh
    # On Linux
    ./build/assembler <input_file.asm> -o <output_file>
    # On Windows
    build\assembler.exe <input_file.asm> -o <output_file>
    ```
    This will create `<output_file>.elf` and `<output_file>.exe`.

3.  **To Generate a Specific Format:**
    Use the `--format` flag to specify either `elf` or `pe`.
    ```sh
    # Generate only an ELF file
    ./build/assembler <input_file.asm> -o <output_file> --format elf

    # Generate only a PE file
    ./build/assembler <input_file.asm> -o <output_file> --format pe
    ```

4.  **To Generate a Relocatable Object File:**
    Use the `-c` flag to generate a standard `.o` file that can be linked with other object files.
    ```sh
    ./build/assembler -c <input_file.asm> -o <output_file>
    ```
    This will create a relocatable object file named `<output_file>.o`.

5.  **Linking with GCC:**
    You can link the generated object file with other object files or libraries using a standard linker like GCC.
    ```sh
    gcc -no-pie <output_file>.o -o <final_executable>
    ```

## Sample Assembly Program

The following sample program is included in `test.asm`. It performs simple arithmetic and uses the result as the program's exit code.

```asm
section .text
  global _start

_start:
  mov rax, 10      ; Start with 10
  mov rbx, 5       ; Load 5 into another register
  add rax, rbx     ; Add them, rax = 15
  add rax, 7       ; Add an immediate value, rax = 22
  mov rdi, rax     ; Move the result to rdi for the exit code
  mov rax, 60      ; syscall number for exit
  syscall
```
When targeting Windows, the assembler will automatically translate the `syscall` instruction into a call to the `ExitProcess` function from `kernel32.dll`.
