# x86-64 Assembler and Executable Generator

## Description

This project is a functional, albeit simplified, toolchain for assembling and linking x86-64 assembly code into a runnable 64-bit ELF executable for Linux. It was developed by incrementally refactoring a non-functional assembler into a working tool.

The core components are:
- **A two-pass Assembler:** Parses a subset of x86-64 assembly syntax and generates the corresponding machine code.
- **An ELF Generator:** Takes the machine code and symbol information from the assembler and packages it into a valid, static ELF executable.

## Features

- **Architecture:** x86-64 (64-bit)
- **Output Format:** Static ELF executable for Linux
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
- **System Calls:** `syscall`

## Usage

1.  **Build the Assembler:**
    ```sh
    ./build.sh
    ```
2.  **To Generate an Executable:**
    By default, the assembler generates a complete executable.
    ```sh
    ./build/assembler <input_file.asm> -o <output_file>
    ```
    This will create an executable file named `<output_file>.elf`.

3.  **To Generate a Relocatable Object File:**
    Use the `-c` flag to generate a standard `.o` file that can be linked with other object files.
    ```sh
    ./build/assembler -c <input_file.asm> -o <output_file>
    ```
    This will create a relocatable object file named `<output_file>.o`.

4.  **Linking with GCC:**
    You can link the generated object file with other object files or libraries using a standard linker like GCC.
    ```sh
    gcc -no-pie <output_file>.o -o <final_executable>
    ```

## Sample Assembly Program

The following program is included in `main.cpp` and demonstrates function calls, stack operations, conditional logic, and heap management.

```asm
.section .text
.global _start

; This function checks a value passed on the stack.
; It expects a value at [rsp+8].
; It returns 42 in rax if the value is 123, otherwise 99.
check_value:
    pop rcx         ; Pop return address
    pop rbx         ; Pop the argument (123)
    
    cmp rbx, 123
    je .success
    
.failure:
    mov rax, 99
    push rcx        ; Push return address back
    ret

.success:
    mov rax, 42
    push rcx        ; Push return address back
    ret

_start:
    ; First, let's test the brk syscall to get the heap address.
    ; The result will be in rax, but we won't use it further.
    mov rax, 12
    mov rdi, 0
    syscall

    ; Now, test stack, call, and conditional jumps.
    push 123
    call check_value
    
    ; The result from check_value is in rax.
    ; We will use it as the exit code.
    mov rdi, rax
    mov rax, 60
    syscall
```
