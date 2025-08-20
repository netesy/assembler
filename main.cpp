#include "assembler.hh"
#include "elf.hh"
#include <filesystem>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    std::string asmCode = R"(
; Example demonstrating enhanced assembler features

%define EXIT_SUCCESS 0
%define EXIT_FAILURE 1
%define SYSCALL_EXIT 60
%define SYSCALL_WRITE 1

; Macro for system call wrapper
%macro SYSCALL 1
    mov rax, %1
    syscall
%endmacro

; Macro to push all general purpose registers
%macro PUSH_ALL 0
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
%endmacro

; Macro to pop all general purpose registers
%macro POP_ALL 0
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

.section .rodata
    pi_value: .dword 0x40490fdb    ; Single precision PI (3.14159...)
    message: .asciz "Hello from enhanced assembler!\n"
    message_len = 32

.section .data
    counter: .quad 0
    float_result: .dword 0
    test_bytes: .byte 0x41, 0x42, 0x43, 0x44
    test_words: .word 0x1234, 0x5678
    buffer: .space 64

.section .bss
    temp_storage: .space 1024

.section .text
.global _start
.global add_floats
.global test_sizes

; Function to test different operand sizes
test_sizes:
    ; Test 8-bit operations
    mov al, 0x42
    mov bl, 0x24
    add al, bl          ; 8-bit addition

    ; Test 16-bit operations
    mov ax, 0x1234
    mov bx, 0x5678
    add ax, bx          ; 16-bit addition

    ; Test 32-bit operations
    mov eax, 0x12345678
    mov ebx, 0x87654321
    add eax, ebx        ; 32-bit addition (zeros upper 32 bits)

    ; Test explicit sizing with memory
    mov byte ptr [buffer], al
    mov word ptr [buffer+1], ax
    mov dword ptr [buffer+3], eax
    mov qword ptr [buffer+7], rax

    ret

; Function to demonstrate SSE floating-point operations
add_floats:
    ; Load PI value into XMM register
    movss xmm0, [pi_value]

    ; Create another float value in XMM1 (2.0)
    mov eax, 0x40000000     ; 2.0 in IEEE 754 single precision
    mov dword ptr [float_result], eax
    movss xmm1, [float_result]

    ; Add the floats: PI + 2.0
    addss xmm0, xmm1

    ; Multiply by 2.0
    mulss xmm0, xmm1

    ; Store result back to memory
    movss [float_result], xmm0

    ret

_start:
    ; Test macro expansion
    PUSH_ALL

    ; Test different size operations
    call test_sizes

    ; Test SSE floating point
    call add_floats

    ; Test write system call with our message
    mov rax, SYSCALL_WRITE
    mov rdi, 1                  ; stdout
    mov rsi, message            ; message address
    mov rdx, message_len        ; message length
    syscall

    ; Increment counter using different sizes
    mov al, 1
    add byte ptr [counter], al      ; 8-bit memory operation

    mov ax, 256
    add word ptr [counter], ax      ; 16-bit memory operation

    mov eax, 65536
    add dword ptr [counter], eax    ; 32-bit memory operation

    ; Final counter value should be 1 + 256 + 65536 = 65793
    mov rax, [counter]

    ; Restore registers
    POP_ALL

    ; Use counter value as exit code (modulo 256)
    mov rdi, rax
    and rdi, 0xFF              ; Keep only low 8 bits for exit code

    ; Exit system call using macro
    SYSCALL SYSCALL_EXIT
)";

    std::string outputFile = "enhanced-exec";

    Assembler assembler;
    ElfGenerator elfGen(true, 0x400000);

    if (!assembler.assemble(asmCode, outputFile)) {
        std::cerr << "Assembly failed\n";
        return 1;
    }

    // Print debug information showing all the new features
    assembler.printDebugInfo();

    const auto& symbols = assembler.getSymbols();

    // Use the new ELF generator method that supports all sections
    if (!elfGen.generateElfWithAllSections(
            assembler.getTextSection(),
            outputFile + ".elf",
            symbols,
            assembler.getDataSection(),
            assembler.getBssSection(),
            assembler.getRodataSection(),
            assembler.getEntryPoint(),
            0x600000,  // data base
            0x601000,  // bss base
            0x602000   // rodata base
            )) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    std::cout << "Enhanced ELF executable generated successfully: " << outputFile << ".elf\n";
    std::cout << "\nThis executable demonstrates:\n";
    std::cout << "  - Multiple sections (.text, .data, .bss, .rodata)\n";
    std::cout << "  - Explicit operand sizing (byte/word/dword/qword ptr)\n";
    std::cout << "  - SSE floating-point instructions (movss, addss, mulss)\n";
    std::cout << "  - Macro system with parameters\n";
    std::cout << "  - %define preprocessor directives\n";
    std::cout << "  - Various data directives (.byte, .word, .dword, .asciz, .space)\n";
    std::cout << "  - Register operations in different sizes (8/16/32/64-bit)\n";
    std::cout << "\nRun with: ./" << outputFile << ".elf\n";

    return 0;
}
