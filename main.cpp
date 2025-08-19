#include "assembler.hh"
#include "elf.hh"
#include <filesystem>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    std::string asmCode = R"(
.section .data
    counter: .quad 0

.section .text
.global _start
.global check_value

; This function checks a value passed on the stack.
; On entry, [rsp] holds the return address, and [rsp+8] holds the argument.
check_value:
    mov rbx, [rsp+8]    ; Load argument from the stack into rbx
    cmp rbx, 123
    je .success

.failure:
    mov rax, 99         ; Return 99 on failure
    ret

.success:
    mov rax, 42         ; Return 42 on success
    ret

_start:
    ; Test brk syscall
    mov rax, 12
    mov rdi, 0
    syscall

    ; Test stack, call, and conditional jumps.
    mov rax, 123
    push rax
    call check_value

    add rsp, 8          ; Clean up stack after call

    ; The result from check_value is in rax. Use it as the exit code.
    mov rdi, rax        ; Expected exit code: 42
    mov rax, 60
    syscall
)";

    std::string outputFile = "sample-exec";

    Assembler assembler;
    ElfGenerator elfGen(true, 0x400000);

    if (!assembler.assemble(asmCode, outputFile)) {
        std::cerr << "Assembly failed\n";
        return 1;
    }

    assembler.printDebugInfo();

    const auto& symbols = assembler.getSymbols();

    if (!elfGen.generateElf(
            assembler.getTextSection(),
            outputFile + ".elf",
            symbols,
            assembler.getDataSection(),
            assembler.getEntryPoint(),
            0x600000)) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    std::cout << "ELF executable generated successfully: " << outputFile << ".elf\n";

    return 0;
}
