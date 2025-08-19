#include "assembler.hh"
#include "elf.hh"
#include <filesystem>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    std::string asmCode = R"(
.section .data
    msg: .asciz "Hello from a function!\n"

.section .text
.global _start
.global print_message

print_message:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, 24
    syscall
    ret

_start:
    call print_message

    ; Test conditional jump
    mov rax, 10
    cmp rax, 10     ; This will set the Zero Flag
    jne exit_error  ; This jump should NOT be taken

    ; Normal exit
    mov rax, 60
    mov rdi, 0      ; Exit code 0
    syscall

exit_error:
    mov rax, 60
    mov rdi, 1      ; Exit code 1
    syscall
)";

    std::string outputFile = "sample-exec";

    Assembler assembler;
    ElfGenerator elfGen(true, 0x400000);

    if (!assembler.assemble(asmCode, outputFile + ".o")) {
        std::cerr << "Assembly failed\n";
        return 1;
    }

    assembler.printDebugInfo();

    const auto& symbols = assembler.getSymbols();

    std::cout << "Entry Point: 0x" << std::hex << assembler.getEntryPoint() << std::dec << std::endl;

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
