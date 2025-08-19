#include "assembler.hh"
#include "elf.hh"
#include <filesystem>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    std::string asmCode = R"(
.section .data
    val1: .quad 10
    val2: .quad 5
    result: .quad 0

.section .text
.global _start
_start:
    ; Read values from memory
    mov rax, [val1]     ; rax = 10
    mov rbx, [val2]     ; rbx = 5

    ; Perform arithmetic
    add rax, rbx        ; rax = 15

    ; Write result back to memory
    mov [result], rax   ; result = 15

    ; For verification, read the result back and use it as the exit code
    mov rdi, [result]   ; exit_code = 15
    mov rax, 60         ; syscall number for sys_exit
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
