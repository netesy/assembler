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
_start:
    ; Atomically add 1 to the counter variable in memory
    lock add [counter], 1

    ; For verification, read the counter's value and use it as the exit code.
    ; The exit code should be 1.
    mov rdi, [counter]
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
