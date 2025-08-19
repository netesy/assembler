#include "assembler.hh"
#include "elf.hh"
#include "pe.hh"
#include <filesystem>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    std::string asmCode = R"(
.section .data
    msg: .asciz "Hello, world!\n"

.section .text
.global _start
_start:
    ; Simple arithmetic example
    mov r8, 10
    add r8, 5       ; r8 is now 15
    sub r8, 1       ; r8 is now 14

    ; sys_write call
    mov rax, 1      ; syscall number for sys_write
    mov rdi, 1      ; file descriptor 1 (stdout)
    mov rsi, msg    ; address of the message
    mov rdx, 14     ; length of the message
    syscall

    ; sys_exit call
    mov rax, 60     ; syscall number for sys_exit
    mov rdi, 0      ; exit code 0
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
            0x600000)) { // Pass the data base address
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    std::cout << "ELF executable generated successfully: " << outputFile << ".elf\n";

    // PE Generation is not the focus of this task and will likely fail with the new assembler
    // PEGenerator peGen(true);
    // peGen.addImport("KERNEL32.dll", {"ExitProcess"});
    // peGen.setSubsystem(IMAGE_SUBSYSTEM_WINDOWS_CUI);
    // if (peGen.generateExecutable(outputFile + ".exe", assembler.getMachineCode(), symbols)) {
    //     std::cout << "PE Executable generated successfully" << std::endl;
    // } else {
    //     std::cerr << "Error: " << peGen.getLastError() << std::endl;
    // }

    return 0;
}
