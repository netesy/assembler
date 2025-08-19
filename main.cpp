#include "assembler.hh"
#include "elf.hh"
#include "pe.hh"
#include <filesystem>
#include <iostream>

using namespace std;

std::string getExecutableName(const std::string& inputFile) {
    std::filesystem::path path(inputFile);
    return path.stem().string();  // Get filename without extension
}

int main(int argc, char* argv[]) {
    // if (argc != 3) {
    //     std::cerr << "Usage: " << argv[0] << " <input.asm> <output.bin>\n";
    //     return 1;
    // }
    std::string asmCode = R"(
.data
message: .asciz "Hello, World!\n"   # String with automatic length and null terminator
buffer: .space 100                  # 100 byte buffer

.text
.global _start
_start:
    MOV R0, 1              # stdout
    MOV R1, message        # string address
    MOV R2, message_len    # length is automatically available
    MOV R3, 1              # sys_write

    MOV R0, 0              # exit code 0
    MOV R3, 60             # syscall number (sys_exit)

)";

    std::string inputFile = asmCode; // argv[1];
    std::string outputFile = "sample-exec";

    // if (argc == 3) {
    //     outputFile = argv[2];
    // } else {
    //     // Generate output name from input file
    //     outputFile = getExecutableName(inputFile);
    // }
    Assembler assembler;
    ElfGenerator elfGen(true, 0x400000); // 64-bit, base address at 0x400000;
    PEGenerator peGen(true);  // false = 32-bit

    if (!assembler.assemble(inputFile, outputFile + ".o")) {
        std::cerr << "Assembly failed\n";
        return 1;
    }

    assembler.printDebugInfo();

    // Get the machine code and symbols from the assembler
    const auto& symbols = assembler.getSymbols();

    std::cout << "Entry Point: 0x" << std::hex << assembler.getEntryPoint() << std::dec << std::endl;

    // Generate the final ELF executable using assembler's sections
    if (!elfGen.generateElf(
            assembler.getTextSection(),
            outputFile + ".elf",
            symbols,
            assembler.getDataSection(),
            assembler.getEntryPoint())) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    std::cout << "ELF executable generated successfully: " << outputFile << ".elf\n";

    // PE Generation (for windows)
    peGen.addImport("KERNEL32.dll", {"ExitProcess"});
    peGen.setSubsystem(IMAGE_SUBSYSTEM_WINDOWS_CUI);

    if (peGen.generateExecutable(outputFile + ".exe", assembler.getMachineCode(), symbols)) {
        std::cout << "PE Executable generated successfully" << std::endl;
    } else {
        std::cerr << "Error: " << peGen.getLastError() << std::endl;
    }

    return 0;
}
