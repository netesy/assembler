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
message "Hello, World!\n"   # String with automatic length
buffer 100                  # 100 byte buffer

.text
_start:
    MOV R0, 1              # stdout
    MOV R1, message        # string address
    MOV R2, [message_len]  # length is automatically available
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

   // elfGen.setEntryPoint(assembler.getEntryPoint());
    assembler.printDebugInfo();
    // Get the machine code and symbols from the assembler
    const std::vector<uint8_t>& machineCode = assembler.getMachineCode();
    const std::unordered_map<std::string, uint64_t>& symbols = assembler.getSymbols();

     std::cout << "Entry Point: " <<  assembler.getEntryPoint() << std::endl;
    // Add imports
    peGen.addImport("KERNEL32.dll", {"ExitProcess"});

    // Generate the final ELF executable using assembler's sections
    if (!elfGen.generateElf(
            assembler.getTextSection(),
            outputFile + ".elf",
            assembler.getSymbols(),
            assembler.getDataSection(),
            0x400000)) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    peGen.setSubsystem(IMAGE_SUBSYSTEM_WINDOWS_CUI);

    // Generate the executable
    if (peGen.generateExecutable(outputFile + ".exe", machineCode)) {
        std::cout << "Pe Executable generated successfully" << std::endl;
    } else {
        std::cerr << "Error: " << peGen.getLastError() << std::endl;
    }

   // set executable permissions
    // std::filesystem::permissions(outputFile,
    //                              std::filesystem::perms::owner_exec |
    //                                  std::filesystem::perms::owner_read |
    //                                  std::filesystem::perms::owner_write,
    //                              std::filesystem::perm_options::add);

    std::cout << "ELF executable generated successfully: " << argv[2] << "\n";
    return 0;
}

