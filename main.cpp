#include "assembler.hh"
#include "elf.hh"
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
)";

    std::string inputFile = asmCode; // argv[1];
    std::string outputFile = "sample-exec";
    outputFile =  outputFile + ".elf";

    // if (argc == 3) {
    //     outputFile = argv[2];
    // } else {
    //     // Generate output name from input file
    //     outputFile = getExecutableName(inputFile);
    // }
    Assembler assembler;
    ElfGenerator elfGen(true, 0x400000); // 64-bit, base address at 0x400000;

    if (!assembler.assemble(inputFile, outputFile + ".o")) {
        std::cerr << "Assembly failed\n";
        return 1;
    }

    // Get the machine code and symbols from the assembler
    const std::vector<uint8_t>& machineCode = assembler.getMachineCode();
    const std::unordered_map<std::string, uint64_t>& symbols = assembler.getSymbols();

    // Generate the final ELF executable using assembler's sections
    if (!elfGen.generateElf(
            assembler.getTextSection(),
            outputFile,
            assembler.getSymbols(),
            assembler.getDataSection(),
            assembler.getEntryPoint())) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return 1;
    }

    // ElfGenerator generator(true);  // true for 64-bit
    // if (!generator.generateExecutable(outputFile, machineCode, symbols)) {
    //     std::cerr << "Error: " << generator.getLastError() << std::endl;
    //     return 1;
    // }

    // Set executable permissions
    std::filesystem::permissions(outputFile,
                                 std::filesystem::perms::owner_exec |
                                     std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::add);

    std::cout << "ELF executable generated successfully: " << argv[2] << "\n";
    return 0;
}

