#include "assembler.hh"
#include "elf.hh"
#include "pe.hh"
#include <filesystem>
#include <iostream>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    bool generateRelocatable = false;
    std::string inputFilename;
    std::string outputFilename;
    std::string format = "elf";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c") {
            generateRelocatable = true;
        } else if (arg == "-o") {
            if (i + 1 < argc) {
                outputFilename = argv[++i];
            } else {
                std::cerr << "-o option requires one argument." << std::endl;
                return 1;
            }
        } else if (arg == "--format") {
            if (i + 1 < argc) {
                format = argv[++i];
            } else {
                std::cerr << "--format option requires one argument." << std::endl;
                return 1;
            }
        } else {
            if (!inputFilename.empty()) {
                std::cerr << "Multiple input files not supported." << std::endl;
                return 1;
            }
            inputFilename = arg;
        }
    }

    if (inputFilename.empty()) {
        std::cerr << "No input file specified." << std::endl;
        return 1;
    }

    if (outputFilename.empty()) {
        std::filesystem::path p(inputFilename);
        outputFilename = p.stem().string();
    }

    std::ifstream file(inputFilename);
    if (!file) {
        std::cerr << "Cannot open input file: " << inputFilename << std::endl;
        return 1;
    }
    std::string asmCodeFromFile((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());

    Assembler assembler(format);
    if (!assembler.assemble(asmCodeFromFile, outputFilename)) {
        std::cerr << "Assembly failed" << std::endl;
        return 1;
    }

    // Print debug information showing all the new features
    assembler.printDebugInfo();

    const auto& symbols = assembler.getSymbols();

    if (format == "elf") {
        ElfGenerator elfGen(assembler, inputFilename, true, 0x400000);

        // Use the new ELF generator method that supports all sections
        std::string finalOutputFile = outputFilename;
        if (finalOutputFile.find('.') == std::string::npos) {
            finalOutputFile += (generateRelocatable ? ".o" : ".elf");
        }
        if (!elfGen.generateElfWithAllSections(
                assembler.getTextSection(),
                finalOutputFile,
                symbols,
                assembler.getRelocations(),
                assembler.getDataSection(),
                assembler.getBssSection(),
                assembler.getRodataSection(),
                assembler.getEntryPoint(),
                0x600000,  // data base
                0x601000,  // bss base
                0x602000,  // rodata base
                generateRelocatable
                )) {
            std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
            return 1;
        }

        std::cout << "File generated successfully: " << finalOutputFile << "\n";
        if (!generateRelocatable) {
            std::cout << "\nThis executable demonstrates:\n"
                      << "  - Multiple sections (.text, .data, .bss, .rodata)\n"
                      << "  - Explicit operand sizing (byte/word/dword/qword ptr)\n"
                      << "  - SSE floating-point instructions (movss, addss, mulss)\n"
                      << "  - Macro system with parameters\n"
                      << "  - %define preprocessor directives\n"
                      << "  - Various data directives (.byte, .word, .dword, .asciz, .space)\n"
                      << "  - Register operations in different sizes (8/16/32/64-bit)\n"
                      << "\nRun with: ./" << finalOutputFile << "\n";
        }
    } else if (format == "pe") {
        PEGenerator peGen(true); // Assuming 64-bit

        for (const auto& imp : assembler.getWinApiImports()) {
            peGen.addImport(imp.dll, imp.function);
        }

        peGen.addSection(".text", assembler.getTextSection(), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        if(!assembler.getDataSection().empty()){
            peGen.addSection(".data", assembler.getDataSection(), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        }
        if(!assembler.getRodataSection().empty()){
            peGen.addSection(".rdata", assembler.getRodataSection(), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
        }

        std::string finalOutputFile = outputFilename;
        if (finalOutputFile.find('.') == std::string::npos) {
            finalOutputFile += ".exe";
        }

        if (!peGen.generateExecutable(finalOutputFile, symbols)) {
             std::cerr << "PE generation failed: " << peGen.getLastError() << std::endl;
             return 1;
        }
        std::cout << "File generated successfully: " << finalOutputFile << "\n";
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
        return 1;
    }

    return 0;
}
