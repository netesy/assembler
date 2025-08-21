#include "assembler.hh"
#include "elf.hh"
#include "pe.hh"
#include <filesystem>
#include <iostream>
#include <string>

using namespace std;

// Function to generate ELF output
bool generateElf(Assembler& assembler, const std::string& inputFilename, const std::string& outputFilename, bool generateRelocatable) {
    const auto& symbols = assembler.getSymbols();
    ElfGenerator elfGen(assembler, inputFilename, true, 0x400000);

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
            0x600000,
            0x601000,
            0x602000,
            generateRelocatable
            )) {
        std::cerr << "ELF generation failed: " << elfGen.getLastError() << std::endl;
        return false;
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
    return true;
}

// Function to generate PE output
bool generatePe(Assembler& assembler, const std::string& outputFilename) {
    const auto& symbols = assembler.getSymbols();
    PEGenerator peGen(true); // Assuming 64-bit

    for (const auto& imp : assembler.getWinApiImports()) {
        peGen.addImport(imp.dll, imp.function);
    }

    peGen.addSection(".text", assembler.getTextSection(), assembler.getTextSection().size(), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if(!assembler.getDataSection().empty()){
        peGen.addSection(".data", assembler.getDataSection(), assembler.getDataSection().size(), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    }
    if(!assembler.getRodataSection().empty()){
        peGen.addSection(".rdata", assembler.getRodataSection(), assembler.getRodataSection().size(), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    }
    if(assembler.getBssSize() > 0) {
        peGen.addSection(".bss", {}, assembler.getBssSize(), IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    }

    std::string finalOutputFile = outputFilename;
    if (finalOutputFile.find('.') == std::string::npos) {
        finalOutputFile += ".exe";
    }

    if (!peGen.generateExecutable(finalOutputFile, symbols)) {
         std::cerr << "PE generation failed: " << peGen.getLastError() << std::endl;
         return false;
    }
    std::cout << "File generated successfully: " << finalOutputFile << "\n";
    return true;
}


int main(int argc, char* argv[]) {
    bool generateRelocatable = false;
    std::string inputFilename;
    std::string outputFilename;
    std::string format = "default";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c") {
            generateRelocatable = true;
        } else if (arg == "-o") {
            if (i + 1 < argc && argv[i+1][0] != '-') {
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

    if (format == "default") {
        cout << "No format specified, generating for both ELF and PE..." << endl;

        Assembler elf_assembler("elf");
        if (!elf_assembler.assemble(asmCodeFromFile, outputFilename)) {
            std::cerr << "Assembly for ELF failed" << std::endl;
            return 1;
        }
        elf_assembler.printDebugInfo();
        if(!generateElf(elf_assembler, inputFilename, outputFilename, generateRelocatable)) {
            return 1;
        }

        Assembler pe_assembler("pe");
        if (!pe_assembler.assemble(asmCodeFromFile, outputFilename)) {
            std::cerr << "Assembly for PE failed" << std::endl;
            return 1;
        }
        pe_assembler.printDebugInfo();
        if(!generatePe(pe_assembler, outputFilename)) {
            return 1;
        }

    } else if (format == "elf") {
        Assembler assembler("elf");
        if (!assembler.assemble(asmCodeFromFile, outputFilename)) {
            std::cerr << "Assembly failed" << std::endl;
            return 1;
        }
        assembler.printDebugInfo();
        if (!generateElf(assembler, inputFilename, outputFilename, generateRelocatable)) {
            return 1;
        }
    } else if (format == "pe") {
        Assembler assembler("pe");
        if (!assembler.assemble(asmCodeFromFile, outputFilename)) {
            std::cerr << "Assembly failed" << std::endl;
            return 1;
        }
        assembler.printDebugInfo();
        if (!generatePe(assembler, outputFilename)) {
            return 1;
        }
    } else {
        std::cerr << "Unsupported format: " << format << std::endl;
        return 1;
    }

    return 0;
}
