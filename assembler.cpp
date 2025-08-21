#include "assembler.hh"
#include "parser.hh"
#include "translator.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <set>
#include <fstream>

// COFF structures
struct COFFHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct Symbol {
    char Name[8];
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
};

static const std::map<std::string, uint8_t> register_map = {
    {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
    {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
    {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
    {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
    {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3},
    {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
    {"r8d", 8}, {"r9d", 9}, {"r10d", 10}, {"r11d", 11},
    {"r12d", 12}, {"r13d", 13}, {"r14d", 14}, {"r15d", 15},
    {"ax", 0}, {"cx", 1}, {"dx", 2}, {"bx", 3},
    {"sp", 4}, {"bp", 5}, {"si", 6}, {"di", 7},
    {"r8w", 8}, {"r9w", 9}, {"r10w", 10}, {"r11w", 11},
    {"r12w", 12}, {"r13w", 13}, {"r14w", 14}, {"r15w", 15},
    {"al", 0}, {"cl", 1}, {"dl", 2}, {"bl", 3},
    {"ah", 4}, {"ch", 5}, {"dh", 6}, {"bh", 7},
    {"r8b", 8}, {"r9b", 9}, {"r10b", 10}, {"r11b", 11},
    {"r12b", 12}, {"r13b", 13}, {"r14b", 14}, {"r15b", 15}
};

Assembler::Assembler(const std::string& target_format, uint64_t textBase, uint64_t dataBase)
    : textSectionBase(textBase), dataSectionBase(dataBase),
      bssSectionBase(dataBase + 0x1000), rodataSectionBase(dataBase + 0x2000),
      entryPoint(0), target_format_(target_format), parser_(*this), translator_(*this) {
    includePaths.push_back("."); // Default include path
}

bool Assembler::assemble(const std::string &source, const std::string &outputFile) {
    try {
        auto instructions = preprocess(source);
        translator_.translate_syscalls_to_winapi(instructions);
        first_pass(instructions);
        second_pass(instructions);

        if (target_format_ == "coff") {
            write_coff(outputFile);
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Assembly Error: " << e.what() << std::endl;
        return false;
    }
}

void Assembler::write_coff(const std::string& outputFile) {
    std::ofstream file(outputFile, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open output file: " + outputFile);
    }

    COFFHeader header;
    header.Machine = 0x8664; // x86-64
    header.NumberOfSections = 3; // .text, .data, .rdata
    header.TimeDateStamp = time(nullptr);
    header.PointerToSymbolTable = 0; // Will be set later
    header.NumberOfSymbols = 0; // Will be set later
    header.SizeOfOptionalHeader = 0;
    header.Characteristics = 0;

    file.write(reinterpret_cast<const char*>(&header), sizeof(header));

    SectionHeader text_header;
    strncpy(text_header.Name, ".text", 8);
    text_header.VirtualSize = textSection.size();
    text_header.VirtualAddress = 0;
    text_header.SizeOfRawData = textSection.size();
    text_header.PointerToRawData = sizeof(COFFHeader) + 3 * sizeof(SectionHeader);
    text_header.PointerToRelocations = 0;
    text_header.PointerToLinenumbers = 0;
    text_header.NumberOfRelocations = 0;
    text_header.NumberOfLinenumbers = 0;
    text_header.Characteristics = 0x60500020; // Code, Execute, Read

    file.write(reinterpret_cast<const char*>(&text_header), sizeof(text_header));

    SectionHeader data_header;
    strncpy(data_header.Name, ".data", 8);
    data_header.VirtualSize = dataSection.size();
    data_header.VirtualAddress = 0;
    data_header.SizeOfRawData = dataSection.size();
    data_header.PointerToRawData = text_header.PointerToRawData + text_header.SizeOfRawData;
    data_header.PointerToRelocations = 0;
    data_header.PointerToLinenumbers = 0;
    data_header.NumberOfRelocations = 0;
    data_header.NumberOfLinenumbers = 0;
    data_header.Characteristics = 0xC0300040; // Initialized Data, Read, Write

    file.write(reinterpret_cast<const char*>(&data_header), sizeof(data_header));

    SectionHeader rdata_header;
    strncpy(rdata_header.Name, ".rdata", 8);
    rdata_header.VirtualSize = 0;
    rdata_header.VirtualAddress = 0;
    rdata_header.SizeOfRawData = 0;
    rdata_header.PointerToRawData = data_header.PointerToRawData + data_header.SizeOfRawData;
    rdata_header.PointerToRelocations = 0;
    rdata_header.PointerToLinenumbers = 0;
    rdata_header.NumberOfRelocations = 0;
    rdata_header.NumberOfLinenumbers = 0;
    rdata_header.Characteristics = 0x40300040; // Initialized Data, Read

    file.write(reinterpret_cast<const char*>(&rdata_header), sizeof(rdata_header));

    file.write(reinterpret_cast<const char*>(textSection.data()), textSection.size());
    file.write(reinterpret_cast<const char*>(dataSection.data()), dataSection.size());

    // Symbol table and string table would go here

    file.close();
}

// ... rest of the file
