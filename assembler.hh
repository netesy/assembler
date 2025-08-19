#ifndef ASSEMBLER_HH
#define ASSEMBLER_HH

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <set>

enum class Section {
    NONE,
    TEXT,
    DATA,
    BSS
};

struct Instruction {
    std::string mnemonic;
    std::vector<std::string> operands;
    Section section = Section::TEXT;

    bool is_label = false;
    std::string label;
    std::string data_str;

    // Members for two-pass assembly
    uint64_t address = 0;
    uint64_t size = 0;
};

struct SymbolEntry
{
    std::string name;
    uint64_t address;
    bool isGlobal;
    bool isExternal;
};


struct RelocationEntry
{
    uint64_t offset;
    SymbolEntry symbol;
    std::string section;
};

class Assembler
{
public:
    Assembler(uint64_t textBase = 0x400000, uint64_t dataBase = 0x600000);

    bool assemble(const std::string &source, const std::string &outputFile);

    const std::unordered_map<std::string, SymbolEntry> &getSymbols() const;
    const std::vector<uint8_t> &getMachineCode() const;
    const std::vector<uint8_t> &getTextSection() const;
    const std::vector<uint8_t> &getDataSection() const;
    const std::vector<uint8_t> &getBssSection() const;
    const std::vector<RelocationEntry> &getRelocations() const;
    uint64_t getEntryPoint() const;

    void printDebugInfo() const;

private:
    std::vector<Instruction> parse(const std::string& code);
    void first_pass(std::vector<Instruction>& instructions);
    void second_pass(const std::vector<Instruction>& instructions);
    void encode_x86_64(const Instruction& instr);
    uint64_t get_instruction_size(const Instruction& instr);

    Section currentSection;
    uint64_t textSectionBase;
    uint64_t dataSectionBase;
    uint64_t entryPoint;

    std::vector<uint8_t> textSection;
    std::vector<uint8_t> dataSection;

    std::unordered_map<std::string, SymbolEntry> symbolTable;
    std::set<std::string> global_symbols;
};

#endif // ASSEMBLER_HH
