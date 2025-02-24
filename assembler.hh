#ifndef ASSEMBLER_HH
#define ASSEMBLER_HH

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint>

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
    Assembler();

    bool assemble(const std::string &inputFile, const std::string &outputFile);

    const std::unordered_map<std::string, uint64_t> &getSymbols() const;
    const std::vector<uint8_t> &getMachineCode() const;
    const std::vector<uint8_t> &getTextSection() const;
    const std::vector<uint8_t> &getDataSection() const;
    const std::vector<uint8_t> &getBssSection() const;
    const std::vector<RelocationEntry> &getRelocations() const;
    uint64_t getEntryPoint() const;

private:
    Section currentSection;
    uint64_t currentAddress;
    uint64_t dataAddress;
    uint64_t bssAddress;

    std::unordered_map<std::string, uint64_t> labels;
    std::unordered_map<std::string, std::vector<uint64_t>> unresolvedSymbols;
    std::unordered_map<std::string, uint64_t> dataLabels;
    std::unordered_map<std::string, uint64_t> bssLabels;

    std::vector<uint8_t> textSection;
    std::vector<uint8_t> dataSection;
    std::vector<uint8_t> bssSection;
    uint64_t entryPoint;
    std::string entrySymbol;
    std::unordered_map<std::string, uint64_t> symbols;

    std::unordered_map<std::string, SymbolEntry> symbolTable;
    std::vector<RelocationEntry> relocationEntries;

    std::vector<Instruction> parse(const std::string& code);
    uint32_t encodeInstruction(const Instruction& instr);
    uint32_t parseOperand(const std::string& operand);

    void resolveLabels(std::vector<Instruction>& instructions);
    void resolveSymbols();
    void patchUnresolvedSymbols(const std::string& symbol, uint64_t address);
    void findEntryPoint(const std::vector<Instruction>& instructions);
    void processDataSection(std::vector<Instruction>& instructions);


};

#endif // ASSEMBLER_HH
