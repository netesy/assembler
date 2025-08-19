#ifndef ASSEMBLER_HH
#define ASSEMBLER_HH

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <variant>
#include <cstdint>

enum class Section { TEXT, DATA };

enum class OperandType { REGISTER, IMMEDIATE, MEMORY_LABEL, MEMORY_REG_DISP };

struct MemoryOperand {
    std::string base_reg;
    std::string index_reg;
    int scale = 1;
    int64_t displacement = 0;
};

using OperandValue = std::variant<std::string, int64_t, MemoryOperand>;

struct Operand {
    OperandType type;
    OperandValue value;
};

struct Instruction {
    std::string mnemonic;
    std::vector<Operand> operands;
    Section section = Section::TEXT;
    std::string prefix;

    bool is_label = false;
    std::string label;
    std::variant<std::string, int64_t> data;

    uint64_t address = 0;
    uint64_t size = 0;
};

struct SymbolEntry {
    std::string name;
    uint64_t address;
    bool isGlobal;
};

class Assembler {
public:
    Assembler(uint64_t textBase = 0x400000, uint64_t dataBase = 0x600000);
    bool assemble(const std::string &source, const std::string &outputFile = "");
    const std::unordered_map<std::string, SymbolEntry> &getSymbols() const;
    const std::vector<uint8_t> &getTextSection() const;
    const std::vector<uint8_t> &getDataSection() const;
    uint64_t getEntryPoint() const;
    void printDebugInfo() const;

private:
    std::vector<Instruction> parse(const std::string& code);
    Operand parse_operand(const std::string& op_str);
    void first_pass(std::vector<Instruction>& instructions);
    void second_pass(const std::vector<Instruction>& instructions);
    void encode_x86_64(const Instruction& instr);
    uint64_t get_instruction_size(const Instruction& instr);

    uint64_t textSectionBase;
    uint64_t dataSectionBase;
    uint64_t entryPoint;
    std::vector<uint8_t> textSection;
    std::vector<uint8_t> dataSection;
    std::unordered_map<std::string, SymbolEntry> symbolTable;
    std::set<std::string> global_symbols;
};

#endif // ASSEMBLER_HH
