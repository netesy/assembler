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
#include <variant>
#include <regex>

enum class Section {
    NONE,
    TEXT,
    DATA,
    BSS,
    RODATA,
    INIT,
    FINI,
    CUSTOM
};

enum class OperandType {
    NONE,
    REGISTER,
    XMM_REGISTER,
    IMMEDIATE,
    MEMORY,
    LABEL
};

enum class OperandSize {
    BYTE = 1,   // 8-bit
    WORD = 2,   // 16-bit
    DWORD = 4,  // 32-bit
    QWORD = 8,  // 64-bit
    INFERRED = 0 // Size determined by context
};

struct Operand {
    OperandType type = OperandType::NONE;
    std::string value;
    OperandSize size = OperandSize::INFERRED;
    bool size_explicit = false; // Was size explicitly specified (e.g., "byte ptr")
};

struct SectionInfo {
    std::string name;
    Section type;
    std::string attributes; // e.g., "awx" for alloc,write,exec
    std::string section_type; // e.g., "@progbits"
};

struct Macro {
    std::string name;
    std::vector<std::string> parameters;
    std::vector<std::string> body;
};

struct Instruction {
    std::string mnemonic;
    std::vector<Operand> operands;
    Section section = Section::TEXT;
    SectionInfo section_info;

    bool is_label = false;
    std::string label;
    std::variant<std::string, int64_t, std::vector<uint8_t>> data; // For various data types
    std::string prefix;

    uint64_t address = 0;
    uint64_t size = 0;

    // For macro expansion
    bool from_macro = false;
    std::string original_line;
};

struct SymbolEntry
{
    std::string name;
    uint64_t address;
    bool isGlobal;
    bool isExternal;
    std::string type; // "function", "object", "notype"
    Section section;
};

class Assembler
{
public:
    Assembler(uint64_t textBase = 0x400000, uint64_t dataBase = 0x600000);

    bool assemble(const std::string &source, const std::string &outputFile = "");
    bool assembleFile(const std::string &inputFile, const std::string &outputFile = "");

    const std::unordered_map<std::string, SymbolEntry> &getSymbols() const;
    const std::vector<uint8_t> &getTextSection() const;
    const std::vector<uint8_t> &getDataSection() const;
    const std::vector<uint8_t> &getBssSection() const;
    const std::vector<uint8_t> &getRodataSection() const;
    const std::unordered_map<std::string, std::vector<uint8_t>> &getCustomSections() const;
    uint64_t getEntryPoint() const;

    void printDebugInfo() const;

private:
    // Core assembly functions
    std::vector<Instruction> parse(const std::string& code);
    void first_pass(std::vector<Instruction>& instructions);
    void second_pass(const std::vector<Instruction>& instructions);
    void encode_x86_64(const Instruction& instr);
    uint64_t get_instruction_size(const Instruction& instr);

    // Parsing helpers
    Operand parse_operand(const std::string& operand_str);
    OperandSize parse_size_prefix(const std::string& operand_str, std::string& cleaned_operand);
    std::vector<Instruction> preprocess(const std::string& source);
    std::string process_includes(const std::string& source);
    std::vector<Instruction> expand_macros(const std::vector<Instruction>& instructions);

    // Instruction encoding helpers
    void encode_sse_instruction(const Instruction& instr);
    uint8_t get_register_code(const std::string& reg);
    uint8_t get_xmm_register_code(const std::string& reg);
    void encode_modrm_sib(uint8_t mod, uint8_t reg, uint8_t rm,
                          const std::string& memory_expr, uint64_t instr_addr, uint64_t instr_size);

    // Data directive handlers
    void handle_data_directive(Instruction& instr, const std::string& directive,
                               const std::string& data_str);

    // Section management
    void switch_section(const SectionInfo& section_info);
    uint64_t get_section_base(Section section) const;
    std::vector<uint8_t>& get_section_data(Section section);

    // Macro system
    void define_macro(const std::string& line);
    bool is_macro_call(const std::string& mnemonic) const;
    std::vector<std::string> expand_macro_call(const std::string& macro_name,
                                               const std::vector<std::string>& args);

    // Member variables
    Section currentSection;
    SectionInfo currentSectionInfo;
    uint64_t textSectionBase;
    uint64_t dataSectionBase;
    uint64_t bssSectionBase;
    uint64_t rodataSectionBase;
    uint64_t entryPoint;

    std::vector<uint8_t> textSection;
    std::vector<uint8_t> dataSection;
    std::vector<uint8_t> bssSection;
    std::vector<uint8_t> rodataSection;
    std::unordered_map<std::string, std::vector<uint8_t>> customSections;
    std::unordered_map<std::string, SectionInfo> sectionInfoMap;

    std::unordered_map<std::string, SymbolEntry> symbolTable;
    std::set<std::string> global_symbols;
    std::unordered_map<std::string, Macro> macros;
    std::unordered_map<std::string, std::string> defines; // For %define

    // Include path for file processing
    std::vector<std::string> includePaths;
};

#endif // ASSEMBLER_HH
