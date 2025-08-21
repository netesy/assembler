#ifndef TYPES_HH
#define TYPES_HH

#include <string>
#include <vector>
#include <variant>
#include <cstdint>

struct WinApiImport {
    std::string dll;
    std::string function;
};

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

enum class SymbolBinding {
    LOCAL,
    GLOBAL,
    WEAK
};

enum class SymbolType {
    NOTYPE,
    OBJECT,
    FUNCTION,
    SECTION
};

enum class SymbolVisibility {
    DEFAULT,
    HIDDEN,
    PROTECTED
};

struct SymbolEntry
{
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    SymbolBinding binding = SymbolBinding::LOCAL;
    SymbolType type = SymbolType::NOTYPE;
    SymbolVisibility visibility = SymbolVisibility::DEFAULT;
    Section section = Section::NONE;
    bool isDefined = false;
};

enum class RelocationType {
    R_X86_64_64,
    R_X86_64_PC32,
    R_X86_64_PLT32
};

struct RelocationEntry {
    uint64_t offset;
    std::string symbolName;
    RelocationType type;
    int64_t addend;
    Section section;
};

#endif // TYPES_HH
