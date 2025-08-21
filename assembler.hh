#ifndef ASSEMBLER_HH
#define ASSEMBLER_HH

#include "types.hh"
#include "parser.hh"
#include "translator.hh"
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

class Assembler
{
public:
    Assembler(const std::string& target_format = "elf", uint64_t textBase = 0x400000, uint64_t dataBase = 0x600000);

    bool assemble(const std::string &source, const std::string &outputFile = "");
    bool assembleFile(const std::string &inputFile, const std::string &outputFile = "");

    const std::unordered_map<std::string, SymbolEntry> &getSymbols() const;
    const std::vector<RelocationEntry> &getRelocations() const;
    const std::vector<uint8_t> &getTextSection() const;
    uint64_t getSectionBase(Section s) const;
    std::string getSectionName(Section s) const;
    const std::vector<uint8_t> &getDataSection() const;
    const std::vector<uint8_t> &getBssSection() const;
    uint64_t getBssSize() const;
    const std::vector<uint8_t> &getRodataSection() const;
    const std::unordered_map<std::string, std::vector<uint8_t>> &getCustomSections() const;
    uint64_t getEntryPoint() const;
    const std::vector<WinApiImport>& getWinApiImports() const;

    void printDebugInfo() const;

    bool is_register(const std::string& reg) const;
    bool is_xmm_register(const std::string& reg) const;

    friend class Parser;
    friend class Translator;

private:
    void add_winapi_import(const std::string& dll, const std::string& function);
    void first_pass(std::vector<Instruction>& instructions);
    void second_pass(const std::vector<Instruction>& instructions);
    void encode_x86_64(const Instruction& instr);
    uint64_t get_instruction_size(const Instruction& instr);
    std::vector<Instruction> preprocess(const std::string& source);
    std::string process_includes(const std::string& source);
    std::vector<Instruction> expand_macros(const std::vector<Instruction>& instructions);
    void encode_sse_instruction(const Instruction& instr);
    uint8_t get_register_code(const std::string& reg) const;
    uint8_t get_xmm_register_code(const std::string& reg) const;
    void encode_modrm_sib(uint8_t mod, uint8_t reg, uint8_t rm,
                          const std::string& memory_expr, uint64_t instr_addr, uint64_t instr_size);
    uint64_t get_section_base_address(Section section) const;
    std::vector<uint8_t>& get_section_data(Section section);
    bool is_macro_call(const std::string& mnemonic) const;

    uint64_t textSectionBase;
    uint64_t dataSectionBase;
    uint64_t bssSectionBase;
    uint64_t rodataSectionBase;
    uint64_t entryPoint;
    std::vector<uint8_t> textSection;
    std::vector<uint8_t> dataSection;
    std::vector<uint8_t> bssSection;
    uint64_t bssSize = 0;
    std::vector<uint8_t> rodataSection;
    std::unordered_map<std::string, std::vector<uint8_t>> customSections;
    std::unordered_map<std::string, SectionInfo> sectionInfoMap;
    std::unordered_map<std::string, SymbolEntry> symbolTable;
    std::vector<RelocationEntry> relocations;
    std::unordered_map<std::string, Macro> macros;
    std::unordered_map<std::string, std::string> defines;
    std::vector<WinApiImport> winapi_imports;
    std::vector<std::string> includePaths;
    std::string target_format_;
    Parser parser_;
    Translator translator_;
};

#endif // ASSEMBLER_HH
