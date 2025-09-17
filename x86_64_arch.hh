#pragma once

#include "architecture.hh"
#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <set>

// Forward declarations
class Assembler;
struct Instruction;

class X86_64Arch : public Architecture {
public:
    X86_64Arch();
    ~X86_64Arch() override = default;

    bool is_register(const std::string& reg) const override;
    uint64_t get_instruction_size(const Instruction& instr) override;
    void encode_instruction(Assembler& assembler, const Instruction& instr) override;
    uint16_t get_elf_machine_type() const override;
    uint16_t get_pe_machine_type() const override;

private:
    // Helper methods to be moved from assembler.cpp
    bool is_xmm_register(const std::string& reg) const;
    uint8_t get_register_code(const std::string& reg) const;
    uint8_t get_xmm_register_code(const std::string& reg) const;
    void encode_sse_instruction(Assembler& assembler, const Instruction& instr);
    void encode_modrm_sib(uint8_t mod, uint8_t reg, uint8_t rm,
                          const std::string& memory_expr, uint64_t instr_addr, uint64_t instr_size);


    // Data to be moved from assembler.cpp
    std::map<std::string, uint8_t> register_map_;
    std::map<std::string, uint8_t> xmm_register_map_;
    std::set<std::string> lockable_instructions_;
    std::set<std::string> sse_instructions_;
};
