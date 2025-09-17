#pragma once

#include "architecture.hh"
#include <map>
#include <string>

class AArch64Arch : public Architecture {
public:
    AArch64Arch();
    ~AArch64Arch() override = default;

    bool is_register(const std::string& reg) const override;
    uint64_t get_instruction_size(const Instruction& instr) override;
    void encode_instruction(Assembler& assembler, const Instruction& instr) override;
    uint16_t get_elf_machine_type() const override;
    uint16_t get_pe_machine_type() const override;

private:
    uint8_t get_register_code(const std::string& reg) const;
    std::map<std::string, uint8_t> register_map_;
};
