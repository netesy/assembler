#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// Forward declarations to avoid circular dependencies
class Assembler;
struct Instruction;
struct Operand;

class Architecture {
public:
    virtual ~Architecture() = default;

    // Check if a string is a valid register name for this architecture
    virtual bool is_register(const std::string& reg) const = 0;

    // Get the size of a given instruction
    virtual uint64_t get_instruction_size(const Instruction& instr) = 0;

    // Encode an instruction into machine code
    virtual void encode_instruction(Assembler& assembler, const Instruction& instr) = 0;

    // Get the machine type constant for ELF headers
    virtual uint16_t get_elf_machine_type() const = 0;

    // Get the machine type constant for PE/COFF headers
    virtual uint16_t get_pe_machine_type() const = 0;
};

// Factory function to create architecture-specific objects
std::unique_ptr<Architecture> create_architecture(const std::string& arch_name);
