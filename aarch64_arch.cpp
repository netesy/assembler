#include "aarch64_arch.hh"
#include "assembler.hh"
#include "parser.hh"
#include <stdexcept>

// AArch64 ELF machine type
constexpr uint16_t EM_AARCH64 = 183;

AArch64Arch::AArch64Arch() {
    // General purpose registers (64-bit and 32-bit)
    for (int i = 0; i < 31; ++i) {
        register_map_["x" + std::to_string(i)] = i;
        register_map_["w" + std::to_string(i)] = i;
    }
    register_map_["sp"] = 31;
    register_map_["wsp"] = 31;
}

bool AArch64Arch::is_register(const std::string& reg) const {
    return register_map_.count(reg);
}

uint8_t AArch64Arch::get_register_code(const std::string& reg) const {
    auto it = register_map_.find(reg);
    if (it != register_map_.end()) {
        return it->second;
    }
    throw std::runtime_error("Unknown AArch64 register: " + reg);
}

uint64_t AArch64Arch::get_instruction_size(const Instruction& instr) {
    (void)instr; // Unused parameter
    // All AArch64 instructions are 4 bytes wide
    return 4;
}

uint16_t AArch64Arch::get_elf_machine_type() const {
    return EM_AARCH64;
}

uint16_t AArch64Arch::get_pe_machine_type() const {
    throw std::runtime_error("PE file format is not supported for AArch64 in this assembler.");
}

void AArch64Arch::encode_instruction(Assembler& assembler, const Instruction& instr) {
    auto& textSection = assembler.get_section_data(instr.section);
    const auto& m = instr.mnemonic;

    uint32_t opcode = 0;

    if (m == "mov") { // MOV is a pseudo-instruction, we'll implement MOVZ
        if (instr.operands.size() != 2) throw std::runtime_error("mov requires 2 operands");
        const auto& dest = instr.operands[0];
        const auto& src = instr.operands[1];

        if (dest.type == OperandType::REGISTER && src.type == OperandType::IMMEDIATE) {
            uint8_t rd = get_register_code(dest.value);
            uint16_t imm = std::stoi(src.value);

            // MOVZ: 1 0 1 0 0 1 0 1 hw imm16 rd
            // For now, only handle W registers (sf=0) and LSL 0 (hw=00)
            opcode = 0b01010010100000000000000000000000; // MOVZ Wd, #0, LSL 0
            opcode |= (imm & 0xFFFF) << 5;
            opcode |= rd;
        } else {
            throw std::runtime_error("Unsupported mov format for aarch64");
        }
    } else if (m == "svc") {
        if (instr.operands.size() != 1) throw std::runtime_error("svc requires 1 operand");
        const auto& op = instr.operands[0];
        if (op.type != OperandType::IMMEDIATE) throw std::runtime_error("svc operand must be an immediate");

        uint16_t imm = std::stoi(op.value);
        // SVC: 1 1 0 1 0 1 0 0 imm16 0 0 0 1 op0=0
        opcode = 0b11010100000000000000000100000000;
        opcode |= (imm & 0xFFFF) << 5;
    } else {
        throw std::runtime_error("Unsupported aarch64 instruction: " + m);
    }

    textSection.push_back((opcode >> 0) & 0xFF);
    textSection.push_back((opcode >> 8) & 0xFF);
    textSection.push_back((opcode >> 16) & 0xFF);
    textSection.push_back((opcode >> 24) & 0xFF);
}
