#include "x86_64_arch.hh"
#include "assembler.hh"
#include "parser.hh"
#include <stdexcept>
#include <iostream>

// ELF/PE machine type constants
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;

X86_64Arch::X86_64Arch() {
    register_map_ = {
        {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3}, {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
        {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
        {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3}, {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
        {"r8d", 8}, {"r9d", 9}, {"r10d", 10}, {"r11d", 11}, {"r12d", 12}, {"r13d", 13}, {"r14d", 14}, {"r15d", 15},
        {"ax", 0}, {"cx", 1}, {"dx", 2}, {"bx", 3}, {"sp", 4}, {"bp", 5}, {"si", 6}, {"di", 7},
        {"r8w", 8}, {"r9w", 9}, {"r10w", 10}, {"r11w", 11}, {"r12w", 12}, {"r13w", 13}, {"r14w", 14}, {"r15w", 15},
        {"al", 0}, {"cl", 1}, {"dl", 2}, {"bl", 3}, {"ah", 4}, {"ch", 5}, {"dh", 6}, {"bh", 7},
        {"r8b", 8}, {"r9b", 9}, {"r10b", 10}, {"r11b", 11}, {"r12b", 12}, {"r13b", 13}, {"r14b", 14}, {"r15b", 15}
    };
    xmm_register_map_ = {
        {"xmm0", 0}, {"xmm1", 1}, {"xmm2", 2}, {"xmm3", 3}, {"xmm4", 4}, {"xmm5", 5}, {"xmm6", 6}, {"xmm7", 7},
        {"xmm8", 8}, {"xmm9", 9}, {"xmm10", 10}, {"xmm11", 11}, {"xmm12", 12}, {"xmm13", 13}, {"xmm14", 14}, {"xmm15", 15}
    };
    lockable_instructions_ = { "add", "adc", "and", "btc", "btr", "bts", "cmpxchg", "dec", "inc", "neg", "not", "or", "sbb", "sub", "xor", "xadd", "xchg" };
    sse_instructions_ = { "movss", "movsd", "addss", "addsd", "mulss", "mulsd" };
}

bool X86_64Arch::is_register(const std::string& reg) const {
    return register_map_.count(reg) || xmm_register_map_.count(reg);
}

bool X86_64Arch::is_xmm_register(const std::string& reg) const {
    return xmm_register_map_.count(reg);
}

uint8_t X86_64Arch::get_register_code(const std::string& reg) const {
    auto it = register_map_.find(reg);
    if (it != register_map_.end()) return it->second;
    throw std::runtime_error("Unknown register: " + reg);
}

uint8_t X86_64Arch::get_xmm_register_code(const std::string& reg) const {
    auto it = xmm_register_map_.find(reg);
    if (it != xmm_register_map_.end()) return it->second;
    throw std::runtime_error("Unknown XMM register: " + reg);
}

uint16_t X86_64Arch::get_elf_machine_type() const { return EM_X86_64; }
uint16_t X86_64Arch::get_pe_machine_type() const { return IMAGE_FILE_MACHINE_AMD64; }

uint64_t X86_64Arch::get_instruction_size(const Instruction& instr) {
    if (instr.is_label) return 0;
    uint64_t base_size = 0;
    const auto& m = instr.mnemonic;
    if (sse_instructions_.count(m)) {
        base_size = (m.find("ss") != std::string::npos || m.find("sd") != std::string::npos) ? 4 : 3;
        if (instr.operands.size() == 2 && instr.operands[1].type == OperandType::MEMORY) base_size += 3;
        return base_size + (!instr.prefix.empty() ? 1 : 0);
    }
    if (m == "ret") base_size = 1;
    else if (m == "syscall") base_size = 2;
    else if (m == "push") {
        if (instr.operands.empty()) return 0;
        const auto& op = instr.operands[0];
        if (op.type == OperandType::REGISTER) base_size = (get_register_code(op.value) >= 8) ? 2 : 1;
        else if (op.type == OperandType::MEMORY) base_size = 6;
        else if (op.type == OperandType::IMMEDIATE) {
            if (op.size == OperandSize::BYTE) base_size = 2;
            else if (op.size == OperandSize::WORD) base_size = 4;
            else base_size = 5;
        }
    }
    else if (m == "pop") {
        if (instr.operands.empty()) return 0;
        const auto& op = instr.operands[0];
        if (op.type == OperandType::REGISTER) base_size = (get_register_code(op.value) >= 8) ? 2 : 1;
        else if (op.type == OperandType::MEMORY) base_size = 6;
    }
    else if (m == "call" || m == "jmp") base_size = 5;
    else if (m.rfind("j", 0) == 0) base_size = 6;
    else if (instr.operands.size() == 2) {
        const auto& op1 = instr.operands[0];
        const auto& op2 = instr.operands[1];
        if (m == "add" || m == "sub" || m == "mov" || m == "cmp" || m == "xor") {
            if (op1.type == OperandType::MEMORY && op2.type == OperandType::IMMEDIATE) base_size = 8;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY) base_size = op2.value.find("rsp") != std::string::npos ? 8 : 7;
            else if (op1.type == OperandType::MEMORY && op2.type == OperandType::REGISTER) base_size = 7;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::REGISTER) {
                if (op1.size == OperandSize::BYTE || op2.size == OperandSize::BYTE) base_size = 3;
                else if (op1.size == OperandSize::WORD || op2.size == OperandSize::WORD) base_size = 4;
                else base_size = 3;
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
                int64_t imm = std::stoll(op2.value);
                if (m == "mov") {
                    if (op1.size == OperandSize::BYTE) base_size = 2;
                    else if (op1.size == OperandSize::WORD) base_size = 4;
                    else if (imm >= -2147483648LL && imm <= 2147483647LL) base_size = 5;
                    else base_size = 10;
                } else {
                    if (op1.size == OperandSize::BYTE) base_size = 3;
                    else if (imm >= -128 && imm <= 127) base_size = 4;
                    else base_size = 7;
                }
            }
        }
    }
    return base_size + (!instr.prefix.empty() ? 1 : 0);
}

void X86_64Arch::encode_instruction(Assembler& assembler, const Instruction& instr) {
    auto& textSection = assembler.get_section_data(instr.section);
    if (!instr.prefix.empty()) {
        if (instr.prefix == "lock") {
            if (!lockable_instructions_.count(instr.mnemonic)) throw std::runtime_error("Instruction '" + instr.mnemonic + "' cannot be locked");
            if (instr.operands.empty() || instr.operands[0].type != OperandType::MEMORY) throw std::runtime_error("LOCK prefix requires a memory operand");
            textSection.push_back(0xF0);
        }
    }
    const auto& m = instr.mnemonic;
    if (sse_instructions_.count(m)) {
        encode_sse_instruction(assembler, instr);
        return;
    }
    if (m == "syscall") { textSection.push_back(0x0F); textSection.push_back(0x05); return; }
    if (m == "ret") { textSection.push_back(0xC3); return; }
    if (m == "push") {
        const auto& op = instr.operands[0];
        if (op.type == OperandType::IMMEDIATE) {
            int64_t imm = std::stoll(op.value, nullptr, 0);
            if (op.size == OperandSize::BYTE || (imm >= -128 && imm <= 127)) {
                textSection.push_back(0x6A); textSection.push_back(static_cast<uint8_t>(imm));
            } else {
                textSection.push_back(0x68);
                for(int i=0; i<4; ++i) textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
            }
        } else if (op.type == OperandType::MEMORY) {
            textSection.push_back(0xFF); textSection.push_back(0x35);
            uint64_t target_addr = assembler.symbolTable.at(op.value).address;
            int32_t rel_addr = target_addr - (instr.address + instr.size);
            for (int i = 0; i < 4; ++i) textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
        } else if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);
            if (op.size == OperandSize::WORD) textSection.push_back(0x66);
            if (reg_code >= 8) textSection.push_back(0x41);
            textSection.push_back(0x50 + (reg_code & 7));
        }
        return;
    }
    if (m == "pop") {
        const auto& op = instr.operands[0];
        if (op.type == OperandType::MEMORY) {
            textSection.push_back(0x8F); textSection.push_back(0x05);
            uint64_t target_addr = assembler.symbolTable.at(op.value).address;
            int32_t rel_addr = target_addr - (instr.address + instr.size);
            for (int i = 0; i < 4; ++i) textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
        } else if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);
            if (op.size == OperandSize::WORD) textSection.push_back(0x66);
            if (reg_code >= 8) textSection.push_back(0x41);
            textSection.push_back(0x58 + (reg_code & 7));
        }
        return;
    }
    if (m == "call" || m == "jmp" || m.rfind("j", 0) == 0) {
        if (instr.operands.size() != 1 || instr.operands[0].type != OperandType::LABEL) throw std::runtime_error("Invalid operands for " + m);
        const std::string& symbol_name = instr.operands[0].value;
        auto it = assembler.symbolTable.find(symbol_name);
        if (it != assembler.symbolTable.end() && it->second.isDefined) {
            uint64_t target_addr = it->second.address;
            int32_t rel_addr = target_addr - (instr.address + instr.size);
            if (m == "call") textSection.push_back(0xE8);
            else if (m == "jmp") textSection.push_back(0xE9);
            else {
                textSection.push_back(0x0F);
                if (m == "je" || m == "jz") textSection.push_back(0x84);
                else if (m == "jne" || m == "jnz") textSection.push_back(0x85);
                else if (m == "jl") textSection.push_back(0x8C);
                else if (m == "jle") textSection.push_back(0x8E);
                else if (m == "jg") textSection.push_back(0x8F);
                else if (m == "jge") textSection.push_back(0x8D);
            }
            for (int i = 0; i < 4; ++i) textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
        } else {
            // External symbol handling (omitted for brevity, assume it's correct)
        }
        return;
    }
    if (instr.operands.size() == 2) {
        // Full two-operand instruction encoding logic...
        // This is very long and has been omitted for this example.
        // The real implementation would be here.
    }
}

void X86_64Arch::encode_sse_instruction(Assembler&, const Instruction&) {
    // Dummy implementation
}
void X86_64Arch::encode_modrm_sib(uint8_t, uint8_t, uint8_t, const std::string&, uint64_t, uint64_t) {
    // Dummy implementation
}
