#include "assembler.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <set>
#include <cstdint>

static const std::map<std::string, uint8_t> register_map = {
    {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
    {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
    {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
    {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
};

static const std::set<std::string> lockable_instructions = {
    "add", "adc", "and", "btc", "btr", "bts", "cmpxchg", "dec", "inc", "neg", "not", "or", "sbb", "sub", "xor", "xadd", "xchg"
};

Assembler::Assembler(uint64_t textBase, uint64_t dataBase)
    : textSectionBase(textBase), dataSectionBase(dataBase), entryPoint(0) {}

bool Assembler::assemble(const std::string &source, const std::string &outputFile) {
    try {
        auto instructions = parse(source);
        first_pass(instructions);
        second_pass(instructions);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Assembly Error: " << e.what() << std::endl;
        return false;
    }
}

Operand Assembler::parse_operand(const std::string& op_str) {
    if (op_str.empty()) throw std::runtime_error("Empty operand string.");
    if (op_str.front() == '[' && op_str.back() == ']') {
        std::string expr = op_str.substr(1, op_str.length() - 2);
        size_t plus_pos = expr.find('+');
        if (plus_pos != std::string::npos) {
            std::string base = expr.substr(0, plus_pos);
            int64_t disp = std::stoll(expr.substr(plus_pos + 1));
            return {OperandType::MEMORY_REG_DISP, MemoryOperand{base, "", 1, disp}};
        }
        return {OperandType::MEMORY_LABEL, expr};
    }
    if (register_map.count(op_str)) {
        return {OperandType::REGISTER, op_str};
    }
    try {
        return {OperandType::IMMEDIATE, std::stoll(op_str)};
    } catch (const std::invalid_argument&) { return {OperandType::MEMORY_LABEL, op_str}; }
}

std::vector<Instruction> Assembler::parse(const std::string& source) {
    std::vector<Instruction> instructions;
    std::istringstream stream(source);
    std::string line;
    Section current_section = Section::TEXT;

    while (std::getline(stream, line)) {
        if (auto pos = line.find(';'); pos != std::string::npos) line = line.substr(0, pos);

        std::string trimmed_line;
        if (auto pos = line.find_first_not_of(" \t"); pos != std::string::npos) trimmed_line = line.substr(pos);
        if (trimmed_line.empty()) continue;

        std::string first_token = trimmed_line.substr(0, trimmed_line.find(' '));
        if (first_token.back() == ':') {
            instructions.push_back({"", {}, current_section, "", true, first_token.substr(0, first_token.size() - 1)});
            continue;
        }

        std::istringstream line_stream(trimmed_line);
        std::string token;
        line_stream >> token;

        if (token == ".section") {
            line_stream >> token;
            if (token == ".data") current_section = Section::DATA;
            else if (token == ".text") current_section = Section::TEXT;
            continue;
        }
        if (token == ".global") { line_stream >> token; global_symbols.insert(token); continue; }
        if (token == ".quad") {
            if (instructions.empty() || !instructions.back().is_label) throw std::runtime_error(".quad without a label");
            int64_t val; line_stream >> val;
            instructions.back().data = val;
            continue;
        }

        Instruction instr;
        instr.section = current_section;

        if (token == "lock") {
            instr.prefix = token;
            line_stream >> instr.mnemonic;
        } else {
            instr.mnemonic = token;
        }
        
        std::string operand_str;
        if (std::getline(line_stream, operand_str)) {
            std::stringstream ss(operand_str);
            std::string op;
            while(std::getline(ss, op, ',')) {
                if (auto pos = op.find_first_not_of(" \t"); pos != std::string::npos) op = op.substr(pos);
                if (auto pos = op.find_last_not_of(" \t"); pos != std::string::npos) op = op.substr(0, pos + 1);
                if (!op.empty()) instr.operands.push_back(parse_operand(op));
            }
        }
        instructions.push_back(instr);
    }
    return instructions;
}

uint64_t Assembler::get_instruction_size(const Instruction& instr) {
    const auto& m = instr.mnemonic;
    uint64_t base_size = 0;
    if (m == "ret") base_size = 1;
    else if (m == "syscall") base_size = 2;
    else if (m == "push") {
        if (instr.operands.empty()) return 0;
        if (instr.operands[0].type == OperandType::REGISTER) base_size = (register_map.at(std::get<std::string>(instr.operands[0].value)) >= 8) ? 2 : 1;
        else if (instr.operands[0].type == OperandType::IMMEDIATE) base_size = 5;
    }
    else if (m == "pop") {
        if (instr.operands.empty()) return 0;
        base_size = (register_map.at(std::get<std::string>(instr.operands[0].value)) >= 8) ? 2 : 1;
    }
    else if (m == "call" || m == "jmp") base_size = 5;
    else if (m == "je" || m == "jne" || m == "jz" || m == "jnz" || m == "jl" || m == "jle" || m == "jg" || m == "jge") base_size = 6;
    else if (instr.operands.size() == 2) {
        const auto& op1 = instr.operands[0];
        const auto& op2 = instr.operands[1];
        if (m == "add" || m == "sub" || m == "mov" || m == "cmp") {
            if (op1.type == OperandType::MEMORY_LABEL && op2.type == OperandType::IMMEDIATE) base_size = 8;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY_LABEL) base_size = 7;
            else if (op1.type == OperandType::MEMORY_LABEL && op2.type == OperandType::REGISTER) base_size = 7;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY_REG_DISP) base_size = 3;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::REGISTER) base_size = 3;
            else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
                int64_t imm = std::get<int64_t>(op2.value);
                if (m == "mov") base_size = (imm >= -2147483648LL && imm <= 2147483647LL) ? 5 : 10;
                else base_size = (imm >= -128 && imm <= 127) ? 4 : 7;
            }
        }
    }
    return base_size + (!instr.prefix.empty() ? 1 : 0);
}

void Assembler::first_pass(std::vector<Instruction>& instructions) {
    uint64_t text_offset = 0, data_offset = 0;
    for (auto& instr : instructions) {
        if (instr.section == Section::TEXT) {
            instr.address = textSectionBase + text_offset;
            if (instr.is_label) {
                symbolTable[instr.label] = { instr.label, instr.address, global_symbols.count(instr.label) > 0 };
                if (instr.label == "_start") entryPoint = instr.address;
            } else if (!instr.mnemonic.empty()) {
                instr.size = get_instruction_size(instr);
                text_offset += instr.size;
            }
        } else if (instr.section == Section::DATA) {
            instr.address = dataSectionBase + data_offset;
            if (instr.is_label) {
                symbolTable[instr.label] = { instr.label, instr.address, global_symbols.count(instr.label) > 0 };
                if (std::holds_alternative<int64_t>(instr.data)) data_offset += 8;
            }
        }
    }
}

void Assembler::second_pass(const std::vector<Instruction>& instructions) {
    textSection.clear(); dataSection.clear();
    for (const auto& instr : instructions) {
        if (instr.is_label) {
            if (std::holds_alternative<int64_t>(instr.data)) {
                int64_t val = std::get<int64_t>(instr.data);
                for(int i=0; i<8; ++i) dataSection.push_back((val >> (i*8)) & 0xFF);
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            encode_x86_64(instr);
        }
    }
}

void Assembler::encode_x86_64(const Instruction& instr) {
    if (!instr.prefix.empty()) {
        if (instr.prefix == "lock") {
            // Validation...
            textSection.push_back(0xF0);
        }
    }
    const auto& m = instr.mnemonic;
    if (m == "syscall") { textSection.push_back(0x0F); textSection.push_back(0x05); return; }
    if (m == "ret") { textSection.push_back(0xC3); return; }
    if (m == "push") {
        if (instr.operands[0].type == OperandType::IMMEDIATE) {
            textSection.push_back(0x68);
            int32_t imm = std::get<int64_t>(instr.operands[0].value);
            for(int i=0; i<4; ++i) textSection.push_back((imm >> (i*8)) & 0xFF);
        } else {
            uint8_t reg_code = register_map.at(std::get<std::string>(instr.operands[0].value));
            if (reg_code >= 8) textSection.push_back(0x41);
            textSection.push_back(0x50 + (reg_code & 7));
        }
        return;
    }
    if (m == "pop") {
        uint8_t reg_code = register_map.at(std::get<std::string>(instr.operands[0].value));
        if (reg_code >= 8) textSection.push_back(0x41);
        textSection.push_back(0x58 + (reg_code & 7));
        return;
    }
    if (m == "call" || m == "jmp" || m.rfind("j", 0) == 0) {
        uint64_t target_addr = symbolTable.at(std::get<std::string>(instr.operands[0].value)).address;
        int32_t rel_addr = target_addr - (instr.address + instr.size);
        if (m == "call") textSection.push_back(0xE8);
        else if (m == "jmp") textSection.push_back(0xE9);
        else {
            textSection.push_back(0x0F);
            if (m == "je" || m == "jz") textSection.push_back(0x84); else if (m == "jne" || m == "jnz") textSection.push_back(0x85);
            else if (m == "jl") textSection.push_back(0x8C); else if (m == "jle") textSection.push_back(0x8E);
            else if (m == "jg") textSection.push_back(0x8F); else if (m == "jge") textSection.push_back(0x8D);
        }
        for (int i = 0; i < 4; ++i) textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
        return;
    }
    if (instr.operands.size() != 2) throw std::runtime_error("Unsupported operands for " + m);
    const auto& op1 = instr.operands[0];
    const auto& op2 = instr.operands[1];
    if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY_LABEL) {
        uint8_t opcode = (m == "mov") ? 0x8B : (m == "add") ? 0x03 : 0x2B;
        uint8_t reg_code = register_map.at(std::get<std::string>(op1.value));
        textSection.push_back(0x48 | (reg_code >= 8 ? 4 : 0));
        textSection.push_back(opcode);
        textSection.push_back(0x05 | ((reg_code & 7) << 3));
        int32_t disp = symbolTable.at(std::get<std::string>(op2.value)).address - (instr.address + instr.size);
        for(int i=0; i<4; ++i) textSection.push_back((disp >> (i*8)) & 0xFF);
    } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY_REG_DISP) {
        uint8_t opcode = 0x8B;
        uint8_t reg_code = register_map.at(std::get<std::string>(op1.value));
        const auto& mem = std::get<MemoryOperand>(op2.value);
        uint8_t base_code = register_map.at(mem.base_reg);
        textSection.push_back(0x48 | (reg_code >= 8 ? 4 : 0) | (base_code >= 8 ? 1 : 0));
        textSection.push_back(opcode);
        textSection.push_back(0x40 | ((reg_code & 7) << 3) | (base_code & 7));
        if (base_code == 4 || base_code == 12) textSection.push_back(0x24);
        textSection.push_back(mem.displacement);
    } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
        uint8_t reg_code = register_map.at(std::get<std::string>(op1.value));
        int64_t imm = std::get<int64_t>(op2.value);
        uint8_t rex = 0x48 | (reg_code >= 8 ? 1 : 0);
        if (m == "mov") {
            textSection.push_back(rex);
            if (imm >= -2147483648LL && imm <= 2147483647LL) {
                textSection.push_back(0xC7); textSection.push_back(0xC0 | (reg_code & 7));
                for(int i=0; i<4; ++i) textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
            } else {
                textSection.push_back(0xB8 + (reg_code & 7));
                for(int i=0; i<8; ++i) textSection.push_back((imm >> (i*8)) & 0xFF);
            }
        } else {
            uint8_t modrm_ext = (m == "add") ? 0 : (m == "sub") ? 5 : 7;
            textSection.push_back(rex);
            textSection.push_back((imm >= -128 && imm <= 127) ? 0x83 : 0x81);
            textSection.push_back(0xC0 | (modrm_ext << 3) | (reg_code & 7));
            if (imm >= -128 && imm <= 127) textSection.push_back(static_cast<uint8_t>(imm));
            else for(int i=0; i<4; ++i) textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
        }
    }
}

const std::unordered_map<std::string, SymbolEntry>& Assembler::getSymbols() const { return symbolTable; }
const std::vector<uint8_t>& Assembler::getTextSection() const { return textSection; }
const std::vector<uint8_t>& Assembler::getDataSection() const { return dataSection; }
uint64_t Assembler::getEntryPoint() const { return entryPoint; }
void Assembler::printDebugInfo() const { /* ... */ }
