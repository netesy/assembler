#include "assembler.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>

static const std::map<std::string, uint8_t> register_map = {
    {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
    {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
    {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
    {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
};

Assembler::Assembler(uint64_t textBase, uint64_t dataBase)
    : currentSection(Section::TEXT), textSectionBase(textBase), dataSectionBase(dataBase), entryPoint(0) {}

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
    if (op_str.empty()) return {OperandType::NONE};

    if (op_str.front() == '[' && op_str.back() == ']') {
        return {OperandType::MEMORY, op_str.substr(1, op_str.length() - 2)};
    }

    if (register_map.count(op_str)) {
        return {OperandType::REGISTER, op_str};
    }

    try {
        std::stoll(op_str);
        return {OperandType::IMMEDIATE, op_str};
    } catch (const std::invalid_argument&) {
        // Not a number, so it must be a label for a memory operand
        // This case is typically handled by the [] syntax, but we can be lenient
        return {OperandType::MEMORY, op_str};
    }
}


std::vector<Instruction> Assembler::parse(const std::string& source) {
    std::vector<Instruction> instructions;
    std::istringstream stream(source);
    std::string line;
    Section current_section = Section::TEXT;

    while (std::getline(stream, line)) {
        if (auto pos = line.find(';'); pos != std::string::npos) line = line.substr(0, pos);

        std::istringstream line_stream(line);
        std::string token;
        line_stream >> token;
        if (token.empty()) continue;

        if (token == ".section") {
            line_stream >> token;
            if (token == ".data") current_section = Section::DATA;
            else if (token == ".text") current_section = Section::TEXT;
            continue;
        }

        if (token.back() == ':') {
            std::string label_name = token.substr(0, token.size() - 1);
            Instruction label_instr;
            label_instr.is_label = true;
            label_instr.label = label_name;
            label_instr.section = current_section;

            std::string next_token;
            line_stream >> next_token;

            if (next_token == ".asciz") {
                std::string str_data;
                std::getline(line_stream, str_data);
                if (auto pos = str_data.find_first_not_of(" \t\""); pos != std::string::npos) str_data = str_data.substr(pos);
                if (auto pos = str_data.find_last_of('\"'); pos != std::string::npos) str_data = str_data.substr(0, pos);
                label_instr.data = str_data;
                instructions.push_back(label_instr);
                continue;
            } else if (next_token == ".quad") {
                int64_t val;
                line_stream >> val;
                label_instr.data = val;
                instructions.push_back(label_instr);
                continue;
            }

            instructions.push_back(label_instr);
            if (next_token.empty()) continue;
            token = next_token;
        }

        if (token == ".global") {
            line_stream >> token;
            global_symbols.insert(token);
            continue;
        }

        Instruction instr;
        instr.mnemonic = token;
        instr.section = current_section;

        std::string operand_str;
        if (std::getline(line_stream, operand_str)) {
            std::stringstream ss(operand_str);
            std::string operand;
            while(std::getline(ss, operand, ',')) {
                if (auto pos = operand.find_first_not_of(" \t"); pos != std::string::npos) operand = operand.substr(pos);
                if (auto pos = operand.find_last_not_of(" \t"); pos != std::string::npos) operand = operand.substr(0, pos + 1);
                if (!operand.empty()) instr.operands.push_back(parse_operand(operand));
            }
        }
        instructions.push_back(instr);
    }
    return instructions;
}

uint64_t Assembler::get_instruction_size(const Instruction& instr) {
    const auto& m = instr.mnemonic;
    if (m == "ret") return 1;
    if (m == "syscall") return 2;

    if (m == "mov" || m == "add") {
        if (instr.operands.size() != 2) return 0;
        const auto& dst = instr.operands[0];
        const auto& src = instr.operands[1];

        if (dst.type == OperandType::REGISTER && src.type == OperandType::MEMORY) return 7; // REX + Opcode + ModR/M + disp32
        if (dst.type == OperandType::MEMORY && src.type == OperandType::REGISTER) return 7; // REX + Opcode + ModR/M + disp32
        if (dst.type == OperandType::REGISTER && src.type == OperandType::REGISTER) return 3; // REX + Opcode + ModR/M
        if (dst.type == OperandType::REGISTER && src.type == OperandType::IMMEDIATE) {
            int64_t imm = std::stoll(src.value);
            if (imm >= -2147483648LL && imm <= 2147483647LL) return 7; // REX + Opcode + ModR/M + imm32
            return 10; // REX + Opcode + imm64
        }
    }
    return 0; // Default/unknown
}

void Assembler::first_pass(std::vector<Instruction>& instructions) {
    uint64_t text_offset = 0;
    uint64_t data_offset = 0;

    for (auto& instr : instructions) {
        instr.address = (instr.section == Section::TEXT) ? textSectionBase + text_offset : dataSectionBase + data_offset;
        if (instr.is_label) {
            symbolTable[instr.label] = { instr.label, instr.address, global_symbols.count(instr.label) > 0, false };
            if (instr.label == "_start") entryPoint = instr.address;

            if (std::holds_alternative<std::string>(instr.data)) {
                data_offset += std::get<std::string>(instr.data).length() + 1;
            } else if (std::holds_alternative<int64_t>(instr.data)) {
                data_offset += 8; // .quad
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            instr.size = get_instruction_size(instr);
            text_offset += instr.size;
        }
    }
}

void Assembler::second_pass(const std::vector<Instruction>& instructions) {
    textSection.clear();
    dataSection.clear();

    for (const auto& instr : instructions) {
        if (instr.is_label) {
            if (std::holds_alternative<std::string>(instr.data)) {
                const auto& str = std::get<std::string>(instr.data);
                dataSection.insert(dataSection.end(), str.begin(), str.end());
                dataSection.push_back(0);
            } else if (std::holds_alternative<int64_t>(instr.data)) {
                int64_t val = std::get<int64_t>(instr.data);
                for(int i=0; i<8; ++i) dataSection.push_back((val >> (i*8)) & 0xFF);
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            encode_x86_64(instr);
        }
    }
}

void Assembler::encode_x86_64(const Instruction& instr) {
    if (instr.mnemonic == "syscall") { textSection.push_back(0x0F); textSection.push_back(0x05); return; }
    if (instr.mnemonic == "ret") { textSection.push_back(0xC3); return; }

    if (instr.operands.size() != 2) throw std::runtime_error("Unsupported operands for " + instr.mnemonic);

    const auto& op1 = instr.operands[0];
    const auto& op2 = instr.operands[1];

    uint8_t opcode = 0;
    if (instr.mnemonic == "mov") opcode = 0x8B; // mov reg, r/m
    if (instr.mnemonic == "add") opcode = 0x03; // add reg, r/m

    // reg, r/m
    if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY) {
        uint8_t reg_code = register_map.at(op1.value);
        bool is_ext_reg = reg_code >= 8;
        uint8_t rex = 0x48 | (is_ext_reg ? 4 : 0);
        textSection.push_back(rex);
        textSection.push_back(opcode);
        // ModR/M for [rip+disp32] is mod=00, reg=reg_code, rm=101
        textSection.push_back( (0b00 << 6) | ((reg_code & 7) << 3) | 0b101 );
        int32_t disp = symbolTable.at(op2.value).address - (instr.address + instr.size);
        for(int i=0; i<4; ++i) textSection.push_back((disp >> (i*8)) & 0xFF);
    }
    // r/m, reg
    else if (op1.type == OperandType::MEMORY && op2.type == OperandType::REGISTER) {
        if (instr.mnemonic == "mov") opcode = 0x89; // mov r/m, reg
        if (instr.mnemonic == "add") opcode = 0x01; // add r/m, reg
        uint8_t reg_code = register_map.at(op2.value);
        bool is_ext_reg = reg_code >= 8;
        uint8_t rex = 0x48 | (is_ext_reg ? 4 : 0);
        textSection.push_back(rex);
        textSection.push_back(opcode);
        textSection.push_back( (0b00 << 6) | ((reg_code & 7) << 3) | 0b101 );
        int32_t disp = symbolTable.at(op1.value).address - (instr.address + instr.size);
        for(int i=0; i<4; ++i) textSection.push_back((disp >> (i*8)) & 0xFF);
    }
    // reg, reg
    else if (op1.type == OperandType::REGISTER && op2.type == OperandType::REGISTER) {
         if (instr.mnemonic == "mov") opcode = 0x89; // mov r/m, reg
         if (instr.mnemonic == "add") opcode = 0x01; // add r/m, reg
         uint8_t dst_code = register_map.at(op1.value);
         uint8_t src_code = register_map.at(op2.value);
         uint8_t rex = 0x48 | ( (src_code >= 8) ? 4 : 0) | ( (dst_code >= 8) ? 1 : 0);
         textSection.push_back(rex);
         textSection.push_back(opcode);
         textSection.push_back(0xC0 | ((src_code & 7) << 3) | (dst_code & 7));
    }
    // reg, imm
    else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
        uint8_t reg_code = register_map.at(op1.value);
        uint8_t rex = 0x48 | ((reg_code >= 8) ? 1 : 0);
        textSection.push_back(rex);
        textSection.push_back(0xC7);
        textSection.push_back(0xC0 | (reg_code & 7));
        int32_t imm = std::stoll(op2.value);
        for(int i=0; i<4; ++i) textSection.push_back((imm >> (i*8)) & 0xFF);
    }
}

const std::unordered_map<std::string, SymbolEntry>& Assembler::getSymbols() const { return symbolTable; }
const std::vector<uint8_t>& Assembler::getTextSection() const { return textSection; }
const std::vector<uint8_t>& Assembler::getDataSection() const { return dataSection; }
uint64_t Assembler::getEntryPoint() const { return entryPoint; }

void Assembler::printDebugInfo() const {
    std::cout << "\n==== ASSEMBLER DEBUG INFORMATION ====\n\n";
    std::cout << "SYMBOLS:\n";
    for(const auto& pair : symbolTable) {
        std::cout << "  " << pair.first << ": 0x" << std::hex << pair.second.address << " (global: " << pair.second.isGlobal << ")\n";
    }
    std::cout << "\nENTRY POINT: 0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "\nSECTION SIZES:\n";
    std::cout << "  .text: " << textSection.size() << " bytes\n";
    std::cout << "  .data: " << dataSection.size() << " bytes\n";
    std::cout << "\n.text hexdump:\n";
    for(size_t i = 0; i < textSection.size(); ++i) {
        printf("%02x ", textSection[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
    std::cout << "\n==== END DEBUG INFORMATION ====\n\n";
}
