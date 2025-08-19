#include "assembler.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>

// Maps x86-64 register names to their 3-bit encoding.
// The 4th bit (for R8-R15) is handled by the REX.B/REX.R prefix.
static const std::map<std::string, uint8_t> register_map = {
    {"rax", 0}, {"eax", 0}, {"ax", 0}, {"al", 0},
    {"rcx", 1}, {"ecx", 1}, {"cx", 1}, {"cl", 1},
    {"rdx", 2}, {"edx", 2}, {"dx", 2}, {"dl", 2},
    {"rbx", 3}, {"ebx", 3}, {"bx", 3}, {"bl", 3},
    {"rsp", 4}, {"esp", 4}, {"sp", 4}, {"spl", 4},
    {"rbp", 5}, {"ebp", 5}, {"bp", 5}, {"bpl", 5},
    {"rsi", 6}, {"esi", 6}, {"si", 6}, {"sil", 6},
    {"rdi", 7}, {"edi", 7}, {"di", 7}, {"dil", 7},
    {"r8", 0}, {"r8d", 0}, {"r8w", 0}, {"r8b", 0},
    {"r9", 1}, {"r9d", 1}, {"r9w", 1}, {"r9b", 1},
    {"r10", 2}, {"r10d", 2}, {"r10w", 2}, {"r10b", 2},
    {"r11", 3}, {"r11d", 3}, {"r11w", 3}, {"r11b", 3},
    {"r12", 4}, {"r12d", 4}, {"r12w", 4}, {"r12b", 4},
    {"r13", 5}, {"r13d", 5}, {"r13w", 5}, {"r13b", 5},
    {"r14", 6}, {"r14d", 6}, {"r14w", 6}, {"r14b", 6},
    {"r15", 7}, {"r15d", 7}, {"r15w", 7}, {"r15b", 7},
};

static bool is_extended_register(const std::string& reg) {
    if (reg.length() < 2 || reg[0] != 'r') return false;
    if (isdigit(reg[1])) {
        if (reg.length() >= 3 && isdigit(reg[2])) {
            return std::stoi(reg.substr(1)) >= 8;
        }
        return reg[1] >= '8';
    }
    return false;
}

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

std::vector<Instruction> Assembler::parse(const std::string& source) {
    std::vector<Instruction> instructions;
    std::istringstream stream(source);
    std::string line;
    Section current_section = Section::TEXT;

    while (std::getline(stream, line)) {
        if (auto pos = line.find(';'); pos != std::string::npos) {
            line = line.substr(0, pos);
        }

        std::istringstream line_stream(line);
        std::string token;
        line_stream >> token;
        if (token.empty()) continue;

        if (token == ".section") {
            std::string section_name;
            line_stream >> section_name;
            if (section_name == ".data") current_section = Section::DATA;
            else if (section_name == ".text") current_section = Section::TEXT;
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
                label_instr.data_str = str_data;
                instructions.push_back(label_instr);
                continue;
            }

            instructions.push_back(label_instr);
            if (next_token.empty()) continue;
            token = next_token;
        }

        if (token == ".global") {
            std::string symbol_name;
            line_stream >> symbol_name;
            global_symbols.insert(symbol_name);
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
                if (!operand.empty()) instr.operands.push_back(operand);
            }
        }
        instructions.push_back(instr);
    }
    return instructions;
}

uint64_t Assembler::get_instruction_size(const Instruction& instr) {
    if (instr.mnemonic == "ret") return 1;
    if (instr.mnemonic == "syscall") return 2;
    if (instr.mnemonic == "call" || instr.mnemonic == "jmp" || instr.mnemonic == "je" || instr.mnemonic == "jne") return 5;
    if (instr.mnemonic == "mov") {
        if (instr.operands.size() != 2) return 0;
        if (register_map.count(instr.operands[1])) return 3; // mov reg, reg
        return 10; // mov reg, imm64
    }
    if (instr.mnemonic == "add" || instr.mnemonic == "sub") {
        if (instr.operands.size() != 2) return 0;
        long imm = std::stol(instr.operands[1]);
        return (imm >= -128 && imm <= 127) ? 4 : 7;
    }
    if (instr.mnemonic == "cmp") {
        if (instr.operands.size() != 2) return 0;
        return 7; // cmp rax, imm32
    }
    return 0;
}

void Assembler::first_pass(std::vector<Instruction>& instructions) {
    uint64_t text_offset = 0;
    uint64_t data_offset = 0;

    for (auto& instr : instructions) {
        instr.address = (instr.section == Section::TEXT) ? textSectionBase + text_offset : dataSectionBase + data_offset;
        if (instr.is_label) {
            symbolTable[instr.label] = {
                instr.label,
                instr.address,
                global_symbols.count(instr.label) > 0,
                false
            };
            if (instr.label == "_start") entryPoint = instr.address;
            if (!instr.data_str.empty()) data_offset += instr.data_str.length() + 1;
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
        if (instr.is_label && !instr.data_str.empty()) {
            dataSection.insert(dataSection.end(), instr.data_str.begin(), instr.data_str.end());
            dataSection.push_back(0);
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            encode_x86_64(instr);
        }
    }
}

void Assembler::encode_x86_64(const Instruction& instr) {
    if (instr.mnemonic == "syscall") { textSection.push_back(0x0F); textSection.push_back(0x05); return; }
    if (instr.mnemonic == "ret") { textSection.push_back(0xC3); return; }

    if (instr.mnemonic == "call" || instr.mnemonic == "jmp" || instr.mnemonic == "je" || instr.mnemonic == "jne") {
        if (instr.operands.size() != 1) throw std::runtime_error("Invalid operands for " + instr.mnemonic);
        if (!symbolTable.count(instr.operands[0])) throw std::runtime_error("Undefined label: " + instr.operands[0]);

        uint64_t target_addr = symbolTable.at(instr.operands[0]).address;
        int32_t rel_addr = target_addr - (instr.address + instr.size);

        if (instr.mnemonic == "call") textSection.push_back(0xE8);
        else if (instr.mnemonic == "jmp") textSection.push_back(0xE9);
        else if (instr.mnemonic == "je") { textSection.push_back(0x0F); textSection.push_back(0x84); }
        else if (instr.mnemonic == "jne") { textSection.push_back(0x0F); textSection.push_back(0x85); }

        for (int i = 0; i < 4; ++i) textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
        return;
    }

    if (instr.operands.size() != 2) throw std::runtime_error("Unsupported number of operands for " + instr.mnemonic);

    std::string dst = instr.operands[0];
    std::string src = instr.operands[1];
    if (!register_map.count(dst)) throw std::runtime_error("Unknown destination register: " + dst);
    uint8_t dst_code = register_map.at(dst);

    if (instr.mnemonic == "mov") {
        if (register_map.count(src)) { // mov reg, reg
            uint8_t src_code = register_map.at(src);
            uint8_t rex = 0x48 | (is_extended_register(src) ? 4 : 0) | (is_extended_register(dst) ? 1 : 0);
            textSection.push_back(rex);
            textSection.push_back(0x89);
            textSection.push_back(0xC0 | (src_code << 3) | dst_code);
        } else { // mov reg, imm64
            uint64_t imm = symbolTable.count(src) ? symbolTable.at(src).address : std::stoll(src);
            uint8_t rex = 0x48 | (is_extended_register(dst) ? 1 : 0);
            textSection.push_back(rex);
            textSection.push_back(0xB8 + dst_code);
            for (int i = 0; i < 8; ++i) textSection.push_back((imm >> (i * 8)) & 0xFF);
        }
    } else if (instr.mnemonic == "add" || instr.mnemonic == "sub") {
        uint8_t opcode_ext = (instr.mnemonic == "add") ? 0 : 5;
        long imm = std::stol(src);
        uint8_t rex = 0x48 | (is_extended_register(dst) ? 1 : 0);
        textSection.push_back(rex);
        if (imm >= -128 && imm <= 127) {
            textSection.push_back(0x83);
            textSection.push_back(0xC0 | (opcode_ext << 3) | dst_code);
            textSection.push_back(static_cast<uint8_t>(imm));
        } else {
            textSection.push_back(0x81);
            textSection.push_back(0xC0 | (opcode_ext << 3) | dst_code);
            for (int i = 0; i < 4; ++i) textSection.push_back((static_cast<uint32_t>(imm) >> (i * 8)) & 0xFF);
        }
    } else if (instr.mnemonic == "cmp") {
        long imm = std::stol(src);
        if (dst != "rax") throw std::runtime_error("CMP only supported with RAX for now");
        textSection.push_back(0x48);
        textSection.push_back(0x3D);
        for (int i = 0; i < 4; ++i) textSection.push_back((static_cast<uint32_t>(imm) >> (i * 8)) & 0xFF);
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

const std::vector<uint8_t>& Assembler::getMachineCode() const { return textSection; }
const std::vector<uint8_t>& Assembler::getBssSection() const { static std::vector<uint8_t> empty; return empty; }
const std::vector<RelocationEntry>& Assembler::getRelocations() const { static std::vector<RelocationEntry> empty; return empty; }
