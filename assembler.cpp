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
            return std::stoi(reg.substr(1)) >= 8; // Handles r10-r15
        }
        return reg[1] >= '8'; // Handles r8, r9
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
        // Remove comments
        if (auto pos = line.find(';'); pos != std::string::npos) {
            line = line.substr(0, pos);
        }

        std::istringstream line_stream(line);
        std::string first_token;
        line_stream >> first_token;

        if (first_token.empty()) continue;

        if (first_token == ".section") {
            std::string section_name;
            line_stream >> section_name;
            if (section_name == ".data") current_section = Section::DATA;
            else if (section_name == ".text") current_section = Section::TEXT;
            else if (section_name == ".bss") current_section = Section::BSS;
            continue;
        }

        if (first_token.back() == ':') {
            std::string label_name = first_token.substr(0, first_token.size() - 1);
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
            first_token = next_token;
        }

        if (first_token == ".global") {
            std::string symbol_name;
            line_stream >> symbol_name;
            global_symbols.insert(symbol_name);
            continue;
        }

        Instruction instr;
        instr.mnemonic = first_token;
        instr.section = current_section;

        std::string operand_str;
        if (std::getline(line_stream, operand_str)) {
            std::stringstream ss(operand_str);
            std::string operand;
            while(std::getline(ss, operand, ',')) {
                // trim whitespace
                if (auto pos = operand.find_first_not_of(" \t"); pos != std::string::npos) {
                    operand = operand.substr(pos);
                }
                if (auto pos = operand.find_last_not_of(" \t"); pos != std::string::npos) {
                    operand = operand.substr(0, pos + 1);
                }
                if (!operand.empty()) {
                    instr.operands.push_back(operand);
                }
            }
        }
        instructions.push_back(instr);
    }
    return instructions;
}

void Assembler::first_pass(const std::vector<Instruction>& instructions) {
    uint64_t text_offset = 0;
    uint64_t data_offset = 0;

    for (const auto& instr : instructions) {
        if (instr.is_label) {
            uint64_t address = 0;
            if (instr.section == Section::TEXT) {
                address = textSectionBase + text_offset;
            } else if (instr.section == Section::DATA) {
                address = dataSectionBase + data_offset;
            }

            symbolTable[instr.label] = {
                instr.label,
                address,
                global_symbols.count(instr.label) > 0,
                false
            };

            if (instr.label == "_start") {
                entryPoint = address;
            }

            if (!instr.data_str.empty()) {
                data_offset += instr.data_str.length() + 1; // +1 for null terminator
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            // Rough estimation of instruction size. This will be refined in second pass.
            // For now, this is a placeholder as the exact encoding is complex.
            // Let's assume a simplified encoding scheme for now.
            if(instr.mnemonic == "syscall") text_offset += 2;
            else if(instr.mnemonic == "mov" && instr.operands.size() == 2) {
                if(register_map.count(instr.operands[0]) && !register_map.count(instr.operands[1])) {
                    // mov reg, imm
                    text_offset += 7; // REX.W + opcode + ModR/M + 4-byte immediate
                } else {
                    // mov reg, reg
                    text_offset += 3;
                }
            }
             else if(instr.mnemonic == "add" || instr.mnemonic == "sub") text_offset += 4;
        }
    }
}

void Assembler::second_pass(const std::vector<Instruction>& instructions) {
    textSection.clear();
    dataSection.clear();

    for (const auto& instr : instructions) {
        if (instr.is_label && !instr.data_str.empty()) {
            dataSection.insert(dataSection.end(), instr.data_str.begin(), instr.data_str.end());
            dataSection.push_back(0); // Null terminator for .asciz
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            encode_x86_64(instr);
        }
    }
}

void Assembler::encode_x86_64(const Instruction& instr) {
    if (instr.mnemonic == "syscall") {
        textSection.push_back(0x0F);
        textSection.push_back(0x05);
        return;
    }

    if (instr.operands.size() != 2) {
        throw std::runtime_error("Unsupported number of operands for " + instr.mnemonic);
    }

    std::string dst = instr.operands[0];
    std::string src = instr.operands[1];

    auto it_dst = register_map.find(dst);
    if (it_dst == register_map.end()) {
        throw std::runtime_error("Unknown destination register: " + dst);
    }
    uint8_t dst_code = it_dst->second;

    uint8_t REX_W = 0x48; // 64-bit operand size
    uint8_t REX_R = is_extended_register(dst) ? 0x4C : 0x48;
    uint8_t REX_B = 0; // Reset for each instruction

    // Handle mov
    if (instr.mnemonic == "mov") {
        auto it_src = register_map.find(src);
        if (it_src != register_map.end()) { // mov reg, reg
            uint8_t src_code = it_src->second;
            REX_R = is_extended_register(src) ? 0x4D : 0x48;
            REX_B = is_extended_register(dst) ? 0x49 : 0x48;
            if(is_extended_register(src) && is_extended_register(dst)) REX_B = 0x4D;

            textSection.push_back( (REX_W & 0xF0) | (is_extended_register(src) ? 4 : 0) | (is_extended_register(dst) ? 1 : 0) );
            textSection.push_back(0x89);
            textSection.push_back(0xC0 | (src_code << 3) | dst_code);
        } else { // mov reg, imm or mov reg, label
            uint64_t imm = 0;
            bool is_label = symbolTable.count(src);
            if (is_label) {
                imm = symbolTable.at(src).address;
            } else {
                imm = std::stoll(src);
            }

            if (is_extended_register(dst)) REX_B = 0x49;
            textSection.push_back(REX_B != 0 ? REX_B : REX_W);
            textSection.push_back(0xB8 + dst_code);
            for (int i = 0; i < 8; ++i) {
                textSection.push_back((imm >> (i * 8)) & 0xFF);
            }
        }
    }
    // Handle add/sub
    else if (instr.mnemonic == "add" || instr.mnemonic == "sub") {
        uint8_t opcode_ext = (instr.mnemonic == "add") ? 0 : 5;
        long imm = std::stol(src);

        REX_B = is_extended_register(dst) ? 0x49 : 0x48;
        textSection.push_back(REX_B);

        if (imm >= -128 && imm <= 127) { // 8-bit immediate
            textSection.push_back(0x83);
            textSection.push_back(0xC0 | (opcode_ext << 3) | dst_code);
            textSection.push_back(static_cast<uint8_t>(imm));
        } else { // 32-bit immediate
            textSection.push_back(0x81);
            textSection.push_back(0xC0 | (opcode_ext << 3) | dst_code);
            uint32_t imm32 = imm;
            for (int i = 0; i < 4; ++i) {
                textSection.push_back((imm32 >> (i * 8)) & 0xFF);
            }
        }
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
        std::cout << "  " << pair.first << ": 0x" << std::hex << pair.second.address
                  << " (global: " << pair.second.isGlobal << ")\n";
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

// Stubs for old methods that are not used in the new flow
const std::vector<uint8_t>& Assembler::getMachineCode() const { return textSection; }
const std::vector<uint8_t>& Assembler::getBssSection() const { static std::vector<uint8_t> empty; return empty; }
const std::vector<RelocationEntry>& Assembler::getRelocations() const { static std::vector<RelocationEntry> empty; return empty; }
