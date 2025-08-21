#include "assembler.hh"
#include "parser.hh"
#include "translator.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <set>
#include <fstream>

// COFF structures
struct COFFHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct Symbol {
    char Name[8];
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
};

static const std::map<std::string, uint8_t> register_map = {
    {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
    {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
    {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
    {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
    {"eax", 0}, {"ecx", 1}, {"edx", 2}, {"ebx", 3},
    {"esp", 4}, {"ebp", 5}, {"esi", 6}, {"edi", 7},
    {"r8d", 8}, {"r9d", 9}, {"r10d", 10}, {"r11d", 11},
    {"r12d", 12}, {"r13d", 13}, {"r14d", 14}, {"r15d", 15},
    {"ax", 0}, {"cx", 1}, {"dx", 2}, {"bx", 3},
    {"sp", 4}, {"bp", 5}, {"si", 6}, {"di", 7},
    {"r8w", 8}, {"r9w", 9}, {"r10w", 10}, {"r11w", 11},
    {"r12w", 12}, {"r13w", 13}, {"r14w", 14}, {"r15w", 15},
    {"al", 0}, {"cl", 1}, {"dl", 2}, {"bl", 3},
    {"ah", 4}, {"ch", 5}, {"dh", 6}, {"bh", 7},
    {"r8b", 8}, {"r9b", 9}, {"r10b", 10}, {"r11b", 11},
    {"r12b", 12}, {"r13b", 13}, {"r14b", 14}, {"r15b", 15}
};

static const std::map<std::string, uint8_t> xmm_register_map = {
    {"xmm0", 0}, {"xmm1", 1}, {"xmm2", 2}, {"xmm3", 3},
    {"xmm4", 4}, {"xmm5", 5}, {"xmm6", 6}, {"xmm7", 7},
    {"xmm8", 8}, {"xmm9", 9}, {"xmm10", 10}, {"xmm11", 11},
    {"xmm12", 12}, {"xmm13", 13}, {"xmm14", 14}, {"xmm15", 15}
};

static const std::set<std::string> lockable_instructions = {
    "add", "adc", "and", "btc", "btr", "bts", "cmpxchg", "dec", "inc",
    "neg", "not", "or", "sbb", "sub", "xor", "xadd", "xchg"
};

static const std::set<std::string> sse_instructions = {
    "movss", "movsd", "movaps", "movapd", "movups", "movupd",
    "addss", "addsd", "addps", "addpd", "subss", "subsd", "subps", "subpd",
    "mulss", "mulsd", "mulps", "mulpd", "divss", "divsd", "divps", "divpd",
    "cmpss", "cmpsd", "cmpps", "cmppd", "ucomiss", "ucomisd"
};

Assembler::Assembler(const std::string& target_format, uint64_t textBase, uint64_t dataBase)
    : textSectionBase(textBase), dataSectionBase(dataBase),
      bssSectionBase(dataBase + 0x1000), rodataSectionBase(dataBase + 0x2000),
      entryPoint(0), target_format_(target_format), parser_(*this), translator_(*this) {
    includePaths.push_back("."); // Default include path
}

bool Assembler::assemble(const std::string &source, const std::string &outputFile) {
    try {
        auto instructions = preprocess(source);
        translator_.translate_syscalls_to_winapi(instructions);
        first_pass(instructions);
        second_pass(instructions);

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Assembly Error: " << e.what() << std::endl;
        return false;
    }
}

bool Assembler::assembleFile(const std::string &inputFile, const std::string &outputFile) {
    std::ifstream file(inputFile);
    if (!file) {
        std::cerr << "Cannot open input file: " << inputFile << std::endl;
        return false;
    }
    std::string source((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    return assemble(source, outputFile);
}

std::vector<Instruction> Assembler::preprocess(const std::string& source) {
    std::string processed = process_includes(source);
    auto instructions = parser_.parse(processed);
    return expand_macros(instructions);
}

std::string Assembler::process_includes(const std::string& source) {
    std::istringstream stream(source);
    std::ostringstream result;
    std::string line;

    while (std::getline(stream, line)) {
        std::istringstream line_stream(line);
        std::string token;
        line_stream >> token;

        if (token == "%include") {
            std::string filename;
            line_stream >> filename;
            // Remove quotes if present
            if (filename.front() == '"' && filename.back() == '"') {
                filename = filename.substr(1, filename.length() - 2);
            }

            // Try to find file in include paths
            bool found = false;
            for (const auto& path : includePaths) {
                std::string fullPath = path + "/" + filename;
                std::ifstream incFile(fullPath);
                if (incFile) {
                    std::string incContent((std::istreambuf_iterator<char>(incFile)),
                                           std::istreambuf_iterator<char>());
                    result << process_includes(incContent) << "\n"; // Recursive include
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw std::runtime_error("Cannot find include file: " + filename);
            }
        } else {
            result << line << "\n";
        }
    }
    return result.str();
}

bool Assembler::is_register(const std::string& reg) const {
    return register_map.count(reg);
}

bool Assembler::is_xmm_register(const std::string& reg) const {
    return xmm_register_map.count(reg);
}

bool Assembler::is_macro_call(const std::string& mnemonic) const {
    return macros.count(mnemonic) > 0;
}

std::vector<std::string> expand_macro_call(const std::string& macro_name,
                                           const std::vector<std::string>& args,
                                           const std::unordered_map<std::string, Macro>& macros) {
    if (!macros.count(macro_name)) return {};

    const auto& macro = macros.at(macro_name);
    std::vector<std::string> expanded;

    for (const auto& line : macro.body) {
        std::string expanded_line = line;
        for (size_t i = 0; i < macro.parameters.size() && i < args.size(); ++i) {
            std::string param_placeholder = "%" + std::to_string(i + 1);
            size_t pos = 0;
            while ((pos = expanded_line.find(param_placeholder, pos)) != std::string::npos) {
                expanded_line.replace(pos, param_placeholder.length(), args[i]);
                pos += args[i].length();
            }
        }
        expanded.push_back(expanded_line);
    }

    return expanded;
}

std::vector<Instruction> Assembler::expand_macros(const std::vector<Instruction>& instructions) {
    std::vector<Instruction> expanded;
    for (const auto& instr : instructions) {
        if (is_macro_call(instr.mnemonic)) {
            std::vector<std::string> args;
            for (const auto& op : instr.operands) {
                args.push_back(op.value);
            }
            auto macro_lines = expand_macro_call(instr.mnemonic, args, macros);
            for (const auto& line : macro_lines) {
                auto macro_instrs = parser_.parse(line);
                for (auto& macro_instr : macro_instrs) {
                    macro_instr.from_macro = true;
                    macro_instr.original_line = instr.original_line;
                    expanded.push_back(macro_instr);
                }
            }
        } else {
            expanded.push_back(instr);
        }
    }
    return expanded;
}

uint8_t Assembler::get_register_code(const std::string& reg) const {
    auto it = register_map.find(reg);
    if (it != register_map.end()) {
        return it->second;
    }
    throw std::runtime_error("Unknown register: " + reg);
}

uint8_t Assembler::get_xmm_register_code(const std::string& reg) const {
    auto it = xmm_register_map.find(reg);
    if (it != xmm_register_map.end()) {
        return it->second;
    }
    throw std::runtime_error("Unknown XMM register: " + reg);
}

void Assembler::encode_modrm_sib(uint8_t mod, uint8_t reg, uint8_t rm,
                                 const std::string& memory_expr, uint64_t instr_addr, uint64_t instr_size) {
    // Simplified implementation for now
}

uint64_t Assembler::get_section_base_address(Section section) const {
    switch (section) {
    case Section::TEXT: return textSectionBase;
    case Section::DATA: return dataSectionBase;
    case Section::BSS: return bssSectionBase;
    case Section::RODATA: return rodataSectionBase;
    default: return 0; // Default for custom/unknown sections
    }
}

uint64_t Assembler::getSectionBase(Section s) const {
    return get_section_base_address(s);
}

std::string Assembler::getSectionName(Section s) const {
    for (const auto& pair : sectionInfoMap) {
        if (pair.second.type == s) {
            return pair.first;
        }
    }
    return "";
}

std::vector<uint8_t>& Assembler::get_section_data(Section section) {
    switch (section) {
    case Section::TEXT: return textSection;
    case Section::DATA: return dataSection;
    case Section::BSS: return bssSection;
    case Section::RODATA: return rodataSection;
    default: throw std::runtime_error("Invalid section for data access");
    }
}

uint64_t Assembler::get_instruction_size(const Instruction& instr) {
    if (instr.is_label) return 0;

    uint64_t base_size = 0;
    const auto& m = instr.mnemonic;

    // SSE instructions
    if (sse_instructions.count(m)) {
        if (m.find("ss") != std::string::npos || m.find("sd") != std::string::npos) {
            // Scalar SSE - typically 4-5 bytes
            base_size = 4;
            if (instr.operands.size() == 2 && instr.operands[1].type == OperandType::MEMORY) {
                base_size += 3; // Additional bytes for memory addressing
            }
        } else {
            // Packed SSE - typically 3-4 bytes
            base_size = 3;
            if (instr.operands.size() == 2 && instr.operands[1].type == OperandType::MEMORY) {
                base_size += 3; // Additional bytes for memory addressing
            }
        }
        return base_size + (!instr.prefix.empty() ? 1 : 0);
    }

    if (m == "ret") base_size = 1;
    else if (m == "syscall") base_size = 2;
    else if (m == "push") {
        if (instr.operands.empty()) return 0;
        const auto& op = instr.operands[0];
        if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);
            base_size = (reg_code >= 8) ? 2 : 1;
        } else if (op.type == OperandType::MEMORY) {
            base_size = 6;
        } else if (op.type == OperandType::IMMEDIATE) {
            // Size depends on operand size
            if (op.size == OperandSize::BYTE) base_size = 2;
            else if (op.size == OperandSize::WORD) base_size = 4;
            else base_size = 5; // 32-bit immediate
        }
    }
    else if (m == "pop") {
        if (instr.operands.empty()) return 0;
        const auto& op = instr.operands[0];
        if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);
            base_size = (reg_code >= 8) ? 2 : 1;
        } else if (op.type == OperandType::MEMORY) {
            base_size = 6;
        }
    }
    else if (m == "call" || m == "jmp") base_size = 5;
    else if (m == "je" || m == "jne" || m == "jz" || m == "jnz" ||
             m == "jl" || m == "jle" || m == "jg" || m == "jge") base_size = 6;
    else if (instr.operands.size() == 2) {
        const auto& op1 = instr.operands[0];
        const auto& op2 = instr.operands[1];

        if (m == "add" || m == "sub" || m == "mov" || m == "cmp" || m == "xor") {
            if (op1.type == OperandType::MEMORY && op2.type == OperandType::IMMEDIATE) {
                base_size = 8;
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY) {
                if (op2.value.find("rsp") != std::string::npos) base_size = 8;
                else base_size = 7;
            } else if (op1.type == OperandType::MEMORY && op2.type == OperandType::REGISTER) {
                base_size = 7;
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::REGISTER) {
                // Size depends on operand size
                if (op1.size == OperandSize::BYTE || op2.size == OperandSize::BYTE) {
                    base_size = 3; // REX + opcode + ModR/M
                } else if (op1.size == OperandSize::WORD || op2.size == OperandSize::WORD) {
                    base_size = 4; // 66h prefix + REX + opcode + ModR/M
                } else {
                    base_size = 3; // REX + opcode + ModR/M
                }
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
                int64_t imm = std::stoll(op2.value);
                if (m == "mov") {
                    if (op1.size == OperandSize::BYTE) base_size = 2;
                    else if (op1.size == OperandSize::WORD) base_size = 4;
                    else if (imm >= -2147483648LL && imm <= 2147483647LL) base_size = 5;
                    else base_size = 10;
                } else {
                    if (op1.size == OperandSize::BYTE) {
                        base_size = 3; // REX + opcode + ModR/M + imm8
                    } else if (imm >= -128 && imm <= 127) {
                        base_size = 4; // REX + opcode + ModR/M + imm8
                    } else {
                        base_size = 7; // REX + opcode + ModR/M + imm32
                    }
                }
            }
        }
    }
    return base_size + (!instr.prefix.empty() ? 1 : 0);
}

void Assembler::first_pass(std::vector<Instruction>& instructions) {
    std::map<Section, uint64_t> section_offsets;
    section_offsets[Section::TEXT] = 0;
    section_offsets[Section::DATA] = 0;
    section_offsets[Section::BSS] = 0;
    section_offsets[Section::RODATA] = 0;

    for (auto& instr : instructions) {
        Section section = instr.section;
        uint64_t& offset = section_offsets[section];
        uint64_t base_addr = get_section_base_address(section);

        instr.address = base_addr + offset;

        if (instr.is_label) {
            if (symbolTable.find(instr.label) == symbolTable.end()) {
                symbolTable[instr.label] = SymbolEntry{};
            }
            SymbolEntry& entry = symbolTable[instr.label];
            entry.name = instr.label;
            entry.address = instr.address;
            entry.section = section;
            entry.isDefined = true;

            if (entry.type == SymbolType::NOTYPE) {
                if (section == Section::TEXT) {
                    entry.type = SymbolType::FUNCTION;
                } else {
                    entry.type = SymbolType::OBJECT;
                }
            }

            if (instr.label == "_start") {
                entryPoint = instr.address;
            }

            uint64_t data_size = 0;
            if (std::holds_alternative<std::vector<uint8_t>>(instr.data)) {
                data_size = std::get<std::vector<uint8_t>>(instr.data).size();
            } else if (std::holds_alternative<int64_t>(instr.data)) {
                data_size = 8; // Legacy .quad support
            }
            entry.size = data_size;
            offset += data_size;

        } else if (!instr.mnemonic.empty()) {
            instr.size = get_instruction_size(instr);
            offset += instr.size;
        }
    }

    bssSize = section_offsets[Section::BSS];
}

void Assembler::encode_sse_instruction(const Instruction& instr) {
    const auto& m = instr.mnemonic;

    if (instr.operands.size() != 2) {
        throw std::runtime_error("SSE instructions require exactly 2 operands");
    }

    const auto& dst = instr.operands[0];
    const auto& src = instr.operands[1];

    // For most SSE instructions, destination must be XMM register
    // Some instructions like movss can have different patterns
    if (m.find("mov") == 0) {
        // MOV instructions can have XMM->memory or memory->XMM
        if (dst.type != OperandType::XMM_REGISTER && src.type != OperandType::XMM_REGISTER) {
            throw std::runtime_error("At least one operand must be XMM register for SSE MOV instruction");
        }
    } else {
        // Arithmetic instructions require XMM destination
        if (dst.type != OperandType::XMM_REGISTER) {
            throw std::runtime_error("First operand must be XMM register for SSE instruction");
        }
    }

    uint8_t dst_reg = (dst.type == OperandType::XMM_REGISTER) ? get_xmm_register_code(dst.value) : 0;
    uint8_t src_reg = (src.type == OperandType::XMM_REGISTER) ? get_xmm_register_code(src.value) : 0;

    // SSE instruction prefixes and opcodes
    if (m == "movss") {
        textSection.push_back(0xF3); // REP prefix for scalar single
        textSection.push_back(0x0F);

        if (dst.type == OperandType::XMM_REGISTER && src.type == OperandType::XMM_REGISTER) {
            textSection.push_back(0x10); // MOVSS xmm, xmm
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        } else if (dst.type == OperandType::XMM_REGISTER && src.type == OperandType::MEMORY) {
            textSection.push_back(0x10); // MOVSS xmm, m32
            textSection.push_back((0b00 << 6) | (dst_reg << 3) | 0b101); // ModR/M for RIP-relative
            // Add displacement (RIP-relative addressing)
            if (symbolTable.find(src.value) != symbolTable.end()) {
                uint64_t target_addr = symbolTable.at(src.value).address;
                int32_t rel_addr = target_addr - (instr.address + instr.size);
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
                }
            } else {
                // Symbol not found, add zero displacement for now
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back(0);
                }
            }
        } else if (dst.type == OperandType::MEMORY && src.type == OperandType::XMM_REGISTER) {
            textSection.push_back(0x11); // MOVSS m32, xmm
            textSection.push_back((0b00 << 6) | (src_reg << 3) | 0b101); // ModR/M for RIP-relative
            if (symbolTable.find(dst.value) != symbolTable.end()) {
                uint64_t target_addr = symbolTable.at(dst.value).address;
                int32_t rel_addr = target_addr - (instr.address + instr.size);
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
                }
            } else {
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back(0);
                }
            }
        }
    } else if (m == "movsd") {
        textSection.push_back(0xF2); // REPNE prefix for scalar double
        textSection.push_back(0x0F);

        if (dst.type == OperandType::XMM_REGISTER && src.type == OperandType::XMM_REGISTER) {
            textSection.push_back(0x10); // MOVSD xmm, xmm
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        } else if (dst.type == OperandType::XMM_REGISTER && src.type == OperandType::MEMORY) {
            textSection.push_back(0x10); // MOVSD xmm, m64
            textSection.push_back((0b00 << 6) | (dst_reg << 3) | 0b101); // ModR/M
            if (symbolTable.find(src.value) != symbolTable.end()) {
                uint64_t target_addr = symbolTable.at(src.value).address;
                int32_t rel_addr = target_addr - (instr.address + instr.size);
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
                }
            } else {
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back(0);
                }
            }
        } else if (dst.type == OperandType::MEMORY && src.type == OperandType::XMM_REGISTER) {
            textSection.push_back(0x11); // MOVSD m64, xmm
            textSection.push_back((0b00 << 6) | (src_reg << 3) | 0b101); // ModR/M
            if (symbolTable.find(dst.value) != symbolTable.end()) {
                uint64_t target_addr = symbolTable.at(dst.value).address;
                int32_t rel_addr = target_addr - (instr.address + instr.size);
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
                }
            } else {
                for (int i = 0; i < 4; ++i) {
                    textSection.push_back(0);
                }
            }
        }
    } else if (m == "addss") {
        textSection.push_back(0xF3);
        textSection.push_back(0x0F);
        textSection.push_back(0x58); // ADDSS
        if (src.type == OperandType::XMM_REGISTER) {
            uint8_t src_reg = get_xmm_register_code(src.value);
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        } else {
            throw std::runtime_error("ADDSS with memory operand not yet implemented");
        }
    } else if (m == "addsd") {
        textSection.push_back(0xF2);
        textSection.push_back(0x0F);
        textSection.push_back(0x58); // ADDSD
        if (src.type == OperandType::XMM_REGISTER) {
            uint8_t src_reg = get_xmm_register_code(src.value);
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        } else {
            throw std::runtime_error("ADDSD with memory operand not yet implemented");
        }
    } else if (m == "mulss") {
        textSection.push_back(0xF3);
        textSection.push_back(0x0F);
        textSection.push_back(0x59); // MULSS
        if (src.type == OperandType::XMM_REGISTER) {
            uint8_t src_reg = get_xmm_register_code(src.value);
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        }
    } else if (m == "mulsd") {
        textSection.push_back(0xF2);
        textSection.push_back(0x0F);
        textSection.push_back(0x59); // MULSD
        if (src.type == OperandType::XMM_REGISTER) {
            uint8_t src_reg = get_xmm_register_code(src.value);
            textSection.push_back(0xC0 | (dst_reg << 3) | src_reg);
        }
    }
}

void Assembler::second_pass(const std::vector<Instruction>& instructions) {
    // Clear all section data
    textSection.clear();
    dataSection.clear();
    bssSection.clear();
    rodataSection.clear();
    customSections.clear();

    for (const auto& instr : instructions) {
        if (instr.is_label) {
            if (instr.section != Section::BSS) {
                // Handle data for labels, but not for .bss section
                if (std::holds_alternative<std::vector<uint8_t>>(instr.data)) {
                    auto& data_bytes = std::get<std::vector<uint8_t>>(instr.data);
                    auto& section_data = get_section_data(instr.section);
                    section_data.insert(section_data.end(), data_bytes.begin(), data_bytes.end());
                } else if (std::holds_alternative<int64_t>(instr.data)) {
                    // Legacy .quad support
                    int64_t val = std::get<int64_t>(instr.data);
                    auto& section_data = get_section_data(instr.section);
                    for(int i = 0; i < 8; ++i) {
                        section_data.push_back((val >> (i*8)) & 0xFF);
                    }
                }
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            encode_x86_64(instr);
        }
    }
}

void Assembler::encode_x86_64(const Instruction& instr) {
    // Handle prefix
    if (!instr.prefix.empty()) {
        if (instr.prefix == "lock") {
            if (!lockable_instructions.count(instr.mnemonic)) {
                throw std::runtime_error("Instruction '" + instr.mnemonic + "' cannot be locked");
            }
            if (instr.operands.empty() || instr.operands[0].type != OperandType::MEMORY) {
                throw std::runtime_error("LOCK prefix requires a memory operand");
            }
            textSection.push_back(0xF0);
        }
    }

    const auto& m = instr.mnemonic;

    // Handle SSE instructions
    if (sse_instructions.count(m)) {
        encode_sse_instruction(instr);
        return;
    }

    // Handle basic instructions
    if (m == "syscall") {
        textSection.push_back(0x0F);
        textSection.push_back(0x05);
        return;
    }

    if (m == "ret") {
        textSection.push_back(0xC3);
        return;
    }

    if (m == "push") {
        const auto& op = instr.operands[0];
        if (op.type == OperandType::IMMEDIATE) {
            int64_t imm = 0;
            try {
                imm = std::stoll(op.value, nullptr, 0);
            } catch (const std::exception& e) {
                // maybe it's a define
                if (defines.count(op.value)) {
                    imm = std::stoll(defines.at(op.value), nullptr, 0);
                } else {
                    throw;
                }
            }

            if (op.size == OperandSize::BYTE || (imm >= -128 && imm <= 127)) {
                textSection.push_back(0x6A); // PUSH imm8
                textSection.push_back(static_cast<uint8_t>(imm));
            } else {
                textSection.push_back(0x68); // PUSH imm32
                for(int i = 0; i < 4; ++i) {
                    textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
                }
            }
        } else if (op.type == OperandType::MEMORY) {
            textSection.push_back(0xFF);
            textSection.push_back(0x35);
            uint64_t target_addr = symbolTable.at(op.value).address;
            int32_t rel_addr = target_addr - (instr.address + instr.size);
            for (int i = 0; i < 4; ++i) {
                textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
            }
        } else if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);

            // Handle different register sizes
            if (op.size == OperandSize::WORD) {
                textSection.push_back(0x66); // Operand size override
            }

            if (reg_code >= 8) {
                textSection.push_back(0x41); // REX.B
            }
            textSection.push_back(0x50 + (reg_code & 7));
        }
        return;
    }

    if (m == "pop") {
        const auto& op = instr.operands[0];
        if (op.type == OperandType::MEMORY) {
            textSection.push_back(0x8F);
            textSection.push_back(0x05);
            uint64_t target_addr = symbolTable.at(op.value).address;
            int32_t rel_addr = target_addr - (instr.address + instr.size);
            for (int i = 0; i < 4; ++i) {
                textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
            }
        } else if (op.type == OperandType::REGISTER) {
            uint8_t reg_code = get_register_code(op.value);

            if (op.size == OperandSize::WORD) {
                textSection.push_back(0x66); // Operand size override
            }

            if (reg_code >= 8) {
                textSection.push_back(0x41); // REX.B
            }
            textSection.push_back(0x58 + (reg_code & 7));
        }
        return;
    }

    // Handle control flow instructions
    if (m == "call" || m == "jmp" || m == "je" || m == "jne" || m == "jz" || m == "jnz" ||
        m == "jl" || m == "jle" || m == "jg" || m == "jge") {

        if (instr.operands.size() != 1 || instr.operands[0].type != OperandType::LABEL) {
            throw std::runtime_error("Invalid operands for " + m);
        }

        const std::string& symbol_name = instr.operands[0].value;
        auto it = symbolTable.find(symbol_name);

        if (it != symbolTable.end() && it->second.isDefined) {
            // Internal symbol, calculate relative address
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
            for (int i = 0; i < 4; ++i) {
                textSection.push_back((rel_addr >> (i * 8)) & 0xFF);
            }
        } else {
            // External symbol, create relocation
            if (it == symbolTable.end()) {
                symbolTable[symbol_name] = {symbol_name, 0, 0, SymbolBinding::GLOBAL, SymbolType::NOTYPE, SymbolVisibility::DEFAULT, Section::NONE, false};
            }

            uint64_t relocation_offset = textSection.size() + 1; // Relocation is for the 4 bytes after opcode
            if (m != "call" && m != "jmp") {
                relocation_offset++; // 2-byte opcode for conditional jumps
            }

            RelocationEntry reloc = {
                relocation_offset,
                symbol_name,
                RelocationType::R_X86_64_PC32,
                -4,
                Section::TEXT
            };
            relocations.push_back(reloc);

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

            // Write 4 bytes of placeholder
            for (int i = 0; i < 4; ++i) {
                textSection.push_back(0);
            }
        }
        return;
    }

    // Handle two-operand instructions
    if (instr.operands.size() == 2) {
        const auto& op1 = instr.operands[0];
        const auto& op2 = instr.operands[1];

        // Enhanced operand handling with size support
        if (op1.type == OperandType::REGISTER && op2.type == OperandType::LABEL) {
            // This should be a RIP-relative LEA instruction
            uint8_t reg_code = get_register_code(op1.value);
            textSection.push_back(0x48);
            textSection.push_back(0x8d);
            textSection.push_back((0b00 << 6) | (reg_code << 3) | 0b101);

            const std::string& symbol_name = op2.value;
            auto it = symbolTable.find(symbol_name);
            if (it == symbolTable.end()) {
                symbolTable[symbol_name] = {symbol_name, 0, 0, SymbolBinding::GLOBAL, SymbolType::OBJECT, SymbolVisibility::DEFAULT, Section::NONE, false};
            }
            RelocationEntry reloc = {
                textSection.size(),
                it->second.section == Section::DATA ? ".data" : symbol_name,
                RelocationType::R_X86_64_PC32,
                it->second.section == Section::DATA ? it->second.address - get_section_base_address(it->second.section) : -4,
                Section::TEXT
            };
            relocations.push_back(reloc);
            for(int i = 0; i < 4; ++i) {
                textSection.push_back(0); // Placeholder
            }
        }
        else if (op1.type == OperandType::REGISTER && op2.type == OperandType::IMMEDIATE) {
            uint8_t reg_code = get_register_code(op1.value);
            int64_t imm = std::stoll(op2.value);
            uint8_t modrm_ext = (m == "add") ? 0 : (m == "sub") ? 5 : (m == "cmp") ? 7 : 0;

            // Determine operand size
            OperandSize actual_size = op1.size;
            if (actual_size == OperandSize::INFERRED) {
                // Infer from register name
                if (op1.value.length() == 2 && (op1.value[1] == 'l' || op1.value[1] == 'h')) {
                    actual_size = OperandSize::BYTE;
                } else if (op1.value[0] == 'e' || op1.value.find('d') == op1.value.length()-1) {
                    actual_size = OperandSize::DWORD;
                } else {
                    actual_size = OperandSize::QWORD;
                }
            }

            // Generate appropriate prefixes
            uint8_t rex = 0x40;
            if (actual_size == OperandSize::QWORD) rex |= 0x08; // REX.W
            if (reg_code >= 8) rex |= 0x01; // REX.B

            if (actual_size == OperandSize::WORD) {
                textSection.push_back(0x66); // Operand size override
            }

            if (m == "mov") {
                if (rex != 0x40) textSection.push_back(rex);

                if (actual_size == OperandSize::BYTE) {
                    textSection.push_back(0xB0 + (reg_code & 7)); // MOV r8, imm8
                    textSection.push_back(static_cast<uint8_t>(imm));
                } else if (imm >= -2147483648LL && imm <= 2147483647LL) {
                    textSection.push_back(0xC7);
                    textSection.push_back(0xC0 | (reg_code & 7));
                    for(int i = 0; i < 4; ++i) {
                        textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
                    }
                } else {
                    textSection.push_back(0xB8 + (reg_code & 7)); // MOV r64, imm64
                    for(int i = 0; i < 8; ++i) {
                        textSection.push_back((imm >> (i*8)) & 0xFF);
                    }
                }
            } else {
                if (rex != 0x40) textSection.push_back(rex);

                if (actual_size == OperandSize::BYTE) {
                    textSection.push_back(0x80);
                    textSection.push_back(0xC0 | (modrm_ext << 3) | (reg_code & 7));
                    textSection.push_back(static_cast<uint8_t>(imm));
                } else if (imm >= -128 && imm <= 127) {
                    textSection.push_back(0x83);
                    textSection.push_back(0xC0 | (modrm_ext << 3) | (reg_code & 7));
                    textSection.push_back(static_cast<uint8_t>(imm));
                } else {
                    textSection.push_back(0x81);
                    textSection.push_back(0xC0 | (modrm_ext << 3) | (reg_code & 7));
                    for(int i = 0; i < 4; ++i) {
                        textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
                    }
                }
            }
        }
        // Add other operand combinations as needed...
        else {
            // Fall back to original implementation for now
            if (op1.type == OperandType::MEMORY && op2.type == OperandType::IMMEDIATE) {
                uint8_t modrm_ext = (m == "add") ? 0 : (m == "sub") ? 5 : 7;
                int64_t imm = std::stoll(op2.value);
                textSection.push_back(0x48);
                textSection.push_back((imm >= -128 && imm <= 127) ? 0x83 : 0x81);
                textSection.push_back((0b00 << 6) | (modrm_ext << 3) | 0b101);
                int32_t disp = symbolTable.at(op1.value).address - (instr.address + instr.size);
                for(int i = 0; i < 4; ++i) {
                    textSection.push_back((disp >> (i*8)) & 0xFF);
                }
                if (imm >= -128 && imm <= 127) {
                    textSection.push_back(static_cast<uint8_t>(imm));
                } else {
                    for(int i = 0; i < 4; ++i) {
                        textSection.push_back((static_cast<uint32_t>(imm) >> (i*8)) & 0xFF);
                    }
                }
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::MEMORY) {
                uint8_t opcode = (m == "mov") ? 0x8B : (m == "add") ? 0x03 : 0x2B;
                uint8_t reg_code = get_register_code(op1.value);

                const std::string& symbol_name = op2.value;
                auto it = symbolTable.find(symbol_name);

                if (it != symbolTable.end() && it->second.isDefined) {
                    textSection.push_back(0x48 | ((reg_code >= 8) ? 4 : 0));
                    textSection.push_back(opcode);
                    if (op2.value.find("rsp") != std::string::npos) {
                        textSection.push_back((0b01 << 6) | ((reg_code & 7) << 3) | 0b100);
                        textSection.push_back(0x24);
                        textSection.push_back(8);
                    } else {
                        textSection.push_back((0b00 << 6) | ((reg_code & 7) << 3) | 0b101);
                        int32_t disp = it->second.address - (instr.address + instr.size);
                        for(int i = 0; i < 4; ++i) {
                            textSection.push_back((disp >> (i*8)) & 0xFF);
                        }
                    }
                } else {
                    if (it == symbolTable.end()) {
                        symbolTable[symbol_name] = {symbol_name, 0, 0, SymbolBinding::GLOBAL, SymbolType::OBJECT, SymbolVisibility::DEFAULT, Section::NONE, false};
                    }
                    RelocationEntry reloc = {
                        textSection.size() + 3, // Offset of displacement from start of instruction
                        symbol_name,
                        RelocationType::R_X86_64_PC32,
                        -4,
                        Section::TEXT
                    };
                    relocations.push_back(reloc);
                    textSection.push_back(0x48 | ((reg_code >= 8) ? 4 : 0));
                    textSection.push_back(opcode);
                    textSection.push_back((0b00 << 6) | ((reg_code & 7) << 3) | 0b101); // ModR/M for RIP-relative
                    for(int i = 0; i < 4; ++i) {
                        textSection.push_back(0); // Placeholder
                    }
                }
            } else if (op1.type == OperandType::REGISTER && op2.type == OperandType::REGISTER) {
                uint8_t opcode = (m == "mov") ? 0x89 : (m == "add") ? 0x01 : (m == "sub") ? 0x29 : (m == "xor") ? 0x31 : 0x39;
                uint8_t dst_reg = get_register_code(op1.value);
                uint8_t src_reg = get_register_code(op2.value);

                // Determine operand size
                OperandSize actual_size = op1.size;
                if (actual_size == OperandSize::INFERRED) {
                    actual_size = OperandSize::QWORD; // Default
                }

                // Generate REX prefix
                uint8_t rex = 0x40;
                if (actual_size == OperandSize::QWORD) rex |= 0x08; // REX.W
                if (src_reg >= 8) rex |= 0x04; // REX.R
                if (dst_reg >= 8) rex |= 0x01; // REX.B

                if (actual_size == OperandSize::WORD) {
                    textSection.push_back(0x66); // Operand size override
                }

                if (rex != 0x40) textSection.push_back(rex);

                if (actual_size == OperandSize::BYTE) {
                    textSection.push_back(opcode - 1); // Byte variants are one less
                } else {
                    textSection.push_back(opcode);
                }

                textSection.push_back(0xC0 | ((src_reg & 7) << 3) | (dst_reg & 7));
            }
        }
    }
}

const std::unordered_map<std::string, SymbolEntry>& Assembler::getSymbols() const {
    return symbolTable;
}

const std::vector<RelocationEntry>& Assembler::getRelocations() const {
    return relocations;
}

const std::vector<uint8_t>& Assembler::getTextSection() const {
    return textSection;
}

const std::vector<uint8_t>& Assembler::getDataSection() const {
    return dataSection;
}

const std::vector<uint8_t>& Assembler::getBssSection() const {
    return bssSection;
}

uint64_t Assembler::getBssSize() const {
    return bssSize;
}

const std::vector<uint8_t>& Assembler::getRodataSection() const {
    return rodataSection;
}

const std::unordered_map<std::string, std::vector<uint8_t>>& Assembler::getCustomSections() const {
    return customSections;
}

void Assembler::add_winapi_import(const std::string& dll, const std::string& function) {
    for (const auto& imp : winapi_imports) {
        if (imp.dll == dll && imp.function == function) {
            return;
        }
    }
    winapi_imports.push_back({dll, function});
    symbolTable[function] = { function, 0, 0, SymbolBinding::GLOBAL, SymbolType::FUNCTION, SymbolVisibility::DEFAULT, Section::NONE, false };
}

uint64_t Assembler::getEntryPoint() const {
    return entryPoint;
}

const std::vector<WinApiImport>& Assembler::getWinApiImports() const {
    return winapi_imports;
}

void Assembler::printDebugInfo() const {
    std::cout << "\n==== ASSEMBLER DEBUG INFORMATION ====\n\n";

    std::cout << "SYMBOLS:\n";
    for(const auto& pair : symbolTable) {
        const auto& sym = pair.second;
        std::cout << "  " << pair.first << ": 0x" << std::hex << sym.address
                  << " (binding: ";
        switch (sym.binding) {
            case SymbolBinding::LOCAL: std::cout << "LOCAL"; break;
            case SymbolBinding::GLOBAL: std::cout << "GLOBAL"; break;
            case SymbolBinding::WEAK: std::cout << "WEAK"; break;
        }
        std::cout << ", type: ";
        switch (sym.type) {
            case SymbolType::NOTYPE: std::cout << "NOTYPE"; break;
            case SymbolType::OBJECT: std::cout << "OBJECT"; break;
            case SymbolType::FUNCTION: std::cout << "FUNC"; break;
            case SymbolType::SECTION: std::cout << "SECTION"; break;
        }
        std::cout << ", defined: " << sym.isDefined << ")\n";
    }

    std::cout << "\nENTRY POINT: 0x" << std::hex << entryPoint << std::dec << "\n";

    std::cout << "\nSECTION SIZES:\n";
    std::cout << "  .text: " << textSection.size() << " bytes\n";
    std::cout << "  .data: " << dataSection.size() << " bytes\n";
    std::cout << "  .bss: " << bssSection.size() << " bytes\n";
    std::cout << "  .rodata: " << rodataSection.size() << " bytes\n";

    for (const auto& pair : customSections) {
        std::cout << "  " << pair.first << ": " << pair.second.size() << " bytes\n";
    }

    if (textSection.size() > 0) {
        std::cout << "\n.text hexdump:\n";
        for(size_t i = 0; i < textSection.size(); ++i) {
            printf("%02x ", textSection[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }

    if (dataSection.size() > 0) {
        std::cout << "\n.data hexdump:\n";
        for(size_t i = 0; i < dataSection.size(); ++i) {
            printf("%02x ", dataSection[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }

    if (rodataSection.size() > 0) {
        std::cout << "\n.rodata hexdump:\n";
        for(size_t i = 0; i < rodataSection.size(); ++i) {
            printf("%02x ", rodataSection[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }

    std::cout << "\nMACROS DEFINED:\n";
    for (const auto& pair : macros) {
        std::cout << "  " << pair.first << " (";
        for (size_t i = 0; i < pair.second.parameters.size(); ++i) {
            std::cout << pair.second.parameters[i];
            if (i < pair.second.parameters.size() - 1) std::cout << ", ";
        }
        std::cout << ")\n";
    }

    std::cout << "\nDEFINES:\n";
    for (const auto& pair : defines) {
        std::cout << "  " << pair.first << " = " << pair.second << "\n";
    }

    std::cout << "\n==== END DEBUG INFORMATION ====\n\n";
}
