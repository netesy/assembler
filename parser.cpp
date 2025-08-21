#include "parser.hh"
#include "assembler.hh"
#include <sstream>
#include <stdexcept>
#include <regex>

Parser::Parser(Assembler& assembler) : assembler_(assembler) {
    currentSection = Section::TEXT;
    currentSectionInfo = {"", Section::TEXT, "", ""};
}

OperandSize Parser::parse_size_prefix(const std::string& operand_str, std::string& cleaned_operand) {
    cleaned_operand = operand_str;

    if (operand_str.find("byte ptr") == 0) {
        cleaned_operand = operand_str.substr(8);
        cleaned_operand.erase(0, cleaned_operand.find_first_not_of(" \t"));
        return OperandSize::BYTE;
    } else if (operand_str.find("word ptr") == 0) {
        cleaned_operand = operand_str.substr(8);
        cleaned_operand.erase(0, cleaned_operand.find_first_not_of(" \t"));
        return OperandSize::WORD;
    } else if (operand_str.find("dword ptr") == 0) {
        cleaned_operand = operand_str.substr(9);
        cleaned_operand.erase(0, cleaned_operand.find_first_not_of(" \t"));
        return OperandSize::DWORD;
    } else if (operand_str.find("qword ptr") == 0) {
        cleaned_operand = operand_str.substr(9);
        cleaned_operand.erase(0, cleaned_operand.find_first_not_of(" \t"));
        return OperandSize::QWORD;
    }

    return OperandSize::INFERRED;
}

Operand Parser::parse_operand(const std::string& op_str) {
    if (op_str.empty()) return {OperandType::NONE, ""};

    std::string cleaned_operand;
    OperandSize explicit_size = parse_size_prefix(op_str, cleaned_operand);
    bool size_explicit = (explicit_size != OperandSize::INFERRED);

    Operand operand;
    operand.size = explicit_size;
    operand.size_explicit = size_explicit;

    if (cleaned_operand.front() == '[' && cleaned_operand.back() == ']') {
        operand.type = OperandType::MEMORY;
        operand.value = cleaned_operand.substr(1, cleaned_operand.length() - 2);
        return operand;
    }

    if (assembler_.is_register(cleaned_operand)) {
        operand.type = OperandType::REGISTER;
        operand.value = cleaned_operand;
        if (!size_explicit) {
            if (cleaned_operand.length() == 3 && (cleaned_operand[0] == 'e' || (cleaned_operand[0] == 'r' && cleaned_operand[2] == 'd'))) {
                operand.size = OperandSize::DWORD;
            } else if (cleaned_operand.length() == 2 || (cleaned_operand.length() == 3 && cleaned_operand[2] == 'w')) {
                operand.size = OperandSize::WORD;
            } else if ((cleaned_operand.length() == 2 && (cleaned_operand[1] == 'l' || cleaned_operand[1] == 'h')) || (cleaned_operand.length() == 3 && cleaned_operand[2] == 'b')) {
                operand.size = OperandSize::BYTE;
            } else {
                operand.size = OperandSize::QWORD;
            }
        }
        return operand;
    }

    if (assembler_.is_xmm_register(cleaned_operand)) {
        operand.type = OperandType::XMM_REGISTER;
        operand.value = cleaned_operand;
        operand.size = OperandSize::QWORD;
        return operand;
    }

    try {
        std::stoll(cleaned_operand, nullptr, 0);
        operand.type = OperandType::IMMEDIATE;
        operand.value = cleaned_operand;
        return operand;
    } catch (const std::invalid_argument&) {
        operand.type = OperandType::LABEL;
        operand.value = cleaned_operand;
        return operand;
    }
}

void Parser::handle_data_directive(Instruction& instr, const std::string& directive, const std::string& data_str) {
    std::vector<uint8_t> data_bytes;

    if (directive == ".db") {
        std::istringstream iss(data_str);
        std::string item;
        while(std::getline(iss, item, ',')) {
            item.erase(0, item.find_first_not_of(" \t"));
            item.erase(item.find_last_not_of(" \t") + 1);
            if (item.front() == '"' && item.back() == '"') {
                std::string s = item.substr(1, item.length() - 2);
                std::string unescaped;
                for (size_t i = 0; i < s.length(); ++i) {
                    if (s[i] == '\\' && i + 1 < s.length()) {
                        switch (s[i+1]) {
                            case 'n': unescaped += '\n'; i++; break;
                            case 'r': unescaped += '\r'; i++; break;
                            case 't': unescaped += '\t'; i++; break;
                            case '0': unescaped += '\0'; i++; break;
                            default: unescaped += s[i];
                        }
                    } else {
                        unescaped += s[i];
                    }
                }
                for (char c : unescaped) {
                    data_bytes.push_back(c);
                }
            } else {
                data_bytes.push_back(static_cast<uint8_t>(std::stoll(item, nullptr, 0)));
            }
        }
    } else if (directive == ".dw") {
        std::istringstream iss(data_str);
        std::string value;
        while (std::getline(iss, value, ',')) {
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            uint16_t word_val = static_cast<uint16_t>(std::stoll(value, nullptr, 0));
            data_bytes.push_back(word_val & 0xFF);
            data_bytes.push_back((word_val >> 8) & 0xFF);
        }
    } else if (directive == ".dword" || directive == ".dd") {
        std::istringstream iss(data_str);
        std::string value;
        while (std::getline(iss, value, ',')) {
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            uint32_t dword_val = static_cast<uint32_t>(std::stoll(value, nullptr, 0));
            for (int i = 0; i < 4; ++i) {
                data_bytes.push_back((dword_val >> (i * 8)) & 0xFF);
            }
        }
    } else if (directive == ".quad" || directive == ".dq") {
        std::istringstream iss(data_str);
        std::string value;
        while (std::getline(iss, value, ',')) {
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            uint64_t quad_val = static_cast<uint64_t>(std::stoll(value, nullptr, 0));
            for (int i = 0; i < 8; ++i) {
                data_bytes.push_back((quad_val >> (i * 8)) & 0xFF);
            }
        }
    } else if (directive == ".asciz") {
        std::string str_val = data_str;
        if (str_val.front() == '"' && str_val.back() == '"') {
            str_val = str_val.substr(1, str_val.length() - 2);
        }
        for (size_t i = 0; i < str_val.length(); ++i) {
            if (str_val[i] == '\\' && i + 1 < str_val.length()) {
                switch (str_val[i + 1]) {
                case 'n': data_bytes.push_back('\n'); i++; break;
                case 't': data_bytes.push_back('\t'); i++; break;
                case 'r': data_bytes.push_back('\r'); i++; break;
                case '\\': data_bytes.push_back('\\'); i++; break;
                case '"': data_bytes.push_back('"'); i++; break;
                default: data_bytes.push_back(str_val[i]); break;
                }
            } else {
                data_bytes.push_back(str_val[i]);
            }
        }
        data_bytes.push_back(0);
    } else if (directive == ".space") {
        size_t space_size = std::stoull(data_str);
        data_bytes.resize(space_size, 0);
    } else if (directive == ".resb") {
        size_t space_size = std::stoull(data_str);
        data_bytes.resize(space_size, 0);
    } else if (directive == ".times") {
        std::istringstream iss(data_str);
        size_t count;
        std::string directive_str;
        iss >> count >> directive_str;
        std::string data_val;
        std::getline(iss, data_val);
        data_val.erase(0, data_val.find_first_not_of(" \t"));

        std::vector<uint8_t> single_item_bytes;
        if (directive_str == "db") {
            single_item_bytes.push_back(static_cast<uint8_t>(std::stoll(data_val, nullptr, 0)));
        } // Add other directives as needed

        for (size_t i = 0; i < count; ++i) {
            data_bytes.insert(data_bytes.end(), single_item_bytes.begin(), single_item_bytes.end());
        }
    }
    instr.data = data_bytes;
}

std::vector<Instruction> Parser::parse(const std::string& source) {
    std::vector<Instruction> instructions;
    std::istringstream stream(source);
    std::string line;

    while (std::getline(stream, line)) {
        std::string original_line = line;
        if (auto pos = line.find(';'); pos != std::string::npos) {
            line = line.substr(0, pos);
        }

        std::istringstream line_stream(line);
        std::string token;
        line_stream >> token;
        if (token.empty()) continue;

        if (token == "%macro") {
            in_macro = true;
            line_stream >> current_macro_name;
            assembler_.macros[current_macro_name] = Macro{current_macro_name, {}, {}};
            continue;
        } else if (token == "%endmacro") {
            in_macro = false;
            current_macro_name = "";
            continue;
        } else if (in_macro) {
            assembler_.macros[current_macro_name].body.push_back(line);
            continue;
        }

        if (token == "%define") {
            std::string def_name, def_value;
            line_stream >> def_name;
            std::getline(line_stream, def_value);
            def_value.erase(0, def_value.find_first_not_of(" \t"));
            assembler_.defines[def_name] = def_value;
            continue;
        }

        if (token.back() == ':') {
            Instruction instr;
            instr.section = currentSection;
            instr.section_info = currentSectionInfo;
            instr.is_label = true;
            instr.label = token.substr(0, token.size() - 1);
            instr.original_line = original_line;
            instructions.push_back(instr);
            if (!(line_stream >> token)) continue;
        }

        if (token == ".section") {
            std::string section_name;
            line_stream >> section_name;
            SectionInfo section_info;
            section_info.name = section_name;
            std::string attr;
            if (line_stream >> attr) {
                if (attr.front() == '"' && attr.back() == '"') {
                    section_info.attributes = attr.substr(1, attr.length() - 2);
                } else {
                    section_info.attributes = attr;
                }
            }
            if (line_stream >> attr) {
                section_info.section_type = attr;
            }
            if (section_name == ".text") section_info.type = Section::TEXT;
            else if (section_name == ".data") section_info.type = Section::DATA;
            else if (section_name == ".bss") section_info.type = Section::BSS;
            else if (section_name == ".rodata") section_info.type = Section::RODATA;
            else if (section_name == ".init") section_info.type = Section::INIT;
            else if (section_name == ".fini") section_info.type = Section::FINI;
            else section_info.type = Section::CUSTOM;
            currentSection = section_info.type;
            currentSectionInfo = section_info;
            assembler_.sectionInfoMap[section_name] = section_info;
            continue;
        }

        if (token == "global" || token == ".global" || token == ".globl") {
            std::string symbol_name;
            while (line_stream >> symbol_name) {
                if (assembler_.symbolTable.find(symbol_name) == assembler_.symbolTable.end()) {
                    assembler_.symbolTable[symbol_name] = SymbolEntry{};
                }
                assembler_.symbolTable[symbol_name].binding = SymbolBinding::GLOBAL;
            }
            continue;
        }
        if (token == ".weak" || token == ".local" || token == ".extern" || token == ".type" || token == ".align") {
            // Simplified handling for now
            continue;
        }

        if (token == ".byte" || token == ".db" || token == ".word" || token == ".dw" ||
            token == ".dword" || token == ".dd" || token == ".quad" || token == ".dq" ||
            token == ".asciz" || token == ".space") {
            if (instructions.empty() || !instructions.back().is_label) {
                throw std::runtime_error("Data directive without a label: " + token);
            }
            std::string data_str;
            std::getline(line_stream, data_str);
            data_str.erase(0, data_str.find_first_not_of(" \t"));
            handle_data_directive(instructions.back(), token, data_str);
            continue;
        }

        Instruction instr;
        instr.section = currentSection;
        instr.section_info = currentSectionInfo;
        instr.original_line = original_line;
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
