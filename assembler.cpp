#include "assembler.hh"
#include "parser.hh"
#include "translator.hh"
#include "architecture.hh"
#include "x86_64_arch.hh"
#include "aarch64_arch.hh"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <set>
#include <fstream>

std::unique_ptr<Architecture> create_architecture(const std::string& arch_name) {
    if (arch_name == "x86-64") {
        return std::make_unique<X86_64Arch>();
    }
    if (arch_name == "aarch64") {
        return std::make_unique<AArch64Arch>();
    }
    return nullptr;
}

Assembler::Assembler(const std::string& arch, const std::string& target_format, uint64_t textBase, uint64_t dataBase)
    : textSectionBase(textBase), dataSectionBase(dataBase),
      bssSectionBase(dataBase + 0x1000), rodataSectionBase(dataBase + 0x2000),
      entryPoint(0), target_format_(target_format), parser_(*this), translator_(*this) {

    arch_ = create_architecture(arch);
    if (!arch_) {
        throw std::runtime_error("Unsupported architecture: " + arch);
    }
    includePaths.push_back("."); // Default include path
}

bool Assembler::assemble(const std::string &source, const std::string &outputFile) {
    (void)outputFile;
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
    std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
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
            if (filename.front() == '"' && filename.back() == '"') {
                filename = filename.substr(1, filename.length() - 2);
            }
            bool found = false;
            for (const auto& path : includePaths) {
                std::string fullPath = path + "/" + filename;
                std::ifstream incFile(fullPath);
                if (incFile) {
                    std::string incContent((std::istreambuf_iterator<char>(incFile)), std::istreambuf_iterator<char>());
                    result << process_includes(incContent) << "\n";
                    found = true;
                    break;
                }
            }
            if (!found) throw std::runtime_error("Cannot find include file: " + filename);
        } else {
            result << line << "\n";
        }
    }
    return result.str();
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
            for (const auto& op : instr.operands) args.push_back(op.value);
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

uint64_t Assembler::get_section_base_address(Section section) const {
    switch (section) {
    case Section::TEXT: return textSectionBase;
    case Section::DATA: return dataSectionBase;
    case Section::BSS: return bssSectionBase;
    case Section::RODATA: return rodataSectionBase;
    default: return 0;
    }
}

uint64_t Assembler::getSectionBase(Section s) const { return get_section_base_address(s); }

std::string Assembler::getSectionName(Section s) const {
    for (const auto& pair : sectionInfoMap) {
        if (pair.second.type == s) return pair.first;
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
            if (symbolTable.find(instr.label) == symbolTable.end()) symbolTable[instr.label] = SymbolEntry{};
            SymbolEntry& entry = symbolTable[instr.label];
            entry.name = instr.label;
            entry.address = instr.address;
            entry.section = section;
            entry.isDefined = true;
            if (entry.type == SymbolType::NOTYPE) {
                entry.type = (section == Section::TEXT) ? SymbolType::FUNCTION : SymbolType::OBJECT;
            }
            if (instr.label == "_start") entryPoint = instr.address;
            uint64_t data_size = 0;
            if (std::holds_alternative<std::vector<uint8_t>>(instr.data)) {
                data_size = std::get<std::vector<uint8_t>>(instr.data).size();
            } else if (std::holds_alternative<int64_t>(instr.data)) {
                data_size = 8;
            }
            entry.size = data_size;
            offset += data_size;
        } else if (!instr.mnemonic.empty()) {
            instr.size = arch_->get_instruction_size(instr);
            offset += instr.size;
        }
    }
    bssSize = section_offsets[Section::BSS];
}

void Assembler::second_pass(const std::vector<Instruction>& instructions) {
    textSection.clear();
    dataSection.clear();
    bssSection.clear();
    rodataSection.clear();
    customSections.clear();
    for (const auto& instr : instructions) {
        if (instr.is_label) {
            if (instr.section != Section::BSS) {
                if (std::holds_alternative<std::vector<uint8_t>>(instr.data)) {
                    auto& data_bytes = std::get<std::vector<uint8_t>>(instr.data);
                    auto& section_data = get_section_data(instr.section);
                    section_data.insert(section_data.end(), data_bytes.begin(), data_bytes.end());
                } else if (std::holds_alternative<int64_t>(instr.data)) {
                    int64_t val = std::get<int64_t>(instr.data);
                    auto& section_data = get_section_data(instr.section);
                    for(int i = 0; i < 8; ++i) section_data.push_back((val >> (i*8)) & 0xFF);
                }
            }
        } else if (instr.section == Section::TEXT && !instr.mnemonic.empty()) {
            size_t before_size = textSection.size();
            arch_->encode_instruction(*this, instr);
            size_t after_size = textSection.size();
            std::cout << "Encoded '" << instr.mnemonic << "': ";
            for(size_t k = before_size; k < after_size; ++k) printf("%02x ", textSection[k]);
            std::cout << "\n";
        }
    }
}

// Getters
const std::unordered_map<std::string, SymbolEntry>& Assembler::getSymbols() const { return symbolTable; }
const std::vector<RelocationEntry>& Assembler::getRelocations() const { return relocations; }
const std::vector<uint8_t>& Assembler::getTextSection() const { return textSection; }
const std::vector<uint8_t>& Assembler::getDataSection() const { return dataSection; }
const std::vector<uint8_t>& Assembler::getBssSection() const { return bssSection; }
uint64_t Assembler::getBssSize() const { return bssSize; }
const std::vector<uint8_t>& Assembler::getRodataSection() const { return rodataSection; }
const std::unordered_map<std::string, std::vector<uint8_t>>& Assembler::getCustomSections() const { return customSections; }
uint64_t Assembler::getEntryPoint() const { return entryPoint; }
const std::vector<WinApiImport>& Assembler::getWinApiImports() const { return winapi_imports; }

void Assembler::add_winapi_import(const std::string& dll, const std::string& function) {
    winapi_imports.push_back({dll, function});
    symbolTable[function] = { function, 0, 0, SymbolBinding::GLOBAL, SymbolType::FUNCTION, SymbolVisibility::DEFAULT, Section::NONE, false };
}

void Assembler::printDebugInfo() const {
    // ... (implementation can be copied later)
}
