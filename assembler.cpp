#include "assembler.hh"

std::unordered_map<std::string, uint8_t> opcodeMap = {{"MOV", 0x01},  {"ADD", 0x02}, {"SUB", 0x03},
                                                      {"CMP", 0x09},  {"JE", 0x0A},  {"JNE", 0x0B},
                                                      {"JG", 0x0C},   {"JL", 0x0D},  {"JMP", 0x04},
                                                      {"CALL", 0x05}, {"RET", 0x06}, {"PUSH", 0x07},
                                                      {"POP", 0x08},  {"AND", 0x0E}, {"OR", 0x0F},
                                                      {"XOR", 0x10},  {"NOT", 0x11}, {"SHL", 0x12},
                                                      {"SHR", 0x13},  {"ROL", 0x14}, {"ROR", 0x15},
                                                      {"BT", 0x16},   {"BTS", 0x17}, {"BTR", 0x18}};

std::unordered_map<std::string, uint8_t> registerMap = {{"R0", 0x00},
                                                        {"R1", 0x01},
                                                        {"R2", 0x02},
                                                        {"R3", 0x03},
                                                        {"R4", 0x04},
                                                        {"R5", 0x05},
                                                        {"R6", 0x06},
                                                        {"R7", 0x07}};

Assembler::Assembler()
    : currentAddress(0)
    , dataAddress(0)
    , dataSectionBase(0x00600000) // Explicitly initialize dataSectionBase
{}

std::vector<Instruction> Assembler::parse(const std::string &code)
{
    std::vector<Instruction> instructions;
    std::istringstream stream(code);
    std::string line;

    while (std::getline(stream, line)) {
        std::istringstream lineStream(line);
        std::string mnemonic;
        lineStream >> mnemonic;

        if (mnemonic.empty() || mnemonic[0] == '#')
            continue; // Skip comments

        Instruction instr;
        instr.mnemonic = mnemonic;
        std::string operand;

        while (lineStream >> operand) {
            instr.operands.push_back(operand);
        }

        instructions.push_back(instr);
    }
    return instructions;
}

uint32_t Assembler::parseOperand(const std::string &operand)
{
    std::cout << "Parsing operand: '" << operand << "' ";

    // Check if this is a memory dereference like [message_len]
    if (operand.size() >= 2 && operand[0] == '[' && operand[operand.size()-1] == ']') {
        std::string innerOperand = operand.substr(1, operand.size() - 2);
        std::cout << "(dereference of '" << innerOperand << "') ";

        if (dataLabels.find(innerOperand) != dataLabels.end()) {
            std::cout << "-> value: " << dataLabels[innerOperand] << "\n";
            return dataLabels[innerOperand];
        }
    }

    if (registerMap.find(operand) != registerMap.end()) {
        std::cout << "-> register: " << (int)registerMap[operand] << "\n";
        return registerMap[operand];
    } else if (labels.find(operand) != labels.end()) {
        std::cout << "-> text label: 0x" << std::hex << labels[operand] << std::dec << "\n";
        return labels[operand];
    } else if (dataLabels.find(operand) != dataLabels.end()) {
        std::cout << "-> data label: 0x" << std::hex << dataLabels[operand] << std::dec << "\n";
        return dataLabels[operand];
    } else if (bssLabels.find(operand) != bssLabels.end()) {
        std::cout << "-> bss label: 0x" << std::hex << bssLabels[operand] << std::dec << "\n";
        return bssLabels[operand];
    } else {
        // Handle numeric literals
        try {
            int value = std::stoi(operand);
            std::cout << "-> numeric literal: " << value << "\n";
            return value;
        } catch (const std::exception& e) {
            // Not a number, treat as unresolved symbol
            std::cout << "-> unresolved symbol (will be fixed up later)\n";
            unresolvedSymbols[operand].push_back(currentAddress);
            return 0;
        }
    }
}

uint32_t Assembler::encodeInstruction(const Instruction &instr)
{
    if (opcodeMap.find(instr.mnemonic) == opcodeMap.end()) {
        throw std::runtime_error("Invalid mnemonic: " + instr.mnemonic);
    }

    uint8_t opcode = opcodeMap[instr.mnemonic];
    uint8_t mode = 0, reg = 0;
    int32_t value = 0;

    if (instr.operands.size() == 2) {
        reg = parseOperand(instr.operands[0]);
        value = parseOperand(instr.operands[1]);
    } else if (instr.operands.size() == 1) {
        value = parseOperand(instr.operands[0]);
    }

    return (opcode << 24) | (mode << 16) | (reg << 8) | (value & 0xFFFF);
}

void Assembler::resolveLabels(std::vector<Instruction> &instructions)
{
    // Define base addresses for each section
    textSectionBase = 0x00400000;  // Common base address for text section
    dataSectionBase = 0x00600000;  // Common base address for data section
    bssSectionBase = 0x00800000;   // Common base address for bss section

    // Reset counters for each section
    currentAddress = textSectionBase;
    dataAddress = dataSectionBase;
    bssAddress = bssSectionBase;

    // First pass: identify all labels
    for (size_t i = 0; i < instructions.size(); i++) {
        if (instructions[i].mnemonic.back() == ':') { // Label detected
            std::string labelName = instructions[i].mnemonic.substr(0,
                                                                    instructions[i].mnemonic.size() - 1);
            // Assign address based on current section
            switch (instructions[i].section) {
            case Section::TEXT:
                labels[labelName] = currentAddress;
                break;
            case Section::DATA:
                dataLabels[labelName] = dataAddress;
                break;
            case Section::BSS:
                bssLabels[labelName] = bssAddress;
                break;
            }
            instructions.erase(instructions.begin() + i);
            i--;
        } else if (instructions[i].mnemonic == ".data") {
            if (instructions[i].operands.size() >= 2) {
                dataLabels[instructions[i].operands[0]] = dataAddress;
                int dataSize = std::stoi(instructions[i].operands[1]);
                dataAddress += dataSize;
            }
        } else if (instructions[i].mnemonic == ".bss") {
            if (instructions[i].operands.size() >= 2) {
                bssLabels[instructions[i].operands[0]] = bssAddress;
                int bssSize = std::stoi(instructions[i].operands[1]);
                bssAddress += bssSize;
            }
        } else if (instructions[i].section == Section::TEXT) {
            // Only increment address for actual instructions in TEXT section
            currentAddress += 4;
        }
    }

    // Patch unresolved symbols now that we have all labels
    for (const auto& symbol : unresolvedSymbols) {
        if (labels.find(symbol.first) != labels.end()) {
            patchUnresolvedSymbols(symbol.first, labels[symbol.first]);
        } else if (dataLabels.find(symbol.first) != dataLabels.end()) {
            patchUnresolvedSymbols(symbol.first, dataLabels[symbol.first]);
        } else if (bssLabels.find(symbol.first) != bssLabels.end()) {
            patchUnresolvedSymbols(symbol.first, bssLabels[symbol.first]);
        }
    }

    // Set entry point if _start is defined
    auto it = labels.find("_start");
    if (it != labels.end()) {
        entryPoint = it->second;
        std::cout << "DEBUG: _start label found at address 0x" << std::hex << entryPoint << std::dec << "\n";
    } else {
        throw std::runtime_error("No _start label found");
    }
}

void Assembler::resolveSymbols()
{
    for (const auto &sym : symbolTable) {
        if (sym.second.isExternal) {
            // Generate relocation entry for external symbols
            RelocationEntry reloc;
            reloc.symbol.name = sym.first;
            reloc.offset = sym.second.address;
            relocationEntries.push_back(reloc);
        }
    }
}

bool Assembler::assemble(const std::string &inputFile, const std::string &outputFile)
{
    // std::ifstream file(inputFile);
    // if (!file.is_open()) {
    //     std::cerr << "Error: Cannot open input file.\n";
    //     return false;
    // }

    // std::stringstream buffer;
    // buffer << file.rdbuf();
    // file.close();

    // std::vector<Instruction> instructions = parse(buffer.str());

    try {
        std::vector<Instruction> instructions = parse(inputFile);

        // First pass: mark all instructions with their section
        Section currentSection = Section::TEXT;
        for (auto& instr : instructions) {
            if (instr.mnemonic == ".text") {
                currentSection = Section::TEXT;
                continue;
            } else if (instr.mnemonic == ".data") {
                currentSection = Section::DATA;
                continue;
            } else if (instr.mnemonic == ".bss") {
                currentSection = Section::BSS;
                continue;
            }

            instr.section = currentSection;
        }

        // Process sections and resolve labels
        processDataSection(instructions);
        resolveLabels(instructions);

        // Second pass: generate machine code
        currentAddress = textSectionBase;  // Reset address counter for code generation
        for (const auto& instr : instructions) {
            if (instr.section == Section::TEXT) {
                uint32_t encoded = encodeInstruction(instr);
                textSection.push_back(encoded >> 24);
                textSection.push_back((encoded >> 16) & 0xFF);
                textSection.push_back((encoded >> 8) & 0xFF);
                textSection.push_back(encoded & 0xFF);
                currentAddress += 4;
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Assembly error: " << e.what() << std::endl;
        return false;
    }
}

void Assembler::patchUnresolvedSymbols(const std::string& symbol, uint64_t address) {
    if (unresolvedSymbols.find(symbol) != unresolvedSymbols.end()) {
        for (uint64_t offset : unresolvedSymbols[symbol]) {
            int32_t value = address;
            textSection[offset / 4] |= (value & 0xFFFF);
        }
        unresolvedSymbols.erase(symbol);
    }
}

void Assembler::findEntryPoint(const std::vector<Instruction> &instructions)
{
    for (const auto &instr : instructions) {
        if (instr.mnemonic == "_start:" || instr.mnemonic == "start:") {
            entrySymbol = instr.mnemonic.substr(0, instr.mnemonic.size() - 1);
            return;
        }
    }
    throw std::runtime_error("No entry point (_start or start) found");
}

const std::unordered_map<std::string, uint64_t>& Assembler::getSymbols() const {
    return labels;
}

const std::vector<uint8_t>& Assembler::getMachineCode() const {
    return textSection;
}

const std::vector<RelocationEntry>& Assembler::getRelocations() const { return relocationEntries; }
const std::vector<uint8_t>& Assembler::getTextSection() const { return textSection; }
const std::vector<uint8_t>& Assembler::getDataSection() const { return dataSection; }
const std::vector<uint8_t>& Assembler::getBssSection() const { return bssSection; }
uint64_t Assembler::getEntryPoint() const { return entryPoint; }

void Assembler::printDebugInfo() const
{
    std::cout << "\n==== ASSEMBLER DEBUG INFORMATION ====\n\n";

    // Print text section labels
    std::cout << "TEXT SECTION LABELS (.text starts at 0x" << std::hex << textSectionBase
              << std::dec << "):\n";
    for (const auto &label : labels) {
        std::cout << "  " << label.first << ": 0x" << std::hex << label.second << std::dec << "\n";
    }

    // Print data section labels
    std::cout << "\nDATA SECTION LABELS (.data starts at 0x" << std::hex << dataSectionBase
              << std::dec << "):\n";
    for (const auto &label : dataLabels) {
        std::cout << "  " << label.first << ": 0x" << std::hex << label.second << std::dec;

        // If this is a string length label, show the value
        if (label.first.find("_len") != std::string::npos) {
            std::cout << " (value: " << label.second << ")";
        }
        std::cout << "\n";
    }

    // Print BSS section labels
    std::cout << "\nBSS SECTION LABELS (.bss starts at 0x" << std::hex << bssSectionBase << std::dec
              << "):\n";
    for (const auto &label : bssLabels) {
        std::cout << "  " << label.first << ": 0x" << std::hex << label.second << std::dec << "\n";
    }

    // Print unresolved symbols
    std::cout << "\nUNRESOLVED SYMBOLS:\n";
    if (unresolvedSymbols.empty()) {
        std::cout << "  None\n";
    } else {
        for (const auto &sym : unresolvedSymbols) {
            std::cout << "  " << sym.first << " (referenced at:";
            for (const auto &addr : sym.second) {
                std::cout << " 0x" << std::hex << addr << std::dec;
            }
            std::cout << ")\n";
        }
    }

    // Print entry point
    std::cout << "\nENTRY POINT: 0x" << std::hex << entryPoint << std::dec << "\n";

    // Print section sizes
    std::cout << "\nSECTION SIZES:\n";
    std::cout << "  .text: " << textSection.size() << " bytes\n";
    std::cout << "  .data: " << dataSection.size() << " bytes\n";
    std::cout << "  .bss: " << bssSection.size() << " bytes\n";

    std::cout << "\n";
    std::cout << "\n==== END DEBUG INFORMATION ====\n\n";
}

void Assembler::processDataSection(std::vector<Instruction> &instructions)
{
    std::cout << "DEBUG: processDataSection - dataSectionBase = 0x" << std::hex << dataSectionBase << std::dec << "\n";

    Section currentSection = Section::TEXT;

    // First pass - mark each instruction with its section
    for (auto& instr : instructions) {
        if (instr.mnemonic == ".text") {
            currentSection = Section::TEXT;
            continue;
        } else if (instr.mnemonic == ".data") {
            currentSection = Section::DATA;
            continue;
        } else if (instr.mnemonic == ".bss") {
            currentSection = Section::BSS;
            continue;
        }

        instr.section = currentSection;
    }

    // Second pass - process data declarations
    currentSection = Section::TEXT;
    for (auto it = instructions.begin(); it != instructions.end();) {
        if (it->mnemonic == ".text") {
            currentSection = Section::TEXT;
            it = instructions.erase(it);
            continue;
        } else if (it->mnemonic == ".data") {
            currentSection = Section::DATA;
            it = instructions.erase(it);
            continue;
        } else if (it->mnemonic == ".bss") {
            currentSection = Section::BSS;
            it = instructions.erase(it);
            continue;
        }

        // Process data declarations
        if (currentSection == Section::DATA && it->mnemonic.back() != ':') {
            std::string label = it->mnemonic;
            if (it->operands.size() >= 1) {
                // Check if it's a string (first char is quote)
                if (it->operands[0][0] == '"') {
                    // Find the last quote
                    std::string rawString = it->operands[0];
                    size_t lastQuotePos = rawString.rfind('"');

                    // If we don't have a closing quote, join operands
                    if (lastQuotePos == 0 && it->operands.size() > 1) {
                        // Join all operands to handle strings with spaces
                        std::string fullString = it->operands[0];
                        for (size_t i = 1; i < it->operands.size(); i++) {
                            fullString += " " + it->operands[i];
                        }

                        // Find the last quote in the full string
                        lastQuotePos = fullString.rfind('"');
                        if (lastQuotePos != std::string::npos && lastQuotePos > 0) {
                            rawString = fullString;
                        }
                    }

                    // Extract the string content
                    std::string str;
                    if (lastQuotePos != std::string::npos && lastQuotePos > 0) {
                        str = rawString.substr(1, lastQuotePos - 1);
                    } else {
                        str = rawString.substr(1, rawString.size() - 2);
                    }

                    // Handle escape sequences
                    std::string processedStr;
                    for (size_t i = 0; i < str.size(); i++) {
                        if (str[i] == '\\' && i + 1 < str.size()) {
                            switch (str[i+1]) {
                            case 'n': processedStr += '\n'; break;
                            case 't': processedStr += '\t'; break;
                            case 'r': processedStr += '\r'; break;
                            case '\\': processedStr += '\\'; break;
                            case '"': processedStr += '"'; break;
                            default: processedStr += str[i+1];
                            }
                            i++; // Skip the next character
                        } else {
                            processedStr += str[i];
                        }
                    }

                    std::cout << "Processing string data '" << label << "': \""
                              << processedStr << "\" (length: " << processedStr.length() << ")\n";

                    // Store in data section
                    uint64_t address = static_cast<uint64_t>(dataSectionBase) + static_cast<uint64_t>(dataSection.size());
                    dataLabels[label] = address;
                    for (char c : processedStr) {
                        dataSection.push_back(static_cast<uint8_t>(c));
                    }

                    // Add null terminator
                    dataSection.push_back(0);

                    // Store length in symbol table (excluding null terminator)
                    std::string lenLabel = label + "_len";
                    dataLabels[lenLabel] = processedStr.length();

                    std::cout << "  Created data at 0x" << std::hex
                              << address << std::dec
                              << " with length " << processedStr.length() << "\n";
                } else {
                    // Numeric data
                    int size = std::stoi(it->operands[0]);
                    uint64_t address = static_cast<uint64_t>(dataSectionBase) + static_cast<uint64_t>(dataSection.size());
                    dataLabels[label] = address;
                    dataSection.resize(dataSection.size() + size);

                    std::cout << "Processing numeric data '" << label
                              << "': " << size << " bytes at 0x"
                              << std::hex << address << std::dec << "\n";
                }
            }
            it = instructions.erase(it);
        } else {
            ++it;
        }
    }
}
