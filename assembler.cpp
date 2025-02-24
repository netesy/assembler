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
    if (registerMap.find(operand) != registerMap.end()) {
        return registerMap[operand];
    } else if (labels.find(operand) != labels.end()) {
        return labels[operand];
    } else if (dataLabels.find(operand) != dataLabels.end()) {
        return dataLabels[operand];
    } else if (bssLabels.find(operand) != bssLabels.end()) {
        return bssLabels[operand];
    } else {
        unresolvedSymbols[operand].push_back(currentAddress);
        return 0;
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
    currentAddress = 0;
    dataAddress = 0;
    bssAddress = 0;

    for (size_t i = 0; i < instructions.size(); i++) {
        if (instructions[i].mnemonic.back() == ':') { // Label detected
            std::string labelName = instructions[i].mnemonic.substr(0,
                                                                    instructions[i].mnemonic.size()
                                                                        - 1);
            labels[labelName] = currentAddress;
            patchUnresolvedSymbols(labelName, currentAddress);
            instructions.erase(instructions.begin() + i);
            i--;
        } else if (instructions[i].mnemonic == ".data") {
            dataLabels[instructions[i].operands[0]] = dataAddress;
            patchUnresolvedSymbols(instructions[i].operands[0], dataAddress);
            int dataSize = std::stoi(instructions[i].operands[1]);
            dataAddress += dataSize;
        } else if (instructions[i].mnemonic == ".bss") {
            bssLabels[instructions[i].operands[0]] = bssAddress;
            patchUnresolvedSymbols(instructions[i].operands[0], bssAddress);
            int bssSize = std::stoi(instructions[i].operands[1]);
            bssAddress += bssSize;
        } else {
            currentAddress += 4;
        }
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

        // First pass: process sections and labels
        processDataSection(instructions);
        resolveLabels(instructions);

        // Set entry point if _start is defined
        auto it = labels.find("_start");
        if (it != labels.end()) {
            entryPoint = it->second;
        } else {
            throw std::runtime_error("No _start label found");
        }

        // Second pass: generate machine code
        for (const auto& instr : instructions) {
            if (instr.section == Section::TEXT) {
                uint32_t encoded = encodeInstruction(instr);
                textSection.push_back(encoded >> 24);
                textSection.push_back((encoded >> 16) & 0xFF);
                textSection.push_back((encoded >> 8) & 0xFF);
                textSection.push_back(encoded & 0xFF);
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

void Assembler::processDataSection(std::vector<Instruction> &instructions)
{
    Section currentSection = Section::TEXT;

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

        it->section = currentSection;

        // Process data declarations
        if (currentSection == Section::DATA && it->mnemonic.back() != ':') {
            std::string label = it->mnemonic;
            if (it->operands.size() >= 1) {
                if (it->operands[0][0] == '"') {
                    // String data
                    std::string str = it->operands[0].substr(1, it->operands[0].size() - 2);
                    dataLabels[label] = dataSection.size();

                    // Store string in data section
                    for (char c : str) {
                        dataSection.push_back(static_cast<uint8_t>(c));
                    }

                    // Store length in symbol table
                    std::string lenLabel = label + "_len";
                    dataLabels[lenLabel] = str.length();
                } else {
                    // Numeric data
                    dataLabels[label] = dataSection.size();
                    int size = std::stoi(it->operands[0]);
                    dataSection.resize(dataSection.size() + size);
                }
            }
            it = instructions.erase(it);
        } else {
            ++it;
        }
    }
}
