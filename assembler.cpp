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

        if (mnemonic.empty() || mnemonic[0] == '#' || mnemonic == ".global")
            continue; // Skip comments and directives we don't handle

        Instruction instr;
        instr.mnemonic = mnemonic;
        std::string operand;

        while (lineStream >> operand) {
            // Remove trailing comma if present
            if (!operand.empty() && operand.back() == ',') {
                operand.pop_back();
            }
            if (!operand.empty()) {
                instr.operands.push_back(operand);
            }
        }

        instructions.push_back(instr);
    }
    return instructions;
}

uint32_t Assembler::parseOperand(const std::string &operand)
{
    std::cout << "Parsing operand: '" << operand << "' ";

    // Validate operand is not empty
    if (operand.empty()) {
        throw std::runtime_error("Empty operand");
    }

    // Check if this is a memory dereference like [message_len] or [R1+4]
    if (operand.size() >= 2 && operand[0] == '[' && operand[operand.size()-1] == ']') {
        std::string innerOperand = operand.substr(1, operand.size() - 2);
        std::cout << "(memory dereference of '" << innerOperand << "') ";

        // Handle complex memory addressing like [R1+offset]
        size_t plusPos = innerOperand.find('+');
        size_t minusPos = innerOperand.find('-');
        
        if (plusPos != std::string::npos || minusPos != std::string::npos) {
            // Complex addressing mode [reg+offset] or [reg-offset]
            size_t opPos = (plusPos != std::string::npos) ? plusPos : minusPos;
            std::string baseReg = innerOperand.substr(0, opPos);
            std::string offsetStr = innerOperand.substr(opPos + 1);
            
            // Validate base register
            if (registerMap.find(baseReg) == registerMap.end()) {
                throw std::runtime_error("Invalid base register in memory reference: " + baseReg);
            }
            
            // Parse offset
            uint32_t offset = parseOperandValue(offsetStr);
            if (minusPos != std::string::npos) {
                offset = static_cast<uint32_t>(-static_cast<int32_t>(offset));
            }
            
            std::cout << "-> complex memory [" << baseReg << (plusPos != std::string::npos ? "+" : "-") << offsetStr << "]\n";
            // For now, return the offset (TODO: implement proper complex addressing)
            return offset;
        } else {
            // Simple memory dereference [symbol] or [register]
            if (registerMap.find(innerOperand) != registerMap.end()) {
                std::cout << "-> memory dereference of register " << innerOperand << "\n";
                return registerMap[innerOperand];
            } else {
                // Symbol dereference - return the value at that address
                uint32_t address = parseOperandValue(innerOperand);
                std::cout << "-> memory dereference of symbol at 0x" << std::hex << address << std::dec << "\n";
                return address;
            }
        }
    }

    // Check for register operand
    if (registerMap.find(operand) != registerMap.end()) {
        uint8_t regNum = registerMap[operand];
        if (regNum > 7) {
            throw std::runtime_error("Invalid register number: " + operand);
        }
        std::cout << "-> register: " << (int)regNum << "\n";
        return regNum;
    }

    // Check for immediate values (numeric literals)
    if (operand[0] == '#') {
        // Explicit immediate value marker
        std::string numStr = operand.substr(1);
        try {
            int value = std::stoi(numStr);
            if (value < -32768 || value > 65535) {
                throw std::runtime_error("Immediate value out of range: " + operand);
            }
            std::cout << "-> immediate value: " << value << "\n";
            return static_cast<uint32_t>(value);
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("Invalid immediate value: " + operand);
        }
    }

    // Try to parse as numeric literal
    try {
        int value = std::stoi(operand);
        if (value < -32768 || value > 65535) {
            throw std::runtime_error("Numeric literal out of range: " + operand);
        }
        std::cout << "-> numeric literal: " << value << "\n";
        return static_cast<uint32_t>(value);
    } catch (const std::invalid_argument&) {
        // Not a number, continue to symbol lookup
    }

    // Symbol lookup (labels)
    if (labels.find(operand) != labels.end()) {
        std::cout << "-> text label: 0x" << std::hex << labels[operand] << std::dec << "\n";
        return labels[operand];
    } else if (dataLabels.find(operand) != dataLabels.end()) {
        std::cout << "-> data label: 0x" << std::hex << dataLabels[operand] << std::dec << "\n";
        return dataLabels[operand];
    } else if (bssLabels.find(operand) != bssLabels.end()) {
        std::cout << "-> bss label: 0x" << std::hex << bssLabels[operand] << std::dec << "\n";
        return bssLabels[operand];
    } else {
        // Unresolved symbol - will be patched later
        std::cout << "-> unresolved symbol (will be patched later)\n";
        unresolvedSymbols[operand].push_back(currentAddress);
        return 0;
    }
}

uint32_t Assembler::parseOperandValue(const std::string &operand)
{
    std::cout << "Parsing operand value: '" << operand << "' ";

    // Validate operand is not empty
    if (operand.empty()) {
        throw std::runtime_error("Empty operand value");
    }

    // Handle hexadecimal literals (0x prefix)
    if (operand.size() > 2 && operand.substr(0, 2) == "0x") {
        try {
            uint32_t value = static_cast<uint32_t>(std::stoul(operand, nullptr, 16));
            std::cout << "-> hex literal: 0x" << std::hex << value << std::dec << "\n";
            return value;
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid hexadecimal literal: " + operand);
        }
    }

    // Handle binary literals (0b prefix)
    if (operand.size() > 2 && operand.substr(0, 2) == "0b") {
        try {
            uint32_t value = static_cast<uint32_t>(std::stoul(operand.substr(2), nullptr, 2));
            std::cout << "-> binary literal: 0b" << std::bitset<32>(value) << "\n";
            return value;
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid binary literal: " + operand);
        }
    }

    // Symbol lookup
    if (labels.find(operand) != labels.end()) {
        std::cout << "-> text label: 0x" << std::hex << labels[operand] << std::dec << "\n";
        return labels[operand];
    } else if (dataLabels.find(operand) != dataLabels.end()) {
        std::cout << "-> data label: 0x" << std::hex << dataLabels[operand] << std::dec << "\n";
        return dataLabels[operand];
    } else if (bssLabels.find(operand) != bssLabels.end()) {
        std::cout << "-> bss label: 0x" << std::hex << bssLabels[operand] << std::dec << "\n";
        return bssLabels[operand];
    }

    // Handle decimal numeric literals
    try {
        long long value = std::stoll(operand);
        if (value < 0 || value > UINT32_MAX) {
            throw std::runtime_error("Numeric value out of 32-bit range: " + operand);
        }
        std::cout << "-> numeric literal: " << value << "\n";
        return static_cast<uint32_t>(value);
    } catch (const std::invalid_argument&) {
        // Not a number, treat as unresolved symbol
        std::cout << "-> unresolved symbol (will be patched later)\n";
        unresolvedSymbols[operand].push_back(currentAddress);
        return 0;
    } catch (const std::out_of_range&) {
        throw std::runtime_error("Numeric value out of range: " + operand);
    }
}

uint32_t Assembler::encodeInstruction(const Instruction &instr)
{
    if (opcodeMap.find(instr.mnemonic) == opcodeMap.end()) {
        throw std::runtime_error("Invalid mnemonic: " + instr.mnemonic);
    }

    uint8_t opcode = opcodeMap[instr.mnemonic];
    uint8_t mode = 0;
    uint8_t reg1 = 0;
    uint8_t reg2_or_imm = 0;
    uint32_t immediate = 0;
    bool hasImmediate = false;

    if (instr.operands.size() == 2) {
        // Two operand instruction: dest, src
        std::string destOp = instr.operands[0];
        std::string srcOp = instr.operands[1];
        
        // Parse destination operand (should be register)
        if (registerMap.find(destOp) != registerMap.end()) {
            reg1 = registerMap[destOp];
        } else {
            throw std::runtime_error("Invalid destination operand: " + destOp);
        }
        
        // Parse source operand and determine addressing mode
        if (registerMap.find(srcOp) != registerMap.end()) {
            // reg-reg mode
            mode = 0;
            reg2_or_imm = registerMap[srcOp];
        } else if (srcOp.size() >= 2 && srcOp[0] == '[' && srcOp[srcOp.size()-1] == ']') {
            // reg-mem mode (memory dereference)
            mode = 2;
            std::string innerOperand = srcOp.substr(1, srcOp.size() - 2);
            immediate = parseOperandValue(innerOperand);
            hasImmediate = true;
        } else {
            // reg-imm mode (immediate value or symbol)
            mode = 1;
            immediate = parseOperandValue(srcOp);
            hasImmediate = true;
        }
    } else if (instr.operands.size() == 1) {
        // Single operand instruction
        std::string op = instr.operands[0];
        
        if (registerMap.find(op) != registerMap.end()) {
            // Register operand
            mode = 0;
            reg1 = registerMap[op];
        } else if (op.size() >= 2 && op[0] == '[' && op[op.size()-1] == ']') {
            // Memory operand
            mode = 2;
            std::string innerOperand = op.substr(1, op.size() - 2);
            immediate = parseOperandValue(innerOperand);
            hasImmediate = true;
        } else {
            // Immediate operand
            mode = 1;
            immediate = parseOperandValue(op);
            hasImmediate = true;
        }
    }

    // Encode instruction: [opcode:8][mode:8][reg1:8][reg2/imm:8] for first 32 bits
    // Store immediate separately for now to maintain compatibility
    uint32_t encoded = 0;
    encoded |= (static_cast<uint32_t>(opcode) << 24);
    encoded |= (static_cast<uint32_t>(mode) << 16);
    encoded |= (static_cast<uint32_t>(reg1) << 8);
    encoded |= static_cast<uint32_t>(reg2_or_imm);

    // TODO: Handle full 64-bit instruction format with immediate values
    // For now, we'll store immediate in the lower bits if it fits
    if (hasImmediate && immediate <= 0xFF) {
        encoded = (encoded & 0xFFFFFF00) | (immediate & 0xFF);
    }

    return encoded;
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
            SymbolEntry entry;
            entry.name = labelName;
            entry.isGlobal = (!labelName.empty() && labelName[0] == '_');
            entry.isExternal = false;

            // Assign address based on current section
            switch (instructions[i].section) {
            case Section::TEXT:
                labels[labelName] = currentAddress;
                entry.address = currentAddress;
                break;
            case Section::DATA:
                dataLabels[labelName] = dataAddress;
                entry.address = dataAddress;
                break;
            case Section::BSS:
                bssLabels[labelName] = bssAddress;
                entry.address = bssAddress;
                break;
            }
            symbolTable[labelName] = entry;
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

    // Validate all symbol references before patching
    validateSymbolReferences();
    
    // Patch unresolved symbols now that we have all labels
    std::vector<std::string> undefinedSymbols;
    
    for (const auto& symbol : unresolvedSymbols) {
        bool symbolFound = false;
        
        if (labels.find(symbol.first) != labels.end()) {
            patchUnresolvedSymbols(symbol.first, labels[symbol.first]);
            symbolFound = true;
        } else if (dataLabels.find(symbol.first) != dataLabels.end()) {
            patchUnresolvedSymbols(symbol.first, dataLabels[symbol.first]);
            symbolFound = true;
        } else if (bssLabels.find(symbol.first) != bssLabels.end()) {
            patchUnresolvedSymbols(symbol.first, bssLabels[symbol.first]);
            symbolFound = true;
        }
        
        if (!symbolFound) {
            undefinedSymbols.push_back(symbol.first);
        }
    }
    
    // Report undefined symbols
    if (!undefinedSymbols.empty()) {
        std::string errorMsg = "Undefined symbols: ";
        for (size_t i = 0; i < undefinedSymbols.size(); ++i) {
            if (i > 0) errorMsg += ", ";
            errorMsg += undefinedSymbols[i];
        }
        throw std::runtime_error(errorMsg);
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
    if (unresolvedSymbols.find(symbol) == unresolvedSymbols.end()) {
        return; // No references to patch
    }

    std::cout << "Patching symbol '" << symbol << "' with address 0x" << std::hex << address << std::dec << "\n";

    for (uint64_t instructionAddress : unresolvedSymbols[symbol]) {
        // Calculate the byte offset in the text section
        uint64_t byteOffset = instructionAddress - textSectionBase;
        
        if (byteOffset >= textSection.size()) {
            std::cerr << "Warning: Patch offset " << byteOffset << " is beyond text section size " << textSection.size() << "\n";
            continue;
        }

        // Calculate instruction index (each instruction is 4 bytes)
        size_t instrIndex = byteOffset / 4;
        if (instrIndex * 4 + 3 >= textSection.size()) {
            std::cerr << "Warning: Instruction at offset " << byteOffset << " extends beyond text section\n";
            continue;
        }

        // Read the current instruction (little-endian)
        uint32_t currentInstr = 0;
        currentInstr |= textSection[instrIndex * 4];
        currentInstr |= (textSection[instrIndex * 4 + 1] << 8);
        currentInstr |= (textSection[instrIndex * 4 + 2] << 16);
        currentInstr |= (textSection[instrIndex * 4 + 3] << 24);

        // Extract instruction components
        uint8_t opcode = (currentInstr >> 24) & 0xFF;
        uint8_t mode = (currentInstr >> 16) & 0xFF;
        uint8_t reg1 = (currentInstr >> 8) & 0xFF;
        uint8_t reg2_or_imm = currentInstr & 0xFF;

        std::cout << "  Patching instruction at 0x" << std::hex << instructionAddress 
                  << " (opcode=0x" << (int)opcode << ", mode=" << (int)mode << ")\n";

        // Calculate relative address for different addressing modes
        uint32_t patchValue = 0;
        if (mode == 1 || mode == 2) { // Immediate or memory mode
            // For cross-section references, use absolute address
            if ((instructionAddress >= textSectionBase && instructionAddress < textSectionBase + 0x100000) &&
                (address >= dataSectionBase && address < dataSectionBase + 0x100000)) {
                // Text to data section reference - use absolute address
                patchValue = static_cast<uint32_t>(address);
            } else if ((instructionAddress >= textSectionBase && instructionAddress < textSectionBase + 0x100000) &&
                       (address >= bssSectionBase && address < bssSectionBase + 0x100000)) {
                // Text to BSS section reference - use absolute address
                patchValue = static_cast<uint32_t>(address);
            } else {
                // Same section or relative reference
                int64_t relativeAddr = static_cast<int64_t>(address) - static_cast<int64_t>(instructionAddress + 4);
                if (relativeAddr >= INT32_MIN && relativeAddr <= INT32_MAX) {
                    patchValue = static_cast<uint32_t>(relativeAddr);
                } else {
                    patchValue = static_cast<uint32_t>(address);
                }
            }

            // For immediate mode, store in the lower 8 bits if it fits
            if (mode == 1 && patchValue <= 0xFF) {
                reg2_or_imm = static_cast<uint8_t>(patchValue);
            } else {
                // For larger values, we need to extend the instruction format
                // For now, store what we can in the available space
                reg2_or_imm = static_cast<uint8_t>(patchValue & 0xFF);
            }
        }

        // Reconstruct the instruction
        uint32_t patchedInstr = 0;
        patchedInstr |= (static_cast<uint32_t>(opcode) << 24);
        patchedInstr |= (static_cast<uint32_t>(mode) << 16);
        patchedInstr |= (static_cast<uint32_t>(reg1) << 8);
        patchedInstr |= static_cast<uint32_t>(reg2_or_imm);

        // Write back the patched instruction (little-endian)
        textSection[instrIndex * 4] = patchedInstr & 0xFF;
        textSection[instrIndex * 4 + 1] = (patchedInstr >> 8) & 0xFF;
        textSection[instrIndex * 4 + 2] = (patchedInstr >> 16) & 0xFF;
        textSection[instrIndex * 4 + 3] = (patchedInstr >> 24) & 0xFF;

        std::cout << "  Patched with value 0x" << std::hex << patchValue << std::dec << "\n";
    }

    unresolvedSymbols.erase(symbol);
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

const std::unordered_map<std::string, SymbolEntry>& Assembler::getSymbols() const {
    // This is a placeholder until the symbol table is properly populated.
    // The plan is to populate symbolTable in resolveLabels.
    // For now, this will likely return an empty map, which will be handled
    // in the next steps.
    return symbolTable;
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
                    SymbolEntry entry;
                    entry.name = label;
                    entry.address = address;
                    entry.isGlobal = (!label.empty() && label[0] == '_');
                    entry.isExternal = false;
                    symbolTable[label] = entry;
                    for (char c : processedStr) {
                        dataSection.push_back(static_cast<uint8_t>(c));
                    }

                    // Add null terminator
                    dataSection.push_back(0);

                    // Store length in symbol table (excluding null terminator)
                    std::string lenLabel = label + "_len";
                    dataLabels[lenLabel] = processedStr.length();
                    SymbolEntry len_entry;
                    len_entry.name = lenLabel;
                    len_entry.address = processedStr.length(); // This is a value, not an address.
                    len_entry.isGlobal = (!lenLabel.empty() && lenLabel[0] == '_');
                    len_entry.isExternal = false;
                    symbolTable[lenLabel] = len_entry;

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

void Assembler::validateSymbolReferences()
{
    std::vector<std::string> invalidReferences;
    
    for (const auto& symbolRef : unresolvedSymbols) {
        const std::string& symbolName = symbolRef.first;
        
        // Check if symbol exists in any section
        bool found = (labels.find(symbolName) != labels.end()) ||
                     (dataLabels.find(symbolName) != dataLabels.end()) ||
                     (bssLabels.find(symbolName) != bssLabels.end());
        
        if (!found) {
            invalidReferences.push_back(symbolName);
        }
    }
    
    if (!invalidReferences.empty()) {
        std::string errorMsg = "Invalid symbol references: ";
        for (size_t i = 0; i < invalidReferences.size(); ++i) {
            if (i > 0) errorMsg += ", ";
            errorMsg += invalidReferences[i];
        }
        throw std::runtime_error(errorMsg);
    }
}

Section Assembler::getSymbolSection(const std::string& symbol) const
{
    if (labels.find(symbol) != labels.end()) {
        return Section::TEXT;
    } else if (dataLabels.find(symbol) != dataLabels.end()) {
        return Section::DATA;
    } else if (bssLabels.find(symbol) != bssLabels.end()) {
        return Section::BSS;
    }
    return Section::NONE;
}
