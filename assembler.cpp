#include "assembler.hh"

// Define opcodes for Luminar instruction set
std::unordered_map<std::string, uint8_t> opcodeMap = {
    {"MOV",  0x01}, {"ADD",  0x02}, {"SUB",  0x03},
    {"CMP",  0x09}, {"JE",   0x0A}, {"JNE",  0x0B},
    {"JG",   0x0C}, {"JL",   0x0D}, {"JMP",  0x04},
    {"CALL", 0x05}, {"RET",  0x06}, {"PUSH", 0x07},
    {"POP",  0x08}, {"AND",  0x0E}, {"OR",   0x0F},
    {"XOR",  0x10}, {"NOT",  0x11}, {"SHL",  0x12},
    {"SHR",  0x13}, {"ROL",  0x14}, {"ROR",  0x15}
};

// Define register mappings
std::unordered_map<std::string, uint8_t> registerMap = {
    {"R0", 0x00}, {"R1", 0x01}, {"R2", 0x02}, {"R3", 0x03},
    {"R4", 0x04}, {"R5", 0x05}, {"R6", 0x06}, {"R7", 0x07}

};

Assembler::Assembler() {}

std::vector<Instruction> Assembler::parse(const std::string& code) {
    std::vector<Instruction> instructions;
    std::istringstream stream(code);
    std::string line;

    while (std::getline(stream, line)) {
        std::istringstream lineStream(line);
        std::string mnemonic;
        lineStream >> mnemonic;

        if (mnemonic.empty() || mnemonic[0] == '#') continue; // Skip comments

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

uint16_t Assembler::encodeInstruction(const Instruction& instr) {
    uint8_t opcode = opcodeMap[instr.mnemonic];
    uint8_t mode = 0;
    uint8_t reg = 0;
    uint8_t value = 0;

    if (instr.mnemonic == "CMP" || instr.mnemonic == "AND" ||
        instr.mnemonic == "OR"  || instr.mnemonic == "XOR") {
        mode = 0b00;
        reg = registerMap[instr.operands[0]];
        value = registerMap[instr.operands[1]];
    }
    else if (instr.mnemonic == "NOT") {
        mode = 0b00;
        reg = registerMap[instr.operands[0]];
        value = 0;  // Unary operation, no second operand
    }
    else if (instr.mnemonic == "SHL" || instr.mnemonic == "SHR" ||
             instr.mnemonic == "ROL" || instr.mnemonic == "ROR") {
        mode = 0b01;
        reg = registerMap[instr.operands[0]];
        value = std::stoi(instr.operands[1]);
    }
    else if (instr.mnemonic == "JE" || instr.mnemonic == "JNE" ||
             instr.mnemonic == "JG" || instr.mnemonic == "JL") {
        mode = 0b11;
        value = labels[instr.operands[0]];  // Jump address
    }
    else if (instr.mnemonic == "CALL") {
        mode = 0b10;
        value = labels[instr.operands[0]];
    }
    else if (instr.mnemonic == "RET") {
        mode = 0b10;
    }
    else if (instr.operands.size() == 2) {
        std::string dest = instr.operands[0];
        std::string src = instr.operands[1];

        if (registerMap.find(dest) != registerMap.end() && registerMap.find(src) != registerMap.end()) {
            mode = 0b00;
            reg = registerMap[dest];
            value = registerMap[src];
        }
        else if (registerMap.find(dest) != registerMap.end() && src[0] != '[') {
            mode = 0b00;
            reg = registerMap[dest];
            value = std::stoi(src);
        }
        else if (registerMap.find(dest) != registerMap.end() && src[0] == '[') {
            mode = 0b00;
            reg = registerMap[dest];
            value = std::stoi(src.substr(1, src.size() - 2));
        }
        else if (dest[0] == '[' && registerMap.find(src) != registerMap.end()) {
            mode = 0b00;
            reg = registerMap[src];
            value = std::stoi(dest.substr(1, dest.size() - 2));
        }
    }

    return (opcode << 8) | (mode << 6) | (reg << 3) | (value & 0x07);
}

void Assembler::resolveLabels(std::vector<Instruction>& instructions) {
    uint16_t address = 0;
    for (size_t i = 0; i < instructions.size(); i++) {
        if (instructions[i].mnemonic.back() == ':') { // Label detected
            labels[instructions[i].mnemonic.substr(0, instructions[i].mnemonic.size() - 1)] = address;
            instructions.erase(instructions.begin() + i); // Remove label
            i--;
        } else {
            address += 2; // Each instruction is 2 bytes
        }
    }

    for (Instruction& instr : instructions) {
        if (labels.find(instr.operands[0]) != labels.end()) {
            instr.operands[0] = std::to_string(labels[instr.operands[0]]);
        }
    }
}

bool Assembler::assemble(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream file(inputFile);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open input file.\n";
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    std::vector<Instruction> instructions = parse(buffer.str());
    resolveLabels(instructions);

    for (const auto& instr : instructions) {
        uint16_t encoded = encodeInstruction(instr);
        machineCode.push_back(encoded >> 8);
        machineCode.push_back(encoded & 0xFF);
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot open output file.\n";
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(machineCode.data()), machineCode.size());
    outFile.close();

    std::cout << "Assembly successful: " << outputFile << " generated.\n";
    return true;
}
