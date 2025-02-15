#include "assembler.hh"

// Define opcodes for a simple Luminar instruction set
std::unordered_map<std::string, uint8_t> opcodeMap = {
    {"MOV",  0x01}, {"ADD",  0x02}, {"SUB",  0x03},
    {"JMP",  0x04}, {"CALL", 0x05}, {"RET",  0x06}
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
    uint8_t reg = 0;
    uint8_t imm = 0;

    if (instr.operands.size() == 1) { // Single operand (immediate or register)
        if (registerMap.find(instr.operands[0]) != registerMap.end()) {
            reg = registerMap[instr.operands[0]];
        } else {
            imm = std::stoi(instr.operands[0]); // Immediate value
        }
    } else if (instr.operands.size() == 2) { // Register + Immediate
        reg = registerMap[instr.operands[0]];
        imm = std::stoi(instr.operands[1]);
    }

    return (opcode << 8) | (reg << 4) | (imm & 0x0F);
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

    // Second pass: replace label references with addresses
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
