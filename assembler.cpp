#include "assembler.hh"
#include <string>

// Define opcodes for a simple Luminar instruction set
std::unordered_map<std::string, uint16_t> opcodeMap = {
    {"MOV",  0x01}, {"ADD",  0x02}, {"SUB",  0x03},
    {"JMP",  0x04}, {"CALL", 0x05}, {"RET",  0x06}
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
    uint16_t opcode = opcodeMap[instr.mnemonic];
    uint16_t operand = 0;

    if (!instr.operands.empty()) {
        operand = std::stoi(instr.operands[0]); // Basic handling of single immediate values
    }

    return (opcode << 8) | (operand & 0xFF);
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
        machineCode.push_back(encodeInstruction(instr) >> 8);
        machineCode.push_back(encodeInstruction(instr) & 0xFF);
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
