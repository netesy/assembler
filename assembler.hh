#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

struct Instruction {
    std::string mnemonic;
    std::vector<std::string> operands;
};

class Assembler {
public:
    Assembler();
    bool assemble(const std::string& inputFile, const std::string& outputFile);

private:
    std::vector<uint8_t> machineCode;
    std::unordered_map<std::string, uint16_t> labels;

    std::vector<Instruction> parse(const std::string& code);
    uint16_t encodeInstruction(const Instruction& instr);
    void resolveLabels(std::vector<Instruction>& instructions);
};

#endif
