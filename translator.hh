#ifndef TRANSLATOR_HH
#define TRANSLATOR_HH

#include "types.hh"
#include <vector>
#include <string>

class Assembler; // Forward declaration

class Translator {
public:
    Translator(Assembler& assembler);
    void translate_syscalls_to_winapi(std::vector<Instruction>& instructions);

private:
    Assembler& assembler_;
    void print_instructions(const std::string& title, const std::vector<Instruction>& instructions, int start, int end);
};

#endif // TRANSLATOR_HH
