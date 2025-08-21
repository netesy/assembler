#ifndef PARSER_HH
#define PARSER_HH

#include "types.hh"
#include <string>
#include <vector>
#include <map>

class Assembler; // Forward declaration

class Parser {
public:
    Parser(Assembler& assembler);

    std::vector<Instruction> parse(const std::string& source);

private:
    Assembler& assembler_;

    Operand parse_operand(const std::string& op_str);
    OperandSize parse_size_prefix(const std::string& operand_str, std::string& cleaned_operand);
    void handle_data_directive(Instruction& instr, const std::string& directive, const std::string& data_str);

    // State needed for parsing
    Section currentSection;
    SectionInfo currentSectionInfo;
    bool in_macro = false;
    std::string current_macro_name;
};

#endif // PARSER_HH
