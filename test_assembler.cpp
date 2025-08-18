#include "assembler.hh"
#include <iostream>

int main() {
    std::string asmCode = R"(
.data
message "Hello, World!\n"

.text
_start:
    MOV R0, 1
    MOV R1, message
    MOV R2, [message_len]
    MOV R3, 1
)";

    try {
        Assembler assembler;
        if (assembler.assemble(asmCode, "test.o")) {
            std::cout << "Assembly successful!\n";
            assembler.printDebugInfo();
            
            const auto& textSection = assembler.getTextSection();
            std::cout << "Generated " << textSection.size() << " bytes of machine code\n";
            
            return 0;
        } else {
            std::cout << "Assembly failed\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
        return 1;
    }
}