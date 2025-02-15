#include <iostream>
#include "assembler.hh"

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input.asm> <output.bin>\n";
        return 1;
    }

    Assembler assembler;
    if (!assembler.assemble(argv[1], argv[2])) {
        return 1;
    }

    return 0;
}

