#ifndef STRUCTURE_VALIDATION_HH
#define STRUCTURE_VALIDATION_HH

#include <cstdint>
#include <iostream>

namespace StructureValidation {
    // Test structures to validate packing
    #pragma pack(push, 1)
    struct PackedTestStruct {
        uint8_t a;
        uint16_t b;
        uint32_t c;
        uint64_t d;
    };
    #pragma pack(pop)

    struct UnpackedTestStruct {
        uint8_t a;
        uint16_t b;
        uint32_t c;
        uint64_t d;
    };

    // Validation functions
    bool validatePackedStructures();
    bool validateEndianness();
    bool validateAlignment();
    void printSystemInfo();
    
    // Size validation
    template<typename T>
    bool validateSize(const char* name, size_t expected_size) {
        size_t actual_size = sizeof(T);
        if (actual_size != expected_size) {
            std::cerr << "Size validation failed for " << name 
                      << ": expected " << expected_size 
                      << ", got " << actual_size << std::endl;
            return false;
        }
        return true;
    }
}

#endif // STRUCTURE_VALIDATION_HH