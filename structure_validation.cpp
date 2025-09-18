#include "structure_validation.hh"
#include "platform_utils.hh"
#include <iostream>
#include <iomanip>

namespace StructureValidation {

    bool validatePackedStructures() {
        // Packed structure should be exactly the sum of its members
        size_t expected_packed_size = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t);
        size_t actual_packed_size = sizeof(PackedTestStruct);
        
        if (actual_packed_size != expected_packed_size) {
            std::cerr << "Packed structure validation failed:" << std::endl;
            std::cerr << "  Expected size: " << expected_packed_size << std::endl;
            std::cerr << "  Actual size: " << actual_packed_size << std::endl;
            return false;
        }
        
        // Unpacked structure will likely be larger due to alignment
        size_t actual_unpacked_size = sizeof(UnpackedTestStruct);
        
        std::cout << "Structure packing validation:" << std::endl;
        std::cout << "  Packed struct size: " << actual_packed_size << " bytes" << std::endl;
        std::cout << "  Unpacked struct size: " << actual_unpacked_size << " bytes" << std::endl;
        std::cout << "  Packing working correctly: " << (actual_packed_size == expected_packed_size ? "YES" : "NO") << std::endl;
        
        return true;
    }

    bool validateEndianness() {
        // Test endianness detection
        uint32_t test_value = 0x12345678;
        uint8_t* bytes = reinterpret_cast<uint8_t*>(&test_value);
        
        bool detected_little = PlatformUtils::isLittleEndian();
        bool actual_little = (bytes[0] == 0x78);
        
        if (detected_little != actual_little) {
            std::cerr << "Endianness detection failed:" << std::endl;
            std::cerr << "  Detected: " << (detected_little ? "Little" : "Big") << " endian" << std::endl;
            std::cerr << "  Actual: " << (actual_little ? "Little" : "Big") << " endian" << std::endl;
            return false;
        }
        
        // Test byte swapping
        uint16_t test16 = 0x1234;
        uint16_t swapped16 = PlatformUtils::hostToLittleEndian16(test16);
        uint16_t back16 = PlatformUtils::littleEndianToHost16(swapped16);
        
        if (back16 != test16) {
            std::cerr << "16-bit byte swapping validation failed" << std::endl;
            return false;
        }
        
        uint32_t test32 = 0x12345678;
        uint32_t swapped32 = PlatformUtils::hostToLittleEndian32(test32);
        uint32_t back32 = PlatformUtils::littleEndianToHost32(swapped32);
        
        if (back32 != test32) {
            std::cerr << "32-bit byte swapping validation failed" << std::endl;
            return false;
        }
        
        uint64_t test64 = 0x123456789ABCDEF0ULL;
        uint64_t swapped64 = PlatformUtils::hostToLittleEndian64(test64);
        uint64_t back64 = PlatformUtils::littleEndianToHost64(swapped64);
        
        if (back64 != test64) {
            std::cerr << "64-bit byte swapping validation failed" << std::endl;
            return false;
        }
        
        std::cout << "Endianness validation: PASSED" << std::endl;
        return true;
    }

    bool validateAlignment() {
        // Check natural alignment of basic types
        std::cout << "Type alignment validation:" << std::endl;
        std::cout << "  uint8_t alignment: " << alignof(uint8_t) << std::endl;
        std::cout << "  uint16_t alignment: " << alignof(uint16_t) << std::endl;
        std::cout << "  uint32_t alignment: " << alignof(uint32_t) << std::endl;
        std::cout << "  uint64_t alignment: " << alignof(uint64_t) << std::endl;
        std::cout << "  void* alignment: " << alignof(void*) << std::endl;
        
        // Validate expected alignments
        bool valid = true;
        
        if (alignof(uint16_t) < 2) {
            std::cerr << "Warning: uint16_t alignment is less than 2 bytes" << std::endl;
            valid = false;
        }
        
        if (alignof(uint32_t) < 4) {
            std::cerr << "Warning: uint32_t alignment is less than 4 bytes" << std::endl;
            valid = false;
        }
        
        if (alignof(uint64_t) < 8) {
            std::cerr << "Warning: uint64_t alignment is less than 8 bytes" << std::endl;
            valid = false;
        }
        
        return valid;
    }

    void printSystemInfo() {
        std::cout << "=== System Information ===" << std::endl;
        std::cout << "Platform: " << PlatformUtils::getPlatformName() << std::endl;
        std::cout << "Endianness: " << (PlatformUtils::isLittleEndian() ? "Little" : "Big") << " endian" << std::endl;
        std::cout << "Path separator: '" << PlatformUtils::getPathSeparator() << "'" << std::endl;
        std::cout << "Executable extension: '" << PlatformUtils::getExecutableExtension() << "'" << std::endl;
        std::cout << "Default output format: " << PlatformUtils::getDefaultOutputFormat() << std::endl;
        
        std::cout << "\n=== Type Sizes ===" << std::endl;
        std::cout << "sizeof(uint8_t): " << sizeof(uint8_t) << std::endl;
        std::cout << "sizeof(uint16_t): " << sizeof(uint16_t) << std::endl;
        std::cout << "sizeof(uint32_t): " << sizeof(uint32_t) << std::endl;
        std::cout << "sizeof(uint64_t): " << sizeof(uint64_t) << std::endl;
        std::cout << "sizeof(void*): " << sizeof(void*) << std::endl;
        std::cout << "sizeof(size_t): " << sizeof(size_t) << std::endl;
        
        std::cout << "\n=== Structure Sizes ===" << std::endl;
        std::cout << "sizeof(PackedTestStruct): " << sizeof(PackedTestStruct) << std::endl;
        std::cout << "sizeof(UnpackedTestStruct): " << sizeof(UnpackedTestStruct) << std::endl;
        
        std::cout << "\n=== Validation Results ===" << std::endl;
        validatePackedStructures();
        validateEndianness();
        validateAlignment();
        
        std::cout << "=========================" << std::endl;
    }

}