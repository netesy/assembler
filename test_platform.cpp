#include "platform_utils.hh"
#include <iostream>

int main() {
    std::cout << "Platform: " << PlatformUtils::getPlatformName() << std::endl;
    std::cout << "Endianness: " << (PlatformUtils::isLittleEndian() ? "Little" : "Big") << " endian" << std::endl;
    std::cout << "Path separator: '" << PlatformUtils::getPathSeparator() << "'" << std::endl;
    std::cout << "Executable extension: '" << PlatformUtils::getExecutableExtension() << "'" << std::endl;
    std::cout << "Default format: " << PlatformUtils::getDefaultOutputFormat() << std::endl;
    
    if (PlatformUtils::validateStructurePacking()) {
        std::cout << "Structure packing: OK" << std::endl;
    } else {
        std::cout << "Structure packing: WARNING" << std::endl;
    }
    
    return 0;
}