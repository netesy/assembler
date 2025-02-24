#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <stdexcept>

// Forward declarations
struct ElfSection;
struct ElfSegment;

class ElfGenerator {
public:
    // Construction and configuration
    explicit ElfGenerator(bool is64Bit = true, uint64_t baseAddress = 0x400000);
    ~ElfGenerator();

    // Section management
    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint64_t vaddr, uint32_t type, uint64_t flags);
    void addSegment(uint32_t type, uint32_t flags, uint64_t vaddr,
                    uint64_t paddr, uint64_t memsz, uint64_t align);

    // Symbol management
    void addSymbol(const std::string& name, uint64_t value, uint64_t size,
                   uint8_t info, uint8_t other, uint16_t shndx);

    // Relocation management
    void addRelocation(const std::string& section, uint64_t offset,
                       uint32_t type, const std::string& symbol, int64_t addend);

    // Generation methods
    bool generateExecutable(const std::string& outputFile,
                            const std::vector<uint8_t>& code,
                            const std::unordered_map<std::string, uint64_t>& symbols = {});

    bool generateElf(const std::vector<uint8_t> &textSection,
                     const std::string &outputFile,
                     const std::unordered_map<std::string, uint64_t> &symbols,
                     const std::vector<uint8_t> &dataSection,
                     uint64_t entryPoint);

    // Configuration
    void setBaseAddress(uint64_t address);
    void setPageSize(uint64_t size);
    void setStackSize(uint64_t size);
    void setEntryPoint(uint64_t address);

    // Error handling
    std::string getLastError() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
