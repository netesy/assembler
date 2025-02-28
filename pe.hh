#ifndef PE_HH
#define PE_HH

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>


namespace {
// PE constants
constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;       // MZ
constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550;    // PE00
constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x014c;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
constexpr uint16_t IMAGE_FILE_32BIT_MACHINE = 0x0100;
constexpr uint16_t IMAGE_FILE_SYSTEM = 0x1000;
constexpr uint16_t IMAGE_FILE_DLL = 0x2000;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
constexpr uint64_t PAGE_SIZE = 0x1000;
constexpr uint64_t DEFAULT_IMAGE_BASE_X86 = 0x00400000;
constexpr uint64_t DEFAULT_IMAGE_BASE_X64 = 0x0000000140000000;
constexpr uint64_t SECTION_ALIGNMENT = 0x1000;
constexpr uint64_t FILE_ALIGNMENT = 0x200;
}

class PEGenerator {
public:
    PEGenerator(bool is64Bit = false, uint64_t baseAddr = 0);
    ~PEGenerator();

    // Prevent copying
    PEGenerator(const PEGenerator&) = delete;
    PEGenerator& operator=(const PEGenerator&) = delete;

    // Main method to generate an executable
    bool generateExecutable(const std::string& outputFile,
                            const std::vector<uint8_t>& code,
                            const std::unordered_map<std::string, uint64_t>& symbols = {});

    // Section management
    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint32_t characteristics);

    // Import management
    void addImport(const std::string& moduleName,
                   const std::vector<std::string>& functionNames);

    // Configuration methods
    void setBaseAddress(uint64_t addr);
    void setPageSize(uint64_t size);
    void setSectionAlignment(uint32_t align);
    void setFileAlignment(uint32_t align);
    void setEntryPoint(uint64_t addr);
    void setSubsystem(uint16_t subsystem);

    // Error handling
    std::string getLastError() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

#endif // PE_HH
