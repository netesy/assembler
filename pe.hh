#ifndef PE_HH
#define PE_HH

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include "assembler.hh"


#pragma pack(push, 1)

// COFF structures for object file generation
struct CoffHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct CoffSectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct CoffSymbol {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
};

struct CoffRelocation {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
};

#pragma pack(pop)


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

// COFF-specific constants
constexpr uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
constexpr uint8_t IMAGE_SYM_CLASS_EXTERNAL = 2;
constexpr uint8_t IMAGE_SYM_CLASS_STATIC = 3;
constexpr int16_t IMAGE_SYM_DEBUG = -2;
constexpr uint16_t IMAGE_REL_AMD64_REL32 = 0x0004;

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
                            Assembler& assembler);

    // Method to generate an object file
    bool generateObjectFile(const std::string& outputFile,
                            Assembler& assembler);

    // Section management
    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint32_t virtualSize, uint32_t characteristics);

    // Import management
    void addImport(const std::string& moduleName, const std::string& functionName);

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
