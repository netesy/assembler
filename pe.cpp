#include "pe.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>



#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;           // Magic number (MZ)
    uint16_t e_cblp;            // Bytes on last page of file
    uint16_t e_cp;              // Pages in file
    uint16_t e_crlc;            // Relocations
    uint16_t e_cparhdr;         // Size of header in paragraphs
    uint16_t e_minalloc;        // Minimum extra paragraphs needed
    uint16_t e_maxalloc;        // Maximum extra paragraphs needed
    uint16_t e_ss;              // Initial (relative) SS value
    uint16_t e_sp;              // Initial SP value
    uint16_t e_csum;            // Checksum
    uint16_t e_ip;              // Initial IP value
    uint16_t e_cs;              // Initial (relative) CS value
    uint16_t e_lfarlc;          // File address of relocation table
    uint16_t e_ovno;            // Overlay number
    uint16_t e_res[4];          // Reserved words
    uint16_t e_oemid;           // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;         // OEM information; e_oemid specific
    uint16_t e_res2[10];        // Reserved words
    uint32_t e_lfanew;          // File address of new exe header
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};

struct NTHeaders32 {
    uint32_t Signature;
    FileHeader FileHeader;
    OptionalHeader32 OptionalHeader;
};

struct NTHeaders64 {
    uint32_t Signature;
    FileHeader FileHeader;
    OptionalHeader64 OptionalHeader;
};

struct SectionHeader {
    char Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct ImportDirectoryTable {
    uint32_t ImportLookupTableRVA;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t NameRVA;
    uint32_t ImportAddressTableRVA;
};

// Import lookup table entry for 32-bit
struct ImportLookupEntry32 {
    uint32_t Data;  // If high bit is 1, import by ordinal, otherwise by name
};

// Import lookup table entry for 64-bit
struct ImportLookupEntry64 {
    uint64_t Data;  // If high bit is 1, import by ordinal, otherwise by name
};

// Import by name structure
struct ImportByName {
    uint16_t Hint;
    char Name[1];  // Variable length null-terminated string
};
#pragma pack(pop)

class PEGenerator::Impl {
public:
    Impl(bool is64Bit, uint64_t baseAddr)
        : is64Bit_(is64Bit)
        , baseAddress_(is64Bit ? DEFAULT_IMAGE_BASE_X64 : DEFAULT_IMAGE_BASE_X86)
        , pageSize_(PAGE_SIZE)
        , sectionAlignment_(SECTION_ALIGNMENT)
        , fileAlignment_(FILE_ALIGNMENT)
        , entryPoint_(0) {

        if (baseAddr != 0) {
            baseAddress_ = baseAddr;
        }
    }

    // Section management
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t characteristics;
        uint32_t rawDataPointer;
        uint32_t rawDataSize;
    };

    // Import management
    struct Import {
        std::string moduleName;
        std::vector<std::string> functionNames;
    };

    bool generateExecutable(const std::string& outputFile,
                            const std::vector<uint8_t>& code,
                            const std::unordered_map<std::string, uint64_t>& symbols) {
        try {
            setupDefaultSections(code);
            layoutSections();
            setupImports();

            std::ofstream file(outputFile, std::ios::binary);
            if (!file) {
                lastError_ = "Cannot create output file: " + outputFile;
                return false;
            }

            writeDOSHeader(file);
            writeNTHeaders(file);
            writeSectionHeaders(file);
            writeImportDirectory(file);
            writeSectionData(file);

            file.close();
            return true;
        } catch (const std::exception& e) {
            lastError_ = "Error generating PE file: " + std::string(e.what());
            return false;
        }
    }

    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint32_t characteristics) {
        Section section;
        section.name = name;
        section.data = data;
        section.characteristics = characteristics;
        section.virtualSize = data.size();

        sections_.push_back(std::move(section));
    }

    void addImport(const std::string& moduleName, const std::vector<std::string>& functionNames) {
        Import import;
        import.moduleName = moduleName;
        import.functionNames = functionNames;
        imports_.push_back(std::move(import));
    }

    // Getter/setter methods
    void setBaseAddress(uint64_t addr) { baseAddress_ = addr; }
    void setPageSize(uint64_t size) { pageSize_ = size; }
    void setSectionAlignment(uint32_t align) { sectionAlignment_ = align; }
    void setFileAlignment(uint32_t align) { fileAlignment_ = align; }
    void setEntryPoint(uint64_t addr) { entryPoint_ = addr; }
    void setSubsystem(uint16_t subsystem) { subsystem_ = subsystem; }
    std::string getLastError() const { return lastError_; }

private:
    bool is64Bit_;
    uint64_t baseAddress_;
    uint64_t pageSize_;
    uint32_t sectionAlignment_;
    uint32_t fileAlignment_;
    uint64_t entryPoint_;
    uint16_t subsystem_ = IMAGE_SUBSYSTEM_WINDOWS_CUI;  // Default to console
    std::string lastError_;

    std::vector<Section> sections_;
    std::vector<Import> imports_;
    uint32_t importSectionRVA_ = 0;
    uint32_t importDirectoryRVA_ = 0;

    // Helper methods for section management
    void setupDefaultSections(const std::vector<uint8_t>& code) {
        // Create .text section with code
        Section textSection;
        textSection.name = ".text";
        textSection.data = code;
        textSection.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        sections_.push_back(std::move(textSection));

        // Create .rdata section for read-only data (like import tables)
        Section rdataSection;
        rdataSection.name = ".rdata";
        rdataSection.data = {};  // Will be filled later with import data
        rdataSection.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        sections_.push_back(std::move(rdataSection));

        // Create .data section
        Section dataSection;
        dataSection.name = ".data";
        dataSection.data = {};
        dataSection.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        sections_.push_back(std::move(dataSection));

        // Create .bss section
        Section bssSection;
        bssSection.name = ".bss";
        bssSection.data = {};
        bssSection.characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        sections_.push_back(std::move(bssSection));
    }

    void layoutSections() {
        // Calculate size of headers
        uint32_t headerSize = sizeof(DOSHeader) + sizeof(uint32_t);  // DOS header + PE signature
        headerSize += is64Bit_ ? sizeof(NTHeaders64) : sizeof(NTHeaders32);
        headerSize += sections_.size() * sizeof(SectionHeader);

        // Round up to file alignment
        uint32_t alignedHeaderSize = align(headerSize, fileAlignment_);

        // Set the raw data pointers for sections
        uint32_t currentRawPtr = alignedHeaderSize;
        uint32_t currentRVA = align(headerSize, sectionAlignment_);

        for (auto& section : sections_) {
            if (section.name == ".rdata") {
                importSectionRVA_ = currentRVA;
            }

            section.virtualAddress = currentRVA;
            section.virtualSize = align(section.data.size(), 4);  // Align size to 4 bytes for simplicity

            if (!section.data.empty()) {
                section.rawDataPointer = currentRawPtr;
                section.rawDataSize = align(section.data.size(), fileAlignment_);
                currentRawPtr += section.rawDataSize;
            } else {
                section.rawDataPointer = 0;
                section.rawDataSize = 0;
            }

            currentRVA += align(section.virtualSize, sectionAlignment_);
        }
    }

    void setupImports() {
        // Default imports for Windows executable
        if (imports_.empty()) {
            Import kernel32;
            kernel32.moduleName = "KERNEL32.dll";
            kernel32.functionNames = {"ExitProcess"};
            imports_.push_back(std::move(kernel32));
        }

        // Calculate size of import directory
        uint32_t importSize = calculateImportDirectorySize();

        // Find .rdata section and add import directory to it
        for (auto& section : sections_) {
            if (section.name == ".rdata") {
                importDirectoryRVA_ = section.virtualAddress;
                std::vector<uint8_t> importData = createImportDirectory();
                section.data = importData;
                section.virtualSize = importData.size();
                break;
            }
        }
    }

    uint32_t calculateImportDirectorySize() {
        uint32_t size = 0;

        // Import Directory Table (one entry per module + null terminator)
        size += (imports_.size() + 1) * sizeof(ImportDirectoryTable);

        for (const auto& import : imports_) {
            // Module name
            size += import.moduleName.size() + 1;  // +1 for null terminator

            // Import Lookup Table & Import Address Table (one entry per function + null terminator)
            size += (import.functionNames.size() + 1) * (is64Bit_ ? sizeof(ImportLookupEntry64) : sizeof(ImportLookupEntry32)) * 2;

            // Function names
            for (const auto& func : import.functionNames) {
                size += sizeof(uint16_t) + func.size() + 1;  // Hint + name + null terminator
            }
        }

        return size;
    }

    std::vector<uint8_t> createImportDirectory() {
        std::vector<uint8_t> importData;

        // Calculate total size first
        uint32_t totalSize = (imports_.size() + 1) * sizeof(ImportDirectoryTable);

        // Allocate space for module names, ILT entries, IAT entries, and hint/name tables
        for (const auto& import : imports_) {
            totalSize += import.moduleName.size() + 1;  // Module name + null terminator
            totalSize += (import.functionNames.size() + 1) * (is64Bit_ ? sizeof(ImportLookupEntry64) : sizeof(ImportLookupEntry32)) * 2;  // ILT and IAT

            for (const auto& func : import.functionNames) {
                totalSize += sizeof(uint16_t) + func.size() + 1;  // Hint + name + null terminator
            }
        }

        // Resize vector to hold everything
        importData.resize(totalSize);

        // Place the import directory table at the beginning
        uint32_t idtOffset = 0;

        // Calculate offsets for other tables - all offsets should be relative to the start of the import section
        uint32_t nameOffset = (imports_.size() + 1) * sizeof(ImportDirectoryTable);
        uint32_t iltOffset = nameOffset;

        // Calculate the starting offset for ILT/IAT tables
        for (const auto& import : imports_) {
            iltOffset += import.moduleName.size() + 1;
        }

        // Align ILT offset to at least 4-byte boundary
        iltOffset = (iltOffset + 3) & ~3;

        // IAT comes after ILT
        uint32_t iatOffset = iltOffset;
        for (const auto& import : imports_) {
            iatOffset += (import.functionNames.size() + 1) * (is64Bit_ ? sizeof(ImportLookupEntry64) : sizeof(ImportLookupEntry32));
        }

        // Hint/name table comes after IAT
        uint32_t hintNameOffset = iatOffset;
        for (const auto& import : imports_) {
            hintNameOffset += (import.functionNames.size() + 1) * (is64Bit_ ? sizeof(ImportLookupEntry64) : sizeof(ImportLookupEntry32));
        }

        // Now build the tables
        uint32_t currentNamePos = nameOffset;
        uint32_t currentIltPos = iltOffset;
        uint32_t currentIatPos = iatOffset;
        uint32_t currentHintNamePos = hintNameOffset;

        // Process each import
        for (size_t i = 0; i < imports_.size(); i++) {
            const auto& import = imports_[i];

            // Fill import directory table entry
            ImportDirectoryTable idt = {};
            idt.ImportLookupTableRVA = importDirectoryRVA_ + currentIltPos;
            idt.TimeDateStamp = 0;
            idt.ForwarderChain = 0;
            idt.NameRVA = importDirectoryRVA_ + currentNamePos;
            idt.ImportAddressTableRVA = importDirectoryRVA_ + currentIatPos;

            memcpy(&importData[idtOffset], &idt, sizeof(ImportDirectoryTable));
            idtOffset += sizeof(ImportDirectoryTable);

            // Add module name
            strcpy(reinterpret_cast<char*>(&importData[currentNamePos]), import.moduleName.c_str());
            currentNamePos += import.moduleName.size() + 1;

            // Process each function
            for (const auto& func : import.functionNames) {
                // Add hint/name entry
                uint16_t hint = 0;
                memcpy(&importData[currentHintNamePos], &hint, sizeof(uint16_t));
                strcpy(reinterpret_cast<char*>(&importData[currentHintNamePos + sizeof(uint16_t)]), func.c_str());

                // The high bit should not be set - this means import by name, not ordinal
                uint32_t entryRVA = importDirectoryRVA_ + currentHintNamePos;

                // Create import lookup table and import address table entries
                if (is64Bit_) {
                    ImportLookupEntry64 entry = {};
                    entry.Data = entryRVA;

                    memcpy(&importData[currentIltPos], &entry, sizeof(ImportLookupEntry64));
                    memcpy(&importData[currentIatPos], &entry, sizeof(ImportLookupEntry64));

                    currentIltPos += sizeof(ImportLookupEntry64);
                    currentIatPos += sizeof(ImportLookupEntry64);
                } else {
                    ImportLookupEntry32 entry = {};
                    entry.Data = entryRVA;

                    memcpy(&importData[currentIltPos], &entry, sizeof(ImportLookupEntry32));
                    memcpy(&importData[currentIatPos], &entry, sizeof(ImportLookupEntry32));

                    currentIltPos += sizeof(ImportLookupEntry32);
                    currentIatPos += sizeof(ImportLookupEntry32);
                }

                currentHintNamePos += sizeof(uint16_t) + func.size() + 1;
            }

            // Add null terminator for ILT and IAT
            if (is64Bit_) {
                ImportLookupEntry64 nullEntry = {};
                memcpy(&importData[currentIltPos], &nullEntry, sizeof(ImportLookupEntry64));
                memcpy(&importData[currentIatPos], &nullEntry, sizeof(ImportLookupEntry64));

                currentIltPos += sizeof(ImportLookupEntry64);
                currentIatPos += sizeof(ImportLookupEntry64);
            } else {
                ImportLookupEntry32 nullEntry = {};
                memcpy(&importData[currentIltPos], &nullEntry, sizeof(ImportLookupEntry32));
                memcpy(&importData[currentIatPos], &nullEntry, sizeof(ImportLookupEntry32));

                currentIltPos += sizeof(ImportLookupEntry32);
                currentIatPos += sizeof(ImportLookupEntry32);
            }
        }

        // Add null terminator for Import Directory Table
        ImportDirectoryTable nullIDT = {};
        memcpy(&importData[idtOffset], &nullIDT, sizeof(ImportDirectoryTable));

        return importData;
    }

    // File writing methods
    void writeDOSHeader(std::ofstream& file) {
        DOSHeader dosHeader = {};
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
        dosHeader.e_cblp = 0x90;
        dosHeader.e_cp = 3;
        dosHeader.e_cparhdr = 4;
        dosHeader.e_maxalloc = 0xFFFF;
        dosHeader.e_sp = 0xB8;
        dosHeader.e_lfarlc = 0x40;
        dosHeader.e_lfanew = 0x80;  // NT headers start at offset 0x80

        // Simple DOS stub program that prints "This program cannot be run in DOS mode."
        static const uint8_t dosStub[] = {
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
            0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        file.write(reinterpret_cast<const char*>(&dosHeader), sizeof(dosHeader));

        // Write padding until we reach the NT headers offset
        std::vector<uint8_t> padding(dosHeader.e_lfanew - sizeof(dosHeader), 0);
        memcpy(padding.data(), dosStub, std::min(sizeof(dosStub), padding.size()));
        file.write(reinterpret_cast<const char*>(padding.data()), padding.size());
    }

    void writeNTHeaders(std::ofstream& file) {
        // Calculate total image size
        uint32_t imageSize = 0;
        for (const auto& section : sections_) {
            imageSize = std::max(imageSize,
                                 section.virtualAddress + align(section.virtualSize, sectionAlignment_));
        }

        // Write PE signature
        uint32_t peSignature = IMAGE_NT_SIGNATURE;
        file.write(reinterpret_cast<const char*>(&peSignature), sizeof(peSignature));

        // Create and write file header
        FileHeader fileHeader = {};
        fileHeader.Machine = is64Bit_ ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        fileHeader.NumberOfSections = sections_.size();
        fileHeader.TimeDateStamp = static_cast<uint32_t>(time(nullptr));
        fileHeader.PointerToSymbolTable = 0;
        fileHeader.NumberOfSymbols = 0;
        fileHeader.SizeOfOptionalHeader = is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32);
        fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;

        file.write(reinterpret_cast<const char*>(&fileHeader), sizeof(fileHeader));

        // Calculate headers size (aligned to file alignment)
        uint32_t headerSize = sizeof(DOSHeader) + sizeof(uint32_t) + sizeof(FileHeader);
        headerSize += is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32);
        headerSize += sections_.size() * sizeof(SectionHeader);
        uint32_t alignedHeaderSize = align(headerSize, fileAlignment_);

        // Calculate size of code and data
        uint32_t sizeOfCode = 0;
        uint32_t sizeOfInitializedData = 0;
        uint32_t sizeOfUninitializedData = 0;

        for (const auto& section : sections_) {
            if (section.characteristics & IMAGE_SCN_CNT_CODE) {
                sizeOfCode += section.virtualSize;
            }
            if (section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                sizeOfInitializedData += section.virtualSize;
            }
            if (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                sizeOfUninitializedData += section.virtualSize;
            }
        }

        if (is64Bit_) {
            OptionalHeader64 optHeader = {};
            optHeader.Magic = 0x20b;  // PE32+ format
            optHeader.MajorLinkerVersion = 14;
            optHeader.MinorLinkerVersion = 0;
            optHeader.SizeOfCode = sizeOfCode;
            optHeader.SizeOfInitializedData = sizeOfInitializedData;
            optHeader.SizeOfUninitializedData = sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = entryPoint_ != 0 ? entryPoint_ :
                                                (sections_[0].virtualAddress);  // Default to start of .text section
            optHeader.BaseOfCode = sections_[0].virtualAddress;  // Assuming .text is first
            optHeader.ImageBase = baseAddress_;
            optHeader.SectionAlignment = sectionAlignment_;
            optHeader.FileAlignment = fileAlignment_;
            optHeader.MajorOperatingSystemVersion = 6;
            optHeader.MinorOperatingSystemVersion = 0;
            optHeader.MajorImageVersion = 0;
            optHeader.MinorImageVersion = 0;
            optHeader.MajorSubsystemVersion = 6;
            optHeader.MinorSubsystemVersion = 0;
            optHeader.Win32VersionValue = 0;
            optHeader.SizeOfImage = imageSize;
            optHeader.SizeOfHeaders = alignedHeaderSize;
            optHeader.CheckSum = 0;
            optHeader.Subsystem = subsystem_;
            optHeader.DllCharacteristics = 0;
            optHeader.SizeOfStackReserve = 0x100000;
            optHeader.SizeOfStackCommit = 0x1000;
            optHeader.SizeOfHeapReserve = 0x100000;
            optHeader.SizeOfHeapCommit = 0x1000;
            optHeader.LoaderFlags = 0;
            optHeader.NumberOfRvaAndSizes = 16;

            // Set import directory entry
            if (importDirectoryRVA_ != 0) {
                optHeader.DataDirectory[1].VirtualAddress = importDirectoryRVA_;
                optHeader.DataDirectory[1].Size = calculateImportDirectorySize();
            }

            file.write(reinterpret_cast<const char*>(&optHeader), sizeof(optHeader));
        }
        else {
            OptionalHeader32 optHeader = {};
            optHeader.Magic = 0x10b;  // PE32 format
            optHeader.MajorLinkerVersion = 14;
            optHeader.MinorLinkerVersion = 0;
            optHeader.SizeOfCode = sizeOfCode;
            optHeader.SizeOfInitializedData = sizeOfInitializedData;
            optHeader.SizeOfUninitializedData = sizeOfUninitializedData;
            optHeader.AddressOfEntryPoint = entryPoint_ != 0 ? entryPoint_ :
                                                (sections_[0].virtualAddress);  // Default to start of .text section
            optHeader.BaseOfCode = sections_[0].virtualAddress;  // Assuming .text is first
            optHeader.BaseOfData = sections_[1].virtualAddress;  // Assuming .data is second
            optHeader.ImageBase = static_cast<uint32_t>(baseAddress_);
            optHeader.SectionAlignment = sectionAlignment_;
            optHeader.FileAlignment = fileAlignment_;
            optHeader.MajorOperatingSystemVersion = 6;
            optHeader.MinorOperatingSystemVersion = 0;
            optHeader.MajorImageVersion = 0;
            optHeader.MinorImageVersion = 0;
            optHeader.MajorSubsystemVersion = 6;
            optHeader.MinorSubsystemVersion = 0;
            optHeader.Win32VersionValue = 0;
            optHeader.SizeOfImage = imageSize;
            optHeader.SizeOfHeaders = alignedHeaderSize;
            optHeader.CheckSum = 0;
            optHeader.Subsystem = subsystem_;
            optHeader.DllCharacteristics = 0;
            optHeader.SizeOfStackReserve = 0x100000;
            optHeader.SizeOfStackCommit = 0x1000;
            optHeader.SizeOfHeapReserve = 0x100000;
            optHeader.SizeOfHeapCommit = 0x1000;
            optHeader.LoaderFlags = 0;
            optHeader.NumberOfRvaAndSizes = 16;

            // Set import directory entry
            if (importDirectoryRVA_ != 0) {
                uint32_t importSize = calculateImportDirectorySize();
                optHeader.DataDirectory[1].VirtualAddress = importDirectoryRVA_;
                optHeader.DataDirectory[1].Size = importSize;
            }

            file.write(reinterpret_cast<const char*>(&optHeader), sizeof(optHeader));
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        for (const auto& section : sections_) {
            SectionHeader sectionHeader = {};

            // Copy section name (with null padding)
            std::memset(sectionHeader.Name, 0, sizeof(sectionHeader.Name));
            std::memcpy(sectionHeader.Name, section.name.c_str(),
                        std::min(section.name.size(), sizeof(sectionHeader.Name)));

            sectionHeader.Misc.VirtualSize = section.virtualSize;
            sectionHeader.VirtualAddress = section.virtualAddress;
            sectionHeader.SizeOfRawData = section.rawDataSize;
            sectionHeader.PointerToRawData = section.rawDataPointer;
            sectionHeader.PointerToRelocations = 0;
            sectionHeader.PointerToLinenumbers = 0;
            sectionHeader.NumberOfRelocations = 0;
            sectionHeader.NumberOfLinenumbers = 0;
            sectionHeader.Characteristics = section.characteristics;

            file.write(reinterpret_cast<const char*>(&sectionHeader), sizeof(sectionHeader));
        }
    }

    void writeImportDirectory(std::ofstream& file) {
        // This is just a placeholder, the actual import directory is written as part of the section data
    }

    void writeSectionData(std::ofstream& file) {
        // Write each section's data at the appropriate file offset
        for (const auto& section : sections_) {
            if (section.rawDataSize > 0) {
                // Seek to the section's file position
                file.seekp(section.rawDataPointer, std::ios::beg);

                // Write the actual data
                file.write(reinterpret_cast<const char*>(section.data.data()),
                           section.data.size());

                // Write padding if needed
                if (section.rawDataSize > section.data.size()) {
                    std::vector<uint8_t> padding(section.rawDataSize - section.data.size(), 0);
                    file.write(reinterpret_cast<const char*>(padding.data()), padding.size());
                }
            }
        }
    }

    // Utility methods
    uint32_t align(uint32_t value, uint32_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }
};

// Implementation of PEGenerator public methods
PEGenerator::PEGenerator(bool is64Bit, uint64_t baseAddr)
    : pImpl_(std::make_unique<Impl>(is64Bit, baseAddr)) {
}

PEGenerator::~PEGenerator() = default;

bool PEGenerator::generateExecutable(const std::string& outputFile,
                                     const std::vector<uint8_t>& code,
                                     const std::unordered_map<std::string, uint64_t>& symbols) {
    return pImpl_->generateExecutable(outputFile, code, symbols);
}

void PEGenerator::addSection(const std::string& name, const std::vector<uint8_t>& data,
                             uint32_t characteristics) {
    pImpl_->addSection(name, data, characteristics);
}

void PEGenerator::addImport(const std::string& moduleName,
                            const std::vector<std::string>& functionNames) {
    pImpl_->addImport(moduleName, functionNames);
}

void PEGenerator::setBaseAddress(uint64_t addr) {
    pImpl_->setBaseAddress(addr);
}

void PEGenerator::setPageSize(uint64_t size) {
    pImpl_->setPageSize(size);
}

void PEGenerator::setSectionAlignment(uint32_t align) {
    pImpl_->setSectionAlignment(align);
}

void PEGenerator::setFileAlignment(uint32_t align) {
    pImpl_->setFileAlignment(align);
}

void PEGenerator::setEntryPoint(uint64_t addr) {
    pImpl_->setEntryPoint(addr);
}

void PEGenerator::setSubsystem(uint16_t subsystem) {
    pImpl_->setSubsystem(subsystem);
}

std::string PEGenerator::getLastError() const {
    return pImpl_->getLastError();
}

