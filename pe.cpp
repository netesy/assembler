#include "pe.hh"
#include "platform_utils.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <ctime>
#include <ios>
#include <iomanip>
#include <iomanip>


#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
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
    DataDirectory dataDirectory[16];
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
    DataDirectory dataDirectory[16];
};

struct NTHeaders32 {
    uint32_t Signature;
    FileHeader fileHeader;
    OptionalHeader32 OptionalHeader;
};

struct NTHeaders64 {
    uint32_t Signature;
    FileHeader fileHeader;
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

struct ImportLookupEntry32 {
    uint32_t Data;
};

struct ImportLookupEntry64 {
    uint64_t Data;
};

struct ImportByName {
    uint16_t Hint;
    char Name[1];
};

struct BaseRelocationBlock {
    uint32_t VirtualAddress;  // RVA of the block
    uint32_t SizeOfBlock;     // Size of the block including this header
    // Followed by an array of relocation entries (uint16_t)
};

struct BaseRelocationEntry {
    uint16_t offset : 12;     // Offset within the page
    uint16_t type : 4;        // Relocation type
};

// Base relocation types
constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
constexpr uint16_t IMAGE_REL_BASED_HIGH = 1;
constexpr uint16_t IMAGE_REL_BASED_LOW = 2;
constexpr uint16_t IMAGE_REL_BASED_HIGHLOW = 3;
constexpr uint16_t IMAGE_REL_BASED_HIGHADJ = 4;
constexpr uint16_t IMAGE_REL_BASED_DIR64 = 10;

struct COFFSymbol {
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

#pragma pack(pop)

class PEGenerator::Impl {
public:
    Impl(bool is64Bit, uint64_t baseAddr)
        : is64Bit_(is64Bit)
        , baseAddress_(is64Bit ? 0x140000000ULL : DEFAULT_IMAGE_BASE_X86)  // Use 0x140000000 for 64-bit as per requirement 6.4
        , pageSize_(PAGE_SIZE)
        , sectionAlignment_(0x1000)  // Set to 0x1000 as per requirement 6.5
        , fileAlignment_(0x200)      // Set to 0x200 as per requirement 6.5
        , entryPoint_(0) {

        if (baseAddr != 0) {
            baseAddress_ = baseAddr;
        }
    }

    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t characteristics;
        uint32_t rawDataPointer;
        uint32_t rawDataSize;
    };

    bool generateExecutable(const std::string& outputFile,
                            Assembler& assembler) {
        try {
            validateOptions();

            if (!findSection(".text")) {
                throw std::runtime_error("PE Generation Error: No .text section found. An executable must have a .text section.");
            }

            // Ensure all required PE sections exist with proper characteristics (requirement 6.8)
            ensureRequiredSections();

            // Ensure complete import table with KERNEL32.dll ExitProcess (requirement 6.9)
            ensureKernel32Import();

            buildSymbolTable(assembler.getSymbols());

            // Reserve space for the import directory in .idata before the layout pass.
            uint32_t importDirectorySize = calculateImportDirectorySize();
            if (importDirectorySize > 0) {
                Section* idata = findSection(".idata");
                if (idata) {
                    // The import directory will be aligned within the section.
                    uint32_t offset = align(idata->data.size(), 16);
                    // The total virtual size will be the original content + padding + import directory.
                    idata->virtualSize = offset + importDirectorySize;
                }
            }

            // A single, final layout pass determines the correct RVAs for all sections.
            layoutSections();

            // Now that layout is final, generate the import directory with the correct RVAs.
            setupImports();

            // Process relocations to resolve imported function calls
            processRelocations(assembler);

            // Generate base relocations for the .reloc section (requirement 6.7)
            generateBaseRelocations();

            // Validate the complete file structure before writing
            validateFileStructure();

            std::ofstream file(outputFile, std::ios::binary);
            if (!file) {
                lastError_ = "Cannot create output file: " + outputFile;
                return false;
            }

            writeDOSHeader(file);
            writeNTHeaders(file);
            writeSectionHeaders(file);
            writeSectionData(file);
            writeSymbolTable(file);

            file.close();
            return true;
        } catch (const std::exception& e) {
            lastError_ = "Error generating PE file: " + std::string(e.what());
            return false;
        }
    }

    bool generateObjectFile(const std::string& outputFile, Assembler& assembler) {
        try {
            std::vector<std::pair<std::string, const std::vector<uint8_t>*>> sections;
            sections.push_back({".text", &assembler.getTextSection()});
            if (!assembler.getDataSection().empty()) sections.push_back({".data", &assembler.getDataSection()});
            if (assembler.getBssSize() > 0) sections.push_back({".bss", nullptr});
            if (!assembler.getRodataSection().empty()) sections.push_back({".rdata", &assembler.getRodataSection()});

            std::vector<CoffSymbol> symbols;
            std::string stringTable(4, '\0');
            std::map<std::string, uint32_t> symbolIndexMap;

            // .file symbol
            CoffSymbol fileSymbol = {};
            strncpy(fileSymbol.Name.ShortName, ".file", 8);
            fileSymbol.SectionNumber = IMAGE_SYM_DEBUG;
            fileSymbol.StorageClass = 103; // IMAGE_SYM_CLASS_FILE
            fileSymbol.NumberOfAuxSymbols = 1;
            symbols.push_back(fileSymbol);

            CoffSymbol fileAuxSymbol = {};
            // A real implementation would get the input filename from the assembler.
            strncpy(reinterpret_cast<char*>(&fileAuxSymbol), "source.asm", sizeof(fileAuxSymbol));
            symbols.push_back(fileAuxSymbol);


            // Section symbols
            for (size_t i = 0; i < sections.size(); ++i) {
                CoffSymbol secSymbol = {};
                strncpy(secSymbol.Name.ShortName, sections[i].first.c_str(), 8);
                secSymbol.Value = 0;
                secSymbol.SectionNumber = i + 1;
                secSymbol.Type = 0;
                secSymbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
                secSymbol.NumberOfAuxSymbols = 1;
                symbols.push_back(secSymbol);

                CoffSymbol auxSym = {};
                const auto& data_ptr = sections[i].second;
                if (data_ptr) {
                    reinterpret_cast<uint32_t*>(&auxSym)[0] = data_ptr->size(); // Length
                }
                reinterpret_cast<uint16_t*>(&auxSym)[2] = 0; // NumberOfRelocations (will be patched later)
                reinterpret_cast<uint16_t*>(&auxSym)[3] = 0; // NumberOfLinenumbers
                symbols.push_back(auxSym);
            }

            // User symbols
            for (const auto& pair : assembler.getSymbols()) {
                const auto& sym = pair.second;
                symbolIndexMap[sym.name] = symbols.size();
                CoffSymbol s = {};
                if (sym.name.length() > 8) {
                    s.Name.LongName.Zeros = 0;
                    s.Name.LongName.Offset = stringTable.size();
                    stringTable.append(sym.name).append(1, '\0');
                } else {
                    strncpy(s.Name.ShortName, sym.name.c_str(), 8);
                }
                s.Value = sym.address;
                s.Type = (sym.type == SymbolType::FUNCTION) ? 0x20 : 0;
                if (sym.isDefined) {
                    s.StorageClass = (sym.binding == SymbolBinding::GLOBAL) ? IMAGE_SYM_CLASS_EXTERNAL : IMAGE_SYM_CLASS_STATIC;
                    // Find section index
                    for (size_t i = 0; i < sections.size(); ++i) {
                         if (sections[i].first == assembler.getSectionName(sym.section)) {
                             s.SectionNumber = i + 1;
                             break;
                         }
                    }
                } else {
                    s.SectionNumber = 0; // UNDEFINED
                    s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
                }
                symbols.push_back(s);
            }

            // Relocations
            std::vector<std::vector<CoffRelocation>> relocs_per_section(sections.size());
            for (const auto& reloc : assembler.getRelocations()) {
                auto it = symbolIndexMap.find(reloc.symbolName);
                if (it == symbolIndexMap.end()) {
                    throw std::runtime_error("Relocation for unknown symbol: " + reloc.symbolName);
                }
                CoffRelocation r = {};
                r.VirtualAddress = reloc.offset;
                r.SymbolTableIndex = it->second;
                r.Type = IMAGE_REL_AMD64_REL32;
                for (size_t i = 0; i < sections.size(); ++i) {
                    if (sections[i].first == assembler.getSectionName(reloc.section)) {
                        relocs_per_section[i].push_back(r);
                        break;
                    }
                }
            }

            // Layout
            uint32_t currentOffset = sizeof(CoffHeader) + sections.size() * sizeof(CoffSectionHeader);
            std::vector<CoffSectionHeader> sectionHeaders(sections.size());
            for (size_t i = 0; i < sections.size(); ++i) {
                strncpy(sectionHeaders[i].Name, sections[i].first.c_str(), 8);
                const auto& data_ptr = sections[i].second;
                if (data_ptr) {
                    sectionHeaders[i].SizeOfRawData = data_ptr->size();
                    sectionHeaders[i].PointerToRawData = currentOffset;
                    currentOffset += data_ptr->size();
                }
            }

            uint32_t relocsOffset = currentOffset;
            for (size_t i = 0; i < sections.size(); ++i) {
                if (!relocs_per_section[i].empty()) {
                    sectionHeaders[i].PointerToRelocations = relocsOffset;
                    sectionHeaders[i].NumberOfRelocations = relocs_per_section[i].size();
                    relocsOffset += relocs_per_section[i].size() * sizeof(CoffRelocation);
                }
            }

            uint32_t symbolTableOffset = relocsOffset;

            // Write
            std::ofstream file(outputFile, std::ios::binary);
            if (!file) {
                lastError_ = "Cannot open output file";
                return false;
            }

            CoffHeader header = {};
            header.Machine = IMAGE_FILE_MACHINE_AMD64;
            header.NumberOfSections = sections.size();
            header.TimeDateStamp = time(nullptr);
            header.PointerToSymbolTable = symbolTableOffset;
            header.NumberOfSymbols = symbols.size();
            header.Characteristics = IMAGE_FILE_LARGE_ADDRESS_AWARE;
            file.write(reinterpret_cast<const char*>(&header), sizeof(header));

            file.write(reinterpret_cast<const char*>(sectionHeaders.data()), sectionHeaders.size() * sizeof(CoffSectionHeader));

            for (size_t i = 0; i < sections.size(); ++i) {
                const auto& data_ptr = sections[i].second;
                if (data_ptr && !data_ptr->empty()) {
                    file.seekp(sectionHeaders[i].PointerToRawData);
                    file.write(reinterpret_cast<const char*>(data_ptr->data()), data_ptr->size());
                }
            }

            for (size_t i = 0; i < relocs_per_section.size(); ++i) {
                if (!relocs_per_section[i].empty()) {
                    file.seekp(sectionHeaders[i].PointerToRelocations);
                    file.write(reinterpret_cast<const char*>(relocs_per_section[i].data()), relocs_per_section[i].size() * sizeof(CoffRelocation));
                }
            }

            file.seekp(symbolTableOffset);
            file.write(reinterpret_cast<const char*>(symbols.data()), symbols.size() * sizeof(CoffSymbol));

            uint32_t stringTableSize = stringTable.size();
            memcpy(&stringTable[0], &stringTableSize, 4);
            file.write(stringTable.c_str(), stringTableSize);

            file.close();
            return true;

        } catch (const std::exception& e) {
            lastError_ = "Error generating COFF object file: " + std::string(e.what());
            return false;
        }
    }

    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint32_t virtualSize, uint32_t characteristics) {
        Section section;
        section.name = name;
        section.data = data;
        section.characteristics = characteristics;
        section.virtualSize = virtualSize;
        sections_.push_back(std::move(section));
    }

    void addImport(const std::string& moduleName, const std::string& functionName) {
        imports_[moduleName].push_back(functionName);
    }

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
    uint16_t subsystem_ = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    std::string lastError_;

    std::vector<Section> sections_;
    std::unordered_map<std::string, std::vector<std::string>> imports_;
    uint32_t importDirectoryRVA_ = 0;
    std::vector<COFFSymbol> coffSymbols_;
    std::vector<char> stringTable_;
    
    // Helper functions for RVA calculations and validation
    uint32_t fileOffsetToRVA(uint32_t fileOffset) {
        for (const auto& section : sections_) {
            if (fileOffset >= section.rawDataPointer && 
                fileOffset < section.rawDataPointer + section.rawDataSize) {
                uint32_t offsetInSection = fileOffset - section.rawDataPointer;
                return section.virtualAddress + offsetInSection;
            }
        }
        return 0; // Invalid
    }
    
    uint32_t rvaToFileOffset(uint32_t rva) {
        for (const auto& section : sections_) {
            if (rva >= section.virtualAddress && 
                rva < section.virtualAddress + section.virtualSize) {
                uint32_t offsetInSection = rva - section.virtualAddress;
                return section.rawDataPointer + offsetInSection;
            }
        }
        return 0; // Invalid
    }
    
    bool validateRVA(uint32_t rva) {
        if (rva == 0) return false;
        for (const auto& section : sections_) {
            if (rva >= section.virtualAddress && 
                rva < section.virtualAddress + section.virtualSize) {
                return true;
            }
        }
        return false;
    }
    
    void setupDataDirectories(DataDirectory* dataDirectories) {
        // Initialize all data directories to zero
        memset(dataDirectories, 0, 16 * sizeof(DataDirectory));
        
        // Data Directory indices (from winnt.h)
        const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
        const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
        const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
        const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
        const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
        const int IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
        const int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
        const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
        const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
        const int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
        const int IMAGE_DIRECTORY_ENTRY_IAT = 12;
        const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
        const int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
        
        // Set up Import Directory
        if (importDirectoryRVA_ > 0) {
            if (!validateRVA(importDirectoryRVA_)) {
                throw std::runtime_error("Invalid import directory RVA: " + std::to_string(importDirectoryRVA_));
            }
            
            uint32_t importSize = calculateImportDirectorySize();
            if (importSize == 0) {
                throw std::runtime_error("Import directory size is zero");
            }
            
            // Validate that the entire import directory fits within a section
            if (!validateRVA(importDirectoryRVA_ + importSize - 1)) {
                throw std::runtime_error("Import directory extends beyond section boundaries");
            }
            
            dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = importDirectoryRVA_;
            dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = importSize;
            
            // Set up Import Address Table (IAT) directory
            // The IAT is part of the import directory structure in .idata
            Section* idata = findSection(".idata");
            if (idata) {
                // Calculate IAT RVA - it comes after the IDT and ILTs in our layout
                uint32_t idt_size = (imports_.size() + 1) * sizeof(ImportDirectoryTable);
                uint32_t total_ilt_size = 0;
                uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);
                
                for (const auto& pair : imports_) {
                    total_ilt_size += (pair.second.size() + 1) * thunk_size;
                }
                
                uint32_t iat_rva = importDirectoryRVA_ + idt_size + total_ilt_size;
                if (validateRVA(iat_rva)) {
                    dataDirectories[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = iat_rva;
                    dataDirectories[IMAGE_DIRECTORY_ENTRY_IAT].Size = total_ilt_size;
                }
            }
        }
        
        // Set up Base Relocation Directory (requirement 6.7)
        Section* relocSection = findSection(".reloc");
        if (relocSection && relocSection->virtualSize > 0) {
            if (validateRVA(relocSection->virtualAddress)) {
                dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relocSection->virtualAddress;
                dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relocSection->virtualSize;
            }
        }
        
        // TODO: Add other data directories as needed:
        // - Export Directory (if we have exports)
        // - Resource Directory (if we have resources)
        // - Exception Directory (for 64-bit)
        // - Debug Directory (if we have debug info)
        // - TLS Directory (if we use thread-local storage)
    }
    
    void validateFileStructure() {
        // Validate that we have at least a .text section
        if (!findSection(".text")) {
            throw std::runtime_error("PE file must have a .text section");
        }
        
        // Validate section order and alignment
        uint32_t lastVirtualEnd = 0;
        uint32_t lastFileEnd = 0;
        
        for (const auto& section : sections_) {
            // Check virtual address ordering and alignment
            if (section.virtualAddress < lastVirtualEnd) {
                throw std::runtime_error("Section " + section.name + " virtual address is not in ascending order");
            }
            
            if (section.virtualAddress % sectionAlignment_ != 0) {
                throw std::runtime_error("Section " + section.name + " virtual address not aligned");
            }
            
            // Check file offset ordering and alignment (for sections with file data)
            if (section.rawDataSize > 0) {
                if (section.rawDataPointer < lastFileEnd) {
                    throw std::runtime_error("Section " + section.name + " file offset is not in ascending order");
                }
                
                if (section.rawDataPointer % fileAlignment_ != 0) {
                    throw std::runtime_error("Section " + section.name + " file offset not aligned");
                }
                
                lastFileEnd = section.rawDataPointer + section.rawDataSize;
            }
            
            lastVirtualEnd = section.virtualAddress + align(section.virtualSize, sectionAlignment_);
        }
        
        // Validate import directory if present
        if (importDirectoryRVA_ > 0) {
            if (!validateRVA(importDirectoryRVA_)) {
                throw std::runtime_error("Import directory RVA is invalid");
            }
            
            uint32_t importSize = calculateImportDirectorySize();
            if (!validateRVA(importDirectoryRVA_ + importSize - 1)) {
                throw std::runtime_error("Import directory extends beyond section boundaries");
            }
        }
    }

    void validateOptions() {
        if (sectionAlignment_ < fileAlignment_) {
            throw std::runtime_error("PE Options Error: SectionAlignment must be greater than or equal to FileAlignment.");
        }
        auto is_power_of_two = [](uint32_t n) {
            return (n != 0) && ((n & (n - 1)) == 0);
        };
        if (!is_power_of_two(fileAlignment_) || fileAlignment_ < 512 || fileAlignment_ > 65536) {
            throw std::runtime_error("PE Options Error: FileAlignment must be a power of two between 512 and 65536, inclusive.");
        }
        if (!is_power_of_two(sectionAlignment_)) {
            throw std::runtime_error("PE Options Error: SectionAlignment must be a power of two.");
        }
    }

    uint32_t align(uint32_t value, uint32_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    Section* findSection(const std::string& name) {
        for(auto& s : sections_) {
            if(s.name == name) return &s;
        }
        return nullptr;
    }

    int16_t getSectionIndex(const std::string& name) {
        for(size_t i = 0; i < sections_.size(); ++i) {
            if(sections_[i].name == name) return static_cast<int16_t>(i + 1);
        }
        return -1;
    }

    void setupDefaultSections(const std::vector<uint8_t>& code) {
        addSection(".text", code, code.size(), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        addSection(".rdata", {}, 0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
        addSection(".data", {}, 0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    }

    void ensureRequiredSections() {
        // Create .text section with executable code and proper characteristics (requirement 6.8)
        // .text section should already exist, but verify characteristics
        Section* textSection = findSection(".text");
        if (textSection) {
            textSection->characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        }

        // Only create .rdata section if we have read-only data
        // (Don't create empty sections that will cause layout issues)

        // Only create .data section if we have writable data
        // (Don't create empty sections that will cause layout issues)

        // Always create .idata section since we ensure KERNEL32.dll imports (requirement 6.8)
        if (!findSection(".idata")) {
            addSection(".idata", {}, 0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        }

        // Always create .reloc section for base relocations (requirement 6.8)
        if (!findSection(".reloc")) {
            addSection(".reloc", {}, 0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE);
        }
    }

    void ensureKernel32Import() {
        // Ensure complete import table with KERNEL32.dll ExitProcess (requirement 6.9)
        bool hasKernel32 = false;
        bool hasExitProcess = false;
        
        // Check if KERNEL32.dll is already imported
        for (const auto& pair : imports_) {
            std::string moduleName = pair.first;
            // Convert to lowercase for comparison
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
            
            if (moduleName == "kernel32.dll") {
                hasKernel32 = true;
                
                // Check if ExitProcess is imported
                for (const auto& funcName : pair.second) {
                    if (funcName == "ExitProcess") {
                        hasExitProcess = true;
                        break;
                    }
                }
                break;
            }
        }
        
        // Add KERNEL32.dll with ExitProcess if not present
        if (!hasKernel32) {
            addImport("kernel32.dll", "ExitProcess");
            std::cout << "Added KERNEL32.dll ExitProcess import for PE compliance" << std::endl;
        } else if (!hasExitProcess) {
            // Add ExitProcess to existing KERNEL32.dll imports
            imports_["kernel32.dll"].push_back("ExitProcess");
            std::cout << "Added ExitProcess to existing KERNEL32.dll imports" << std::endl;
        }
    }

    void layoutSections() {
        // Calculate header size including all components
        uint32_t headerSize = sizeof(DOSHeader) + DOS_STUB_SIZE + sizeof(uint32_t) + sizeof(FileHeader) + 
                             (is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32)) + 
                             (sections_.size() * sizeof(SectionHeader));
        
        // Align to section boundary for virtual addresses, file boundary for file offsets
        uint32_t currentRVA = align(headerSize, sectionAlignment_);
        uint32_t currentRawPtr = align(headerSize, fileAlignment_);

        for (auto& section : sections_) {
            // Validate section alignment requirements
            if (sectionAlignment_ < fileAlignment_) {
                throw std::runtime_error("Section alignment must be >= file alignment");
            }
            
            // Set virtual address (RVA)
            section.virtualAddress = currentRVA;
            
            // Set file pointer for raw data
            section.rawDataPointer = currentRawPtr;
            
            // Calculate raw data size (file-aligned)
            if (section.data.empty() && section.virtualSize == 0) {
                section.rawDataSize = 0;  // No data to write (e.g., .bss)
            } else {
                uint32_t dataSize = std::max(static_cast<uint32_t>(section.data.size()), section.virtualSize);
                section.rawDataSize = align(dataSize, fileAlignment_);
            }
            
            // Ensure virtual size is set correctly
            if (section.virtualSize == 0) {
                section.virtualSize = section.data.size();
            }
            
            // Validate section characteristics
            validateSectionCharacteristics(section);
            
            // Move to next section positions
            // Only advance RVA if section has virtual size > 0
            uint32_t nextRVA = currentRVA;
            if (section.virtualSize > 0) {
                nextRVA = currentRVA + align(section.virtualSize, sectionAlignment_);
            }
            
            uint32_t nextRawPtr = currentRawPtr;
            if (section.rawDataSize > 0) {
                nextRawPtr = currentRawPtr + section.rawDataSize;
            }
            
            // Validate no overlaps with previous sections
            for (const auto& prevSection : sections_) {
                if (&prevSection == &section) break; // Don't compare with self
                
                // Check virtual address overlap
                if (section.virtualAddress < prevSection.virtualAddress + align(prevSection.virtualSize, sectionAlignment_) &&
                    prevSection.virtualAddress < section.virtualAddress + align(section.virtualSize, sectionAlignment_)) {
                    throw std::runtime_error("Virtual address overlap between sections " + prevSection.name + " and " + section.name);
                }
                
                // Check file offset overlap (only for sections with file data)
                if (section.rawDataSize > 0 && prevSection.rawDataSize > 0) {
                    if (section.rawDataPointer < prevSection.rawDataPointer + prevSection.rawDataSize &&
                        prevSection.rawDataPointer < section.rawDataPointer + section.rawDataSize) {
                        throw std::runtime_error("File offset overlap between sections " + prevSection.name + " and " + section.name);
                    }
                }
            }
            
            currentRVA = nextRVA;
            currentRawPtr = nextRawPtr;
        }
        
        // Final validation: ensure all sections fit within reasonable bounds
        for (const auto& section : sections_) {
            if (section.virtualAddress + section.virtualSize > 0x80000000) { // 2GB limit
                throw std::runtime_error("Section " + section.name + " virtual address exceeds reasonable bounds");
            }
            
            if (section.rawDataPointer + section.rawDataSize > 0x40000000) { // 1GB file size limit
                throw std::runtime_error("Section " + section.name + " file size exceeds reasonable bounds");
            }
        }
    }
    
    void validateSectionCharacteristics(const Section& section) {
        uint32_t chars = section.characteristics;
        
        // Validate that sections have appropriate characteristics
        if (section.name == ".text") {
            if (!(chars & IMAGE_SCN_CNT_CODE) || !(chars & IMAGE_SCN_MEM_EXECUTE)) {
                throw std::runtime_error(".text section must have CODE and EXECUTE characteristics");
            }
        } else if (section.name == ".data") {
            if (!(chars & IMAGE_SCN_CNT_INITIALIZED_DATA) || !(chars & IMAGE_SCN_MEM_WRITE)) {
                throw std::runtime_error(".data section must have INITIALIZED_DATA and WRITE characteristics");
            }
        } else if (section.name == ".rdata") {
            if (!(chars & IMAGE_SCN_CNT_INITIALIZED_DATA) || (chars & IMAGE_SCN_MEM_WRITE)) {
                throw std::runtime_error(".rdata section must have INITIALIZED_DATA but not WRITE characteristics");
            }
        } else if (section.name == ".bss") {
            if (!(chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) || !(chars & IMAGE_SCN_MEM_WRITE)) {
                throw std::runtime_error(".bss section must have UNINITIALIZED_DATA and WRITE characteristics");
            }
        }
        
        // Validate alignment requirements
        if (chars & IMAGE_SCN_ALIGN_1BYTES) {
            // 1-byte alignment is valid
        } else if (chars & IMAGE_SCN_ALIGN_2BYTES) {
            // 2-byte alignment is valid
        } else if (chars & IMAGE_SCN_ALIGN_4BYTES) {
            // 4-byte alignment is valid
        } else if (chars & IMAGE_SCN_ALIGN_8BYTES) {
            // 8-byte alignment is valid
        } else if (chars & IMAGE_SCN_ALIGN_16BYTES) {
            // 16-byte alignment is valid
        }
        // Add more alignment checks as needed
    }

    void setupImports() {
        if (imports_.empty()) return;

        Section* idata = findSection(".idata");
        if (!idata) {
            throw std::runtime_error(".idata section not found for imports.");
        }

        // The virtualSize of .idata was already calculated to reserve space.
        // Now, we generate the import directory data and place it into the .idata section.

        // Pad the existing data to ensure the import directory is aligned.
        uint32_t import_data_offset_in_section = align(idata->data.size(), 16);
        if (import_data_offset_in_section > idata->data.size()) {
            idata->data.insert(idata->data.end(), import_data_offset_in_section - idata->data.size(), 0);
        }

        // The RVA of the import directory is now final and correct.
        importDirectoryRVA_ = idata->virtualAddress + import_data_offset_in_section;
        
        // Validate the import directory RVA
        if (!validateRVA(importDirectoryRVA_)) {
            throw std::runtime_error("Invalid import directory RVA calculated: " + std::to_string(importDirectoryRVA_));
        }

        std::vector<uint8_t> import_directory_data = createImportDirectory();

        // Append the generated import data to the .idata section.
        idata->data.insert(idata->data.end(), import_directory_data.begin(), import_directory_data.end());
        // Do NOT modify idata->virtualSize here; it was set before the layout pass.
    }

    // A helper to write values to a vector<uint8_t>
    template<typename T>
    void write_to_vector(std::vector<uint8_t>& vec, size_t offset, T value) {
        if (offset + sizeof(T) > vec.size()) {
            vec.resize(offset + sizeof(T));
        }
        memcpy(vec.data() + offset, &value, sizeof(T));
    }

    uint32_t calculateImportDirectorySize() {
        if (imports_.empty()) return 0;

        uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);
        
        // Import Directory Table (including null terminator)
        uint32_t idt_size = (imports_.size() + 1) * sizeof(ImportDirectoryTable);
        
        // Import Lookup Tables and Import Address Tables
        uint32_t total_ilt_size = 0;
        uint32_t total_iat_size = 0;
        
        // Names (module names + function hint/name entries)
        uint32_t total_names_size = 0;

        for (const auto& pair : imports_) {
            // ILT and IAT sizes (each function + null terminator)
            uint32_t dll_table_size = (pair.second.size() + 1) * thunk_size;
            total_ilt_size += dll_table_size;
            total_iat_size += dll_table_size;

            // Module name
            total_names_size += pair.first.size() + 1;
            
            // Function hint/name entries
            for (const auto& funcName : pair.second) {
                uint32_t hint_name_size = sizeof(uint16_t) + funcName.size() + 1; // hint + name + null
                if (hint_name_size % 2 != 0) hint_name_size++; // Align to 2-byte boundary
                total_names_size += hint_name_size;
            }
        }
        
        return idt_size + total_ilt_size + total_iat_size + total_names_size;
    }

    std::vector<uint8_t> createImportDirectory() {
        if (imports_.empty()) return {};

        // Layout:
        // 1. Import Directory Table (IDT) - includes null terminator
        // 2. Import Lookup Tables (ILTs) for each DLL
        // 3. Import Address Tables (IATs) for each DLL - initially copies of ILTs
        // 4. Module names (DLL names)
        // 5. Hint/Name data (function names with hints)

        uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);

        // Calculate structure sizes
        uint32_t idt_size = (imports_.size() + 1) * sizeof(ImportDirectoryTable); // +1 for null terminator
        
        uint32_t total_ilt_size = 0;
        uint32_t total_names_size = 0;
        
        for (const auto& pair : imports_) {
            // Each ILT needs space for function pointers + null terminator
            total_ilt_size += (pair.second.size() + 1) * thunk_size;
            
            // Module name
            total_names_size += pair.first.size() + 1;
            
            // Function names with hints (aligned to 2-byte boundaries)
            for (const auto& funcName : pair.second) {
                uint32_t hint_name_size = sizeof(uint16_t) + funcName.size() + 1; // hint + name + null
                if (hint_name_size % 2 != 0) hint_name_size++; // Align to 2-byte boundary
                total_names_size += hint_name_size;
            }
        }
        
        // Calculate offsets for each section
        uint32_t ilts_offset = idt_size;
        uint32_t iats_offset = ilts_offset + total_ilt_size;
        uint32_t module_names_offset = iats_offset + total_ilt_size;
        uint32_t hint_names_offset = module_names_offset;
        
        // Pre-calculate module name positions
        std::vector<uint32_t> module_name_offsets;
        uint32_t current_module_offset = module_names_offset;
        for (const auto& pair : imports_) {
            module_name_offsets.push_back(current_module_offset);
            current_module_offset += pair.first.size() + 1;
        }
        hint_names_offset = current_module_offset;

        uint32_t total_size = calculateImportDirectorySize();
        std::vector<uint8_t> data(total_size, 0);

        // Track current positions
        uint32_t idt_pos = 0;
        uint32_t ilt_pos = ilts_offset;
        uint32_t iat_pos = iats_offset;
        uint32_t hint_name_pos = hint_names_offset;
        
        size_t module_index = 0;

        // Build import directory for each DLL
        for (const auto& pair : imports_) {
            const std::string& moduleName = pair.first;
            const std::vector<std::string>& functionNames = pair.second;

            uint32_t current_ilt_start = ilt_pos;
            uint32_t current_iat_start = iat_pos;
            
            // Build ILT entries for this DLL
            std::vector<uint32_t> function_name_rvas;
            for (size_t i = 0; i < functionNames.size(); ++i) {
                const auto& funcName = functionNames[i];
                
                // Calculate RVA for this function's hint/name entry
                uint32_t hint_name_rva = importDirectoryRVA_ + hint_name_pos;
                
                // Validate the RVA
                if (!validateRVA(hint_name_rva)) {
                    throw std::runtime_error("Invalid hint/name RVA for function " + funcName + ": " + std::to_string(hint_name_rva));
                }
                
                function_name_rvas.push_back(hint_name_rva);
                
                // Write hint/name entry
                uint16_t hint = static_cast<uint16_t>(i); // Use index as hint
                write_to_vector<uint16_t>(data, hint_name_pos, hint);
                hint_name_pos += sizeof(uint16_t);
                
                // Write function name
                memcpy(data.data() + hint_name_pos, funcName.c_str(), funcName.size() + 1);
                hint_name_pos += funcName.size() + 1;
                
                // Align to 2-byte boundary
                if (hint_name_pos % 2 != 0) {
                    hint_name_pos++;
                }
                
                // Write to ILT
                if (is64Bit_) {
                    write_to_vector<uint64_t>(data, ilt_pos, hint_name_rva);
                } else {
                    write_to_vector<uint32_t>(data, ilt_pos, hint_name_rva);
                }
                ilt_pos += thunk_size;
            }
            
            // Add null terminator to ILT
            ilt_pos += thunk_size; // Already zero-initialized
            
            // Copy ILT to IAT
            uint32_t ilt_size = (functionNames.size() + 1) * thunk_size;
            memcpy(data.data() + iat_pos, data.data() + current_ilt_start, ilt_size);
            iat_pos += ilt_size;

            // Write module name
            uint32_t module_name_offset = module_name_offsets[module_index];
            memcpy(data.data() + module_name_offset, moduleName.c_str(), moduleName.size() + 1);

            // Fill Import Directory Table entry
            ImportDirectoryTable idt = {};
            idt.ImportLookupTableRVA = importDirectoryRVA_ + current_ilt_start;
            idt.ImportAddressTableRVA = importDirectoryRVA_ + current_iat_start;
            idt.NameRVA = importDirectoryRVA_ + module_name_offset;
            idt.TimeDateStamp = 0;
            idt.ForwarderChain = 0;
            
            // Validate all RVAs in the IDT entry
            if (!validateRVA(idt.ImportLookupTableRVA)) {
                throw std::runtime_error("Invalid ILT RVA for module " + moduleName + ": " + std::to_string(idt.ImportLookupTableRVA));
            }
            if (!validateRVA(idt.ImportAddressTableRVA)) {
                throw std::runtime_error("Invalid IAT RVA for module " + moduleName + ": " + std::to_string(idt.ImportAddressTableRVA));
            }
            if (!validateRVA(idt.NameRVA)) {
                throw std::runtime_error("Invalid name RVA for module " + moduleName + ": " + std::to_string(idt.NameRVA));
            }
            
            memcpy(data.data() + idt_pos, &idt, sizeof(idt));
            idt_pos += sizeof(idt);
            
            module_index++;
        }

        // The final IDT entry is already zero-initialized (null terminator)
        
        return data;
    }

    void processRelocations(Assembler& assembler) {
        if (imports_.empty()) return;

        const auto& relocations = assembler.getRelocations();
        Section* textSection = findSection(".text");
        
        if (!textSection) {
            throw std::runtime_error("No .text section found for relocation processing");
        }

        // Create a map of imported function names to their IAT RVAs
        std::unordered_map<std::string, uint32_t> functionToIatRva;
        
        // Calculate IAT RVAs for each imported function
        uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);
        uint32_t idt_size = (imports_.size() + 1) * sizeof(ImportDirectoryTable);
        uint32_t total_ilt_size = 0;
        
        // Calculate total ILT size first
        for (const auto& pair : imports_) {
            total_ilt_size += (pair.second.size() + 1) * thunk_size;
        }
        
        // IAT starts after IDT and ILTs
        uint32_t iat_start_offset = idt_size + total_ilt_size;
        uint32_t current_iat_offset = iat_start_offset;
        
        // Map each function to its IAT RVA
        for (const auto& pair : imports_) {
            const std::string& moduleName = pair.first;
            const std::vector<std::string>& functionNames = pair.second;
            
            for (const auto& funcName : functionNames) {
                uint32_t iat_rva = importDirectoryRVA_ + current_iat_offset;
                functionToIatRva[funcName] = iat_rva;
                current_iat_offset += thunk_size;
            }
            current_iat_offset += thunk_size; // Skip null terminator
        }

        // Process each relocation
        for (const auto& reloc : relocations) {
            // Only process relocations for imported functions
            if (functionToIatRva.find(reloc.symbolName) == functionToIatRva.end()) {
                continue; // Not an imported function
            }
            
            // Only process TEXT section relocations for now
            if (reloc.section != ::Section::TEXT) {
                continue;
            }
            
            uint32_t iat_rva = functionToIatRva[reloc.symbolName];
            
            // Calculate the instruction address where the relocation needs to be applied
            uint64_t instruction_rva = textSection->virtualAddress + reloc.offset;
            
            // For PC-relative relocations (like call instructions), calculate the displacement
            if (reloc.type == RelocationType::R_X86_64_PC32) {
                // The displacement is: target_address - (instruction_address + 4)
                // where instruction_address points to the byte after the displacement
                int32_t displacement = static_cast<int32_t>(iat_rva - (instruction_rva + 4)) + reloc.addend;
                
                // Update the machine code in the .text section
                if (reloc.offset + 4 <= textSection->data.size()) {
                    // Show before and after
                    std::cout << "Before relocation at offset 0x" << std::hex << reloc.offset << ": ";
                    for (int i = 0; i < 4; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)textSection->data[reloc.offset + i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    // Write the displacement in little-endian format
                    textSection->data[reloc.offset] = displacement & 0xFF;
                    textSection->data[reloc.offset + 1] = (displacement >> 8) & 0xFF;
                    textSection->data[reloc.offset + 2] = (displacement >> 16) & 0xFF;
                    textSection->data[reloc.offset + 3] = (displacement >> 24) & 0xFF;
                    
                    std::cout << "After relocation at offset 0x" << std::hex << reloc.offset << ": ";
                    for (int i = 0; i < 4; i++) {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)textSection->data[reloc.offset + i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                    
                    std::cout << "Processed relocation for " << reloc.symbolName 
                              << " at offset 0x" << std::hex << reloc.offset 
                              << " -> IAT RVA 0x" << iat_rva 
                              << " (displacement: 0x" << displacement << ")" << std::dec << std::endl;
                } else {
                    throw std::runtime_error("Relocation offset " + std::to_string(reloc.offset) + 
                                           " is beyond .text section size " + std::to_string(textSection->data.size()));
                }
            } else {
                std::cerr << "Warning: Unsupported relocation type for symbol " << reloc.symbolName << std::endl;
            }
        }
    }

    void generateBaseRelocations() {
        // Generate base relocation directory structure (requirement 6.7)
        Section* relocSection = findSection(".reloc");
        if (!relocSection) {
            return; // No .reloc section to populate
        }

        std::vector<uint8_t> relocData;
        
        // For a simple implementation, we'll create relocations for addresses that need fixing
        // when the image is loaded at a different base address
        
        // Collect all addresses that need relocation
        std::vector<uint32_t> relocationRVAs;
        
        // Add relocations for import table addresses (these are absolute addresses)
        if (importDirectoryRVA_ > 0) {
            // The import directory contains absolute RVAs that need relocation
            // For now, we'll create a minimal relocation table
            
            // Add relocation for the ImageBase itself (this is a common practice)
            Section* textSection = findSection(".text");
            if (textSection && textSection->virtualAddress > 0) {
                // Add a relocation for the start of the text section
                relocationRVAs.push_back(textSection->virtualAddress);
            }
        }
        
        if (relocationRVAs.empty()) {
            // Create a minimal relocation table with just a terminating block
            BaseRelocationBlock block = {};
            block.VirtualAddress = 0;
            block.SizeOfBlock = sizeof(BaseRelocationBlock);
            
            relocData.resize(sizeof(BaseRelocationBlock));
            memcpy(relocData.data(), &block, sizeof(BaseRelocationBlock));
        } else {
            // Group relocations by 4KB pages
            std::map<uint32_t, std::vector<uint16_t>> pageRelocations;
            
            for (uint32_t rva : relocationRVAs) {
                uint32_t pageRVA = rva & ~0xFFF; // Align to 4KB boundary
                uint16_t offset = rva & 0xFFF;   // Offset within page
                
                // Create relocation entry
                BaseRelocationEntry entry = {};
                entry.offset = offset;
                entry.type = is64Bit_ ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
                
                pageRelocations[pageRVA].push_back(*(uint16_t*)&entry);
            }
            
            // Generate relocation blocks
            for (const auto& pair : pageRelocations) {
                uint32_t pageRVA = pair.first;
                const std::vector<uint16_t>& entries = pair.second;
                
                // Calculate block size (header + entries, padded to DWORD boundary)
                uint32_t entriesSize = entries.size() * sizeof(uint16_t);
                uint32_t blockSize = sizeof(BaseRelocationBlock) + entriesSize;
                
                // Pad to DWORD boundary
                if (blockSize % 4 != 0) {
                    blockSize += 4 - (blockSize % 4);
                }
                
                // Create block header
                BaseRelocationBlock block = {};
                block.VirtualAddress = pageRVA;
                block.SizeOfBlock = blockSize;
                
                // Add block to relocation data
                size_t blockStart = relocData.size();
                relocData.resize(blockStart + blockSize);
                
                // Copy block header
                memcpy(relocData.data() + blockStart, &block, sizeof(BaseRelocationBlock));
                
                // Copy entries
                memcpy(relocData.data() + blockStart + sizeof(BaseRelocationBlock), 
                       entries.data(), entriesSize);
                
                // Zero-pad to DWORD boundary
                size_t paddingStart = blockStart + sizeof(BaseRelocationBlock) + entriesSize;
                size_t paddingSize = blockSize - sizeof(BaseRelocationBlock) - entriesSize;
                if (paddingSize > 0) {
                    memset(relocData.data() + paddingStart, 0, paddingSize);
                }
            }
            
            // Add terminating block
            BaseRelocationBlock termBlock = {};
            termBlock.VirtualAddress = 0;
            termBlock.SizeOfBlock = sizeof(BaseRelocationBlock);
            
            size_t termStart = relocData.size();
            relocData.resize(termStart + sizeof(BaseRelocationBlock));
            memcpy(relocData.data() + termStart, &termBlock, sizeof(BaseRelocationBlock));
        }
        
        // Update .reloc section with generated data
        relocSection->data = std::move(relocData);
        relocSection->virtualSize = relocSection->data.size();
        
        // Update rawDataSize to ensure the data gets written to the file
        relocSection->rawDataSize = align(relocSection->data.size(), fileAlignment_);
        
        std::cout << "Generated .reloc section with " << relocSection->data.size() << " bytes (raw size: " << relocSection->rawDataSize << ")" << std::endl;
    }

    void buildSymbolTable(const std::unordered_map<std::string, SymbolEntry>& symbols) {
        coffSymbols_.clear();
        stringTable_.clear();
        stringTable_.resize(4, 0);

        for(const auto& pair : symbols) {
            const auto& sym = pair.second;
            COFFSymbol coffSym = {};

            if (sym.name.length() > 8) {
                coffSym.Name.LongName.Zeros = 0;
                coffSym.Name.LongName.Offset = stringTable_.size();
                stringTable_.insert(stringTable_.end(), sym.name.begin(), sym.name.end());
                stringTable_.push_back(0);
            } else {
                strncpy(coffSym.Name.ShortName, sym.name.c_str(), 8);
            }

            coffSym.Value = sym.address;
            coffSym.Type = 0x20; // Function

            switch(sym.binding) {
                case SymbolBinding::LOCAL: coffSym.StorageClass = 3; break; // C_STAT
                case SymbolBinding::GLOBAL: coffSym.StorageClass = 2; break; // C_EXT
                case SymbolBinding::WEAK: coffSym.StorageClass = 2; break; // C_EXT, with special handling
            }

            Section* text = findSection(".text");
            Section* data = findSection(".data");
            if(text && sym.address >= text->virtualAddress && sym.address < text->virtualAddress + text->virtualSize) {
                coffSym.SectionNumber = getSectionIndex(".text");
            } else if (data && sym.address >= data->virtualAddress && sym.address < data->virtualAddress + data->virtualSize) {
                coffSym.SectionNumber = getSectionIndex(".data");
            } else {
                coffSym.SectionNumber = -1; // IMAGE_SYM_ABSOLUTE
            }

            coffSymbols_.push_back(coffSym);
        }

        uint32_t strTableSize = stringTable_.size();
        memcpy(stringTable_.data(), &strTableSize, 4);
    }

    void writeDOSHeader(std::ofstream& file) {
        DOSHeader dosHeader = {};
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;  // "MZ"
        dosHeader.e_cblp = 0x90;                  // Bytes on last page
        dosHeader.e_cp = 0x03;                    // Pages in file
        dosHeader.e_crlc = 0x00;                  // Relocations
        dosHeader.e_cparhdr = 0x04;               // Size of header in paragraphs
        dosHeader.e_minalloc = 0x00;              // Minimum extra paragraphs
        dosHeader.e_maxalloc = 0xFFFF;            // Maximum extra paragraphs
        dosHeader.e_ss = 0x00;                    // Initial relative SS value
        dosHeader.e_sp = 0xB8;                    // Initial SP value
        dosHeader.e_csum = 0x00;                  // Checksum
        dosHeader.e_ip = 0x00;                    // Initial IP value
        dosHeader.e_cs = 0x00;                    // Initial relative CS value
        dosHeader.e_lfarlc = 0x40;                // File address of relocation table
        dosHeader.e_ovno = 0x00;                  // Overlay number
        // e_res[4] and e_res2[10] are already zero-initialized
        dosHeader.e_lfanew = sizeof(DOSHeader) + DOS_STUB_SIZE;  // Offset to NT headers
        
        file.write(reinterpret_cast<const char*>(&dosHeader), sizeof(dosHeader));
        
        // Write DOS stub - a minimal program that prints "This program cannot be run in DOS mode"
        const uint8_t dosStub[] = {
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
            0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        static_assert(sizeof(dosStub) == DOS_STUB_SIZE, "DOS stub size mismatch");
        file.write(reinterpret_cast<const char*>(dosStub), sizeof(dosStub));
    }

    void writeNTHeaders(std::ofstream& file) {
        uint32_t peSignature = IMAGE_NT_SIGNATURE;
        file.write(reinterpret_cast<const char*>(&peSignature), sizeof(peSignature));

        FileHeader fileHeader = {};
        fileHeader.Machine = is64Bit_ ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        fileHeader.NumberOfSections = sections_.size();
        fileHeader.TimeDateStamp = static_cast<uint32_t>(time(nullptr));
        fileHeader.SizeOfOptionalHeader = is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32);
        // Fix PE file characteristics flags (requirements 6.1, 6.10)
        fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |                    // Ensure executable flag is set
                                   IMAGE_FILE_LARGE_ADDRESS_AWARE |                  // Add >2GB address support
                                   IMAGE_FILE_LINE_NUMBERS_STRIPPED |                // Include line numbers stripped
                                   IMAGE_FILE_LOCAL_SYMS_STRIPPED |                  // Include local symbols stripped
                                   (is64Bit_ ? 0 : IMAGE_FILE_32BIT_MACHINE);
                                   // Remove IMAGE_FILE_RELOCS_STRIPPED to preserve relocations

        uint32_t lastSectionEnd = 0;
        for(const auto& s : sections_) {
            if(s.rawDataPointer + s.rawDataSize > lastSectionEnd) lastSectionEnd = s.rawDataPointer + s.rawDataSize;
        }
        fileHeader.PointerToSymbolTable = coffSymbols_.empty() ? 0 : lastSectionEnd;
        fileHeader.NumberOfSymbols = coffSymbols_.size();

        file.write(reinterpret_cast<const char*>(&fileHeader), sizeof(fileHeader));

        if (is64Bit_) {
            OptionalHeader64 optHeader = {};
            optHeader.Magic = 0x20b;  // PE32+
            optHeader.MajorLinkerVersion = 14;
            optHeader.MinorLinkerVersion = 0;
            
            // Set ImageBase to 0x140000000 for 64-bit PE executables as per requirement 6.4
            optHeader.ImageBase = 0x140000000ULL;
            
            // Configure SectionAlignment = 0x1000 and FileAlignment = 0x200 as per requirement 6.5
            optHeader.SectionAlignment = 0x1000;
            optHeader.FileAlignment = 0x200;
            
            optHeader.MajorOperatingSystemVersion = 6;
            optHeader.MinorOperatingSystemVersion = 0;
            optHeader.MajorImageVersion = 0;
            optHeader.MinorImageVersion = 0;
            optHeader.MajorSubsystemVersion = 6;
            optHeader.MinorSubsystemVersion = 0;
            optHeader.Win32VersionValue = 0;
            optHeader.Subsystem = subsystem_;
            optHeader.DllCharacteristics = 0x8160;  // DYNAMIC_BASE | NX_COMPAT | NO_SEH | TERMINAL_SERVER_AWARE
            optHeader.SizeOfStackReserve = 0x100000;
            optHeader.SizeOfStackCommit = 0x1000;
            optHeader.SizeOfHeapReserve = 0x100000;
            optHeader.SizeOfHeapCommit = 0x1000;
            optHeader.LoaderFlags = 0;
            optHeader.NumberOfRvaAndSizes = 16;

            // Calculate sizes
            uint32_t sizeOfCode = 0;
            uint32_t sizeOfInitializedData = 0;
            uint32_t sizeOfUninitializedData = 0;
            
            Section* text = findSection(".text");
            Section* data = findSection(".data");
            Section* rdata = findSection(".rdata");
            Section* bss = findSection(".bss");
            
            if (text) {
                optHeader.BaseOfCode = text->virtualAddress;
                sizeOfCode = align(text->virtualSize, optHeader.FileAlignment);
                
                // Calculate AddressOfEntryPoint as RVA to start of .text section (requirement 6.3)
                optHeader.AddressOfEntryPoint = text->virtualAddress;
                
                // Allow override if explicitly set
                if (entryPoint_ != 0) {
                    optHeader.AddressOfEntryPoint = static_cast<uint32_t>(entryPoint_);
                }
            }
            
            if (data) {
                sizeOfInitializedData += align(data->virtualSize, fileAlignment_);
            }
            if (rdata) {
                sizeOfInitializedData += align(rdata->virtualSize, fileAlignment_);
            }
            if (bss) {
                sizeOfUninitializedData += align(bss->virtualSize, fileAlignment_);
            }
            
            optHeader.SizeOfCode = sizeOfCode;
            optHeader.SizeOfInitializedData = sizeOfInitializedData;
            optHeader.SizeOfUninitializedData = sizeOfUninitializedData;

            // Calculate SizeOfHeaders as properly aligned size of all header structures (requirement 6.6)
            uint32_t headerSize = sizeof(DOSHeader) + DOS_STUB_SIZE + sizeof(uint32_t) + sizeof(FileHeader) + 
                                 sizeof(OptionalHeader64) + sections_.size() * sizeof(SectionHeader);
            optHeader.SizeOfHeaders = align(headerSize, optHeader.FileAlignment);
            
            // Compute SizeOfImage as aligned total size of headers plus all sections (requirement 6.5)
            uint32_t maxVirtualEnd = optHeader.SizeOfHeaders;
            for(const auto& s : sections_) {
                uint32_t sectionEnd = s.virtualAddress + align(s.virtualSize, optHeader.SectionAlignment);
                if (sectionEnd > maxVirtualEnd) {
                    maxVirtualEnd = sectionEnd;
                }
            }
            optHeader.SizeOfImage = align(maxVirtualEnd, optHeader.SectionAlignment);
            optHeader.CheckSum = 0;  // Will be calculated later if needed

            // Set up data directories
            setupDataDirectories(optHeader.dataDirectory);

            file.write(reinterpret_cast<const char*>(&optHeader), sizeof(optHeader));
        } else {
            OptionalHeader32 optHeader = {};
            optHeader.Magic = 0x10b;  // PE32
            optHeader.MajorLinkerVersion = 14;
            optHeader.MinorLinkerVersion = 0;
            
            // Use default 32-bit ImageBase (0x400000)
            optHeader.ImageBase = static_cast<uint32_t>(baseAddress_);
            
            // Configure SectionAlignment = 0x1000 and FileAlignment = 0x200 as per requirement 6.5
            optHeader.SectionAlignment = 0x1000;
            optHeader.FileAlignment = 0x200;
            
            optHeader.MajorOperatingSystemVersion = 6;
            optHeader.MinorOperatingSystemVersion = 0;
            optHeader.MajorImageVersion = 0;
            optHeader.MinorImageVersion = 0;
            optHeader.MajorSubsystemVersion = 6;
            optHeader.MinorSubsystemVersion = 0;
            optHeader.Win32VersionValue = 0;
            optHeader.Subsystem = subsystem_;
            optHeader.DllCharacteristics = 0x8160;  // DYNAMIC_BASE | NX_COMPAT | NO_SEH | TERMINAL_SERVER_AWARE
            optHeader.SizeOfStackReserve = 0x100000;
            optHeader.SizeOfStackCommit = 0x1000;
            optHeader.SizeOfHeapReserve = 0x100000;
            optHeader.SizeOfHeapCommit = 0x1000;
            optHeader.LoaderFlags = 0;
            optHeader.NumberOfRvaAndSizes = 16;

            // Calculate sizes
            uint32_t sizeOfCode = 0;
            uint32_t sizeOfInitializedData = 0;
            uint32_t sizeOfUninitializedData = 0;
            
            Section* text = findSection(".text");
            Section* data = findSection(".data");
            Section* rdata = findSection(".rdata");
            Section* bss = findSection(".bss");
            
            if (text) {
                optHeader.BaseOfCode = text->virtualAddress;
                sizeOfCode = align(text->virtualSize, optHeader.FileAlignment);
                
                // Calculate AddressOfEntryPoint as RVA to start of .text section (requirement 6.3)
                optHeader.AddressOfEntryPoint = text->virtualAddress;
                
                // Allow override if explicitly set
                if (entryPoint_ != 0) {
                    optHeader.AddressOfEntryPoint = static_cast<uint32_t>(entryPoint_);
                }
            }
            
            if (data) {
                optHeader.BaseOfData = data->virtualAddress;
                sizeOfInitializedData += align(data->virtualSize, optHeader.FileAlignment);
            }
            if (rdata) {
                sizeOfInitializedData += align(rdata->virtualSize, optHeader.FileAlignment);
            }
            if (bss) {
                sizeOfUninitializedData += align(bss->virtualSize, optHeader.FileAlignment);
            }
            
            optHeader.SizeOfCode = sizeOfCode;
            optHeader.SizeOfInitializedData = sizeOfInitializedData;
            optHeader.SizeOfUninitializedData = sizeOfUninitializedData;

            // Calculate SizeOfHeaders as properly aligned size of all header structures (requirement 6.6)
            uint32_t headerSize = sizeof(DOSHeader) + DOS_STUB_SIZE + sizeof(uint32_t) + sizeof(FileHeader) + 
                                 sizeof(OptionalHeader32) + sections_.size() * sizeof(SectionHeader);
            optHeader.SizeOfHeaders = align(headerSize, optHeader.FileAlignment);
            
            // Compute SizeOfImage as aligned total size of headers plus all sections (requirement 6.5)
            uint32_t maxVirtualEnd = optHeader.SizeOfHeaders;
            for(const auto& s : sections_) {
                uint32_t sectionEnd = s.virtualAddress + align(s.virtualSize, optHeader.SectionAlignment);
                if (sectionEnd > maxVirtualEnd) {
                    maxVirtualEnd = sectionEnd;
                }
            }
            optHeader.SizeOfImage = align(maxVirtualEnd, optHeader.SectionAlignment);
            optHeader.CheckSum = 0;  // Will be calculated later if needed

            // Set up data directories
            setupDataDirectories(optHeader.dataDirectory);

            file.write(reinterpret_cast<const char*>(&optHeader), sizeof(optHeader));
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        for (const auto& section : sections_) {
            SectionHeader sectionHeader = {};
            
            // Copy section name (max 8 characters, null-terminated if shorter)
            memset(sectionHeader.Name, 0, 8);
            strncpy(sectionHeader.Name, section.name.c_str(), 8);
            
            // Set section properties
            sectionHeader.Misc.VirtualSize = section.virtualSize;
            sectionHeader.VirtualAddress = section.virtualAddress;
            sectionHeader.SizeOfRawData = section.rawDataSize;
            sectionHeader.PointerToRawData = section.rawDataPointer;
            sectionHeader.Characteristics = section.characteristics;
            
            // Initialize unused fields
            sectionHeader.PointerToRelocations = 0;
            sectionHeader.PointerToLinenumbers = 0;
            sectionHeader.NumberOfRelocations = 0;
            sectionHeader.NumberOfLinenumbers = 0;
            
            // Validate section boundaries
            if (section.virtualAddress == 0) {
                throw std::runtime_error("Section " + section.name + " has invalid virtual address");
            }
            
            if (section.rawDataSize > 0 && section.rawDataPointer == 0) {
                throw std::runtime_error("Section " + section.name + " has raw data but no file pointer");
            }
            
            // Check alignment
            if (section.virtualAddress % sectionAlignment_ != 0) {
                throw std::runtime_error("Section " + section.name + " virtual address not aligned");
            }
            
            if (section.rawDataSize > 0 && section.rawDataPointer % fileAlignment_ != 0) {
                throw std::runtime_error("Section " + section.name + " file pointer not aligned");
            }
            
            file.write(reinterpret_cast<const char*>(&sectionHeader), sizeof(sectionHeader));
        }
    }

    void writeSectionData(std::ofstream& file) {
        // Calculate the expected starting position after headers
        uint32_t headerSize = sizeof(DOSHeader) + DOS_STUB_SIZE + sizeof(uint32_t) + sizeof(FileHeader) + 
                             (is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32)) + 
                             (sections_.size() * sizeof(SectionHeader));
        uint32_t alignedHeaderSize = align(headerSize, fileAlignment_);
        
        // Track the current expected file position
        uint32_t currentFilePos = alignedHeaderSize;
        
        // Sort sections by file pointer to ensure correct order
        std::vector<const Section*> sectionsWithData;
        for (const auto& section : sections_) {
            // Only include sections that have file data (not uninitialized like .bss)
            if (!(section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) && section.rawDataSize > 0) {
                sectionsWithData.push_back(&section);
            }
        }
        
        // Sort by file pointer position
        std::sort(sectionsWithData.begin(), sectionsWithData.end(), 
                  [](const Section* a, const Section* b) {
                      return a->rawDataPointer < b->rawDataPointer;
                  });
        
        // Validate section layout before writing
        validateSectionFileLayout(sectionsWithData, alignedHeaderSize);
        
        // Write each section's data
        for (const Section* section : sectionsWithData) {
            // Validate file pointer alignment
            if (section->rawDataPointer % fileAlignment_ != 0) {
                throw std::runtime_error("Section " + section->name + " file pointer (0x" + 
                                       std::to_string(section->rawDataPointer) + ") not aligned to file alignment (0x" + 
                                       std::to_string(fileAlignment_) + ")");
            }
            
            // Fill any gap between current position and section start with zeros
            if (section->rawDataPointer > currentFilePos) {
                uint32_t gapSize = section->rawDataPointer - currentFilePos;
                writeFilePadding(file, currentFilePos, gapSize);
                currentFilePos = section->rawDataPointer;
            } else if (section->rawDataPointer < currentFilePos) {
                throw std::runtime_error("Section " + section->name + " file pointer (0x" + 
                                       std::to_string(section->rawDataPointer) + ") overlaps with previous data (current pos: 0x" + 
                                       std::to_string(currentFilePos) + ")");
            }
            
            // Seek to the section's file position
            file.seekp(section->rawDataPointer);
            if (file.fail()) {
                throw std::runtime_error("Failed to seek to file position 0x" + std::to_string(section->rawDataPointer) + 
                                       " for section " + section->name);
            }
            
            // Verify we're at the expected position
            uint32_t actualPos = static_cast<uint32_t>(file.tellp());
            if (actualPos != section->rawDataPointer) {
                throw std::runtime_error("Seek verification failed for section " + section->name + 
                                       ". Expected: 0x" + std::to_string(section->rawDataPointer) + 
                                       ", Actual: 0x" + std::to_string(actualPos));
            }
            
            // Write the actual section data
            uint32_t dataSize = section->data.size();
            if (dataSize > 0) {
                file.write(reinterpret_cast<const char*>(section->data.data()), dataSize);
                if (file.fail()) {
                    throw std::runtime_error("Failed to write " + std::to_string(dataSize) + 
                                           " bytes of data for section " + section->name);
                }
            }
            
            // Calculate and write padding to reach the required raw data size
            uint32_t paddingSize = calculateSectionPadding(*section);
            if (paddingSize > 0) {
                writeSectionPadding(file, *section, paddingSize);
            }
            
            // Update current file position
            currentFilePos = section->rawDataPointer + section->rawDataSize;
            
            // Validate that we wrote exactly the expected amount
            uint32_t finalPos = static_cast<uint32_t>(file.tellp());
            if (finalPos != currentFilePos) {
                throw std::runtime_error("Section " + section->name + " write size mismatch. " +
                                       "Expected final position: 0x" + std::to_string(currentFilePos) + 
                                       ", Actual: 0x" + std::to_string(finalPos) + 
                                       " (Data size: " + std::to_string(dataSize) + 
                                       ", Padding: " + std::to_string(paddingSize) + 
                                       ", Raw size: " + std::to_string(section->rawDataSize) + ")");
            }
        }
        
        // Validate uninitialized sections (like .bss) have correct layout
        validateUninitializedSections();
        
        // Final file structure validation
        validateFinalFileStructure(file, currentFilePos);
    }
    
    void validateSectionFileLayout(const std::vector<const Section*>& sectionsWithData, uint32_t headerSize) {
        if (sectionsWithData.empty()) {
            return; // No sections with file data
        }
        
        // Check that first section starts after headers
        const Section* firstSection = sectionsWithData[0];
        if (firstSection->rawDataPointer < headerSize) {
            throw std::runtime_error("First section " + firstSection->name + " file pointer (0x" + 
                                   std::to_string(firstSection->rawDataPointer) + ") overlaps with headers (size: 0x" + 
                                   std::to_string(headerSize) + ")");
        }
        
        // Check for overlaps between sections
        for (size_t i = 1; i < sectionsWithData.size(); ++i) {
            const Section* prevSection = sectionsWithData[i-1];
            const Section* currSection = sectionsWithData[i];
            
            uint32_t prevSectionEnd = prevSection->rawDataPointer + prevSection->rawDataSize;
            if (currSection->rawDataPointer < prevSectionEnd) {
                throw std::runtime_error("Section " + currSection->name + " file pointer (0x" + 
                                       std::to_string(currSection->rawDataPointer) + ") overlaps with section " + 
                                       prevSection->name + " (ends at 0x" + std::to_string(prevSectionEnd) + ")");
            }
        }
        
        // Validate each section's internal consistency
        for (const Section* section : sectionsWithData) {
            if (section->rawDataSize == 0) {
                throw std::runtime_error("Section " + section->name + " has rawDataSize of 0 but was included in file data sections");
            }
            
            if (section->data.size() > section->rawDataSize) {
                throw std::runtime_error("Section " + section->name + " data size (" + 
                                       std::to_string(section->data.size()) + ") exceeds raw data size (" + 
                                       std::to_string(section->rawDataSize) + ")");
            }
            
            // Check reasonable size limits (prevent extremely large sections)
            if (section->rawDataSize > 0x10000000) { // 256MB limit
                throw std::runtime_error("Section " + section->name + " raw data size (" + 
                                       std::to_string(section->rawDataSize) + ") exceeds reasonable limit");
            }
        }
    }
    
    uint32_t calculateSectionPadding(const Section& section) {
        uint32_t dataSize = section.data.size();
        
        // Validate that raw data size is at least as large as actual data
        if (section.rawDataSize < dataSize) {
            throw std::runtime_error("Section " + section.name + " raw data size (" + 
                                   std::to_string(section.rawDataSize) + ") is smaller than actual data size (" + 
                                   std::to_string(dataSize) + ")");
        }
        
        uint32_t paddingSize = section.rawDataSize - dataSize;
        
        // Validate padding size is reasonable
        if (paddingSize > fileAlignment_ * 2) {
            // Allow up to 2x file alignment for padding (should be enough for any valid case)
            throw std::runtime_error("Section " + section.name + " requires excessive padding (" + 
                                   std::to_string(paddingSize) + " bytes). This may indicate a layout error.");
        }
        
        return paddingSize;
    }
    
    void writeSectionPadding(std::ofstream& file, const Section& section, uint32_t paddingSize) {
        if (paddingSize == 0) {
            return;
        }
        
        // Write padding in chunks to avoid large memory allocation
        const uint32_t CHUNK_SIZE = 4096; // 4KB chunks
        std::vector<char> paddingChunk(std::min(paddingSize, CHUNK_SIZE), 0);
        
        uint32_t remainingPadding = paddingSize;
        while (remainingPadding > 0) {
            uint32_t chunkSize = std::min(remainingPadding, CHUNK_SIZE);
            file.write(paddingChunk.data(), chunkSize);
            
            if (file.fail()) {
                throw std::runtime_error("Failed to write " + std::to_string(chunkSize) + 
                                       " bytes of padding for section " + section.name + 
                                       " (remaining: " + std::to_string(remainingPadding) + ")");
            }
            
            remainingPadding -= chunkSize;
        }
    }
    
    void writeFilePadding(std::ofstream& file, uint32_t startPos, uint32_t size) {
        if (size == 0) {
            return;
        }
        
        file.seekp(startPos);
        if (file.fail()) {
            throw std::runtime_error("Failed to seek to position 0x" + std::to_string(startPos) + " for file padding");
        }
        
        // Write padding in chunks
        const uint32_t CHUNK_SIZE = 4096;
        std::vector<char> paddingChunk(std::min(size, CHUNK_SIZE), 0);
        
        uint32_t remainingSize = size;
        while (remainingSize > 0) {
            uint32_t chunkSize = std::min(remainingSize, CHUNK_SIZE);
            file.write(paddingChunk.data(), chunkSize);
            
            if (file.fail()) {
                throw std::runtime_error("Failed to write " + std::to_string(chunkSize) + 
                                       " bytes of file padding at position 0x" + std::to_string(startPos));
            }
            
            remainingSize -= chunkSize;
            startPos += chunkSize;
        }
    }
    
    void validateUninitializedSections() {
        for (const auto& section : sections_) {
            if (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                // Uninitialized sections should not have file data
                if (section.rawDataSize > 0) {
                    throw std::runtime_error("Uninitialized section " + section.name + 
                                           " should not have raw data size > 0 (has: " + 
                                           std::to_string(section.rawDataSize) + ")");
                }
                
                if (!section.data.empty()) {
                    throw std::runtime_error("Uninitialized section " + section.name + 
                                           " should not have data (has " + std::to_string(section.data.size()) + " bytes)");
                }
                
                // Virtual size should be set for uninitialized sections
                if (section.virtualSize == 0) {
                    throw std::runtime_error("Uninitialized section " + section.name + 
                                           " must have virtualSize > 0");
                }
                
                // Virtual address should be properly aligned
                if (section.virtualAddress % sectionAlignment_ != 0) {
                    throw std::runtime_error("Uninitialized section " + section.name + 
                                           " virtual address (0x" + std::to_string(section.virtualAddress) + 
                                           ") not aligned to section alignment (0x" + std::to_string(sectionAlignment_) + ")");
                }
            }
        }
    }
    
    void validateFinalFileStructure(std::ofstream& file, uint32_t expectedSize) {
        // Get actual file size
        file.seekp(0, std::ios::end);
        uint32_t actualFileSize = static_cast<uint32_t>(file.tellp());
        
        // Calculate expected minimum file size
        uint32_t expectedMinSize = 0;
        for (const auto& section : sections_) {
            if (section.rawDataSize > 0) {
                uint32_t sectionEnd = section.rawDataPointer + section.rawDataSize;
                if (sectionEnd > expectedMinSize) {
                    expectedMinSize = sectionEnd;
                }
            }
        }
        
        // File size should match our expectations
        if (actualFileSize < expectedMinSize) {
            throw std::runtime_error(std::string("Final file size validation failed. ") +
                                   "Actual size: " + std::to_string(actualFileSize) + 
                                   ", Expected minimum: " + std::to_string(expectedMinSize));
        }
        
        if (actualFileSize != expectedSize) {
            throw std::runtime_error(std::string("Final file size mismatch. ") +
                                   "Actual size: " + std::to_string(actualFileSize) + 
                                   ", Expected size: " + std::to_string(expectedSize));
        }
        
        // Validate file size is reasonable (not too large)
        if (actualFileSize > 0x40000000) { // 1GB limit
            throw std::runtime_error("Generated file size (" + std::to_string(actualFileSize) + 
                                   ") exceeds reasonable limit (1GB)");
        }
        
        // Additional structural validation
        validateFileStructureIntegrity(actualFileSize);
    }
    
    void validateFileStructureIntegrity(uint32_t fileSize) {
        // Validate that all sections fit within the file
        for (const auto& section : sections_) {
            if (section.rawDataSize > 0) {
                uint32_t sectionEnd = section.rawDataPointer + section.rawDataSize;
                if (sectionEnd > fileSize) {
                    throw std::runtime_error("Section " + section.name + " extends beyond file end. " +
                                           "Section end: 0x" + std::to_string(sectionEnd) + 
                                           ", File size: 0x" + std::to_string(fileSize));
                }
            }
        }
        
        // Validate import directory is within file bounds if present
        if (importDirectoryRVA_ > 0) {
            uint32_t importFileOffset = rvaToFileOffset(importDirectoryRVA_);
            if (importFileOffset == 0) {
                throw std::runtime_error("Import directory RVA (0x" + std::to_string(importDirectoryRVA_) + 
                                       ") does not map to a valid file offset");
            }
            
            uint32_t importSize = calculateImportDirectorySize();
            if (importFileOffset + importSize > fileSize) {
                throw std::runtime_error(std::string("Import directory extends beyond file end. ") +
                                       "Import end: 0x" + std::to_string(importFileOffset + importSize) + 
                                       ", File size: 0x" + std::to_string(fileSize));
            }
        }
        
        // Validate that file alignment is consistent throughout
        uint32_t headerSize = sizeof(DOSHeader) + DOS_STUB_SIZE + sizeof(uint32_t) + sizeof(FileHeader) + 
                             (is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32)) + 
                             (sections_.size() * sizeof(SectionHeader));
        uint32_t alignedHeaderSize = align(headerSize, fileAlignment_);
        
        if (alignedHeaderSize % fileAlignment_ != 0) {
            throw std::runtime_error("Header size alignment error. Aligned size: 0x" + 
                                   std::to_string(alignedHeaderSize) + ", File alignment: 0x" + 
                                   std::to_string(fileAlignment_));
        }
    }

    void writeSymbolTable(std::ofstream& file) {
        if(coffSymbols_.empty()) return;

        uint32_t lastSectionEnd = 0;
        for(const auto& s : sections_) {
            if(s.rawDataPointer + s.rawDataSize > lastSectionEnd) lastSectionEnd = s.rawDataPointer + s.rawDataSize;
        }
        file.seekp(lastSectionEnd);
        file.write(reinterpret_cast<const char*>(coffSymbols_.data()), coffSymbols_.size() * sizeof(COFFSymbol));
        file.write(stringTable_.data(), stringTable_.size());
    }
};

PEGenerator::PEGenerator(bool is64Bit, uint64_t baseAddr)
    : pImpl_(std::make_unique<Impl>(is64Bit, baseAddr)) {}

PEGenerator::~PEGenerator() = default;

bool PEGenerator::generateExecutable(const std::string& outputFile,
                                     Assembler& assembler) {
    return pImpl_->generateExecutable(outputFile, assembler);
}

bool PEGenerator::generateObjectFile(const std::string& outputFile,
                                     Assembler& assembler) {
    return pImpl_->generateObjectFile(outputFile, assembler);
}

void PEGenerator::addSection(const std::string& name, const std::vector<uint8_t>& data,
                             uint32_t virtualSize, uint32_t characteristics) {
    pImpl_->addSection(name, data, virtualSize, characteristics);
}

void PEGenerator::addImport(const std::string& moduleName, const std::string& functionName) {
    pImpl_->addImport(moduleName, functionName);
}

void PEGenerator::setBaseAddress(uint64_t addr) { pImpl_->setBaseAddress(addr); }
void PEGenerator::setPageSize(uint64_t size) { pImpl_->setPageSize(size); }
void PEGenerator::setSectionAlignment(uint32_t align) { pImpl_->setSectionAlignment(align); }
void PEGenerator::setFileAlignment(uint32_t align) { pImpl_->setFileAlignment(align); }
void PEGenerator::setEntryPoint(uint64_t addr) { pImpl_->setEntryPoint(addr); }
void PEGenerator::setSubsystem(uint16_t subsystem) { pImpl_->setSubsystem(subsystem); }
std::string PEGenerator::getLastError() const { return pImpl_->getLastError(); }
