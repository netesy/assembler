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
#include <ctime>


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
        , baseAddress_(is64Bit ? DEFAULT_IMAGE_BASE_X64 : DEFAULT_IMAGE_BASE_X86)
        , pageSize_(PAGE_SIZE)
        , sectionAlignment_(SECTION_ALIGNMENT)
        , fileAlignment_(FILE_ALIGNMENT)
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
            // Ensure .rdata section exists if we have imports
            if (!imports_.empty() && !findSection(".rdata")) {
                addSection(".rdata", {}, 0, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
            }

            buildSymbolTable(assembler.getSymbols());

            // Two-pass layout to solve chicken-and-egg problem with import directory size and RVA
            layoutSections(); // First pass to get preliminary RVAs
            setupImports();   // Creates and adds import data, resizing .rdata
            layoutSections(); // Second pass to finalize layout with correct sizes

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

    void layoutSections() {
        uint32_t headerSize = sizeof(DOSHeader) + sizeof(uint32_t) + (is64Bit_ ? sizeof(NTHeaders64) : sizeof(NTHeaders32)) + (sections_.size() * sizeof(SectionHeader));
        uint32_t currentRVA = align(headerSize, sectionAlignment_);
        uint32_t currentRawPtr = align(headerSize, fileAlignment_);

        for (auto& section : sections_) {
            section.virtualAddress = currentRVA;
            section.rawDataPointer = currentRawPtr;
            section.rawDataSize = align(section.data.size(), fileAlignment_);

            currentRVA += align(section.virtualSize, sectionAlignment_);
            currentRawPtr += section.rawDataSize;
        }
    }

    void setupImports() {
        if (imports_.empty()) return;

        Section* rdata = findSection(".rdata");
        if (!rdata) {
             // This should be handled by the check in generateExecutable before layouting.
             // If we get here, something is wrong, as we don't have a virtualAddress yet.
            throw std::runtime_error(".rdata section not found for imports.");
        }

        // Align the start of the import directory data within the section to a 16-byte boundary
        while (rdata->data.size() % 16 != 0) {
            rdata->data.push_back(0);
        }

        // The RVA of the import directory is the section's base RVA plus its offset within the section
        uint32_t import_data_offset_in_section = rdata->data.size();
        importDirectoryRVA_ = rdata->virtualAddress + import_data_offset_in_section;

        std::vector<uint8_t> import_directory_data = createImportDirectory();

        // Append new import data to existing .rdata content
        rdata->data.insert(rdata->data.end(), import_directory_data.begin(), import_directory_data.end());
        rdata->virtualSize = rdata->data.size();
        // The rawDataSize will be correctly recalculated in the second layout pass
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

        uint32_t size = (imports_.size() + 1) * sizeof(ImportDirectoryTable);

        uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);

        uint32_t lookup_and_address_table_size = 0;
        uint32_t hint_name_table_size = 0;

        for (const auto& pair : imports_) {
            lookup_and_address_table_size += (pair.second.size() + 1) * thunk_size; // For ILT
            lookup_and_address_table_size += (pair.second.size() + 1) * thunk_size; // For IAT

            hint_name_table_size += pair.first.size() + 1; // Module name
            for (const auto& funcName : pair.second) {
                size_t hint_name_size = sizeof(uint16_t) + funcName.size() + 1;
                if (hint_name_size % 2 != 0) hint_name_size++;
                hint_name_table_size += hint_name_size;
            }
        }
        return size + lookup_and_address_table_size + hint_name_table_size;
    }

    std::vector<uint8_t> createImportDirectory() {
        if (imports_.empty()) return {};

        // Layout:
        // 1. Import Directory Table (IDT)
        // 2. Import Lookup Tables (ILTs)
        // 3. Import Address Tables (IATs) - A copy of ILTs initially
        // 4. Hint/Name data (function names and module names)

        uint32_t thunk_size = is64Bit_ ? sizeof(uint64_t) : sizeof(uint32_t);

        // Calculate offsets
        uint32_t idt_size = (imports_.size() + 1) * sizeof(ImportDirectoryTable);

        uint32_t ilts_base_offset = idt_size;
        uint32_t iats_base_offset = 0;
        uint32_t names_base_offset = 0;

        uint32_t total_ilt_size = 0;
        for (const auto& pair : imports_) {
            total_ilt_size += (pair.second.size() + 1) * thunk_size;
        }
        iats_base_offset = ilts_base_offset + total_ilt_size;
        names_base_offset = iats_base_offset + total_ilt_size;

        uint32_t total_size = calculateImportDirectorySize();
        std::vector<uint8_t> data(total_size, 0);

        uint32_t idt_offset = 0;
        uint32_t ilt_offset = ilts_base_offset;
        uint32_t iat_offset = iats_base_offset;
        uint32_t name_offset = names_base_offset;

        for (const auto& pair : imports_) {
            const std::string& moduleName = pair.first;
            const std::vector<std::string>& functionNames = pair.second;

            uint32_t current_ilt_start_offset = ilt_offset;

            // --- Fill ILT and prepare Hint/Name data ---
            for (const auto& funcName : functionNames) {
                uint32_t hint_name_rva = importDirectoryRVA_ + name_offset;

                if (is64Bit_) write_to_vector<uint64_t>(data, ilt_offset, hint_name_rva);
                else write_to_vector<uint32_t>(data, ilt_offset, hint_name_rva);
                ilt_offset += thunk_size;

                // Write Hint/Name data
                write_to_vector<uint16_t>(data, name_offset, 0); // Hint
                memcpy(data.data() + name_offset + 2, funcName.c_str(), funcName.size() + 1);
                size_t hint_name_size = 2 + funcName.size() + 1;
                if (hint_name_size % 2 != 0) {
                    name_offset += hint_name_size + 1;
                } else {
                    name_offset += hint_name_size;
                }
            }
            ilt_offset += thunk_size; // Null terminator for ILT

            // --- Fill IDT entry ---
            ImportDirectoryTable idt = {};
            idt.ImportLookupTableRVA = importDirectoryRVA_ + current_ilt_start_offset;
            idt.ImportAddressTableRVA = importDirectoryRVA_ + iat_offset;
            idt.NameRVA = importDirectoryRVA_ + name_offset;
            memcpy(data.data() + idt_offset, &idt, sizeof(idt));
            idt_offset += sizeof(idt);

            // Write module name
            memcpy(data.data() + name_offset, moduleName.c_str(), moduleName.size() + 1);
            name_offset += moduleName.size() + 1;

            // --- Copy ILT to IAT ---
            memcpy(data.data() + iat_offset, data.data() + current_ilt_start_offset, (functionNames.size() + 1) * thunk_size);
            iat_offset += (functionNames.size() + 1) * thunk_size;
        }

        return data;
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
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
        dosHeader.e_lfanew = sizeof(DOSHeader);
        file.write(reinterpret_cast<const char*>(&dosHeader), sizeof(dosHeader));
    }

    void writeNTHeaders(std::ofstream& file) {
        uint32_t peSignature = IMAGE_NT_SIGNATURE;
        file.write(reinterpret_cast<const char*>(&peSignature), sizeof(peSignature));

        FileHeader fileHeader = {};
        fileHeader.Machine = is64Bit_ ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        fileHeader.NumberOfSections = sections_.size();
        fileHeader.TimeDateStamp = time(nullptr);
        fileHeader.SizeOfOptionalHeader = is64Bit_ ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32);
        fileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

        uint32_t lastSectionEnd = 0;
        for(const auto& s : sections_) {
            if(s.rawDataPointer + s.rawDataSize > lastSectionEnd) lastSectionEnd = s.rawDataPointer + s.rawDataSize;
        }
        fileHeader.PointerToSymbolTable = coffSymbols_.empty() ? 0 : lastSectionEnd;
        fileHeader.NumberOfSymbols = coffSymbols_.size();

        file.write(reinterpret_cast<const char*>(&fileHeader), sizeof(fileHeader));

        if (is64Bit_) {
            OptionalHeader64 optHeader = {};
            optHeader.Magic = 0x20b;
            optHeader.ImageBase = baseAddress_;
            optHeader.SectionAlignment = sectionAlignment_;
            optHeader.FileAlignment = fileAlignment_;
            optHeader.MajorOperatingSystemVersion = 6;
            optHeader.MajorSubsystemVersion = 6;
            optHeader.Subsystem = subsystem_;
            optHeader.SizeOfStackReserve = 0x100000;
            optHeader.SizeOfStackCommit = 0x1000;
            optHeader.NumberOfRvaAndSizes = 16;

            Section* text = findSection(".text");
            if(text) {
                optHeader.BaseOfCode = text->virtualAddress;
                optHeader.AddressOfEntryPoint = text->virtualAddress;
                if (entryPoint_ != 0) optHeader.AddressOfEntryPoint = entryPoint_;
            }

            uint32_t sizeOfImage = 0;
            uint32_t sizeOfHeaders = align(sizeof(DOSHeader) + sizeof(NTHeaders64) + sections_.size() * sizeof(SectionHeader), fileAlignment_);
            for(const auto& s : sections_) sizeOfImage = s.virtualAddress + align(s.virtualSize, sectionAlignment_);
            optHeader.SizeOfImage = align(sizeOfImage, sectionAlignment_);
            optHeader.SizeOfHeaders = sizeOfHeaders;

            if(importDirectoryRVA_ > 0) {
                optHeader.dataDirectory[1].VirtualAddress = importDirectoryRVA_;
                optHeader.dataDirectory[1].Size = calculateImportDirectorySize();
            }

            file.write(reinterpret_cast<const char*>(&optHeader), sizeof(optHeader));
        } else {
            // 32-bit header not fully implemented
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        for (const auto& section : sections_) {
            SectionHeader sectionHeader = {};
            strncpy(sectionHeader.Name, section.name.c_str(), 8);
            sectionHeader.Misc.VirtualSize = section.virtualSize;
            sectionHeader.VirtualAddress = section.virtualAddress;
            sectionHeader.SizeOfRawData = section.rawDataSize;
            sectionHeader.PointerToRawData = section.rawDataPointer;
            sectionHeader.Characteristics = section.characteristics;
            file.write(reinterpret_cast<const char*>(&sectionHeader), sizeof(sectionHeader));
        }
    }

    void writeSectionData(std::ofstream& file) {
        for (const auto& section : sections_) {
            if (section.rawDataSize > 0) {
                file.seekp(section.rawDataPointer);
                if (!section.data.empty()) {
                    file.write(reinterpret_cast<const char*>(section.data.data()), section.data.size());
                }
                if (section.rawDataSize > section.data.size()) {
                    std::vector<char> padding(section.rawDataSize - section.data.size(), 0);
                    file.write(padding.data(), padding.size());
                }
            }
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
