#include "elf.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>

#include <fstream>
#include <algorithm>
#include <cstring>
#include <sys/stat.h>
#include <map>

namespace {
// ELF constants
constexpr uint32_t ELF_MAGIC = 0x464C457F;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t EM_386 = 3;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_PHDR = 6;
constexpr uint64_t PAGE_SIZE = 0x1000;
constexpr uint64_t STACK_SIZE = 0x800000;

// Program header permission flags
constexpr uint32_t PF_X = 0x1;  // Executable
constexpr uint32_t PF_W = 0x2;  // Writable
constexpr uint32_t PF_R = 0x4;  // Readable
}

#pragma pack(push, 1)
struct ElfHeader {
    uint32_t e_ident_magic;
    uint8_t e_ident_class;
    uint8_t e_ident_data;
    uint8_t e_ident_version;
    uint8_t e_ident_osabi;
    uint8_t e_ident_abiversion;
    uint8_t e_ident_pad[7];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ProgramHeader {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct SectionHeader {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Symbol {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Relocation {
    uint64_t r_offset;
    uint32_t r_type;
    uint32_t r_sym;
    int64_t r_addend;
};
#pragma pack(pop)

class ElfGenerator::Impl {
public:
    Impl(bool is64Bit, uint64_t baseAddr)
        : is64Bit_(is64Bit)
        , baseAddress_(baseAddr)
        , pageSize_(PAGE_SIZE)
        , stackSize_(STACK_SIZE)
        , entryPoint_(baseAddr) {}

    // Section management
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        uint64_t vaddr;
        uint32_t type;
        uint64_t flags;
        uint64_t align;
        uint32_t name_offset;
        uint64_t offset;
        uint32_t index;
    };

    // Segment management
    struct Segment {
        uint32_t type;
        uint32_t flags;
        uint64_t vaddr;
        uint64_t paddr;
        uint64_t memsz;
        uint64_t align;
        uint64_t offset;
        uint64_t filesz;
        std::vector<Section*> sections;
    };

    bool generateExecutable(const std::string& outputFile,
                            const std::vector<uint8_t>& code,
                            const std::unordered_map<std::string, uint64_t>& symbols) {
        try {
            setupDefaultSections(code);
            layoutSections();
            createSegments();

            std::ofstream file(outputFile, std::ios::binary);
            if (!file) {
                lastError_ = "Cannot create output file: " + outputFile;
                return false;
            }

            writeElfHeader(file);
            writeProgramHeaders(file);
            writeSectionData(file);
            writeSectionHeaders(file);
            writeSymbolTable(file);
            writeStringTables(file);

            file.close();

            // Make file executable on Unix-like systems
#ifdef __unix__
            chmod(outputFile.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
#endif

            return true;
        } catch (const std::exception& e) {
            lastError_ = "Error generating ELF file: " + std::string(e.what());
            return false;
        }
    }

    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint64_t vaddr, uint32_t type, uint64_t flags) {
        Section section;
        section.name = name;
        section.data = data;
        section.vaddr = vaddr;
        section.type = type;
        section.flags = flags;
        section.align = determineAlignment(flags);
        section.index = static_cast<uint32_t>(sections_.size());

        // Add section name to string table
        if (!name.empty()) {
            section.name_offset = addSectionString(name);
        }

        sections_.push_back(std::move(section));
    }

    void addSymbol(const std::string& name, uint64_t value, uint64_t size,
                   uint8_t info, uint8_t other, uint16_t shndx) {
        Symbol sym = {};
        sym.st_name = addString(name);
        sym.st_value = value;
        sym.st_size = size;
        sym.st_info = info;
        sym.st_other = other;
        sym.st_shndx = shndx;
        symbols_.push_back(sym);
    }

    void addRelocation(const std::string& section, uint64_t offset,
                       uint32_t type, const std::string& symbol, int64_t addend) {
        Relocation rel = {};
        rel.r_offset = offset;
        rel.r_type = type;
        rel.r_sym = findSymbol(symbol);
        rel.r_addend = addend;
        relocations_[section].push_back(rel);
    }

    // Getter/setter methods
    void setBaseAddress(uint64_t addr) { baseAddress_ = addr; }
    void setPageSize(uint64_t size) { pageSize_ = size; }
    void setStackSize(uint64_t size) { stackSize_ = size; }
    void setEntryPoint(uint64_t addr) { entryPoint_ = addr; }
    std::string getLastError() const { return lastError_; }

private:
    bool is64Bit_;
    uint64_t baseAddress_;
    uint64_t pageSize_;
    uint64_t stackSize_;
    uint64_t entryPoint_;
    std::string lastError_;

    std::vector<Section> sections_;
    std::vector<Segment> segments_;
    std::vector<Symbol> symbols_;
    std::map<std::string, std::vector<Relocation>> relocations_;
    std::string stringTable_;
    std::string shstringTable_;

    // Helper methods for section and segment management
    void setupDefaultSections(const std::vector<uint8_t>& code) {
        // Create null section (mandatory at index 0)
        Section nullSection;
        nullSection.name = "";
        nullSection.data = {};
        nullSection.vaddr = 0;
        nullSection.type = 0;
        nullSection.flags = 0;
        nullSection.align = 0;
        nullSection.name_offset = 0;  // First byte in shstrtab
        nullSection.offset = 0;
        nullSection.index = 0;
        sections_.push_back(std::move(nullSection));

        // Add section names before creating sections
        uint32_t textNameOffset = addSectionString(".text");
        uint32_t dataNameOffset = addSectionString(".data");
        uint32_t bssNameOffset = addSectionString(".bss");
        uint32_t strtabNameOffset = addSectionString(".strtab");
        uint32_t shstrtabNameOffset = addSectionString(".shstrtab");

        // Create .text section with code
        Section textSection;
        textSection.name = ".text";
        textSection.data = code;
        textSection.vaddr = baseAddress_;
        textSection.type = SHT_PROGBITS;
        textSection.flags = SHF_ALLOC | SHF_EXECINSTR;
        textSection.align = 16;  // Common alignment for code
        textSection.name_offset = textNameOffset;
        textSection.index = sections_.size();
        sections_.push_back(std::move(textSection));

        // Create .data section
        Section dataSection;
        dataSection.name = ".data";
        dataSection.data = {};
        dataSection.vaddr = align(baseAddress_ + code.size(), 16);
        dataSection.type = SHT_PROGBITS;
        dataSection.flags = SHF_ALLOC | SHF_WRITE;
        dataSection.align = 8;
        dataSection.name_offset = dataNameOffset;
        dataSection.index = sections_.size();
        sections_.push_back(std::move(dataSection));

        // Create .bss section
        Section bssSection;
        bssSection.name = ".bss";
        bssSection.data = {};
        bssSection.vaddr = align(dataSection.vaddr, 8);
        bssSection.type = SHT_NOBITS;
        bssSection.flags = SHF_ALLOC | SHF_WRITE;
        bssSection.align = 8;
        bssSection.name_offset = bssNameOffset;
        bssSection.index = sections_.size();
        sections_.push_back(std::move(bssSection));

        // Create string tables now that they have content
        // Create .strtab section
        Section strtabSection;
        strtabSection.name = ".strtab";
        strtabSection.vaddr = 0;  // Will be set in layoutSections
        strtabSection.type = SHT_STRTAB;
        strtabSection.flags = 0;
        strtabSection.align = 1;
        strtabSection.name_offset = strtabNameOffset;
        strtabSection.index = sections_.size();
        sections_.push_back(std::move(strtabSection));

        // Create .shstrtab section
        Section shstrtabSection;
        shstrtabSection.name = ".shstrtab";
        shstrtabSection.vaddr = 0;  // Will be set in layoutSections
        shstrtabSection.type = SHT_STRTAB;
        shstrtabSection.flags = 0;
        shstrtabSection.align = 1;
        shstrtabSection.name_offset = shstrtabNameOffset;
        shstrtabSection.index = sections_.size();
        sections_.push_back(std::move(shstrtabSection));
    }

    void layoutSections() {
        uint64_t headerSize = sizeof(ElfHeader) + (2 * sizeof(ProgramHeader));  // Assume at least 2 segments
        uint64_t offset = align(headerSize, pageSize_);  // Align to page size

        for (auto& section : sections_) {
            if (section.type == SHT_NOBITS) {
                // BSS sections don't have file content
                section.offset = 0;
                continue;
            }

            // Align offset according to section alignment
            offset = align(offset, section.align);
            section.offset = offset;

            // Advance offset by section size
            if (!section.data.empty()) {
                offset += section.data.size();
            }
        }
    }

    uint32_t addSectionString(const std::string& str) {
        uint32_t offset = shstringTable_.size();
        shstringTable_ += str;
        shstringTable_ += '\0';
        return offset;
    }

    void createSegments() {
        // Start after ELF header and program headers
        uint64_t currentOffset = sizeof(ElfHeader) + (segments_.size() * sizeof(ProgramHeader));
        currentOffset = align(currentOffset, pageSize_);

        // Text segment
        Segment text = {};
        text.type = PT_LOAD;
        text.flags = PF_R | PF_X;
        text.offset = currentOffset;
        text.vaddr = baseAddress_;
        text.paddr = baseAddress_;
        text.align = pageSize_;

        // Find and add .text section
        auto textIdx = findSectionIndex(".text");
        if (textIdx > 0) {
            auto& textSection = sections_[textIdx];
            textSection.offset = currentOffset;  // Set proper file offset
            text.sections.push_back(&textSection);
            text.filesz = textSection.data.size();
            text.memsz = text.filesz;
            currentOffset = align(currentOffset + text.filesz, pageSize_);
        }
        segments_.push_back(text);

        // Data segment
        Segment data = {};
        data.type = PT_LOAD;
        data.flags = PF_R | PF_W;
        data.offset = currentOffset;
        data.vaddr = align(text.vaddr + text.memsz, pageSize_);
        data.paddr = data.vaddr;
        data.align = pageSize_;

        // Add data and bss sections with proper offsets
        auto dataIdx = findSectionIndex(".data");
        auto bssIdx = findSectionIndex(".bss");

        if (dataIdx > 0) {
            auto& dataSection = sections_[dataIdx];
            dataSection.offset = currentOffset;  // Set proper file offset
            dataSection.vaddr = data.vaddr;
            data.sections.push_back(&dataSection);
            data.filesz += dataSection.data.size();
            data.memsz += dataSection.data.size();
            currentOffset += dataSection.data.size();
        }

        if (bssIdx > 0) {
            auto& bssSection = sections_[bssIdx];
            bssSection.offset = 0;  // BSS has no file content
            bssSection.vaddr = data.vaddr + data.filesz;
            data.sections.push_back(&bssSection);
            data.memsz += bssSection.data.size();
        }

        segments_.push_back(data);

        // String tables should come after all loadable segments
        currentOffset = align(currentOffset, 4);  // Align to 4 bytes

        // // Update string table sections
        // auto shstrIdx = findSectionIndex(".shstrtab");
        // if (shstrIdx > 0) {
        //     sections_[shstrIdx].offset = currentOffset;
        //     currentOffset += shstringTable_.size();
        // }

        // auto strIdx = findSectionIndex(".strtab");
        // if (strIdx > 0) {
        //     sections_[strIdx].offset = currentOffset;
        //     currentOffset += stringTable_.size();
        // }

        // Make sure the string tables have proper offsets
        uint64_t stringTablesOffset = currentOffset;

        // Update string table sections
        auto shstrIdx = findSectionIndex(".shstrtab");
        if (shstrIdx > 0) {
            sections_[shstrIdx].offset = stringTablesOffset;
            // Update the section data from the current string table content
            sections_[shstrIdx].data.assign(shstringTable_.begin(), shstringTable_.end());
            stringTablesOffset += shstringTable_.size();
        }

        auto strIdx = findSectionIndex(".strtab");
        if (strIdx > 0) {
            sections_[strIdx].offset = stringTablesOffset;
            // Update the section data from the current string table content
            sections_[strIdx].data.assign(stringTable_.begin(), stringTable_.end());
        }

        // Update the ELF header shstrndx field
        if (shstrIdx > 0) {
            // This will be set in writeElfHeader
        }
    }

    // File writing methods
    void writeElfHeader(std::ofstream& file) {
        ElfHeader header = {};
        header.e_ident_magic = ELF_MAGIC;
        header.e_ident_class = is64Bit_ ? 2 : 1;
        header.e_ident_data = 1;  // Little endian
        header.e_ident_version = 1;
        header.e_type = ET_EXEC;
        header.e_machine = is64Bit_ ? EM_X86_64 : EM_386;
        header.e_version = 1;
        header.e_entry = entryPoint_;
        header.e_phoff = sizeof(ElfHeader);
        header.e_shoff = calculateSectionHeaderOffset();
        header.e_flags = 0;
        header.e_ehsize = sizeof(ElfHeader);
        header.e_phentsize = sizeof(ProgramHeader);
        header.e_phnum = segments_.size();
        header.e_shentsize = sizeof(SectionHeader);
        header.e_shnum = sections_.size();
        header.e_shstrndx = findSectionIndex(".shstrtab");

        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }

    // Additional helper methods...
    uint64_t align(uint64_t value, uint64_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    uint64_t determineAlignment(uint64_t flags) {
        if (flags & SHF_EXECINSTR) return 16;
        if (flags & SHF_WRITE) return 8;
        return 4;
    }

    uint32_t addString(const std::string& str) {
        uint32_t offset = stringTable_.size();
        stringTable_ += str;
        stringTable_ += '\0';
        return offset;
    }

    uint32_t findSymbol(const std::string& name) {
        for (size_t i = 0; i < symbols_.size(); ++i) {
            if (getString(symbols_[i].st_name) == name) {
                return static_cast<uint32_t>(i);
            }
        }
        throw std::runtime_error("Symbol not found: " + name);
    }

    std::string getString(uint32_t offset) const {
        if (offset >= stringTable_.size()) return "";
        return stringTable_.substr(offset, stringTable_.find('\0', offset) - offset);
    }

    uint32_t findSectionIndex(const std::string& name) {
        for (size_t i = 0; i < sections_.size(); ++i) {
            if (sections_[i].name == name) {
                return static_cast<uint32_t>(i);
            }
        }
        return 0;
    }
    uint64_t calculateSectionHeaderOffset() {
        uint64_t offset = sizeof(ElfHeader);
        offset += segments_.size() * sizeof(ProgramHeader);

        // Add size of all section data
        for (const auto& section : sections_) {
            if (section.type != SHT_NOBITS && !section.data.empty()) {
                offset = align(offset, section.align);
                offset += section.data.size();
            }
        }

        return offset;
    }

    void writeProgramHeaders(std::ofstream& file) {
        for (const auto& segment : segments_) {
            ProgramHeader ph = {};
            ph.p_type = segment.type;
            ph.p_flags = segment.flags;
            ph.p_offset = segment.offset;
            ph.p_vaddr = segment.vaddr;
            ph.p_paddr = segment.paddr;
            ph.p_filesz = segment.filesz;
            ph.p_memsz = segment.memsz;
            ph.p_align = segment.align;

            file.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        }
    }

    void writeSectionData(std::ofstream& file) {
        for (const auto& section : sections_) {
            if (section.type != SHT_NOBITS && !section.data.empty()) {
                // Align the file position
                uint64_t current = file.tellp();
                uint64_t aligned = align(current, section.align);
                if (aligned > current) {
                    std::vector<char> padding(aligned - current, 0);
                    file.write(padding.data(), padding.size());
                }

                // Write section data
                file.write(reinterpret_cast<const char*>(section.data.data()),
                           section.data.size());
            }
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        for (const auto& section : sections_) {
            SectionHeader sh = {};
            // Use the pre-calculated name offset
            sh.sh_name = section.name_offset;
            sh.sh_type = section.type;
            sh.sh_flags = section.flags;
            sh.sh_addr = section.vaddr;
            // Use the correct file offset
            sh.sh_offset = (section.type != SHT_NOBITS) ? section.offset : 0;
            sh.sh_size = (section.type != SHT_NOBITS) ? section.data.size() :
                             (section.name == ".bss" ? 8 : 0);  // Give bss a default size
            sh.sh_link = getShLink(section);
            sh.sh_info = getShInfo(section);
            sh.sh_addralign = section.align;
            sh.sh_entsize = getShEntSize(section);

            file.write(reinterpret_cast<const char*>(&sh), sizeof(sh));
        }
    }

    void writeSymbolTable(std::ofstream& file) {
        if (symbols_.empty()) return;

        // Write symbol table section
        uint64_t symtab_offset = file.tellp();
        for (const auto& symbol : symbols_) {
            file.write(reinterpret_cast<const char*>(&symbol), sizeof(Symbol));
        }

        // Update symbol table section header
        auto& symtab_section = sections_[findSectionIndex(".symtab")];
        symtab_section.data.resize(symbols_.size() * sizeof(Symbol));
        std::memcpy(symtab_section.data.data(), symbols_.data(),
                    symtab_section.data.size());
    }

    void writeStringTables(std::ofstream& file) {
        // Update string table sections with current content
        auto shstrIdx = findSectionIndex(".shstrtab");
        if (shstrIdx > 0) {
            auto& section = sections_[shstrIdx];
            section.data.clear();
            section.data.insert(section.data.end(), shstringTable_.begin(), shstringTable_.end());

            // Make sure it's properly positioned in the file
            file.seekp(section.offset);
            file.write(reinterpret_cast<const char*>(section.data.data()), section.data.size());
        }

        auto strIdx = findSectionIndex(".strtab");
        if (strIdx > 0) {
            auto& section = sections_[strIdx];
            section.data.clear();
            section.data.insert(section.data.end(), stringTable_.begin(), stringTable_.end());

            // Make sure it's properly positioned in the file
            file.seekp(section.offset);
            file.write(reinterpret_cast<const char*>(section.data.data()), section.data.size());
        }
    }

    uint32_t addSectionName(const std::string& name) {
        // Check if name already exists in the string table
        size_t pos = 0;
        while (pos < shstringTable_.size()) {
            std::string existingName = shstringTable_.substr(pos, shstringTable_.find('\0', pos) - pos);
            if (existingName == name) {
                return static_cast<uint32_t>(pos);
            }
            pos += existingName.size() + 1; // +1 for null terminator
        }

        // Add new name if not found
        uint32_t offset = shstringTable_.size();
        shstringTable_ += name;
        shstringTable_ += '\0';
        return offset;
    }

    uint64_t calculateSegmentFileSize(const Segment& segment) {
        uint64_t size = 0;
        for (const auto* section : segment.sections) {
            if (section->type != SHT_NOBITS) {
                size += align(section->data.size(), section->align);
            }
        }
        return size;
    }

    uint64_t calculateSegmentMemSize(const Segment& segment) {
        uint64_t size = 0;
        for (const auto* section : segment.sections) {
            size += align(section->data.size(), section->align);
        }
        return size;
    }

    uint32_t getShLink(const Section& section) {
        if (section.type == SHT_SYMTAB) {
            return findSectionIndex(".strtab");
        }
        return 0;
    }

    uint32_t getShInfo(const Section& section) {
        if (section.type == SHT_SYMTAB) {
            return symbols_.empty() ? 0 :
                       static_cast<uint32_t>(symbols_.size());
        }
        return 0;
    }

    uint64_t getShEntSize(const Section& section) {
        switch (section.type) {
        case SHT_SYMTAB: return sizeof(Symbol);
        case SHT_RELA: return sizeof(Relocation);
        default: return 0;
        }
    }
};

// ElfGenerator implementation
ElfGenerator::ElfGenerator(bool is64Bit, uint64_t baseAddress)
    : pImpl(std::make_unique<Impl>(is64Bit, baseAddress)) {}

ElfGenerator::~ElfGenerator() = default;

void ElfGenerator::addSection(const std::string& name, const std::vector<uint8_t>& data,
                              uint64_t vaddr, uint32_t type, uint64_t flags) {
    pImpl->addSection(name, data, vaddr, type, flags);
}

void ElfGenerator::addSymbol(const std::string& name, uint64_t value, uint64_t size,
                             uint8_t info, uint8_t other, uint16_t shndx) {
    pImpl->addSymbol(name, value, size, info, other, shndx);
}

void ElfGenerator::addRelocation(const std::string& section, uint64_t offset,
                                 uint32_t type, const std::string& symbol, int64_t addend) {
    pImpl->addRelocation(section, offset, type, symbol, addend);
}

bool ElfGenerator::generateExecutable(const std::string& outputFile,
                                      const std::vector<uint8_t>& code,
                                      const std::unordered_map<std::string, uint64_t>& symbols) {
    return pImpl->generateExecutable(outputFile, code, symbols);
}

bool ElfGenerator::generateElf(const std::vector<uint8_t> &textSection,
                               const std::string &outputFile,
                               const std::unordered_map<std::string, uint64_t> &symbols,
                               const std::vector<uint8_t> &dataSection,
                               uint64_t entryPoint)
{
    // Update entry point
     pImpl->setBaseAddress(entryPoint);

    // Combine sections
    std::vector<uint8_t> fullCode = textSection;
    fullCode.insert(fullCode.end(), dataSection.begin(), dataSection.end());

    return pImpl->generateExecutable(outputFile, fullCode, symbols);
}

void ElfGenerator::setBaseAddress(uint64_t address) { pImpl->setBaseAddress(address); }
void ElfGenerator::setPageSize(uint64_t size) { pImpl->setPageSize(size); }
void ElfGenerator::setStackSize(uint64_t size) { pImpl->setStackSize(size); }
void ElfGenerator::setEntryPoint(uint64_t address) { pImpl->setEntryPoint(address); }
std::string ElfGenerator::getLastError() const { return pImpl->getLastError(); }
