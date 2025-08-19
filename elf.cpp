#include "elf.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>
#include <map>

// ELF constants
namespace {
constexpr uint32_t ELF_MAGIC = 0x464C457F;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t SHT_NULL = 0;
constexpr uint16_t SHT_PROGBITS = 1;
constexpr uint16_t SHT_SYMTAB = 2;
constexpr uint16_t SHT_STRTAB = 3;
constexpr uint16_t SHT_NOBITS = 8;
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 0x1;
constexpr uint32_t PF_W = 0x2;
constexpr uint32_t PF_R = 0x4;
constexpr uint8_t STB_LOCAL = 0;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STT_NOTYPE = 0;
constexpr uint8_t STT_OBJECT = 1;
constexpr uint8_t STT_FUNC = 2;
constexpr uint16_t SHN_ABS = 0xFFF1;
}

#pragma pack(push, 1)
struct ElfHeader64 {
    unsigned char e_ident[16];
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

struct ProgramHeader64 {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct SectionHeader64 {
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

struct Symbol64 {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};
#pragma pack(pop)

inline uint8_t ELF64_ST_INFO(uint8_t bind, uint8_t type) {
    return (bind << 4) + (type & 0xF);
}

class ElfGenerator::Impl {
public:
    Impl(bool is64Bit, uint64_t baseAddr)
        : is64Bit_(is64Bit), baseAddress_(baseAddr), entryPoint_(0), pageSize_(0x1000) {}

    bool generate(const std::string& outputFile,
                  const std::vector<uint8_t>& textSectionData,
                  const std::vector<uint8_t>& dataSectionData,
                  const std::unordered_map<std::string, SymbolEntry>& symbols,
                  uint64_t entryPoint)
    {
        if (!is64Bit_) {
            lastError_ = "32-bit ELF generation is not supported.";
            return false;
        }

        entryPoint_ = entryPoint;

        try {
            // 1. Reset and add sections
            sections_.clear();
            shstringTable_ = "\0";
            stringTable_ = "\0";
            symbols_.clear();

            addSection("", {}, 0, SHT_NULL, 0); // Null section
            addSection(".text", textSectionData, 0, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
            if (!dataSectionData.empty()) {
                addSection(".data", dataSectionData, 0, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
            }
            addSection(".bss", {}, 0, SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
            addSection(".shstrtab", {}, 0, SHT_STRTAB, 0);
            addSection(".symtab", {}, 0, SHT_SYMTAB, 0);
            addSection(".strtab", {}, 0, SHT_STRTAB, 0);

            // 2. Layout sections to calculate their virtual addresses and file offsets
            layoutSections();

            // 3. Create symbol table
            createSymbolTable(symbols);

            // 4. Prepare data for string and symbol table sections
            prepareTableSections();

            // 5. Create program segments
            createSegments();
            
            // 6. Write to file
            std::ofstream file(outputFile, std::ios::binary | std::ios::trunc);
            if (!file) {
                lastError_ = "Cannot open output file: " + outputFile;
                return false;
            }

            writeElfHeader(file);
            writeProgramHeaders(file);
            writeSectionData(file);
            writeSectionHeaders(file);

            file.close();
            return true;

        } catch (const std::exception& e) {
            lastError_ = "Error generating ELF: " + std::string(e.what());
            return false;
        }
    }

    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint64_t vaddr, uint32_t type, uint64_t flags)
    {
        Section s;
        s.name = name;
        s.data = data;
        s.header.sh_addr = vaddr;
        s.header.sh_type = type;
        s.header.sh_flags = flags;
        s.header.sh_addralign = (type == SHT_PROGBITS || type == SHT_NOBITS) ? 16 : 1;
        s.header.sh_name = addToStringTable(shstringTable_, name);
        sections_.push_back(s);
    }

    void addSymbol(const std::string& name, uint64_t value, uint64_t size,
                   uint8_t info, uint8_t other, uint16_t shndx)
    {
        Symbol64 sym;
        sym.st_name = addToStringTable(stringTable_, name);
        sym.st_value = value;
        sym.st_size = size;
        sym.st_info = info;
        sym.st_other = other;
        sym.st_shndx = shndx;
        symbols_.push_back(sym);
    }

    void setEntryPoint(uint64_t address) { entryPoint_ = address; }
    std::string getLastError() const { return lastError_; }

private:
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        SectionHeader64 header;
    };

    bool is64Bit_;
    uint64_t baseAddress_;
    uint64_t entryPoint_;
    uint64_t pageSize_;
    std::string lastError_;

    std::vector<Section> sections_;
    std::vector<ProgramHeader64> segments_;
    std::vector<Symbol64> symbols_;
    std::string stringTable_;
    std::string shstringTable_;

    uint32_t addToStringTable(std::string& table, const std::string& str) {
        if (str.empty()) return 0;
        uint32_t offset = table.size();
        table.append(str).append(1, '\0');
        return offset;
    }

    Section* findSection(const std::string& name) {
        for (auto& s : sections_) {
            if (s.name == name) return &s;
        }
        return nullptr;
    }

    uint16_t findSectionIndex(const std::string& name) {
        for (size_t i = 0; i < sections_.size(); ++i) {
            if (sections_[i].name == name) return i;
        }
        return 0;
    }

    void layoutSections() {
        uint64_t fileOffset = sizeof(ElfHeader64); // Start after ELF header
        // Placeholder for program headers
        fileOffset += 3 * sizeof(ProgramHeader64); // Assuming 3 segments: LOAD text, LOAD data, PHDR
        
        uint64_t currentVAddr = baseAddress_;

        for (auto& section : sections_) {
            if (section.header.sh_flags & SHF_ALLOC) {
                currentVAddr = (currentVAddr + section.header.sh_addralign - 1) & -section.header.sh_addralign;
                section.header.sh_addr = currentVAddr;
            }

            if (section.header.sh_type != SHT_NOBITS && section.header.sh_type != SHT_NULL) {
                 fileOffset = (fileOffset + section.header.sh_addralign - 1) & -section.header.sh_addralign;
                 section.header.sh_offset = fileOffset;
                 fileOffset += section.data.size();
            }

            if (section.header.sh_flags & SHF_ALLOC) {
                currentVAddr += (section.header.sh_type == SHT_NOBITS) ? 4096 : section.data.size(); // 4k for bss
            }
        }
        // Layout non-alloc sections at the end
        for (auto& section : sections_) {
            if (!(section.header.sh_flags & SHF_ALLOC) && section.header.sh_type != SHT_NULL) {
                fileOffset = (fileOffset + section.header.sh_addralign - 1) & -section.header.sh_addralign;
                section.header.sh_offset = fileOffset;
                fileOffset += section.data.size();
            }
        }
    }

    void createSymbolTable(const std::unordered_map<std::string, SymbolEntry>& symbols) {
        // Add NULL symbol
        addSymbol("", 0, 0, 0, 0, 0);

        // Add section symbols
        for (size_t i = 1; i < sections_.size(); ++i) {
            if (sections_[i].header.sh_type != SHT_NULL) {
                addSymbol(sections_[i].name, sections_[i].header.sh_addr, 0, ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE), 0, i);
            }
        }

        // Add user-provided symbols
        uint16_t text_idx = findSectionIndex(".text");
        uint16_t data_idx = findSectionIndex(".data");

        for (const auto& pair : symbols) {
            const auto& sym = pair.second;
            uint16_t shndx = 0;
            uint8_t type = STT_NOTYPE;

            Section* text_sec = findSection(".text");
            Section* data_sec = findSection(".data");

            if (text_sec && sym.address >= text_sec->header.sh_addr && sym.address < text_sec->header.sh_addr + text_sec->data.size()) {
                shndx = text_idx;
                type = STT_FUNC;
            } else if (data_sec && sym.address >= data_sec->header.sh_addr && sym.address < data_sec->header.sh_addr + data_sec->data.size()) {
                shndx = data_idx;
                type = STT_OBJECT;
            } else {
                // Check if it's an absolute symbol (like string length)
                bool is_len_symbol = sym.name.size() > 4 && sym.name.substr(sym.name.size() - 4) == "_len";
                if (is_len_symbol) {
                    shndx = SHN_ABS;
                    type = STT_OBJECT;
                }
            }

            uint8_t bind = sym.isGlobal ? STB_GLOBAL : STB_LOCAL;
            addSymbol(sym.name, sym.address, 0, ELF64_ST_INFO(bind, type), 0, shndx);
        }
    }

    void prepareTableSections() {
        Section* shstrtab = findSection(".shstrtab");
        shstrtab->data.assign(shstringTable_.begin(), shstringTable_.end());
        shstrtab->header.sh_size = shstrtab->data.size();

        Section* strtab = findSection(".strtab");
        strtab->data.assign(stringTable_.begin(), stringTable_.end());
        strtab->header.sh_size = strtab->data.size();

        Section* symtab = findSection(".symtab");
        symtab->data.resize(symbols_.size() * sizeof(Symbol64));
        memcpy(symtab->data.data(), symbols_.data(), symtab->data.size());
        symtab->header.sh_size = symtab->data.size();
        symtab->header.sh_link = findSectionIndex(".strtab");
        symtab->header.sh_info = 1; // Index of first non-local symbol
        symtab->header.sh_entsize = sizeof(Symbol64);
    }

    void createSegments() {
        segments_.clear();
        
        // Text segment
        ProgramHeader64 text_phdr = {};
        Section* text_sec = findSection(".text");
        text_phdr.p_type = PT_LOAD;
        text_phdr.p_flags = PF_R | PF_X;
        text_phdr.p_offset = text_sec->header.sh_offset;
        text_phdr.p_vaddr = text_sec->header.sh_addr;
        text_phdr.p_paddr = text_sec->header.sh_addr;
        text_phdr.p_filesz = text_sec->data.size();
        text_phdr.p_memsz = text_sec->data.size();
        text_phdr.p_align = pageSize_;
        segments_.push_back(text_phdr);

        // Data segment
        Section* data_sec = findSection(".data");
        if (data_sec) {
            ProgramHeader64 data_phdr = {};
            data_phdr.p_type = PT_LOAD;
            data_phdr.p_flags = PF_R | PF_W;
            data_phdr.p_offset = data_sec->header.sh_offset;
            data_phdr.p_vaddr = data_sec->header.sh_addr;
            data_phdr.p_paddr = data_sec->header.sh_addr;
            data_phdr.p_filesz = data_sec->data.size();
            data_phdr.p_memsz = data_sec->data.size();
            data_phdr.p_align = pageSize_;
            segments_.push_back(data_phdr);
        }
    }

    void writeElfHeader(std::ofstream& file) {
        ElfHeader64 header = {};
        memcpy(header.e_ident, "\x7f""ELF", 4);
        header.e_ident[4] = 2; // 64-bit
        header.e_ident[5] = 1; // Little-endian
        header.e_ident[6] = 1; // Version
        header.e_type = ET_EXEC;
        header.e_machine = EM_X86_64;
        header.e_version = 1;
        header.e_entry = entryPoint_;
        header.e_phoff = sizeof(ElfHeader64);
        header.e_shoff = calculateSectionHeaderOffset();
        header.e_flags = 0;
        header.e_ehsize = sizeof(ElfHeader64);
        header.e_phentsize = sizeof(ProgramHeader64);
        header.e_phnum = segments_.size();
        header.e_shentsize = sizeof(SectionHeader64);
        header.e_shnum = sections_.size();
        header.e_shstrndx = findSectionIndex(".shstrtab");
        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }

    void writeProgramHeaders(std::ofstream& file) {
        file.seekp(sizeof(ElfHeader64));
        for (const auto& phdr : segments_) {
            file.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
        }
    }

    void writeSectionData(std::ofstream& file) {
        for (const auto& section : sections_) {
            if (section.header.sh_type != SHT_NOBITS && !section.data.empty()) {
                file.seekp(section.header.sh_offset);
                file.write(reinterpret_cast<const char*>(section.data.data()), section.data.size());
            }
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        file.seekp(calculateSectionHeaderOffset());
        for (const auto& section : sections_) {
            file.write(reinterpret_cast<const char*>(&section.header), sizeof(section.header));
        }
    }

    uint64_t calculateSectionHeaderOffset() {
        uint64_t max_offset = 0;
        for(const auto& sec : sections_) {
            if(sec.header.sh_type != SHT_NOBITS) {
                max_offset = std::max(max_offset, sec.header.sh_offset + sec.header.sh_size);
            }
        }
        return (max_offset + 15) & -16;
    }
};

// ElfGenerator public methods
ElfGenerator::ElfGenerator(bool is64Bit, uint64_t baseAddress)
    : pImpl(std::make_unique<Impl>(is64Bit, baseAddress)) {}

ElfGenerator::~ElfGenerator() = default;

bool ElfGenerator::generateElf(const std::vector<uint8_t> &textSection,
                               const std::string &outputFile,
                               const std::unordered_map<std::string, SymbolEntry> &symbols,
                               const std::vector<uint8_t> &dataSection,
                               uint64_t entryPoint)
{
    return pImpl->generate(outputFile, textSection, dataSection, symbols, entryPoint);
}

void ElfGenerator::addSection(const std::string& name, const std::vector<uint8_t>& data,
                              uint64_t vaddr, uint32_t type, uint64_t flags) {
    pImpl->addSection(name, data, vaddr, type, flags);
}

void ElfGenerator::addSymbol(const std::string& name, uint64_t value, uint64_t size,
                             uint8_t info, uint8_t other, uint16_t shndx) {
    pImpl->addSymbol(name, value, size, info, other, shndx);
}

void ElfGenerator::setEntryPoint(uint64_t address) { pImpl->setEntryPoint(address); }
std::string ElfGenerator::getLastError() const { return pImpl->getLastError(); }

// Unimplemented methods
void ElfGenerator::addSegment(uint32_t, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t) {}
void ElfGenerator::addRelocation(const std::string&, uint64_t, uint32_t, const std::string&, int64_t) {}
void ElfGenerator::setBaseAddress(uint64_t) {}
void ElfGenerator::setPageSize(uint64_t) {}
void ElfGenerator::setStackSize(uint64_t) {}
