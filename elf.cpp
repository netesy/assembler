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
constexpr uint16_t ET_REL = 1;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t SHT_NULL = 0;
constexpr uint16_t SHT_PROGBITS = 1;
constexpr uint16_t SHT_SYMTAB = 2;
constexpr uint16_t SHT_STRTAB = 3;
constexpr uint16_t SHT_RELA = 4;
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
constexpr uint8_t STT_SECTION = 3;
constexpr uint8_t STT_FILE = 4;
constexpr uint16_t SHN_UNDEF = 0;
constexpr uint16_t SHN_ABS = 0xFFF1;

// Relocation types for x86-64
constexpr uint32_t R_X86_64_64 = 1;
constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_PLT32 = 4;

}

#pragma pack(push, 1)
struct Elf64_Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

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

inline uint8_t ELF64_ST_BIND(uint8_t info) {
    return info >> 4;
}

inline uint64_t ELF64_R_INFO(uint32_t sym, uint32_t type) {
    return (static_cast<uint64_t>(sym) << 32) + type;
}

class ElfGenerator::Impl {
public:
    Impl(const Assembler& assembler, const std::string& inputFilename, bool is64Bit, uint64_t baseAddr)
        : assembler_(assembler), inputFilename_(inputFilename), is64Bit_(is64Bit), baseAddress_(baseAddr), entryPoint_(0), pageSize_(0x1000) {}

    bool generate(const std::string& outputFile,
                  const std::vector<uint8_t>& textSectionData,
                  const std::vector<uint8_t>& dataSectionData,
                  const std::unordered_map<std::string, SymbolEntry>& symbols,
                  const std::vector<RelocationEntry>& relocations,
                  uint64_t entryPoint,
                  uint64_t dataBase,
                  const std::vector<uint8_t>& bssSectionData,
                  const std::vector<uint8_t>& rodataSectionData,
                  uint64_t bssBase,
                  uint64_t rodataBase,
                  bool generateRelocatable)
    {
        if (!is64Bit_) {
            lastError_ = "32-bit ELF generation is not supported.";
            return false;
        }

        entryPoint_ = generateRelocatable ? 0 : entryPoint;
        uint64_t textBase = generateRelocatable ? 0 : baseAddress_;
        uint64_t currentDataBase = generateRelocatable ? 0 : dataBase;
        uint64_t currentBssBase = generateRelocatable ? 0 : bssBase;
        uint64_t currentRodataBase = generateRelocatable ? 0 : rodataBase;

        try {
            sections_.clear();
            shstringTable_ = "\0";
            stringTable_ = "\0";
            symbols_.clear();

            addSection("", {}, 0, SHT_NULL, 0, 0);
            if (!dataSectionData.empty()) {
                addSection(".data", dataSectionData, currentDataBase, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4);
            }
            addSection(".text", textSectionData, textBase, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16);
            if (!bssSectionData.empty()) {
                // For .bss, the vector is empty but the size is stored in the header
                Section bss_section;
                bss_section.name = ".bss";
                bss_section.header.sh_type = SHT_NOBITS;
                bss_section.header.sh_flags = SHF_ALLOC | SHF_WRITE;
                bss_section.header.sh_addr = currentBssBase;
                bss_section.header.sh_size = bssSectionData.size();
                bss_section.header.sh_addralign = 16;
                bss_section.header.sh_name = addToStringTable(shstringTable_, ".bss");
                sections_.push_back(bss_section);
            }
            if (!rodataSectionData.empty()) {
                addSection(".rodata", rodataSectionData, currentRodataBase, SHT_PROGBITS, SHF_ALLOC, 4);
            }
            addSection(".note.GNU-stack", {}, 0, SHT_PROGBITS, 0, 1);
            addSection(".shstrtab", {}, 0, SHT_STRTAB, 0, 1);
            addSection(".symtab", {}, 0, SHT_SYMTAB, 0, 8);
            addSection(".strtab", {}, 0, SHT_STRTAB, 0, 1);
            if (generateRelocatable && !relocations.empty()) {
                addSection(".rela.text", {}, 0, SHT_RELA, 0, 8);
            }

            createSymbolTable(symbols, relocations, generateRelocatable);
            if (generateRelocatable && !relocations.empty()) {
                prepareRelocationSection(relocations);
            }
            prepareTableSections();
            layoutSections(generateRelocatable);

            if (!generateRelocatable) {
                createSegments();
            }

            std::ofstream file(outputFile, std::ios::binary | std::ios::trunc);
            if (!file) {
                lastError_ = "Cannot open output file: " + outputFile;
                return false;
            }

            writeElfHeader(file, generateRelocatable);
            writeSectionHeaders(file);
            writeSectionData(file);
            if (!generateRelocatable) {
                writeProgramHeaders(file);
            }

            file.close();
            return true;

        } catch (const std::exception& e) {
            lastError_ = "Error generating ELF: " + std::string(e.what());
            return false;
        }
    }

    void addSection(const std::string& name, const std::vector<uint8_t>& data,
                    uint64_t vaddr, uint32_t type, uint64_t flags, uint64_t align = 1)
    {
        Section s;
        memset(&s.header, 0, sizeof(s.header));
        s.name = name;
        s.data = data;
        s.header.sh_addr = vaddr;
        s.header.sh_type = type;
        s.header.sh_flags = flags;
        s.header.sh_addralign = align;
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

    const Assembler& assembler_;
    const std::string& inputFilename_;
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
    std::map<std::string, uint32_t> symbolIndexMap_;
    uint64_t sectionHeadersOffset_ = 0;

    uint64_t get_section_base(::Section section) const {
        // This is a simplified lookup. A more robust implementation
        // would handle custom sections properly.
        switch(section) {
            case ::Section::TEXT: return baseAddress_;
            case ::Section::DATA: return baseAddress_ + 0x200000; // Placeholder
            case ::Section::BSS: return baseAddress_ + 0x201000; // Placeholder
            case ::Section::RODATA: return baseAddress_ + 0x202000; // Placeholder
            default: return 0;
        }
    }

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

    void prepareRelocationSection(const std::vector<RelocationEntry>& relocs) {
        Section* rela_text = findSection(".rela.text");
        if (!rela_text) return;

        rela_text->header.sh_link = findSectionIndex(".symtab");
        rela_text->header.sh_info = findSectionIndex(".text");
        rela_text->header.sh_addralign = 8;
        rela_text->header.sh_entsize = sizeof(Elf64_Rela);

        for (const auto& reloc : relocs) {
            Elf64_Rela r = {};
            r.r_offset = reloc.offset;
            r.r_addend = reloc.addend;

            uint32_t sym_idx = symbolIndexMap_[reloc.symbolName];
            std::cout << "Relocating " << reloc.symbolName << " with index " << sym_idx << std::endl;
            uint32_t type = 0;
            switch(reloc.type) {
                case RelocationType::R_X86_64_PC32: type = R_X86_64_PC32; break;
                case RelocationType::R_X86_64_PLT32: type = R_X86_64_PLT32; break;
                case RelocationType::R_X86_64_64: type = R_X86_64_64; break;
            }
            r.r_info = ELF64_R_INFO(sym_idx, type);

            std::vector<uint8_t> rela_bytes(sizeof(r));
            memcpy(rela_bytes.data(), &r, sizeof(r));
            rela_text->data.insert(rela_text->data.end(), rela_bytes.begin(), rela_bytes.end());
        }
    }

    void layoutSections(bool generateRelocatable) {
        uint64_t data_offset = sizeof(ElfHeader64) + sections_.size() * sizeof(SectionHeader64);

        if (generateRelocatable) {
            // Simple sequential layout for object files
            for (auto& section : sections_) {
                if (section.header.sh_type == SHT_NULL || section.header.sh_type == SHT_NOBITS) {
                    section.header.sh_offset = 0;
                    continue;
                };

                uint64_t align = section.header.sh_addralign;
                if (align > 1) {
                    data_offset = (data_offset + align - 1) & ~(align - 1);
                }
                section.header.sh_offset = data_offset;
                data_offset += section.data.size();
            }
        } else {
            // Layout for executables
            size_t loadable_sections = 0;
            for (const auto& section : sections_) {
                if (section.header.sh_flags & SHF_ALLOC) {
                    loadable_sections++;
                }
            }
            data_offset += loadable_sections * sizeof(ProgramHeader64);

            for (auto& section : sections_) {
                if (section.header.sh_flags & SHF_ALLOC) {
                    data_offset = (data_offset + pageSize_ - 1) & -pageSize_;
                    section.header.sh_offset = data_offset;
                    if (section.header.sh_type != SHT_NOBITS) {
                        data_offset += section.data.size();
                    }
                }
            }
            // Non-allocatable sections are packed at the end
            for (auto& section : sections_) {
                if (!(section.header.sh_flags & SHF_ALLOC) && section.header.sh_type != SHT_NULL) {
                    section.header.sh_offset = data_offset;
                    data_offset += section.data.size();
                }
            }
            sectionHeadersOffset_ = data_offset;
        }
    }

    void createSymbolTable(const std::unordered_map<std::string, SymbolEntry>& symbols, const std::vector<RelocationEntry>& relocations, bool generateRelocatable) {
        symbols_.clear();
        stringTable_ = "\0";
        symbolIndexMap_.clear();

        std::vector<Symbol64> local_symbols;
        std::vector<Symbol64> global_symbols;

        // FILE symbol
        Symbol64 file_sym;
        file_sym.st_name = addToStringTable(stringTable_, inputFilename_);
        file_sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_FILE);
        file_sym.st_other = 0;
        file_sym.st_shndx = SHN_ABS;
        file_sym.st_value = 0;
        file_sym.st_size = 0;
        local_symbols.push_back(file_sym);

        // SECTION symbols
        for (size_t i = 1; i < sections_.size(); ++i) {
            const auto& s = sections_[i];
            if (s.header.sh_type != SHT_NULL) {
                Symbol64 sec_sym;
                sec_sym.st_name = 0; // Section symbols have no name in the string table
                sec_sym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
                sec_sym.st_other = 0;
                sec_sym.st_shndx = i;
                sec_sym.st_value = 0;
                sec_sym.st_size = 0;
                local_symbols.push_back(sec_sym);
            }
        }

        // User-defined symbols
        auto symbols_copy = symbols;
        for (const auto& reloc : relocations) {
            if (symbols_copy.find(reloc.symbolName) == symbols_copy.end()) {
                symbols_copy[reloc.symbolName] = {reloc.symbolName, 0, 0, SymbolBinding::GLOBAL, SymbolType::NOTYPE, SymbolVisibility::DEFAULT, ::Section::NONE, false};
            }
        }
        for (const auto& pair : symbols_copy) {
            const auto& sym = pair.second;
            Symbol64 new_sym;
            new_sym.st_name = addToStringTable(stringTable_, sym.name);
            new_sym.st_size = sym.size;
            new_sym.st_other = 0;

            if (!sym.isDefined) {
                new_sym.st_shndx = SHN_UNDEF;
                new_sym.st_value = 0;
            } else {
                new_sym.st_shndx = findSectionIndex(assembler_.getSectionName(sym.section));
                new_sym.st_value = generateRelocatable ? sym.address - assembler_.getSectionBase(sym.section) : sym.address;
            }

            uint8_t type = STT_NOTYPE;
            if (sym.type == SymbolType::FUNCTION) type = STT_FUNC;
            else if (sym.type == SymbolType::OBJECT) type = STT_OBJECT;

            uint8_t bind = STB_LOCAL;
            if (sym.binding == SymbolBinding::GLOBAL) bind = STB_GLOBAL;
            else if (sym.binding == SymbolBinding::WEAK) bind = STB_GLOBAL; // Simplified

            new_sym.st_info = ELF64_ST_INFO(bind, type);

            if (bind == STB_LOCAL) {
                local_symbols.push_back(new_sym);
            } else {
                global_symbols.push_back(new_sym);
            }
        }

        // Add all symbols to the final list in the correct order
        addSymbol("", 0, 0, 0, 0, 0); // NULL symbol first
        for(const auto& s : local_symbols) symbols_.push_back(s);
        for(const auto& s : global_symbols) symbols_.push_back(s);

        // Create the index map for relocations
        for(size_t i = 0; i < symbols_.size(); ++i) {
            symbolIndexMap_[stringTable_.c_str() + symbols_[i].st_name] = i;
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

        // sh_info should be the index of the first non-local symbol
        uint32_t first_global_idx = 0;
        for(size_t i = 0; i < symbols_.size(); ++i) {
            if (ELF64_ST_BIND(symbols_[i].st_info) != STB_LOCAL) {
                first_global_idx = i;
                break;
            }
        }
        symtab->header.sh_info = first_global_idx;
        symtab->header.sh_entsize = sizeof(Symbol64);
    }

    void createSegments() {
        segments_.clear();

        // Text segment (executable)
        Section* text_sec = findSection(".text");
        if (text_sec) {
            ProgramHeader64 text_phdr = {};
            text_phdr.p_type = PT_LOAD;
            text_phdr.p_flags = PF_R | PF_X;
            text_phdr.p_offset = text_sec->header.sh_offset;
            text_phdr.p_vaddr = text_sec->header.sh_addr;
            text_phdr.p_paddr = text_sec->header.sh_addr;
            text_phdr.p_filesz = text_sec->data.size();
            text_phdr.p_memsz = text_sec->data.size();
            text_phdr.p_align = pageSize_;
            segments_.push_back(text_phdr);
        }

        // Read-only data segment
        Section* rodata_sec = findSection(".rodata");
        if (rodata_sec && !rodata_sec->data.empty()) {
            ProgramHeader64 rodata_phdr = {};
            rodata_phdr.p_type = PT_LOAD;
            rodata_phdr.p_flags = PF_R;
            rodata_phdr.p_offset = rodata_sec->header.sh_offset;
            rodata_phdr.p_vaddr = rodata_sec->header.sh_addr;
            rodata_phdr.p_paddr = rodata_sec->header.sh_addr;
            rodata_phdr.p_filesz = rodata_sec->data.size();
            rodata_phdr.p_memsz = rodata_sec->data.size();
            rodata_phdr.p_align = pageSize_;
            segments_.push_back(rodata_phdr);
        }

        // Data + BSS segment (writable)
        Section* data_sec = findSection(".data");
        Section* bss_sec = findSection(".bss");

        if (data_sec || bss_sec) {
            ProgramHeader64 data_phdr = {};
            data_phdr.p_type = PT_LOAD;
            data_phdr.p_flags = PF_R | PF_W;

            if (data_sec && !data_sec->data.empty()) {
                data_phdr.p_offset = data_sec->header.sh_offset;
                data_phdr.p_vaddr = data_sec->header.sh_addr;
                data_phdr.p_paddr = data_sec->header.sh_addr;
                data_phdr.p_filesz = data_sec->data.size();
                data_phdr.p_memsz = data_sec->data.size();
            }

            // Extend for BSS if present
            if (bss_sec && !bss_sec->data.empty()) {
                if (!data_sec || data_sec->data.empty()) {
                    data_phdr.p_offset = bss_sec->header.sh_offset;
                    data_phdr.p_vaddr = bss_sec->header.sh_addr;
                    data_phdr.p_paddr = bss_sec->header.sh_addr;
                    data_phdr.p_filesz = 0; // BSS has no file content
                    data_phdr.p_memsz = bss_sec->data.size();
                } else {
                    // Extend existing data segment
                    data_phdr.p_memsz += bss_sec->data.size();
                }
            }

            data_phdr.p_align = pageSize_;
            segments_.push_back(data_phdr);
        }
    }

    void writeElfHeader(std::ofstream& file, bool generateRelocatable) {
        ElfHeader64 header = {};
        memcpy(header.e_ident, "\x7f""ELF", 4);
        header.e_ident[4] = 2;  // 64-bit
        header.e_ident[5] = 1;  // Little endian
        header.e_ident[6] = 1;  // ELF version
        header.e_type = generateRelocatable ? ET_REL : ET_EXEC;
        header.e_machine = EM_X86_64;
        header.e_version = 1;
        header.e_entry = entryPoint_; // Already set to 0 for relocatable
        header.e_phoff = generateRelocatable ? 0 : sizeof(ElfHeader64);
        header.e_shoff = generateRelocatable ? sizeof(ElfHeader64) : sectionHeadersOffset_;
        header.e_flags = 0;
        header.e_ehsize = sizeof(ElfHeader64);
        header.e_phentsize = generateRelocatable ? 0 : sizeof(ProgramHeader64);
        header.e_phnum = generateRelocatable ? 0 : segments_.size();
        header.e_shentsize = sizeof(SectionHeader64);
        header.e_shnum = sections_.size();
        header.e_shstrndx = findSectionIndex(".shstrtab");
        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }

    void writeProgramHeaders(std::ofstream& file) {
        file.seekp(sizeof(ElfHeader64));
        if (!segments_.empty()) {
            file.write(reinterpret_cast<const char*>(segments_.data()),
                       segments_.size() * sizeof(ProgramHeader64));
        }
    }

    void writeSectionData(std::ofstream& file) {
        for (const auto& section : sections_) {
            if (section.header.sh_type != SHT_NOBITS && !section.data.empty()) {
                file.seekp(section.header.sh_offset);
                file.write(reinterpret_cast<const char*>(section.data.data()),
                           section.data.size());
            }
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        file.seekp(sizeof(ElfHeader64));
        for (const auto& section : sections_) {
            auto header = section.header;
            header.sh_size = section.data.size();
            file.write(reinterpret_cast<const char*>(&header), sizeof(header));
        }
    }
};

ElfGenerator::ElfGenerator(const Assembler& assembler, const std::string& inputFilename, bool is64Bit, uint64_t baseAddress)
    : pImpl(std::make_unique<Impl>(assembler, inputFilename, is64Bit, baseAddress)) {}

ElfGenerator::~ElfGenerator() = default;

bool ElfGenerator::generateElf(const std::vector<uint8_t> &textSection,
                               const std::string &outputFile,
                               const std::unordered_map<std::string, SymbolEntry> &symbols,
                               const std::vector<RelocationEntry> &relocations,
                               const std::vector<uint8_t> &dataSection,
                               uint64_t entryPoint,
                               uint64_t dataBase,
                               bool generateRelocatable)
{
    return pImpl->generate(outputFile, textSection, dataSection, symbols, relocations, entryPoint, dataBase, {}, {}, 0, 0, generateRelocatable);
}

// New method for enhanced section support
bool ElfGenerator::generateElfWithAllSections(const std::vector<uint8_t> &textSection,
                                              const std::string &outputFile,
                                              const std::unordered_map<std::string, SymbolEntry> &symbols,
                                              const std::vector<RelocationEntry> &relocations,
                                              const std::vector<uint8_t> &dataSection,
                                              const std::vector<uint8_t> &bssSection,
                                              const std::vector<uint8_t> &rodataSection,
                                              uint64_t entryPoint,
                                              uint64_t dataBase,
                                              uint64_t bssBase,
                                              uint64_t rodataBase,
                                              bool generateRelocatable)
{
    return pImpl->generate(outputFile, textSection, dataSection, symbols, relocations, entryPoint,
                           dataBase, bssSection, rodataSection, bssBase, rodataBase, generateRelocatable);
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
void ElfGenerator::addSegment(uint32_t, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t) {}
void ElfGenerator::addRelocation(const std::string&, uint64_t, uint32_t, const std::string&, int64_t) {}
void ElfGenerator::setBaseAddress(uint64_t) {}
void ElfGenerator::setPageSize(uint64_t) {}
void ElfGenerator::setStackSize(uint64_t) {}
