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
constexpr uint16_t ET_DYN = 3;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t EM_386 = 3;
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_DYNAMIC = 6;
constexpr uint32_t SHT_NOTE = 7;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHT_INIT_ARRAY = 14;
constexpr uint32_t SHT_FINI_ARRAY = 15;
constexpr uint32_t SHT_EH_FRAME = 15;

constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint32_t PT_INTERP = 3;
constexpr uint32_t PT_NOTE = 4;
constexpr uint32_t PT_PHDR = 6;
constexpr uint64_t PAGE_SIZE = 0x1000;
constexpr uint64_t STACK_SIZE = 0x800000;

// Symbol binding info
constexpr uint8_t STB_LOCAL = 0;
constexpr uint8_t STB_GLOBAL = 1;

// Symbol types
constexpr uint8_t STT_NOTYPE = 0;
constexpr uint8_t STT_OBJECT = 1;
constexpr uint8_t STT_FUNC = 2;

// Program header permission flags
constexpr uint32_t PF_X = 0x1;  // Executable
constexpr uint32_t PF_W = 0x2;  // Writable
constexpr uint32_t PF_R = 0x4;  // Readable

// Dynamic entry types
constexpr uint64_t DT_NULL = 0;
constexpr uint64_t DT_NEEDED = 1;
constexpr uint64_t DT_HASH = 4;
constexpr uint64_t DT_STRTAB = 5;
constexpr uint64_t DT_SYMTAB = 6;
constexpr uint64_t DT_RELA = 7;
constexpr uint64_t DT_RELASZ = 8;
constexpr uint64_t DT_RELAENT = 9;
constexpr uint64_t DT_INIT = 12;
constexpr uint64_t DT_FINI = 13;

// X86-64 relocation types
constexpr uint32_t R_X86_64_NONE = 0;
constexpr uint32_t R_X86_64_64 = 1;
constexpr uint32_t R_X86_64_PC32 = 2;
constexpr uint32_t R_X86_64_GOT32 = 3;
constexpr uint32_t R_X86_64_PLT32 = 4;
constexpr uint32_t R_X86_64_JUMP_SLOT = 7;
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

// Helper function to combine symbol index and relocation type into r_info field
inline uint64_t ELF64_R_INFO(uint32_t sym, uint32_t type) {
    return (static_cast<uint64_t>(sym) << 32) + type;
}

// Helper function to create symbol info byte
inline uint8_t ELF64_ST_INFO(uint8_t bind, uint8_t type) {
    return (bind << 4) + (type & 0xF);
}

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
            // Setup and layout sections
            setupDefaultSections(code);
            layoutSections();
            createSegments();
            
            // Prepare string tables and symbol table data
            prepareStringTables();
            
            // Validate the layout before writing
            if (!lastError_.empty()) {
                return false;
            }

            std::ofstream file(outputFile, std::ios::binary | std::ios::trunc);
            if (!file) {
                lastError_ = "Cannot create output file: " + outputFile;
                return false;
            }

            // Write file in correct order
            writeElfHeader(file);
            if (!lastError_.empty()) return false;
            
            writeProgramHeaders(file);
            if (!lastError_.empty()) return false;
            
            writeSectionData(file);
            if (!lastError_.empty()) return false;
            
            writeSectionHeaders(file);
            if (!lastError_.empty()) return false;

            file.close();
            
            // Validate file structure
            if (!validateFileStructure(outputFile)) {
                return false;
            }

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
// Helper methods to create section data
std::vector<uint8_t> getInitCode() {
    if (is64Bit_) {
        // Simple x86-64 init code
        return {
            0x48, 0x83, 0xec, 0x08,  // sub rsp, 8
            0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, [rip+0]
            0x48, 0x85, 0xc0,        // test rax, rax
            0x74, 0x05,              // je +5
            0xff, 0xd0,              // call rax
            0x48, 0x83, 0xc4, 0x08,  // add rsp, 8
            0xc3                      // ret
        };
    } else {
        // Simple x86 init code
        return {
            0x53,                    // push ebx
            0x83, 0xec, 0x08,        // sub esp, 8
            0xe8, 0x00, 0x00, 0x00, 0x00,  // call next instruction
            0x5b,                    // pop ebx
            0x81, 0xc3, 0x00, 0x00, 0x00, 0x00,  // add ebx, offset
            0x8b, 0x83, 0x00, 0x00, 0x00, 0x00,  // mov eax, [ebx+offset]
            0x85, 0xc0,              // test eax, eax
            0x74, 0x02,              // je +2
            0xff, 0xd0,              // call eax
            0x83, 0xc4, 0x08,        // add esp, 8
            0x5b,                    // pop ebx
            0xc3                      // ret
        };
    }
}

std::vector<uint8_t> getFiniCode() {
    if (is64Bit_) {
        // Simple x86-64 fini code
        return {
            0x48, 0x83, 0xec, 0x08,  // sub rsp, 8
            0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, [rip+0]
            0x48, 0x85, 0xc0,        // test rax, rax
            0x74, 0x05,              // je +5
            0xff, 0xd0,              // call rax
            0x48, 0x83, 0xc4, 0x08,  // add rsp, 8
            0xc3                      // ret
        };
    } else {
        // Simple x86 fini code
        return {
            0x53,                    // push ebx
            0x83, 0xec, 0x08,        // sub esp, 8
            0xe8, 0x00, 0x00, 0x00, 0x00,  // call next instruction
            0x5b,                    // pop ebx
            0x81, 0xc3, 0x00, 0x00, 0x00, 0x00,  // add ebx, offset
            0x8b, 0x83, 0x00, 0x00, 0x00, 0x00,  // mov eax, [ebx+offset]
            0x85, 0xc0,              // test eax, eax
            0x74, 0x02,              // je +2
            0xff, 0xd0,              // call eax
            0x83, 0xc4, 0x08,        // add esp, 8
            0x5b,                    // pop ebx
            0xc3                      // ret
        };
    }
}

std::vector<uint8_t> getPltCode() {
    if (is64Bit_) {
        // Minimal PLT for x86-64
        return {
            // PLT0 entry (resolver stub)
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00,  // push [rip+0] (GOT+8)
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0] (GOT+16)
            0x0f, 0x1f, 0x40, 0x00,              // nop

            // Example PLT entry
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0] (GOT entry)
            0x68, 0x00, 0x00, 0x00, 0x00,        // push index
            0xe9, 0x00, 0x00, 0x00, 0x00         // jmp PLT0
        };
    } else {
        // Minimal PLT for x86
        return {
            // PLT0 entry (resolver stub)
            0xff, 0xb3, 0x04, 0x00, 0x00, 0x00,  // push dword [ebx+4]
            0xff, 0xa3, 0x08, 0x00, 0x00, 0x00,  // jmp dword [ebx+8]
            0x90, 0x90, 0x90, 0x90,              // nop

            // Example PLT entry
            0xff, 0xa3, 0x00, 0x00, 0x00, 0x00,  // jmp dword [ebx+offset]
            0x68, 0x00, 0x00, 0x00, 0x00,        // push index
            0xe9, 0x00, 0x00, 0x00, 0x00         // jmp PLT0
        };
    }
}

std::vector<uint8_t> getEhFrameData() {
    // Minimal .eh_frame for basic exception handling
    if (is64Bit_) {
        return {
            // CIE (Common Information Entry)
            0x14, 0x00, 0x00, 0x00,              // Length
            0x00, 0x00, 0x00, 0x00,              // CIE ID
            0x01,                                // Version
            'z', 'R', '\0',                      // Augmentation string
            0x01,                                // Code alignment factor
            0x78,                                // Data alignment factor
            0x10,                                // Return address register
            0x01,                                // Augmentation length
            0x1b,                                // FDE encoding
            0x0c, 0x07, 0x08, 0x90,              // DW_CFA instructions
            0x01, 0x00, 0x00, 0x00,              // Padding

            // FDE (Frame Description Entry)
            0x14, 0x00, 0x00, 0x00,              // Length
            0x18, 0x00, 0x00, 0x00,              // CIE pointer
            0x00, 0x00, 0x00, 0x00,              // Initial location
            0x00, 0x00, 0x00, 0x00,              // Address range
            0x00,                                // Augmentation length
            // CFI instructions would go here
            0x00, 0x00, 0x00                     // Padding
        };
    } else {
        return {
            // CIE (Common Information Entry)
            0x10, 0x00, 0x00, 0x00,              // Length
            0x00, 0x00, 0x00, 0x00,              // CIE ID
            0x01,                                // Version
            'z', 'R', '\0',                      // Augmentation string
            0x01,                                // Code alignment factor
            0x7c,                                // Data alignment factor
            0x08,                                // Return address register
            0x01,                                // Augmentation length
            0x1b,                                // FDE encoding
            0x0c, 0x04, 0x04, 0x88,              // DW_CFA instructions

            // FDE (Frame Description Entry)
            0x10, 0x00, 0x00, 0x00,              // Length
            0x14, 0x00, 0x00, 0x00,              // CIE pointer
            0x00, 0x00, 0x00, 0x00,              // Initial location
            0x00, 0x00, 0x00, 0x00,              // Address range
            0x00,                                // Augmentation length
            // CFI instructions would go here
            0x00, 0x00, 0x00                     // Padding
        };
    }
}

std::vector<uint8_t> getDynamicData() {
    struct DynamicEntry {
        uint64_t d_tag;
        uint64_t d_val;
    };

    std::vector<DynamicEntry> entries = {
        {5, 0},    // DT_STRTAB
        {6, 0},    // DT_SYMTAB
        {10, 0},   // DT_STRSZ
        {11, 0},   // DT_SYMENT
        {0, 0}     // DT_NULL (terminator)
    };

    std::vector<uint8_t> result;
    result.resize(entries.size() * sizeof(DynamicEntry));
    memcpy(result.data(), entries.data(), result.size());

    return result;
}

std::vector<uint8_t> getGotData() {
    // Global Offset Table - typically contains addresses of global variables
    std::vector<uint8_t> result(24, 0); // 3 entries of 8 bytes each (64-bit) or 3 entries of 4 bytes each (32-bit)
    return result;
}

std::vector<uint8_t> getGotPltData() {
    // Procedure Linkage Table GOT - contains addresses of imported functions
    if (is64Bit_) {
        std::vector<uint8_t> result(24, 0); // 3 entries of 8 bytes each
        // First entry is typically a pointer to the dynamic section
        // Second entry is used by the dynamic linker
        // Third entry is the address of the dynamic linker's _dl_runtime_resolve
        return result;
    } else {
        std::vector<uint8_t> result(12, 0); // 3 entries of 4 bytes each
        return result;
    }
}

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
        uint32_t symtabNameOffset = addSectionString(".symtab");
        uint32_t initNameOffset = addSectionString(".init");
        uint32_t finiNameOffset = addSectionString(".fini");
        uint32_t pltNameOffset = addSectionString(".plt");
        uint32_t gotNameOffset = addSectionString(".got");
        uint32_t gotPltNameOffset = addSectionString(".got.plt");
        uint32_t dynamicNameOffset = addSectionString(".dynamic");
        uint32_t ehFrameNameOffset = addSectionString(".eh_frame");
        uint32_t interpNameOffset = addSectionString(".interp");

    // Create .init section
    std::vector<uint8_t> initCode = getInitCode();
    Section initSection;
    initSection.name = ".init";
    initSection.data = initCode;
    initSection.vaddr = 0;  // Will be set in layoutSections
    initSection.type = SHT_PROGBITS;
    initSection.flags = SHF_ALLOC | SHF_EXECINSTR;
    initSection.align = 16;
    initSection.name_offset = initNameOffset;
    initSection.index = sections_.size();
    sections_.push_back(std::move(initSection));

        // Create .text section with code
        Section textSection;
        textSection.name = ".text";
        textSection.data = code;
        textSection.vaddr = 0;  // Will be set in layoutSections
        textSection.type = SHT_PROGBITS;
        textSection.flags = SHF_ALLOC | SHF_EXECINSTR;
        textSection.align = 16;  // Common alignment for code
        textSection.name_offset = textNameOffset;
        textSection.index = sections_.size();
        sections_.push_back(std::move(textSection));

            // Create .fini section
    std::vector<uint8_t> finiCode = getFiniCode();
    Section finiSection;
    finiSection.name = ".fini";
    finiSection.data = finiCode;
    finiSection.vaddr = 0;  // Will be set in layoutSections
    finiSection.type = SHT_PROGBITS;
    finiSection.flags = SHF_ALLOC | SHF_EXECINSTR;
    finiSection.align = 16;
    finiSection.name_offset = finiNameOffset;
    finiSection.index = sections_.size();
    sections_.push_back(std::move(finiSection));

    // Create .plt section
    std::vector<uint8_t> pltCode = getPltCode();
    Section pltSection;
    pltSection.name = ".plt";
    pltSection.data = pltCode;
    pltSection.vaddr = 0;  // Will be set in layoutSections
    pltSection.type = SHT_PROGBITS;
    pltSection.flags = SHF_ALLOC | SHF_EXECINSTR;
    pltSection.align = 16;
    pltSection.name_offset = pltNameOffset;
    pltSection.index = sections_.size();
    sections_.push_back(std::move(pltSection));

    // Create .eh_frame section
    std::vector<uint8_t> ehFrameData = getEhFrameData();
    Section ehFrameSection;
    ehFrameSection.name = ".eh_frame";
    ehFrameSection.data = ehFrameData;
    ehFrameSection.vaddr = 0;  // Will be set in layoutSections
    ehFrameSection.type = SHT_PROGBITS;
    ehFrameSection.flags = SHF_ALLOC;
    ehFrameSection.align = 8;
    ehFrameSection.name_offset = ehFrameNameOffset;
    ehFrameSection.index = sections_.size();
    sections_.push_back(std::move(ehFrameSection));

    // Data sections start here - new memory segment with different permissions

    // Create .dynamic section
    std::vector<uint8_t> dynamicData = getDynamicData();
    Section dynamicSection;
    dynamicSection.name = ".dynamic";
    dynamicSection.data = dynamicData;
    dynamicSection.vaddr = 0;  // Will be set in layoutSections
    dynamicSection.type = SHT_PROGBITS;
    dynamicSection.flags = SHF_ALLOC | SHF_WRITE;
    dynamicSection.align = 8;
    dynamicSection.name_offset = dynamicNameOffset;
    dynamicSection.index = sections_.size();
    sections_.push_back(std::move(dynamicSection));

    // Create .got section
    std::vector<uint8_t> gotData = getGotData();
    Section gotSection;
    gotSection.name = ".got";
    gotSection.data = gotData;
    gotSection.vaddr = 0;  // Will be set in layoutSections
    gotSection.type = SHT_PROGBITS;
    gotSection.flags = SHF_ALLOC | SHF_WRITE;
    gotSection.align = 8;
    gotSection.name_offset = gotNameOffset;
    gotSection.index = sections_.size();
    sections_.push_back(std::move(gotSection));

    // Create .got.plt section
    std::vector<uint8_t> gotPltData = getGotPltData();
    Section gotPltSection;
    gotPltSection.name = ".got.plt";
    gotPltSection.data = gotPltData;
    gotPltSection.vaddr = 0;  // Will be set in layoutSections
    gotPltSection.type = SHT_PROGBITS;
    gotPltSection.flags = SHF_ALLOC | SHF_WRITE;
    gotPltSection.align = 8;
    gotPltSection.name_offset = gotPltNameOffset;
    gotPltSection.index = sections_.size();
    sections_.push_back(std::move(gotPltSection));


        // Create .data section
        Section dataSection;
        dataSection.name = ".data";
        dataSection.data = {};
        dataSection.vaddr = 0;  // Will be set in layoutSections
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
        bssSection.vaddr = 0;  // Will be set in layoutSections
        bssSection.type = SHT_NOBITS;
        bssSection.flags = SHF_ALLOC | SHF_WRITE;
        bssSection.align = 8;
        bssSection.name_offset = bssNameOffset;
        bssSection.index = sections_.size();
        sections_.push_back(std::move(bssSection));

            // Create .symtab section
    Section symtabSection;
    symtabSection.name = ".symtab";
    symtabSection.vaddr = 0;  // Not loaded into memory
    symtabSection.type = SHT_SYMTAB;
    symtabSection.flags = 0;
    symtabSection.align = 8;
    symtabSection.name_offset = symtabNameOffset;
    symtabSection.index = sections_.size();
    sections_.push_back(std::move(symtabSection));

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
        // Calculate header size based on actual number of segments
        uint32_t numSegments = 2;  // At least text and data LOAD segments
        if (findSectionIndex(".interp") > 0) numSegments++;
        if (findSectionIndex(".dynamic") > 0) numSegments++;
        numSegments++;  // PHDR segment
        
        uint64_t headerSize = sizeof(ElfHeader) + (numSegments * sizeof(ProgramHeader));
        uint64_t fileOffset = align(headerSize, pageSize_);
        uint64_t virtualAddr = baseAddress_;
        
        // Layout sections in order: executable first, then data, then non-loadable
        
        // Phase 1: Layout executable sections (.init, .text, .fini, .plt, .eh_frame)
        for (auto& section : sections_) {
            if (section.name.empty()) continue;  // Skip null section
            
            if (section.flags & SHF_EXECINSTR) {
                // Align virtual address
                virtualAddr = align(virtualAddr, section.align);
                section.vaddr = virtualAddr;
                
                // Align file offset
                fileOffset = align(fileOffset, section.align);
                section.offset = fileOffset;
                
                // Advance both addresses
                virtualAddr += section.data.size();
                fileOffset += section.data.size();
            }
        }
        
        // Align to page boundary for data sections
        virtualAddr = align(virtualAddr, pageSize_);
        fileOffset = align(fileOffset, pageSize_);
        
        // Phase 2: Layout writable sections (.dynamic, .got, .got.plt, .data)
        for (auto& section : sections_) {
            if (section.name.empty()) continue;  // Skip null section
            
            if ((section.flags & SHF_WRITE) && !(section.flags & SHF_EXECINSTR) && 
                section.type != SHT_NOBITS) {
                // Align virtual address
                virtualAddr = align(virtualAddr, section.align);
                section.vaddr = virtualAddr;
                
                // Align file offset
                fileOffset = align(fileOffset, section.align);
                section.offset = fileOffset;
                
                // Advance both addresses
                virtualAddr += section.data.size();
                fileOffset += section.data.size();
            }
        }
        
        // Phase 3: Layout BSS sections (no file content)
        for (auto& section : sections_) {
            if (section.type == SHT_NOBITS) {
                // Align virtual address
                virtualAddr = align(virtualAddr, section.align);
                section.vaddr = virtualAddr;
                section.offset = 0;  // BSS has no file content
                
                // Advance virtual address by default BSS size
                virtualAddr += 4096;  // Default BSS size
            }
        }
        
        // Phase 4: Layout non-loadable sections (.symtab, .strtab, .shstrtab)
        for (auto& section : sections_) {
            if (section.name.empty()) continue;  // Skip null section
            
            if (!(section.flags & (SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE))) {
                section.vaddr = 0;  // Non-loadable sections have no virtual address
                
                // Align file offset
                fileOffset = align(fileOffset, section.align);
                section.offset = fileOffset;
                
                // Advance file offset
                if (!section.data.empty()) {
                    fileOffset += section.data.size();
                }
            }
        }
        
        // Validate section layout
        validateSectionLayout();
    }
    
    void validateSectionLayout() {
        // Check for overlapping sections
        for (size_t i = 1; i < sections_.size(); ++i) {
            for (size_t j = i + 1; j < sections_.size(); ++j) {
                const auto& sec1 = sections_[i];
                const auto& sec2 = sections_[j];
                
                // Check virtual address overlap for loadable sections
                if ((sec1.flags & SHF_ALLOC) && (sec2.flags & SHF_ALLOC) && 
                    sec1.vaddr > 0 && sec2.vaddr > 0) {
                    uint64_t sec1_end = sec1.vaddr + (sec1.type == SHT_NOBITS ? 4096 : sec1.data.size());
                    uint64_t sec2_end = sec2.vaddr + (sec2.type == SHT_NOBITS ? 4096 : sec2.data.size());
                    
                    if ((sec1.vaddr < sec2_end) && (sec2.vaddr < sec1_end)) {
                        lastError_ = "Virtual address overlap between sections " + sec1.name + " and " + sec2.name;
                        return;
                    }
                }
                
                // Check file offset overlap for sections with file content
                if (sec1.offset > 0 && sec2.offset > 0 && sec1.type != SHT_NOBITS && sec2.type != SHT_NOBITS) {
                    uint64_t sec1_file_end = sec1.offset + sec1.data.size();
                    uint64_t sec2_file_end = sec2.offset + sec2.data.size();
                    
                    if ((sec1.offset < sec2_file_end) && (sec2.offset < sec1_file_end)) {
                        lastError_ = "File offset overlap between sections " + sec1.name + " and " + sec2.name;
                        return;
                    }
                }
            }
        }
        
        // Check alignment
        for (const auto& section : sections_) {
            if (section.vaddr > 0 && (section.vaddr % section.align) != 0) {
                lastError_ = "Section " + section.name + " virtual address not properly aligned";
                return;
            }
            
            if (section.offset > 0 && (section.offset % section.align) != 0) {
                lastError_ = "Section " + section.name + " file offset not properly aligned";
                return;
            }
        }
    }
    
    void createSymbolTable() {
        // Clear existing symbols
        symbols_.clear();
        
        // Add required null symbol at index 0
        Symbol nullSym = {};
        nullSym.st_name = 0;
        nullSym.st_value = 0;
        nullSym.st_size = 0;
        nullSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
        nullSym.st_other = 0;
        nullSym.st_shndx = 0;  // SHN_UNDEF
        symbols_.push_back(nullSym);
        
        // Add section symbols (local symbols for each section)
        for (size_t i = 1; i < sections_.size(); ++i) {
            const auto& section = sections_[i];
            
            // Only add symbols for allocatable sections
            if (section.flags & SHF_ALLOC) {
                Symbol sectionSym = {};
                sectionSym.st_name = 0;  // Section symbols have no name
                sectionSym.st_value = section.vaddr;
                sectionSym.st_size = 0;
                sectionSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
                sectionSym.st_other = 0;
                sectionSym.st_shndx = static_cast<uint16_t>(i);
                symbols_.push_back(sectionSym);
            }
        }
        
        // Add entry point symbol
        auto textIdx = findSectionIndex(".text");
        if (textIdx > 0) {
            Symbol entrySym = {};
            entrySym.st_name = addString("_start");
            entrySym.st_value = entryPoint_;
            entrySym.st_size = 0;
            entrySym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
            entrySym.st_other = 0;
            entrySym.st_shndx = static_cast<uint16_t>(textIdx);
            symbols_.push_back(entrySym);
        }
        
        // Add symbols for important sections
        auto initIdx = findSectionIndex(".init");
        if (initIdx > 0) {
            Symbol initSym = {};
            initSym.st_name = addString("_init");
            initSym.st_value = sections_[initIdx].vaddr;
            initSym.st_size = sections_[initIdx].data.size();
            initSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC);
            initSym.st_other = 0;
            initSym.st_shndx = static_cast<uint16_t>(initIdx);
            symbols_.push_back(initSym);
        }
        
        auto finiIdx = findSectionIndex(".fini");
        if (finiIdx > 0) {
            Symbol finiSym = {};
            finiSym.st_name = addString("_fini");
            finiSym.st_value = sections_[finiIdx].vaddr;
            finiSym.st_size = sections_[finiIdx].data.size();
            finiSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC);
            finiSym.st_other = 0;
            finiSym.st_shndx = static_cast<uint16_t>(finiIdx);
            symbols_.push_back(finiSym);
        }
        
        // Add data section symbols
        auto dataIdx = findSectionIndex(".data");
        if (dataIdx > 0 && sections_[dataIdx].data.size() > 0) {
            Symbol dataSym = {};
            dataSym.st_name = addString("__data_start");
            dataSym.st_value = sections_[dataIdx].vaddr;
            dataSym.st_size = sections_[dataIdx].data.size();
            dataSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
            dataSym.st_other = 0;
            dataSym.st_shndx = static_cast<uint16_t>(dataIdx);
            symbols_.push_back(dataSym);
        }
        
        auto bssIdx = findSectionIndex(".bss");
        if (bssIdx > 0) {
            Symbol bssSym = {};
            bssSym.st_name = addString("__bss_start");
            bssSym.st_value = sections_[bssIdx].vaddr;
            bssSym.st_size = 4096;  // Default BSS size
            bssSym.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT);
            bssSym.st_other = 0;
            bssSym.st_shndx = static_cast<uint16_t>(bssIdx);
            symbols_.push_back(bssSym);
        }
    }

    uint32_t addSectionString(const std::string& str) {
        // Ensure section string table starts with null byte
        if (shstringTable_.empty()) {
            shstringTable_ += '\0';
        }
        
        // Check if string already exists
        size_t pos = shstringTable_.find(str + '\0');
        if (pos != std::string::npos) {
            return static_cast<uint32_t>(pos);
        }
        
        uint32_t offset = static_cast<uint32_t>(shstringTable_.size());
        shstringTable_ += str;
        shstringTable_ += '\0';
        return offset;
    }

    void createSegments() {
    // Clear existing segments
    segments_.clear();
    
    // Calculate actual number of segments we'll create
    uint32_t numSegments = 2;  // At least LOAD segments for text and data
    if (findSectionIndex(".interp") > 0) numSegments++;  // INTERP segment
    if (findSectionIndex(".dynamic") > 0) numSegments++;  // DYNAMIC segment
    numSegments++;  // PHDR segment
    
    uint64_t headerSize = sizeof(ElfHeader) + (numSegments * sizeof(ProgramHeader));
    uint64_t currentOffset = align(headerSize, pageSize_);

    // Create PHDR segment (program headers) - must be first
    Segment phdr = {};
    phdr.type = PT_PHDR;
    phdr.flags = PF_R;
    phdr.offset = sizeof(ElfHeader);
    phdr.vaddr = baseAddress_ + sizeof(ElfHeader);
    phdr.paddr = phdr.vaddr;
    phdr.filesz = numSegments * sizeof(ProgramHeader);
    phdr.memsz = phdr.filesz;
    phdr.align = 8;
    segments_.push_back(phdr);

    // Create INTERP segment if needed
    auto interpIdx = findSectionIndex(".interp");
    if (interpIdx > 0) {
        Segment interp = {};
        interp.type = PT_INTERP;
        interp.flags = PF_R;
        interp.offset = sections_[interpIdx].offset;
        interp.vaddr = sections_[interpIdx].vaddr;
        interp.paddr = interp.vaddr;
        interp.filesz = sections_[interpIdx].data.size();
        interp.memsz = interp.filesz;
        interp.align = 1;
        segments_.push_back(interp);
    }

    // Calculate start of text segment
    uint64_t textStart = 0;
    auto textIdx = findSectionIndex(".text");
    if (textIdx > 0) {
        textStart = sections_[textIdx].vaddr;
    }

    // Create LOAD segment for read-execute sections (.text, .init, .fini, .plt)
    Segment text = {};
    text.type = PT_LOAD;
    text.flags = PF_R | PF_X;
    text.offset = 0;  // Start from beginning of file (includes headers)
    text.vaddr = baseAddress_;
    text.paddr = text.vaddr;
    text.align = pageSize_;
    text.filesz = 0;
    text.memsz = 0;

    // Find the range of executable sections
    uint64_t minVaddr = UINT64_MAX;
    uint64_t maxVaddr = 0;
    uint64_t minOffset = UINT64_MAX;
    uint64_t maxOffset = 0;

    for (auto& section : sections_) {
        if ((section.flags & SHF_EXECINSTR) && section.vaddr >= baseAddress_) {
            text.sections.push_back(&section);
            
            if (section.vaddr < minVaddr) {
                minVaddr = section.vaddr;
            }
            
            uint64_t sectionEnd = section.vaddr + section.data.size();
            if (sectionEnd > maxVaddr) {
                maxVaddr = sectionEnd;
            }
            
            if (section.offset > 0 && section.offset < minOffset) {
                minOffset = section.offset;
            }
            
            if (section.offset > 0) {
                uint64_t sectionFileEnd = section.offset + section.data.size();
                if (sectionFileEnd > maxOffset) {
                    maxOffset = sectionFileEnd;
                }
            }
        }
    }

    // Text segment includes headers and all executable sections
    text.vaddr = baseAddress_;
    text.memsz = align(maxVaddr - baseAddress_, pageSize_);
    text.filesz = text.memsz;  // File size matches memory size for executable segment
    
    segments_.push_back(text);

    // Create LOAD segment for read-write sections (.data, .bss, .dynamic, .got)
    Segment data = {};
    data.type = PT_LOAD;
    data.flags = PF_R | PF_W;
    data.align = pageSize_;
    data.filesz = 0;
    data.memsz = 0;

    // Find the range of writable sections
    uint64_t dataMinVaddr = UINT64_MAX;
    uint64_t dataMaxVaddr = 0;
    uint64_t dataMinOffset = UINT64_MAX;
    uint64_t dataMaxOffset = 0;
    bool hasWritableSections = false;

    for (auto& section : sections_) {
        if ((section.flags & SHF_WRITE) && !(section.flags & SHF_EXECINSTR) && 
            section.vaddr >= baseAddress_) {
            data.sections.push_back(&section);
            hasWritableSections = true;
            
            if (section.vaddr < dataMinVaddr) {
                dataMinVaddr = section.vaddr;
            }
            
            uint64_t sectionEnd = section.vaddr;
            if (section.type == SHT_NOBITS) {
                // BSS sections have virtual size but no file content
                sectionEnd += 4096;  // Default BSS size
            } else {
                sectionEnd += section.data.size();
            }
            
            if (sectionEnd > dataMaxVaddr) {
                dataMaxVaddr = sectionEnd;
            }
            
            // Only count file offset for sections with actual data
            if (section.type != SHT_NOBITS && section.offset > 0) {
                if (section.offset < dataMinOffset) {
                    dataMinOffset = section.offset;
                }
                
                uint64_t sectionFileEnd = section.offset + section.data.size();
                if (sectionFileEnd > dataMaxOffset) {
                    dataMaxOffset = sectionFileEnd;
                }
            }
        }
    }

    if (hasWritableSections) {
        // Data segment starts at page boundary after text segment
        data.vaddr = align(text.vaddr + text.memsz, pageSize_);
        data.paddr = data.vaddr;
        data.offset = dataMinOffset != UINT64_MAX ? dataMinOffset : 0;
        
        // Calculate sizes
        data.memsz = align(dataMaxVaddr - data.vaddr, pageSize_);
        
        // File size is smaller if we have BSS sections
        if (dataMaxOffset > 0) {
            data.filesz = dataMaxOffset - data.offset;
        } else {
            data.filesz = 0;  // Only BSS sections
        }
        
        segments_.push_back(data);
    }

    // Create DYNAMIC segment if we have a .dynamic section
    auto dynamicIdx = findSectionIndex(".dynamic");
    if (dynamicIdx > 0) {
        Segment dynamic = {};
        dynamic.type = PT_DYNAMIC;
        dynamic.flags = PF_R | PF_W;
        dynamic.offset = sections_[dynamicIdx].offset;
        dynamic.vaddr = sections_[dynamicIdx].vaddr;
        dynamic.paddr = dynamic.vaddr;
        dynamic.filesz = sections_[dynamicIdx].data.size();
        dynamic.memsz = dynamic.filesz;
        dynamic.align = 8;
        segments_.push_back(dynamic);
    }

    // Make sure the string tables have proper offsets
    uint64_t stringTablesOffset = align(currentOffset + text.filesz + data.filesz, 4);

    // Update string table sections
    auto shstrIdx = findSectionIndex(".shstrtab");
    if (shstrIdx > 0) {
        sections_[shstrIdx].offset = stringTablesOffset;
        sections_[shstrIdx].data.assign(shstringTable_.begin(), shstringTable_.end());
        stringTablesOffset += shstringTable_.size();
    }

    auto strIdx = findSectionIndex(".strtab");
    if (strIdx > 0) {
        sections_[strIdx].offset = stringTablesOffset;
        sections_[strIdx].data.assign(stringTable_.begin(), stringTable_.end());
        stringTablesOffset += stringTable_.size();
    }

    // Create symbol table
    auto symtabIdx = findSectionIndex(".symtab");
    if (symtabIdx > 0) {
        createSymbolTable();
        
        // Update symtab section
        sections_[symtabIdx].offset = stringTablesOffset;
        sections_[symtabIdx].data.resize(symbols_.size() * sizeof(Symbol));
        std::memcpy(sections_[symtabIdx].data.data(), symbols_.data(),
                    symbols_.size() * sizeof(Symbol));
    }
    }

    // File writing methods
    void writeElfHeader(std::ofstream& file) {
        ElfHeader header = {};
        
        // Fix magic number - should be 0x7F followed by "ELF"
        header.e_ident_magic = 0x464C457F;  // 0x7F, 'E', 'L', 'F' in little endian
        header.e_ident_class = is64Bit_ ? 2 : 1;  // ELFCLASS64 or ELFCLASS32
        header.e_ident_data = 1;  // ELFDATA2LSB (little endian)
        header.e_ident_version = 1;  // EV_CURRENT
        header.e_ident_osabi = 0;  // ELFOSABI_SYSV (System V ABI)
        header.e_ident_abiversion = 0;
        
        // Clear padding bytes
        memset(header.e_ident_pad, 0, sizeof(header.e_ident_pad));
        
        header.e_type = ET_EXEC;  // Executable file
        header.e_machine = is64Bit_ ? EM_X86_64 : EM_386;
        header.e_version = 1;  // EV_CURRENT
        
        // Validate and set entry point
        if (entryPoint_ == 0) {
            entryPoint_ = baseAddress_;  // Default to base address if not set
        }
        header.e_entry = entryPoint_;
        
        // Program header offset immediately follows ELF header
        header.e_phoff = sizeof(ElfHeader);
        
        // Section header offset calculated based on all content
        header.e_shoff = calculateSectionHeaderOffset();
        
        header.e_flags = 0;  // No processor-specific flags
        header.e_ehsize = sizeof(ElfHeader);
        header.e_phentsize = sizeof(ProgramHeader);
        
        // Validate segment count
        if (segments_.empty()) {
            lastError_ = "No program segments defined";
            return;
        }
        header.e_phnum = static_cast<uint16_t>(segments_.size());
        
        header.e_shentsize = sizeof(SectionHeader);
        
        // Validate section count
        if (sections_.empty()) {
            lastError_ = "No sections defined";
            return;
        }
        header.e_shnum = static_cast<uint16_t>(sections_.size());
        
        // Find string table index and validate
        uint32_t shstrndx = findSectionIndex(".shstrtab");
        if (shstrndx == 0) {
            lastError_ = "Section header string table (.shstrtab) not found";
            return;
        }
        header.e_shstrndx = static_cast<uint16_t>(shstrndx);
        
        // Validate header consistency
        if (header.e_phoff + (header.e_phnum * header.e_phentsize) > header.e_shoff) {
            lastError_ = "Program headers overlap with section headers";
            return;
        }

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
        // Ensure string table starts with null byte
        if (stringTable_.empty()) {
            stringTable_ += '\0';
        }
        
        // Check if string already exists
        size_t pos = stringTable_.find(str + '\0');
        if (pos != std::string::npos) {
            return static_cast<uint32_t>(pos);
        }
        
        uint32_t offset = static_cast<uint32_t>(stringTable_.size());
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
        
        // Add program headers size
        offset += segments_.size() * sizeof(ProgramHeader);
        
        // Find the maximum file offset + size from all sections
        uint64_t maxSectionEnd = offset;
        for (const auto& section : sections_) {
            if (section.type != SHT_NOBITS && section.offset > 0) {
                uint64_t sectionEnd = section.offset + section.data.size();
                maxSectionEnd = std::max(maxSectionEnd, sectionEnd);
            }
        }
        
        // Section headers come after all section data
        offset = maxSectionEnd;
        
        // Align section header offset to 8 byte boundary for proper alignment
        return align(offset, 8);
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
        // Write sections in order of their file offsets
        std::vector<const Section*> orderedSections;
        for (const auto& section : sections_) {
            if (section.type != SHT_NOBITS && section.offset > 0 && !section.data.empty()) {
                orderedSections.push_back(&section);
            }
        }
        
        // Sort by file offset
        std::sort(orderedSections.begin(), orderedSections.end(),
                  [](const Section* a, const Section* b) {
                      return a->offset < b->offset;
                  });
        
        for (const auto* section : orderedSections) {
            // Seek to the correct file position
            file.seekp(section->offset);
            
            // Verify we're at the right position
            uint64_t currentPos = file.tellp();
            if (currentPos != section->offset) {
                lastError_ = "Failed to seek to correct offset for section " + section->name;
                return;
            }
            
            // Write section data
            file.write(reinterpret_cast<const char*>(section->data.data()),
                       section->data.size());
            
            // Verify write was successful
            if (file.fail()) {
                lastError_ = "Failed to write data for section " + section->name;
                return;
            }
        }
        
        // Add padding to align file size if needed
        uint64_t currentPos = file.tellp();
        uint64_t alignedPos = align(currentPos, 8);
        if (alignedPos > currentPos) {
            std::vector<char> padding(alignedPos - currentPos, 0);
            file.write(padding.data(), padding.size());
        }
    }

    void writeSectionHeaders(std::ofstream& file) {
        // Seek to section header offset
        uint64_t shoff = calculateSectionHeaderOffset();
        file.seekp(shoff);
        
        for (const auto& section : sections_) {
            SectionHeader sh = {};
            
            // Set section header fields
            sh.sh_name = section.name_offset;
            sh.sh_type = section.type;
            sh.sh_flags = section.flags;
            sh.sh_addr = section.vaddr;
            
            // Set file offset and size
            if (section.type == SHT_NOBITS) {
                sh.sh_offset = 0;  // BSS sections have no file content
                sh.sh_size = (section.name == ".bss") ? 4096 : 0;  // Default BSS size
            } else {
                sh.sh_offset = section.offset;
                sh.sh_size = section.data.size();
            }
            
            sh.sh_link = getShLink(section);
            sh.sh_info = getShInfo(section);
            sh.sh_addralign = section.align;
            sh.sh_entsize = getShEntSize(section);

            // Write section header
            file.write(reinterpret_cast<const char*>(&sh), sizeof(sh));
            
            if (file.fail()) {
                lastError_ = "Failed to write section header for " + section.name;
                return;
            }
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
            // sh_info should contain the index of the first non-local symbol
            uint32_t firstGlobal = 0;
            for (size_t i = 0; i < symbols_.size(); ++i) {
                uint8_t binding = symbols_[i].st_info >> 4;
                if (binding != STB_LOCAL) {
                    firstGlobal = static_cast<uint32_t>(i);
                    break;
                }
            }
            return firstGlobal;
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
    
    void prepareStringTables() {
        // Update .strtab section with current string table content
        auto strIdx = findSectionIndex(".strtab");
        if (strIdx > 0) {
            auto& section = sections_[strIdx];
            section.data.clear();
            section.data.insert(section.data.end(), stringTable_.begin(), stringTable_.end());
        }
        
        // Update .shstrtab section with current section string table content
        auto shstrIdx = findSectionIndex(".shstrtab");
        if (shstrIdx > 0) {
            auto& section = sections_[shstrIdx];
            section.data.clear();
            section.data.insert(section.data.end(), shstringTable_.begin(), shstringTable_.end());
        }
        
        // Update .symtab section with current symbol table content
        auto symtabIdx = findSectionIndex(".symtab");
        if (symtabIdx > 0) {
            auto& section = sections_[symtabIdx];
            section.data.resize(symbols_.size() * sizeof(Symbol));
            std::memcpy(section.data.data(), symbols_.data(), section.data.size());
        }
    }
    
    bool validateFileStructure(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            lastError_ = "Cannot open generated file for validation";
            return false;
        }
        
        // Read and validate ELF header
        ElfHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (file.gcount() != sizeof(header)) {
            lastError_ = "Generated file too small - missing ELF header";
            return false;
        }
        
        // Validate magic number
        if (header.e_ident_magic != 0x464C457F) {
            lastError_ = "Invalid ELF magic number in generated file";
            return false;
        }
        
        // Validate program header count
        if (header.e_phnum == 0) {
            lastError_ = "No program headers in generated file";
            return false;
        }
        
        // Validate section header count
        if (header.e_shnum == 0) {
            lastError_ = "No section headers in generated file";
            return false;
        }
        
        // Check file size is reasonable
        file.seekg(0, std::ios::end);
        uint64_t fileSize = file.tellg();
        if (fileSize < sizeof(ElfHeader) + header.e_phnum * sizeof(ProgramHeader)) {
            lastError_ = "Generated file too small for headers";
            return false;
        }
        
        return true;
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
