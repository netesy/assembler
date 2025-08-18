# Design Document

## Overview

This design addresses critical bugs in the assembler's opcode encoding, ELF generation, and PE generation systems. The current implementation has several fundamental issues that prevent the creation of functional executables. The design focuses on fixing instruction encoding, proper section layout, correct header generation, and ensuring the generated binaries are valid and executable.

## Architecture

The fix involves three main components:

1. **Assembler Core**: Fix instruction encoding, operand parsing, and symbol resolution
2. **ELF Generator**: Correct section layout, program headers, and symbol tables
3. **PE Generator**: Fix import tables, section alignment, and header structures

## Components and Interfaces

### Assembler Fixes

#### Instruction Encoding Issues
The current `encodeInstruction` method has several problems:
- Incorrect bit layout for multi-operand instructions
- Wrong operand parsing for memory references
- Improper handling of immediate values vs register operands

**Fixed Design:**
```cpp
// New instruction format: [opcode:8][mode:8][reg1:8][reg2/imm:8][imm32:32]
struct InstructionEncoding {
    uint8_t opcode;
    uint8_t mode;        // 0=reg-reg, 1=reg-imm, 2=reg-mem, 3=mem-reg
    uint8_t reg1;        // First register
    uint8_t reg2_or_imm; // Second register or immediate (low 8 bits)
    uint32_t immediate;  // Full 32-bit immediate value
};
```

#### Operand Parsing Fixes
- Fix memory dereference parsing `[symbol]` vs direct symbol access
- Correct immediate value encoding
- Proper register encoding

#### Symbol Resolution Improvements
- Fix forward reference patching
- Correct address calculation for different sections
- Proper handling of external symbols

### ELF Generator Fixes

#### Header Issues
Current problems:
- Incorrect program header count calculation
- Wrong section header offsets
- Missing or incorrect segment permissions

**Fixed Design:**
- Calculate exact header sizes before layout
- Proper alignment of all structures
- Correct segment-to-section mapping

#### Section Layout Problems
Current issues:
- Sections not properly aligned in memory
- File offsets don't match virtual addresses correctly
- Missing essential sections (.interp, .dynamic)

**Fixed Layout:**
```
ELF Header
Program Headers
.interp section (if dynamic)
.text section (aligned to page boundary)
.rodata section
.data section (new page, writable)
.bss section (no file content)
.symtab section
.strtab section
.shstrtab section
Section Headers
```

#### Symbol Table Fixes
- Add required null symbol at index 0
- Correct symbol binding and type information
- Proper string table references

### PE Generator Fixes

#### Import Table Issues
Current problems:
- Incorrect import directory structure
- Wrong RVA calculations
- Missing import address table entries

**Fixed Design:**
```
Import Directory Table
├── Import Lookup Table (ILT)
├── Import Address Table (IAT)  
├── Module Names
└── Function Names (with hints)
```

#### Section Alignment Problems
- Fix file vs virtual alignment
- Correct section characteristics
- Proper RVA calculations

#### Header Structure Fixes
- Correct DOS header with proper stub
- Fix NT headers for both 32-bit and 64-bit
- Proper data directory entries

## Data Models

### Fixed Instruction Format
```cpp
struct FixedInstruction {
    uint8_t opcode;
    uint8_t addressing_mode;
    uint8_t dest_reg;
    uint8_t src_reg;
    uint32_t immediate_value;
    bool has_immediate;
    bool is_memory_ref;
};
```

### Section Layout Model
```cpp
struct SectionLayout {
    std::string name;
    uint64_t virtual_address;
    uint64_t file_offset;
    uint32_t virtual_size;
    uint32_t file_size;
    uint32_t alignment;
    uint32_t characteristics;
    std::vector<uint8_t> data;
};
```

### Symbol Resolution Model
```cpp
struct SymbolInfo {
    std::string name;
    uint64_t address;
    uint32_t section_index;
    uint8_t binding;    // LOCAL, GLOBAL, WEAK
    uint8_t type;       // NOTYPE, OBJECT, FUNC
    bool is_defined;
    std::vector<uint64_t> references; // Locations that reference this symbol
};
```

## Error Handling

### Validation Strategy
1. **Pre-assembly validation**: Check syntax and symbol references
2. **Post-assembly validation**: Verify instruction encoding and symbol resolution
3. **Pre-generation validation**: Ensure all sections and symbols are properly defined
4. **Post-generation validation**: Verify file structure and headers

### Error Reporting
- Detailed error messages with line numbers and context
- Specific error codes for different failure types
- Debug output showing section layouts and symbol tables

## Testing Strategy

### Unit Tests
1. **Instruction Encoding Tests**: Verify each opcode generates correct machine code
2. **Symbol Resolution Tests**: Test forward references and cross-section symbols
3. **Section Layout Tests**: Verify proper alignment and addressing
4. **Header Generation Tests**: Check ELF and PE header correctness

### Integration Tests
1. **End-to-End Assembly**: Test complete assembly process with sample programs
2. **Executable Validation**: Verify generated files can be loaded by OS
3. **Cross-Platform Tests**: Test on both Windows and Linux

### Validation Tests
1. **ELF Validation**: Use `readelf` and `objdump` to verify structure
2. **PE Validation**: Use PE analysis tools to check Windows executables
3. **Execution Tests**: Run generated executables and verify output

## Implementation Notes

### Critical Fixes Required

1. **Assembler.cpp Line 89-95**: Fix `encodeInstruction` to use proper bit layout
2. **Assembler.cpp Line 45-75**: Fix `parseOperand` to handle memory references correctly
3. **ELF.cpp Line 200-250**: Fix section layout calculation
4. **ELF.cpp Line 800-900**: Fix program header generation
5. **PE.cpp Line 400-500**: Fix import table generation
6. **PE.cpp Line 600-700**: Fix section alignment calculations

### Architecture-Specific Considerations

#### x86-64 Specifics
- 64-bit addressing for memory operands
- Proper REX prefix handling (if extended)
- Correct calling convention for system calls

#### x86 Specifics  
- 32-bit addressing limitations
- Different system call conventions
- Proper segment handling

### Platform Integration

#### Linux ELF
- Proper dynamic linker path (`/lib64/ld-linux-x86-64.so.2`)
- Correct system call numbers
- Proper section permissions

#### Windows PE
- Correct import from `kernel32.dll`
- Proper subsystem settings
- Valid import address tables