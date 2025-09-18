#!/usr/bin/env python3
import sys
import os
import struct

def analyze_pe_code_section(filename):
    """Extract and analyze the code section from a PE file"""
    print(f"Analyzing PE file: {filename}")
    
    if not os.path.exists(filename):
        print(f"File {filename} not found")
        return None
    
    with open(filename, 'rb') as f:
        # Read DOS header
        dos_header = f.read(64)
        if dos_header[:2] != b'MZ':
            print("Not a valid PE file")
            return None
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', dos_header[60:64])[0]
        
        # Read PE header
        f.seek(pe_offset)
        pe_sig = f.read(4)
        if pe_sig != b'PE\x00\x00':
            print("Invalid PE signature")
            return None
        
        # Read COFF header
        coff_header = f.read(20)
        machine, num_sections, timestamp, sym_table_ptr, num_symbols, opt_header_size, characteristics = struct.unpack('<HHIIIHH', coff_header)
        
        print(f"Machine: 0x{machine:04x}")
        print(f"Number of sections: {num_sections}")
        
        # Skip optional header
        f.seek(pe_offset + 24 + opt_header_size)
        
        # Read section headers
        sections = []
        for i in range(num_sections):
            section_header = f.read(40)
            name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack('<IIII', section_header[8:24])
            
            sections.append({
                'name': name,
                'virtual_size': virtual_size,
                'virtual_addr': virtual_addr,
                'raw_size': raw_size,
                'raw_ptr': raw_ptr
            })
            
            print(f"Section {name}: VA=0x{virtual_addr:x}, Size={virtual_size}, RawPtr=0x{raw_ptr:x}")
        
        # Find and extract .text section
        text_section = None
        for section in sections:
            if section['name'] == '.text':
                text_section = section
                break
        
        if text_section:
            f.seek(text_section['raw_ptr'])
            code_data = f.read(text_section['virtual_size'])
            
            print(f"\n.text section machine code ({len(code_data)} bytes):")
            for i in range(0, len(code_data), 16):
                hex_part = ' '.join(f'{b:02x}' for b in code_data[i:i+16])
                print(f"  {i:04x}: {hex_part}")
            
            return code_data
        
        return None

def analyze_elf_code_section(filename):
    """Extract and analyze the code section from an ELF file"""
    print(f"Analyzing ELF file: {filename}")
    
    if not os.path.exists(filename):
        print(f"File {filename} not found")
        return None
    
    with open(filename, 'rb') as f:
        # Read ELF header
        elf_header = f.read(64)
        if elf_header[:4] != b'\x7fELF':
            print("Not a valid ELF file")
            return None
        
        # Parse ELF header (64-bit)
        ei_class = elf_header[4]
        if ei_class != 2:  # 64-bit
            print("Only 64-bit ELF files supported")
            return None
        
        # Get section header info
        e_shoff = struct.unpack('<Q', elf_header[40:48])[0]  # Section header offset
        e_shentsize = struct.unpack('<H', elf_header[58:60])[0]  # Section header entry size
        e_shnum = struct.unpack('<H', elf_header[60:62])[0]  # Number of section headers
        e_shstrndx = struct.unpack('<H', elf_header[62:64])[0]  # String table index
        
        print(f"Section headers at offset: 0x{e_shoff:x}")
        print(f"Number of sections: {e_shnum}")
        
        # Read section headers
        f.seek(e_shoff)
        sections = []
        for i in range(e_shnum):
            sh_data = f.read(e_shentsize)
            if len(sh_data) < 64:
                break
            
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack('<IIQQQQ', sh_data[:40])
            
            sections.append({
                'name_offset': sh_name,
                'type': sh_type,
                'flags': sh_flags,
                'addr': sh_addr,
                'offset': sh_offset,
                'size': sh_size
            })
        
        # Read string table to get section names
        if e_shstrndx < len(sections):
            strtab_section = sections[e_shstrndx]
            f.seek(strtab_section['offset'])
            string_table = f.read(strtab_section['size'])
            
            # Find .text section
            text_section = None
            for section in sections:
                name_start = section['name_offset']
                name_end = string_table.find(b'\x00', name_start)
                if name_end == -1:
                    continue
                name = string_table[name_start:name_end].decode('ascii', errors='ignore')
                
                if name == '.text':
                    text_section = section
                    print(f"Found .text section: addr=0x{section['addr']:x}, size={section['size']}")
                    break
            
            if text_section and text_section['size'] > 0:
                f.seek(text_section['offset'])
                code_data = f.read(text_section['size'])
                
                print(f"\n.text section machine code ({len(code_data)} bytes):")
                for i in range(0, len(code_data), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in code_data[i:i+16])
                    print(f"  {i:04x}: {hex_part}")
                
                return code_data
        
        return None

def compare_code(code1, code2, name1, name2):
    """Compare two code sections"""
    print(f"\n=== Comparison: {name1} vs {name2} ===")
    
    if code1 is None or code2 is None:
        print("Cannot compare - one or both code sections not found")
        return
    
    print(f"{name1} size: {len(code1)} bytes")
    print(f"{name2} size: {len(code2)} bytes")
    
    min_len = min(len(code1), len(code2))
    differences = 0
    
    for i in range(min_len):
        if code1[i] != code2[i]:
            differences += 1
            print(f"Difference at offset {i:04x}: {code1[i]:02x} vs {code2[i]:02x}")
    
    if len(code1) != len(code2):
        print(f"Size difference: {abs(len(code1) - len(code2))} bytes")
    
    if differences == 0 and len(code1) == len(code2):
        print("Machine code is identical!")
    else:
        print(f"Found {differences} byte differences")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compare_executables.py <file1> <file2>")
        sys.exit(1)
    
    file1, file2 = sys.argv[1], sys.argv[2]
    
    # Determine file types and analyze
    code1 = None
    code2 = None
    
    if file1.endswith('.exe'):
        code1 = analyze_pe_code_section(file1)
    elif file1.endswith('.elf'):
        code1 = analyze_elf_code_section(file1)
    
    print("\n" + "="*60 + "\n")
    
    if file2.endswith('.exe'):
        code2 = analyze_pe_code_section(file2)
    elif file2.endswith('.elf'):
        code2 = analyze_elf_code_section(file2)
    
    compare_code(code1, code2, file1, file2)