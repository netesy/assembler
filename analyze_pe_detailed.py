#!/usr/bin/env python3
import struct
import sys

def analyze_pe_file(filename):
    with open(filename, 'rb') as f:
        # Read DOS header
        dos_header = f.read(64)
        e_magic = struct.unpack('<H', dos_header[0:2])[0]
        e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
        
        print(f"DOS Header:")
        print(f"  e_magic: 0x{e_magic:04x} ({'MZ' if e_magic == 0x5A4D else 'INVALID'})")
        print(f"  e_lfanew: 0x{e_lfanew:08x}")
        
        # Jump to PE header
        f.seek(e_lfanew)
        pe_sig = f.read(4)
        pe_sig_int = struct.unpack('<I', pe_sig)[0]
        pe_valid = pe_sig == b'PE\x00\x00'
        print(f"\nPE Signature: 0x{pe_sig_int:08x} ({'PE' if pe_valid else 'INVALID'})")
        
        # Read COFF header
        coff_header = f.read(20)
        machine, num_sections, timestamp, ptr_to_symbols, num_symbols, size_opt_header, characteristics = struct.unpack('<HHIIIHH', coff_header)
        
        print(f"\nCOFF Header:")
        print(f"  Machine: 0x{machine:04x} ({'AMD64' if machine == 0x8664 else 'i386' if machine == 0x014c else 'UNKNOWN'})")
        print(f"  Number of sections: {num_sections}")
        print(f"  Size of optional header: {size_opt_header}")
        print(f"  Characteristics: 0x{characteristics:04x}")
        
        # Decode characteristics
        char_flags = []
        if characteristics & 0x0001: char_flags.append("RELOCS_STRIPPED")
        if characteristics & 0x0002: char_flags.append("EXECUTABLE_IMAGE")
        if characteristics & 0x0004: char_flags.append("LINE_NUMBERS_STRIPPED")
        if characteristics & 0x0008: char_flags.append("LOCAL_SYMS_STRIPPED")
        if characteristics & 0x0020: char_flags.append("LARGE_ADDRESS_AWARE")
        if characteristics & 0x0100: char_flags.append("32BIT_MACHINE")
        print(f"    Flags: {', '.join(char_flags)}")
        
        # Read optional header
        if size_opt_header > 0:
            opt_header_start = f.tell()
            magic = struct.unpack('<H', f.read(2))[0]
            print(f"\nOptional Header:")
            print(f"  Magic: 0x{magic:04x} ({'PE32+' if magic == 0x20b else 'PE32' if magic == 0x10b else 'INVALID'})")
            
            if magic == 0x20b:  # PE32+
                f.seek(opt_header_start)
                opt_data = f.read(size_opt_header)
                
                # Parse key fields
                major_linker, minor_linker = struct.unpack('<BB', opt_data[2:4])
                size_of_code, size_of_init_data, size_of_uninit_data = struct.unpack('<III', opt_data[4:16])
                entry_point, base_of_code = struct.unpack('<II', opt_data[16:24])
                image_base = struct.unpack('<Q', opt_data[24:32])[0]
                section_align, file_align = struct.unpack('<II', opt_data[32:40])
                
                print(f"  Linker version: {major_linker}.{minor_linker}")
                print(f"  Size of code: 0x{size_of_code:08x}")
                print(f"  Size of initialized data: 0x{size_of_init_data:08x}")
                print(f"  Address of entry point: 0x{entry_point:08x}")
                print(f"  Base of code: 0x{base_of_code:08x}")
                print(f"  Image base: 0x{image_base:016x}")
                print(f"  Section alignment: 0x{section_align:08x}")
                print(f"  File alignment: 0x{file_align:08x}")
                
                # Get more fields
                os_major, os_minor = struct.unpack('<HH', opt_data[40:44])
                img_major, img_minor = struct.unpack('<HH', opt_data[44:48])
                subsys_major, subsys_minor = struct.unpack('<HH', opt_data[48:52])
                size_of_image, size_of_headers = struct.unpack('<II', opt_data[56:64])
                subsystem = struct.unpack('<H', opt_data[68:70])[0]
                
                print(f"  OS version: {os_major}.{os_minor}")
                print(f"  Image version: {img_major}.{img_minor}")
                print(f"  Subsystem version: {subsys_major}.{subsys_minor}")
                print(f"  Size of image: 0x{size_of_image:08x}")
                print(f"  Size of headers: 0x{size_of_headers:08x}")
                print(f"  Subsystem: {subsystem} ({'CONSOLE' if subsystem == 3 else 'GUI' if subsystem == 2 else 'UNKNOWN'})")
        
        # Skip to section headers
        f.seek(e_lfanew + 4 + 20 + size_opt_header)
        
        # Read section headers
        print(f"\nSections ({num_sections}):")
        for i in range(num_sections):
            section_header = f.read(40)
            name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size, virtual_address, size_of_raw_data, ptr_to_raw_data = struct.unpack('<IIII', section_header[8:24])
            characteristics = struct.unpack('<I', section_header[36:40])[0]
            
            print(f"  {i+1}. {name:8s}:")
            print(f"     Virtual Address: 0x{virtual_address:08x}")
            print(f"     Virtual Size: 0x{virtual_size:08x}")
            print(f"     Raw Data Size: 0x{size_of_raw_data:08x}")
            print(f"     Raw Data Pointer: 0x{ptr_to_raw_data:08x}")
            print(f"     Characteristics: 0x{characteristics:08x}")
            
            # Decode section characteristics
            sec_flags = []
            if characteristics & 0x00000020: sec_flags.append("CODE")
            if characteristics & 0x00000040: sec_flags.append("INITIALIZED_DATA")
            if characteristics & 0x00000080: sec_flags.append("UNINITIALIZED_DATA")
            if characteristics & 0x20000000: sec_flags.append("EXECUTE")
            if characteristics & 0x40000000: sec_flags.append("READ")
            if characteristics & 0x80000000: sec_flags.append("WRITE")
            if characteristics & 0x02000000: sec_flags.append("DISCARDABLE")
            print(f"       Flags: {', '.join(sec_flags)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_pe_detailed.py <pe_file>")
        sys.exit(1)
    
    analyze_pe_file(sys.argv[1])