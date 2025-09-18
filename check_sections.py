#!/usr/bin/env python3
import struct
import sys

def read_pe_sections(filename):
    with open(filename, 'rb') as f:
        # Read DOS header
        dos_header = f.read(64)
        e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
        
        # Jump to PE header
        f.seek(e_lfanew)
        pe_sig = f.read(4)
        if pe_sig != b'PE\x00\x00':
            print("Not a valid PE file")
            return
            
        # Read COFF header
        coff_header = f.read(20)
        machine, num_sections, timestamp, ptr_to_symbols, num_symbols, size_opt_header, characteristics = struct.unpack('<HHIIIHH', coff_header)
        
        print(f"Machine: 0x{machine:04x}")
        print(f"Number of sections: {num_sections}")
        print(f"Characteristics: 0x{characteristics:04x}")
        
        # Skip optional header
        f.seek(f.tell() + size_opt_header)
        
        # Read section headers
        print("\nSections:")
        for i in range(num_sections):
            section_header = f.read(40)
            name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size, virtual_address, size_of_raw_data, ptr_to_raw_data = struct.unpack('<IIII', section_header[8:24])
            characteristics = struct.unpack('<I', section_header[36:40])[0]
            
            print(f"  {name:8s}: VirtAddr=0x{virtual_address:08x}, VirtSize=0x{virtual_size:08x}, RawSize=0x{size_of_raw_data:08x}, Characteristics=0x{characteristics:08x}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_sections.py <pe_file>")
        sys.exit(1)
    
    read_pe_sections(sys.argv[1])