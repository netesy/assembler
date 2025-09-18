#!/usr/bin/env python3
import sys
import os

def hexdump(filename, max_bytes=256):
    """Simple hexdump utility"""
    if not os.path.exists(filename):
        print(f"File {filename} not found")
        return
    
    print(f"Hexdump of {filename}:")
    print("=" * 50)
    
    with open(filename, 'rb') as f:
        data = f.read(max_bytes)
        
    for i in range(0, len(data), 16):
        # Address
        addr = f"{i:08x}"
        
        # Hex bytes
        hex_part = ""
        ascii_part = ""
        
        for j in range(16):
            if i + j < len(data):
                byte = data[i + j]
                hex_part += f"{byte:02x} "
                ascii_part += chr(byte) if 32 <= byte <= 126 else "."
            else:
                hex_part += "   "
                ascii_part += " "
        
        print(f"{addr}: {hex_part} |{ascii_part}|")
    
    print(f"\nFile size: {len(data)} bytes")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python hexdump.py <filename>")
        sys.exit(1)
    
    hexdump(sys.argv[1])