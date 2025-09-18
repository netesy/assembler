#!/usr/bin/env python3
import sys

def compare_files(file1, file2):
    with open(file1, 'rb') as f1:
        data1 = f1.read()
    with open(file2, 'rb') as f2:
        data2 = f2.read()
    
    print(f"File 1 ({file1}): {len(data1)} bytes")
    print(f"File 2 ({file2}): {len(data2)} bytes")
    print()
    
    # Show first 512 bytes of each file
    max_bytes = min(512, len(data1), len(data2))
    
    print("First 512 bytes comparison:")
    print("=" * 80)
    
    for i in range(0, max_bytes, 16):
        # File 1 hex
        hex1 = ' '.join(f'{b:02x}' for b in data1[i:i+16])
        # File 2 hex  
        hex2 = ' '.join(f'{b:02x}' for b in data2[i:i+16])
        
        marker = "DIFF" if hex1 != hex2 else "SAME"
        print(f"{i:08x}: {hex1:<48} | {hex2:<48} [{marker}]")
    
    # Check if our executable has the correct call instruction
    print("\nLooking for call instruction in our executable:")
    for i in range(len(data1) - 4):
        if data1[i] == 0xe8:  # call instruction opcode
            displacement = int.from_bytes(data1[i+1:i+5], 'little', signed=True)
            print(f"Found call at offset 0x{i:x}: displacement = 0x{displacement:x} ({displacement})")

if __name__ == "__main__":
    compare_files("compare_test_our.exe", "compare_test_win.exe")