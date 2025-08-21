import pefile
import sys

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        return

    print(f"[*] Analyzing {file_path}")
    print(f"  Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

    print("\n  Sections:")
    for section in pe.sections:
        print(f"    - Name: {section.Name.decode().strip()}")
        print(f"      Virtual Address: {hex(section.VirtualAddress)}")
        print(f"      Virtual Size: {hex(section.Misc_VirtualSize)}")
        print(f"      Raw Size: {hex(section.SizeOfRawData)}")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("\n  Imports:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"    - DLL: {entry.dll.decode()}")
            for imp in entry.imports:
                if imp.name:
                    print(f"      - Function: {imp.name.decode()}")
                else:
                    print(f"      - Ordinal: {imp.ordinal}")
    else:
        print("\n  No import directory found.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_pe.py <executable>")
        sys.exit(1)

    analyze_pe(sys.argv[1])
