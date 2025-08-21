import pefile
import sys

def analyze_pe_file(filepath):
    try:
        pe = pefile.PE(filepath)
        print(f"Analysis for: {filepath}")
        print("-" * 30)

        print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

        print("\nSections:")
        for section in pe.sections:
            print(f"  - {section.Name.decode().rstrip('\\x00')}: Virtual Address={hex(section.VirtualAddress)}, Virtual Size={section.Misc_VirtualSize}")

        print("\nImports:")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"  DLL: {entry.dll.decode()}")
                for imp in entry.imports:
                    if imp.name:
                        print(f"    - {imp.name.decode()}")
                    else:
                        print(f"    - Ordinal: {imp.ordinal}")
        else:
            print("  No imports found.")

        print("-" * 30)

    except pefile.PEFormatError as e:
        print(f"Error: {filepath} is not a valid PE file.")
        print(e)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for filepath in sys.argv[1:]:
            analyze_pe_file(filepath)
    else:
        print("Usage: python analyze_pe.py <file1.exe> <file2.exe> ...")
