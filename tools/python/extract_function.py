#!/usr/bin/env python3
"""
extract_function.py

Extract the raw bytes of a specific function from an ELF object or executable
into a standalone binary file. The ELF must contain symbol information so that
the target function can be located correctly. This is useful for testing,
patching, or injecting individual functions into a larger binary.
"""

import os
import sys
import argparse

from typing import cast
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection, Symbol


def extract_function(elf_path: Path, func_name: str, out_bin: Path):
    if not elf_path.is_file():
        print(f"Error: ELF file '{elf_path}' does not exist")
        sys.exit(1)

    with elf_path.open("rb") as fh:
        elf: ELFFile = ELFFile(fh)

        # Find the symbol table
        symtab: SymbolTableSection | None = cast(SymbolTableSection | None, elf.get_section_by_name(".symtab"))  # pyright: ignore[reportUnknownMemberType]
        if not symtab:
            print("Error: No symbol table found. ELF may be stripped.")
            sys.exit(1)

        # Find the function symbol
        symbol: Symbol | None = None
        for sym in symtab.iter_symbols():
            if cast(str, sym.name) == func_name:  # pyright: ignore[reportUnknownMemberType]
                symbol = sym
                break

        if symbol is None:
            print(f"Error: Function '{func_name}' not found in ELF")
            sys.exit(1)

        # Get section containing the function
        sec_idx: int = cast(int, symbol["st_shndx"])
        section: Section | None = cast(Section | None, elf.get_section(sec_idx))  # pyright: ignore[reportUnknownMemberType]
        if section is None:
            print(f"Error: Section index {sec_idx} not found in ELF")
            sys.exit(1)

        # Compute file offset of function
        func_offset_in_section: int = cast(int, symbol["st_value"]) - cast(int, section["sh_addr"])
        file_offset: int = cast(int, section["sh_offset"]) + func_offset_in_section
        size: int = cast(int, symbol["st_size"])

        # Read the bytes
        fh.seek(file_offset, os.SEEK_SET)
        data = fh.read(size)

    # Write to output binary
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    out_bin.write_bytes(data)

    print(f"Function '{func_name}' extracted to '{out_bin}' ({size} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Extract raw bytes of a function from an ELF into a binary file.")
    parser.add_argument("elf_file", type=Path, help="Path to the ELF file")
    parser.add_argument("function_name", type=str, help="Function name to extract")
    parser.add_argument("output_bin", type=Path, help="Output binary file")

    args = parser.parse_args()

    elf_path: Path = args.elf_file
    func_name: str = args.function_name
    out_bin: Path = args.output_bin

    extract_function(elf_path, func_name, out_bin)


if __name__ == "__main__":
    main()
