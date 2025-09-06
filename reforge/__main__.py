#!/usr/bin/env python3
from __future__ import annotations

import re
import toml
import pydantic
import argparse
import subprocess

from pathlib import Path
from typing import Optional, Any, Iterator, cast
from elftools.elf.elffile import ELFFile  # pyright: ignore[reportUnknownVariableType]
from elftools.elf.sections import Section, SymbolTableSection  # pyright: ignore[reportUnknownVariableType]

PLACEHOLDER_ADDRESS: int = 0x00000000

# DEFAULT_CC: str = "mips-linux-gnu-gcc"
DEFAULT_LD: str = "mips-linux-gnu-ld"
DEFAULT_STRIP: str = "mips-linux-gnu-strip"
DEFAULT_OBJCOPY: str = "mips-linux-gnu-objcopy"

SECTION_ORDER: list[str] = [
    ".text",
    ".rodata",
    ".data",
    ".sdata",
    ".bss",
    ".sbss",
    ".lit4",
    ".lit8",
]
SECTION_BASE_SYMBOLS: dict[str, str] = {
    ".text": "FUNC_ADDR",
    ".rodata": "RODATA_BASE",
    ".data": "DATA_BASE",
    ".sdata": "SDATA_BASE",
    ".bss": "BSS_BASE",
    ".sbss": "SBSS_BASE",
    ".lit4": "LIT4_BASE",
    ".lit8": "LIT8_BASE",
}

ALWAYS_REQUIRED_SYMBOLS: list[str] = [
    "GP_ADDR",
    "FUNC_ADDR",
]


class Tools(pydantic.BaseModel):
    compiler: str
    linker: str = DEFAULT_LD
    strip: str = DEFAULT_STRIP
    objcopy: str = DEFAULT_OBJCOPY


class Flags(pydantic.BaseModel):
    cflags: str = ""
    ldflags: str = ""


class Sections(pydantic.BaseModel):
    rodata: Optional[int] = None
    data: Optional[int] = None
    sdata: Optional[int] = None
    bss: Optional[int] = None
    sbss: Optional[int] = None
    lit4: Optional[int] = None
    lit8: Optional[int] = None


class ReforgeConfig(pydantic.BaseModel):
    name: str
    address: int
    gp: Optional[int] = None
    known_symbols: Optional[str] = None
    tools: Tools
    flags: Flags = Flags()
    sections: Sections = Sections()

    @classmethod
    def load_from_file(cls, path: Path) -> ReforgeConfig:
        """
        Load settings.toml and validate.
        """
        data = toml.load(path)
        return cls.model_validate(data)  # type: ignore


def extract_non_empty_sections(obj_file: Path) -> list[str]:
    """
    Extract non-empty sections from ELF object.
    """
    sections: list[str] = []

    with obj_file.open("rb") as f:
        elf: ELFFile = ELFFile(f)  # pyright: ignore[reportUnknownMemberType]
        all_sections: dict[str, Section] = {s.name: s for s in cast(Iterator[Section], elf.iter_sections())}  # pyright: ignore

        for sec in SECTION_ORDER:
            s: Section | None = all_sections.get(sec)
            if s and cast(Any, s.header).sh_size > 0:  # pyright: ignore[reportUnknownMemberType]
                sections.append(sec)

    return sections


def extract_undefined_symbols(obj_file: Path) -> list[str]:
    """
    Extract undefined symbols from ELF object.
    """
    symbols: list[str] = []

    with obj_file.open("rb") as f:
        elf: ELFFile = ELFFile(f)  # pyright: ignore[reportUnknownMemberType]

        for section in cast(Iterator[Section], elf.iter_sections()):  # pyright: ignore[reportUnknownMemberType]
            if not isinstance(section, SymbolTableSection):
                continue

            for sym in section.iter_symbols():
                if cast(dict[str, str], sym.entry)["st_shndx"] == "SHN_UNDEF" and sym.name:  # pyright: ignore[reportUnknownMemberType]
                    symbols.append(cast(str, sym.name))  # pyright: ignore[reportUnknownMemberType]

    return sorted(set(symbols))


def write_linker_script(sections: list[str], output_file: Path) -> None:
    """
    Write minimal linker script with GP and section bases.
    """
    with output_file.open("w") as out:
        out.write("SECTIONS {\n")
        out.write("  _gp = GP_ADDR;\n\n")

        for sec in sections:
            base_sym: str | None = SECTION_BASE_SYMBOLS.get(sec)

            if base_sym:
                out.write(f"  . = {base_sym};\n")

            out.write(f"  {sec} : {{ *({sec}*) }}\n\n")

        out.write("  /DISCARD/ : { *(*) }\n")
        out.write("}\n")


def load_known_symbols(file_path: Path) -> dict[str, str]:
    """
    Load known symbols file.
    """
    # Matches: SYMBOL = 0x1234; (with optional trailing comment)
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+)\s*;(?:\s*//.*)?$")

    known: dict[str, str] = {}

    with file_path.open() as f:
        for line in f:
            if m := pattern.match(line):
                name, val = m.groups()
                known[name.strip()] = f"0x{int(val, 16):08x}"

    return known


def write_symbols_file(
    symbols: list[str],
    sections: list[str],
    func_addr: int,
    output_file: Path,
    placeholder: str,
    gp: int | None = None,
    known_symbols: dict[str, str] | None = None,
    prefilled_sections: dict[str, int] | None = None,
) -> None:
    """
    Write symbols file including GP_ADDR, section base addresses, FUNC_ADDR, and other undefined symbols.
    """
    known_symbols = known_symbols or {}
    prefilled_sections = prefilled_sections or {}
    used_symbols: set[str] = set(symbols)

    out_lines: list[str] = []

    gp_str: str = f"0x{gp:08x}" if gp is not None else placeholder
    comment = "" if gp is not None else " // TODO: replace with correct address"
    out_lines.append(f"GP_ADDR = {gp_str};{comment}")
    out_lines.append("")

    for sec in sections:
        if sec == ".text":
            continue  # FUNC_ADDR handled separately

        if sec not in SECTION_BASE_SYMBOLS:
            print("[reforge] ERROR: unsupported section {sec}")
            exit(1)

        base_sym: str = SECTION_BASE_SYMBOLS[sec]
        field_name: str = sec.lstrip(".")  # ".data" -> "data"
        addr_val: int | None = prefilled_sections.get(field_name)

        if addr_val is not None:
            addr_str = f"0x{addr_val:08x}"
            comment = ""
        else:
            addr_str = "0x00000000"
            comment = " // TODO: replace with correct address"

        out_lines.append(f"{base_sym} = {addr_str};{comment}")

    out_lines.append("")

    # Populate FUNC_ADDR
    func_addr_str = f"0x{func_addr:08x}"
    out_lines.append(f"FUNC_ADDR = {func_addr_str};")
    out_lines.append("")

    # Populate other undefined symbols
    reserved: set[str] = set(ALWAYS_REQUIRED_SYMBOLS) | {
        SECTION_BASE_SYMBOLS[sec] for sec in sections if sec in SECTION_BASE_SYMBOLS and sec != ".text"
    }
    other_symbols: list[str] = sorted(used_symbols - reserved)
    for sym in other_symbols:
        addr: str = known_symbols.get(sym, placeholder)
        comment = "" if addr != placeholder else " // TODO: replace with correct address"
        out_lines.append(f"{sym} = {addr};{comment}")

    # Write to file
    with output_file.open("w") as out:
        for line in out_lines:
            out.write(line + "\n")


def cmd_init(args: argparse.Namespace) -> None:
    """
    Initialize build environment using settings.toml and source.c in the specified folder.
    """
    env_dir: Path = cast(Path, args.folder).resolve()
    source_file: Path = env_dir / "source.c"
    settings_file: Path = env_dir / "settings.toml"

    if not source_file.exists():
        raise FileNotFoundError(f"source.c not found in {env_dir}")

    if not settings_file.exists():
        raise FileNotFoundError(f"settings.toml not found in {env_dir}")

    config: ReforgeConfig = ReforgeConfig.load_from_file(settings_file)

    build_dir: Path = env_dir / "build"
    build_dir.mkdir(exist_ok=True, parents=True)
    obj_file: Path = build_dir / "source.o"

    # Compile object
    cflags: list[str] = config.flags.cflags.split()
    subprocess.run([config.tools.compiler, "-c", *cflags, "-o", str(obj_file), str(source_file)], check=True)
    subprocess.run([config.tools.strip, str(obj_file), "-N", "dummy-symbol-name"], check=True)

    # Extract sections and symbols
    sections: list[str] = extract_non_empty_sections(obj_file)
    symbols: list[str] = extract_undefined_symbols(obj_file)
    write_linker_script(sections, env_dir / "link.ld")

    known_symbols: dict[str, str] = {}
    if config.known_symbols:
        known_symbols = load_known_symbols(Path(config.known_symbols))

    # Prepare prefilled section addresses from TOML
    prefilled_sections: dict[str, int] = {k: v for k, v in config.sections.model_dump().items() if v is not None}

    write_symbols_file(
        symbols,
        sections,
        config.address,
        env_dir / "symbols.sym",
        f"0x{PLACEHOLDER_ADDRESS:08x}",
        config.gp,
        known_symbols,
        prefilled_sections,
    )

    # Write Makefile
    makefile_path: Path = env_dir / "Makefile"
    makefile_path.write_text(f"""\
CC      := {config.tools.compiler}
STRIP   := {config.tools.strip}
LD      := {config.tools.linker}
OBJCOPY := {config.tools.objcopy}

CFLAGS  := {config.flags.cflags}
LDFLAGS := -T link.ld -T symbols.sym {config.flags.ldflags}

BUILD   := build
OBJ     := $(BUILD)/source.o
ELF     := $(BUILD)/source.elf
BIN     := $(BUILD)/source.bin

.PHONY: all clean hash
.DEFAULT_GOAL := $(BIN)

all: clean $(BIN)

$(BUILD):
\t@mkdir -p $(BUILD)

$(OBJ): source.c | $(BUILD)
\t@echo "[reforge] Compiling $<"
\t@$(CC) -c $(CFLAGS) -o $@ $<
\t@$(STRIP) $@ -N dummy-symbol-name

$(ELF): $(OBJ) link.ld symbols.sym | $(BUILD)
\t@echo "[reforge] Linking $@"
\t@$(LD) -EL -o $@ $(OBJ) $(LDFLAGS)

$(BIN): $(ELF) | $(BUILD)
\t@echo "[reforge] Generating binary $@"
\t@$(OBJCOPY) -O binary --only-section=.text $< $@

hash: $(BIN)
\t@echo -n "[reforge] SHA1 checksum (rebuilt): "; sha1sum $(BIN) | cut -d' ' -f1
\t@if [ -f target.bin ]; then \\
\t\techo -n "[reforge] SHA1 checksum (target):  "; sha1sum target.bin | cut -d' ' -f1; \\
\t\torig=$$(sha1sum target.bin | cut -d' ' -f1); \\
\t\tnew=$$(sha1sum $(BIN) | cut -d' ' -f1); \\
\t\tif [ "$$orig" = "$$new" ]; then echo "[reforge] ✅ Match: binaries are identical"; \\
\t\telse echo "[reforge] ❌ Mismatch: binaries differ"; fi; \\
\telse \\
\t\techo "[reforge] No target.bin found (skipping target checksum)"; \\
\tfi

clean:
\t@echo "[reforge] Cleaning build directory"
\t@rm -rf $(BUILD)
""")

    resolved_count = sum(1 for s in symbols if s in known_symbols)
    print(f"[reforge] Sections found: {len(sections)}")
    print(f"[reforge] Undefined symbols found: {len(symbols)}")
    if known_symbols:
        print(f"[reforge] Resolved using known symbols: {resolved_count}/{len(symbols)}")
    print(f"[reforge] Environment created at: {env_dir}")


def main() -> None:
    """
    Main entry point: parse arguments and dispatch commands.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="reforge", description="Reforge: ELF function build environment generator"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser(
        "init", help="Initialize environment from folder containing source.c and settings.toml"
    )
    p_init.add_argument("folder", type=Path, help="Path to folder containing source.c and settings.toml")
    p_init.set_defaults(func=cmd_init)

    args: argparse.Namespace = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
