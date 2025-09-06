# Reforge

Reforge is a tool to aid in game recompilation and modding. When recompiling a function to inject it into a game in place of the original, the new code must be linked so that all symbols match their original addresses. If the addresses do not line up, the replacement code will not function correctly.  

Reforge automates this process: it analyzes your function, detects undefined symbols, generates a tailored linker script and symbol file, and creates a complete build environment for that single function. With this setup, you can quickly recompile a function in a way that matches the original game binary layout, ensuring compatibility.

## Limitations

Reforge is still in an early stage of development. It is currently designed primarily for MIPS toolchains, with a focus on PlayStation 2 recompilation workflows. The same approach should also work for other MIPS-based platforms such as the PS1 or Nintendo 64, and could likely be adapted for use with compilers other than GCC.  

## Features

- **ELF analysis**: extract non-empty sections and undefined symbols from object files.  
- **Linker script generation**: automatically produce a minimal script with base symbols.  
- **Symbol management**: merge user-provided known symbol databases with auto-discovered undefined symbols.  
- **Environment setup**: generate a ready-to-use build folder with Makefile, linker script, symbols file, and your source.  
- **Hash verification**: compare the `.text` section of the rebuilt function with the original binary if provided.

## Installation

It is recommended to use a Python virtual environment.  
Create and activate a virtual environment as follows:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Once the virtual environment is active, install Reforge using `pip`:

```bash
pip install .
```

or build a wheel first:

```bash
pip install hatchling
hatch build
pip install dist/reforge-0.1.0-py3-none-any.whl
```

## Usage

After installation, the `reforge` CLI is available. To create a build environment for a function:

```bash
reforge init /path/to/function_folder
```

Where `/path/to/function_folder` contains:

- `source.c` — the function source code to recompile.  
- `settings.toml` — the configuration file specifying `name`, `address`, optional `gp`, toolchain paths, compiler/linker flags, and optionally pre-defined section addresses or known symbols.  

Running `reforge init` will generate inside the same folder:

- `Makefile` — for compiling the function.  
- `link.ld` — the tailored linker script.  
- `symbols.sym` — undefined symbols and section base addresses.  
- `build/` — the build folder for object, ELF, and binary outputs.  

Once the environment is ready, you can compile the function using:

```bash
make
```

You can also compute the SHA1 hash of the compiled `.text` section with:

```bash
make hash
```

If you manually extract the original function from the ELF into `target.bin` in the environment folder, `make hash` will additionally compute its hash and compare it to the rebuilt `.text` section to verify they match.
