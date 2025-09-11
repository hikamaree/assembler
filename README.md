# SS Toolchain

A system software project implementing a simple toolchain for an abstract computer system.  
The project consists of three main components:

- **Assembler** – Translates assembly source code into object files based on a custom instruction set.
- **Linker** – Merges one or more object files into an executable memory image.
- **Emulator** – Interprets and executes the program inside a simulated CPU and memory environment.

---

## Features
- One-pass assembler with support for labels, directives, and instruction encoding.
- Linker independent of target architecture with support for relocation and section placement.
- Emulator with register and memory state tracking, instruction execution, and halt detection.
- Support for interrupts, terminal I/O, and timer (depending on implementation level).

---

## Usage

### Assembler
```bash
./assembler -o output.o input.s
```

### Linker
```bash
./linker -hex -place=text@0x40000000 -place=data@0x4000F000 -o program.hex input.o
```

### Emulator
```bash
./emulator program.hex
```

---

## Requirements
- Linux (amd64)
- C compiler (gcc)
- flex, bison
