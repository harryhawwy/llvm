# WebDis — LLVM Web Disassembler

An IDA Pro-style binary analysis tool that runs entirely in your browser — no server, no install.

**Live demo:** https://harryhawwy.github.io/llvm

## Features

- **ELF / PE / Mach-O** binary parsing (drag & drop)
- **x86-64** disassembly via [iced-x86](https://github.com/icedland/iced) (WebAssembly)
- **ARM / ARM64 / MIPS** fallback via Capstone.js
- **Function detection** — symbol table + prologue scanning, start/end boundaries
- **Cross-references (xrefs)** — who calls what, where strings are used
- **String extraction** — from `.rodata`, `.data`, `__cstring`, etc.
- **IndexedDB cache** — re-opening the same binary is instant
- **IDA-like UI** — function list, strings, imports, sections, hex view

## Usage

1. Open https://harryhawwy.github.io/llvm
2. Click **Open** or drag & drop a binary (ELF, PE `.exe`/`.dll`, Mach-O)
3. Navigate functions in the left panel
4. Click any instruction to see cross-references on the right
5. Use **Ctrl+G** to jump to an address or function name

## Keyboard Shortcuts

| Key          | Action                    |
|--------------|---------------------------|
| `Ctrl+O`     | Open file                 |
| `Ctrl+G`     | Jump to address/function  |
| `Escape`     | Close focus from input    |

## GitHub Pages Setup

1. Go to your repo **Settings → Pages**
2. Set Source: **Deploy from branch → `main` → `/ (root)`**
3. Save — site is live within a minute

## Architecture

```
js/
├── app.js          — Main controller
├── analyzer.js     — Function detection, xref building
├── cache.js        — IndexedDB caching
├── ui.js           — Rendering engine
├── parsers/
│   ├── elf.js      — ELF parser
│   ├── pe.js       — PE parser
│   └── macho.js    — Mach-O parser
└── disasm/
    └── engine.js   — iced-x86 + Capstone wrapper
```

Everything runs in the browser — your binary never leaves your machine.
