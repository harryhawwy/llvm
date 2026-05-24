/**
 * Binary analysis: function detection, xrefs, strings, prologue scanning
 */
import { disassemble, disassembleFunction } from './disasm/engine.js';

// ── Function prologue patterns (x86-64) ─────────────────────────────────────
const X64_PROLOGUES = [
  [0x55, 0x48, 0x89, 0xe5],          // push rbp; mov rbp, rsp
  [0x55, 0x48, 0x8b, 0xec],          // push rbp; mov rbp, rsp (alt enc)
  [0x48, 0x83, 0xec],                 // sub rsp, N
  [0x48, 0x81, 0xec],                 // sub rsp, NN
  [0x41, 0x57],                       // push r15
  [0x41, 0x56],                       // push r14
  [0x53, 0x48, 0x83, 0xec],          // push rbx; sub rsp
];

const ARM64_PROLOGUES = [
  [0xfd, 0x7b, 0xbe, 0xa9],          // stp x29, x30, [sp, #-N]!
  [0xfd, 0x43, 0x00, 0x91],          // add x29, sp, #0
];

/** Find function entry points by scanning for prologues */
export function findFunctionsByPrologue(bytes, vaddr, arch) {
  const funcs = [];
  const step  = arch === 'arm64' || arch === 'arm' ? 4 : 1;
  const prologues = arch === 'arm64' ? ARM64_PROLOGUES : X64_PROLOGUES;

  outer:
  for (let i = 0; i < bytes.length - 8; i += step) {
    for (const p of prologues) {
      let match = true;
      for (let j = 0; j < p.length; j++) {
        if (bytes[i + j] !== p[j]) { match = false; break; }
      }
      if (match) {
        funcs.push({ address: vaddr + i, name: `sub_${(vaddr + i).toString(16)}`, size: 0 });
        i += 15; // skip ahead
        continue outer;
      }
    }
  }
  return funcs;
}

// ── Xref analysis ─────────────────────────────────────────────────────────────

export class XrefDatabase {
  constructor() {
    // addr → [ {from, type, func} ]
    this._to   = new Map();
    // addr → [ {to, type, func} ]
    this._from = new Map();
  }

  add(from, to, type, funcName) {
    if (!this._to.has(to)) this._to.set(to, []);
    this._to.get(to).push({ from, type, func: funcName });

    if (!this._from.has(from)) this._from.set(from, []);
    this._from.get(from).push({ to, type, func: funcName });
  }

  /** References TO addr (who calls/jumps to this address) */
  xrefsTo(addr) { return this._to.get(addr) || []; }
  /** References FROM addr (what does this instruction reference) */
  xrefsFrom(addr) { return this._from.get(addr) || []; }

  /** All xref target addresses */
  allTargets() { return this._to; }
}

// ── Full binary analysis ───────────────────────────────────────────────────────

export class BinaryAnalyzer {
  constructor(parser, arch) {
    this.parser = parser;
    this.arch   = arch;
    this.functions   = [];
    this.strings     = [];
    this.xrefs       = new XrefDatabase();
    this.funcMap     = new Map(); // addr → func
    this.stringMap   = new Map(); // addr → string value
    this.addrNames   = new Map(); // addr → display name
    this._sections   = [];
    this._progress   = null; // callback(msg, pct)
  }

  onProgress(cb) { this._progress = cb; return this; }

  _report(msg, pct) {
    if (this._progress) this._progress(msg, pct);
  }

  async analyze() {
    this._report('Parsing binary structure…', 5);

    // 1. Get strings
    this._report('Extracting strings…', 10);
    this.strings = this.parser.getStrings(5);
    for (const s of this.strings) this.stringMap.set(s.address, s.value);

    // 2. Get known functions from symbol table
    this._report('Reading symbol table…', 20);
    const knownFuncs = this.parser.getFunctions();

    // 3. Get code sections
    this._sections = this.parser.getCodeSections ? this.parser.getCodeSections() : [];

    // 4. Prologue scanning for unknown functions
    this._report('Scanning for function prologues…', 30);
    const prologueFuncs = [];
    for (const sec of this._sections) {
      const found = findFunctionsByPrologue(sec.bytes, sec.vaddr, this.arch);
      prologueFuncs.push(...found);
    }

    // 5. Merge functions (known symbols take priority)
    this._report('Building function list…', 40);
    const allFuncs = new Map();
    for (const f of prologueFuncs) allFuncs.set(f.address, f);
    for (const f of knownFuncs)    allFuncs.set(f.address, { ...allFuncs.get(f.address), ...f });

    // 6. Disassemble and compute boundaries + xrefs
    this._report('Disassembling functions…', 50);
    const funcList = [...allFuncs.values()].sort((a, b) => a.address - b.address);

    for (let i = 0; i < funcList.length; i++) {
      const f    = funcList[i];
      const next = funcList[i + 1];

      // Find the section this function lives in
      const sec = this._sections.find(s =>
        f.address >= s.vaddr && f.address < s.vaddr + s.size
      );
      if (!sec) continue;

      const maxEnd = next ? Math.min(next.address, sec.vaddr + sec.size) : sec.vaddr + sec.size;

      const { insns, detectedEnd } = disassembleFunction(
        sec.bytes, sec.vaddr, f.address, maxEnd, this.arch
      );

      f.insns       = insns;
      f.size        = detectedEnd - f.address;
      f.end         = detectedEnd;
      f.sectionName = sec.name;

      // Build xrefs from this function's instructions
      for (const ins of insns) {
        if (ins.isCall || ins.isJmp) {
          const target = ins.branchTarget || _parseImmTarget(ins.op_str);
          if (target) {
            const type = ins.isCall ? 'call' : 'jmp';
            this.xrefs.add(ins.address, target, type, f.name);
          }
        }
        // Data references (address-sized immediates pointing into data sections)
        const dataRef = _extractDataRef(ins.op_str, this.parser);
        if (dataRef) this.xrefs.add(ins.address, dataRef, 'data', f.name);
      }

      const pct = 50 + Math.round((i / funcList.length) * 40);
      if (i % 10 === 0) this._report(`Disassembled ${i}/${funcList.length} functions…`, pct);
    }

    this.functions = funcList.filter(f => f.insns && f.insns.length > 0);

    // 7. Build address → name map
    this._report('Building address map…', 92);
    for (const f of this.functions)     this.addrNames.set(f.address, f.name);
    for (const f of this.parser.imports || []) {
      if (f.address) this.addrNames.set(f.address, f.name + '@plt');
    }
    for (const s of this.strings)       this.stringMap.set(s.address, s.value);

    this._report('Done', 100);
    return this;
  }

  /** Find function by address (exact or containing) */
  functionAt(addr) {
    // Exact
    if (this.funcMap.size === 0) {
      for (const f of this.functions) this.funcMap.set(f.address, f);
    }
    if (this.funcMap.has(addr)) return this.funcMap.get(addr);
    // Containing
    for (const f of this.functions) {
      if (addr >= f.address && addr < f.end) return f;
    }
    return null;
  }

  /** Find function by name (fuzzy) */
  functionByName(name) {
    const lower = name.toLowerCase();
    return this.functions.find(f => f.name.toLowerCase().includes(lower));
  }

  /** Disassemble at arbitrary offset on-demand (for jump targets not in funcList) */
  disasmAt(addr, maxInsns = 64) {
    const sec = this._sections.find(s => addr >= s.vaddr && addr < s.vaddr + s.size);
    if (!sec) return [];
    const off   = addr - sec.vaddr;
    const chunk = sec.bytes.subarray(off, off + maxInsns * 15);
    return disassemble(chunk, addr, this.arch, maxInsns);
  }

  /** Get raw bytes around an address for hex view */
  getBytesAt(addr, length = 256) {
    const sec = this._sections.find(s => addr >= s.vaddr && addr < s.vaddr + s.size);
    if (!sec) return null;
    const off   = addr - sec.vaddr;
    return { bytes: sec.bytes.subarray(off, off + length), vaddr: addr };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _parseImmTarget(opStr) {
  if (!opStr) return null;
  const m = opStr.match(/^(?:qword ptr \[rip [+-] 0x[0-9a-f]+\]|0x([0-9a-fA-F]+))$/);
  if (m && m[1]) return parseInt(m[1], 16);
  const m2 = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (m2) return parseInt(m2[1], 16);
  return null;
}

function _extractDataRef(opStr, parser) {
  if (!opStr) return null;
  const m = opStr.match(/0x([0-9a-fA-F]+)/g);
  if (!m) return null;
  for (const hex of m) {
    const addr = parseInt(hex, 16);
    if (addr > 0x1000 && parser.addrToOffset) {
      const off = parser.addrToOffset(addr);
      if (off !== null) return addr;
    }
  }
  return null;
}
