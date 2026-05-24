import { disassemble, disassembleFunction } from './disasm/engine.js';

const X64_PROLOGUES = [
  [0x55, 0x48, 0x89, 0xe5],
  [0x55, 0x48, 0x8b, 0xec],
  [0x48, 0x83, 0xec],
  [0x48, 0x81, 0xec],
  [0x41, 0x57],
  [0x53, 0x48, 0x83, 0xec],
];

const ARM64_PROLOGUES = [
  [0xfd, 0x7b, 0xbe, 0xa9],
];

export function findFunctionsByPrologue(bytes, vaddr, arch) {
  const funcs = [];
  const step = arch === 'arm64' || arch === 'arm' ? 4 : 1;
  const prologues = arch === 'arm64' ? ARM64_PROLOGUES : X64_PROLOGUES;
  outer:
  for (let i = 0; i < bytes.length - 8; i += step) {
    for (const p of prologues) {
      let match = true;
      for (let j = 0; j < p.length; j++) { if (bytes[i+j] !== p[j]) { match = false; break; } }
      if (match) { funcs.push({ address: vaddr+i, name: `sub_${(vaddr+i).toString(16)}`, size: 0 }); i += 15; continue outer; }
    }
  }
  return funcs;
}

export class XrefDatabase {
  constructor() { this._to = new Map(); this._from = new Map(); }
  add(from, to, type, funcName) {
    if (!this._to.has(to)) this._to.set(to, []);
    this._to.get(to).push({ from, type, func: funcName });
    if (!this._from.has(from)) this._from.set(from, []);
    this._from.get(from).push({ to, type, func: funcName });
  }
  xrefsTo(addr) { return this._to.get(addr) || []; }
  xrefsFrom(addr) { return this._from.get(addr) || []; }
  allTargets() { return this._to; }
}

export class BinaryAnalyzer {
  constructor(parser, arch) {
    this.parser = parser; this.arch = arch;
    this.functions = []; this.strings = [];
    this.xrefs = new XrefDatabase();
    this.funcMap = new Map(); this.stringMap = new Map(); this.addrNames = new Map();
    this._sections = []; this._progress = null;
  }
  onProgress(cb) { this._progress = cb; return this; }
  _report(msg, pct) { if (this._progress) this._progress(msg, pct); }

  async analyze() {
    this._report('Extracting strings…', 10);
    this.strings = this.parser.getStrings(5);
    for (const s of this.strings) this.stringMap.set(s.address, s.value);

    this._report('Reading symbol table…', 20);
    const knownFuncs = this.parser.getFunctions();

    this._sections = this.parser.getCodeSections ? this.parser.getCodeSections() : [];

    this._report('Scanning for function prologues…', 30);
    const prologueFuncs = [];
    for (const sec of this._sections) {
      prologueFuncs.push(...findFunctionsByPrologue(sec.bytes, sec.vaddr, this.arch));
    }

    this._report('Building function list…', 40);
    const allFuncs = new Map();
    for (const f of prologueFuncs) allFuncs.set(f.address, f);
    for (const f of knownFuncs) allFuncs.set(f.address, { ...allFuncs.get(f.address), ...f });

    this._report('Disassembling…', 50);
    const funcList = [...allFuncs.values()].sort((a, b) => a.address - b.address);

    for (let i = 0; i < funcList.length; i++) {
      const f = funcList[i];
      const next = funcList[i+1];
      const sec = this._sections.find(s => f.address >= s.vaddr && f.address < s.vaddr + s.size);
      if (!sec) continue;
      const maxEnd = next ? Math.min(next.address, sec.vaddr + sec.size) : sec.vaddr + sec.size;
      const { insns, detectedEnd } = disassembleFunction(sec.bytes, sec.vaddr, f.address, maxEnd, this.arch);
      f.insns = insns; f.size = detectedEnd - f.address; f.end = detectedEnd; f.sectionName = sec.name;
      for (const ins of insns) {
        if (ins.isCall || ins.isJmp) {
          const target = ins.branchTarget || _parseImmTarget(ins.op_str);
          if (target) this.xrefs.add(ins.address, target, ins.isCall ? 'call' : 'jmp', f.name);
        }
        const dataRef = _extractDataRef(ins.op_str, this.parser);
        if (dataRef) this.xrefs.add(ins.address, dataRef, 'data', f.name);
      }
      if (i % 10 === 0) this._report(`Disassembled ${i}/${funcList.length}…`, 50 + Math.round(i/funcList.length*40));
    }

    this.functions = funcList.filter(f => f.insns && f.insns.length > 0);
    this._report('Building address map…', 92);
    for (const f of this.functions) this.addrNames.set(f.address, f.name);
    for (const f of (this.parser.imports||[])) if (f.address) this.addrNames.set(f.address, f.name+'@plt');
    this._report('Done', 100);
    return this;
  }

  functionAt(addr) {
    if (this.funcMap.size === 0) for (const f of this.functions) this.funcMap.set(f.address, f);
    if (this.funcMap.has(addr)) return this.funcMap.get(addr);
    for (const f of this.functions) if (addr >= f.address && addr < f.end) return f;
    return null;
  }
  functionByName(name) {
    const lower = name.toLowerCase();
    return this.functions.find(f => f.name.toLowerCase().includes(lower));
  }
  getBytesAt(addr, length=256) {
    const sec = this._sections.find(s => addr >= s.vaddr && addr < s.vaddr + s.size);
    if (!sec) return null;
    return { bytes: sec.bytes.subarray(addr - sec.vaddr, addr - sec.vaddr + length), vaddr: addr };
  }
}

function _parseImmTarget(opStr) {
  if (!opStr) return null;
  const m = opStr.match(/^0x([0-9a-fA-F]+)$/);
  return m ? parseInt(m[1], 16) : null;
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