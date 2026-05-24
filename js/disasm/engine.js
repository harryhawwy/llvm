/**
 * Disassembly engine — wraps iced-x86 (WASM) and Capstone.js (WASM)
 *
 * Load priority:
 *   1. iced-x86  (x86 / x86-64, very accurate)
 *   2. Capstone  (multi-arch fallback)
 *   3. Null engine (hex dump only)
 */

// ── iced-x86 WASM CDN ────────────────────────────────────────────────────────
const ICED_CDN = {
  js  : 'https://cdn.jsdelivr.net/npm/iced-x86@1.21.0/js/web/iced_x86.js',
  wasm: 'https://cdn.jsdelivr.net/npm/iced-x86@1.21.0/js/web/iced_x86_bg.wasm',
};

// ── Capstone.js CDN (asm.js, no WASM required) ──────────────────────────────
const CAPSTONE_CDN = 'https://cdn.jsdelivr.net/npm/@xem/capstone@0.0.6/src/capstone.js';

let _icedModule   = null;
let _capstoneReady = false;
let _loadPromise   = null;

// ── Instruction categories (for coloring) ────────────────────────────────────
function classify(mnem) {
  const m = mnem.toLowerCase();
  if (m === 'call')                         return 'call';
  if (m === 'ret' || m === 'retn' || m === 'retf') return 'ret';
  if (m === 'nop')                          return 'nop';
  if (m.startsWith('j'))                   return 'jmp';
  if (m.startsWith('mov') || m === 'lea' || m === 'push' || m === 'pop') return 'mov';
  if (m === 'add' || m === 'sub' || m === 'mul' || m === 'div' ||
      m === 'imul'|| m === 'idiv'|| m === 'inc' || m === 'dec' ||
      m === 'and' || m === 'or'  || m === 'xor' || m === 'not' ||
      m === 'shl' || m === 'shr' || m === 'sar' || m === 'rol' || m === 'ror') return 'math';
  if (m === 'cmp' || m === 'test')          return 'cmp';
  return 'other';
}

// ── IcedX86 engine ───────────────────────────────────────────────────────────
async function loadIced() {
  try {
    const mod = await import(/* @vite-ignore */ ICED_CDN.js);
    if (mod.default) {
      await mod.default(ICED_CDN.wasm);
    }
    _icedModule = mod;
    return true;
  } catch (e) {
    console.warn('[disasm] iced-x86 failed to load:', e.message);
    return false;
  }
}

// ── Capstone fallback ────────────────────────────────────────────────────────
async function loadCapstone() {
  return new Promise((resolve) => {
    if (typeof window.cs !== 'undefined') { resolve(true); return; }
    const s = document.createElement('script');
    s.src = CAPSTONE_CDN;
    s.onload  = () => { _capstoneReady = true; resolve(true); };
    s.onerror = () => resolve(false);
    document.head.appendChild(s);
  });
}

// ── Public loader ─────────────────────────────────────────────────────────────
export async function initDisassembler() {
  if (_loadPromise) return _loadPromise;
  _loadPromise = (async () => {
    const ok = await loadIced();
    if (!ok) await loadCapstone();
  })();
  return _loadPromise;
}

// ── Main disassemble function ─────────────────────────────────────────────────

/**
 * Disassemble bytes starting at virtualAddress.
 * @param {Uint8Array} bytes
 * @param {number}     virtualAddress  base address of bytes[0]
 * @param {string}     arch  'x64'|'x32'|'arm64'|'arm'
 * @param {number}     [maxInsns]  max instructions (0 = all)
 * @returns {Instruction[]}
 */
export function disassemble(bytes, virtualAddress, arch, maxInsns = 0) {
  if (_icedModule && (arch === 'x64' || arch === 'x32')) {
    return _disasmIced(bytes, virtualAddress, arch, maxInsns);
  }
  if (_capstoneReady && typeof window.cs !== 'undefined') {
    return _disasmCapstone(bytes, virtualAddress, arch, maxInsns);
  }
  // Fallback: emit hex rows
  return _disasmHex(bytes, virtualAddress, maxInsns);
}

// ── iced-x86 backend ─────────────────────────────────────────────────────────
function _disasmIced(bytes, ip, arch, maxInsns) {
  const iced = _icedModule;
  const bitness = arch === 'x64' ? 64 : 32;
  const decoder = new iced.Decoder(bitness, bytes, { ip });

  const insns  = [];
  const fmtr   = new iced.Formatter(iced.FormatterSyntax.Intel);
  fmtr.firstOperandCharIndex = 8; // pad mnemonic
  fmtr.uppercaseMnemonics = false;

  while (decoder.canDecode()) {
    if (maxInsns > 0 && insns.length >= maxInsns) break;

    const instr  = decoder.decode();
    const output = new iced.StringOutput();
    fmtr.formatInstruction(instr, output);
    const text   = output.toString().trim();

    // Split mnemonic / operands
    const spaceIdx = text.indexOf(' ');
    const mnem     = spaceIdx === -1 ? text : text.slice(0, spaceIdx);
    const ops      = spaceIdx === -1 ? ''   : text.slice(spaceIdx + 1).trim();

    const byteLen = instr.length;
    const rawBytes = Array.from(bytes.subarray(instr.ip - ip, instr.ip - ip + byteLen));

    insns.push({
      address : instr.ip,
      size    : byteLen,
      bytes   : rawBytes,
      mnemonic: mnem,
      op_str  : ops,
      category: classify(mnem),
      isCall  : mnem.toLowerCase() === 'call',
      isRet   : mnem.toLowerCase().startsWith('ret'),
      isJmp   : /^j(?!a$)/i.test(mnem) && mnem.toLowerCase() !== 'jmp' ? false : mnem.toLowerCase().startsWith('j'),
      branchTarget: instr.nearBranchTarget,
    });
  }

  return insns;
}

// ── Capstone backend ──────────────────────────────────────────────────────────
function _disasmCapstone(bytes, ip, arch, maxInsns) {
  const ARCH_MAP = { x64:'CS_ARCH_X86', x32:'CS_ARCH_X86', arm64:'CS_ARCH_ARM64', arm:'CS_ARCH_ARM' };
  const MODE_MAP = { x64:'CS_MODE_64',  x32:'CS_MODE_32',  arm64:'CS_MODE_ARM',   arm:'CS_MODE_ARM' };
  const cs = window.cs;

  try {
    const handle = new cs.Capstone(cs[ARCH_MAP[arch]] || cs.CS_ARCH_X86,
                                    cs[MODE_MAP[arch]] || cs.CS_MODE_64);
    const result = handle.disasm(bytes, ip);
    handle.close();

    const mapped = result
      .slice(0, maxInsns || result.length)
      .map(i => ({
        address : i.address,
        size    : i.size,
        bytes   : i.bytes,
        mnemonic: i.mnemonic,
        op_str  : i.op_str,
        category: classify(i.mnemonic),
        isCall  : i.mnemonic === 'call',
        isRet   : i.mnemonic.startsWith('ret'),
        isJmp   : i.mnemonic.startsWith('j'),
      }));
    return mapped;
  } catch (e) {
    console.warn('[disasm] capstone error:', e);
    return _disasmHex(bytes, ip, maxInsns);
  }
}

// ── Hex fallback ──────────────────────────────────────────────────────────────
function _disasmHex(bytes, ip, maxInsns) {
  const insns = [];
  const limit = maxInsns > 0 ? Math.min(bytes.length, maxInsns * 16) : bytes.length;
  for (let i = 0; i < limit; i += 16) {
    const chunk = Array.from(bytes.subarray(i, i + 16));
    insns.push({
      address : ip + i,
      size    : chunk.length,
      bytes   : chunk,
      mnemonic: '.byte',
      op_str  : chunk.map(b => '0x' + b.toString(16).padStart(2, '0')).join(', '),
      category: 'data',
      isCall  : false,
      isRet   : false,
      isJmp   : false,
    });
  }
  return insns;
}

// ── Disassemble a single function ─────────────────────────────────────────────

/**
 * Disassemble from startAddr until a RET or function end.
 * @param {Uint8Array} sectionBytes  entire section
 * @param {number}     sectionVaddr
 * @param {number}     startAddr
 * @param {number}     endAddr  (0 = detect automatically)
 * @param {string}     arch
 * @returns {{ insns: Instruction[], detectedEnd: number }}
 */
export function disassembleFunction(sectionBytes, sectionVaddr, startAddr, endAddr, arch) {
  const offset = startAddr - sectionVaddr;
  if (offset < 0 || offset >= sectionBytes.length) return { insns: [], detectedEnd: startAddr };

  const slice   = sectionBytes.subarray(offset);
  const maxBytes= (endAddr > startAddr) ? (endAddr - startAddr) : Math.min(slice.length, 65536);
  const chunk   = slice.subarray(0, maxBytes);

  const allInsns = disassemble(chunk, startAddr, arch, 0);

  // Detect function end: stop after unconditional RET/JMP at depth 0
  const insns = [];
  for (const ins of allInsns) {
    insns.push(ins);
    if (ins.isRet) break;
    if (ins.mnemonic.toLowerCase() === 'jmp' && !_isConditionalJmp(ins.mnemonic)) break;
  }

  const detectedEnd = insns.length > 0
    ? insns[insns.length - 1].address + insns[insns.length - 1].size
    : startAddr;

  return { insns, detectedEnd };
}

function _isConditionalJmp(mnem) {
  return /^j[^m]/i.test(mnem); // jne, je, jz, jnz, etc. — not jmp
}

// ── Operand highlighting ───────────────────────────────────────────────────────

/**
 * Convert op_str to highlighted HTML spans.
 */
export function highlightOperands(mnem, opStr, knownAddrs, stringMap) {
  if (!opStr) return '';
  const m = mnem.toLowerCase();

  // For call/jmp — whole operand is a branch target
  if (m === 'call' || m === 'jmp' || m.startsWith('j')) {
    const addr = parseAddr(opStr);
    if (addr !== null && knownAddrs) {
      const name = knownAddrs.get(addr);
      if (name) {
        const cls = m === 'call' ? 'op-call' : 'op-jmp';
        return `<span class="${cls}" data-addr="0x${addr.toString(16)}">${escHtml(name)}</span>`;
      }
    }
    return `<span class="op-jmp">${escHtml(opStr)}</span>`;
  }

  // Tokenize by comma, then per-token
  return opStr.split(',').map((tok, i) => {
    const t = tok.trim();
    const sep = i === 0 ? '' : '<span class="op-sep">, </span>';

    // Memory reference [...]
    if (t.includes('[')) {
      // Check if this might be a string reference
      const addrMatch = t.match(/0x([0-9a-fA-F]+)/);
      if (addrMatch && stringMap) {
        const addr = parseInt(addrMatch[1], 16);
        const str  = stringMap.get(addr);
        if (str) {
          const preview = str.length > 30 ? str.slice(0, 30) + '…' : str;
          return sep + `<span class="op-mem">${escHtml(t)}</span><span class="op-str"> ; "${escHtml(preview)}"</span>`;
        }
      }
      return sep + `<span class="op-mem">${escHtml(t)}</span>`;
    }

    // Immediate / address
    if (/^(0x[0-9a-fA-F]+|\d+)$/.test(t)) {
      const addr = parseAddr(t);
      if (addr !== null && knownAddrs) {
        const name = knownAddrs.get(addr);
        if (name) return sep + `<span class="op-call" data-addr="0x${addr.toString(16)}">${escHtml(name)}</span>`;
      }
      return sep + `<span class="op-imm">${escHtml(t)}</span>`;
    }

    // Register
    if (isRegister(t)) return sep + `<span class="op-reg">${escHtml(t)}</span>`;

    return sep + escHtml(t);
  }).join('');
}

function parseAddr(s) {
  s = s.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s, 16);
  if (/^\d+$/.test(s))            return parseInt(s, 10);
  return null;
}

const REGS = new Set([
  'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp',
  'r8','r9','r10','r11','r12','r13','r14','r15',
  'eax','ebx','ecx','edx','esi','edi','esp','ebp',
  'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d',
  'ax','bx','cx','dx','si','di','sp','bp',
  'al','bl','cl','dl','ah','bh','ch','dh',
  'sil','dil','spl','bpl',
  'xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7',
  'ymm0','ymm1','ymm2','ymm3','ymm4','ymm5','ymm6','ymm7',
  'zmm0','zmm1','zmm2','zmm3','zmm4','zmm5','zmm6','zmm7',
  'rip','eip','rflags','eflags',
  // ARM
  'x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15',
  'x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','x29','x30',
  'w0','w1','w2','w3','w4','w5','w6','w7','w8','w9','w10','w11','w12','w13','w14','w15',
  'sp','lr','pc','xzr','wzr',
]);

function isRegister(tok) {
  // Remove size prefix like dword ptr, qword ptr
  const t = tok.toLowerCase().replace(/^(byte|word|dword|qword|tbyte|xmmword|ymmword)\s+(ptr\s+)?/, '').trim();
  return REGS.has(t);
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
