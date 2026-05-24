const ICED_CDN = {
  js  : 'https://cdn.jsdelivr.net/npm/iced-x86@1.21.0/js/web/iced_x86.js',
  wasm: 'https://cdn.jsdelivr.net/npm/iced-x86@1.21.0/js/web/iced_x86_bg.wasm',
};

let _icedModule = null;
let _loadPromise = null;

function classify(mnem) {
  const m = mnem.toLowerCase();
  if (m==='call') return 'call';
  if (m==='ret'||m==='retn'||m==='retf') return 'ret';
  if (m==='nop') return 'nop';
  if (m.startsWith('j')) return 'jmp';
  if (m.startsWith('mov')||m==='lea'||m==='push'||m==='pop') return 'mov';
  if (['add','sub','mul','div','imul','idiv','inc','dec','and','or','xor','not','shl','shr','sar'].includes(m)) return 'math';
  if (m==='cmp'||m==='test') return 'cmp';
  return 'other';
}

async function loadIced() {
  try {
    const mod = await import(/* @vite-ignore */ ICED_CDN.js);
    if (mod.default) await mod.default(ICED_CDN.wasm);
    _icedModule = mod;
    return true;
  } catch(e) { console.warn('[disasm] iced-x86 load failed:', e.message); return false; }
}

export async function initDisassembler() {
  if (_loadPromise) return _loadPromise;
  _loadPromise = loadIced();
  return _loadPromise;
}

export function disassemble(bytes, virtualAddress, arch, maxInsns=0) {
  if (_icedModule && (arch==='x64'||arch==='x32')) return _disasmIced(bytes, virtualAddress, arch, maxInsns);
  return _disasmHex(bytes, virtualAddress, maxInsns);
}

function _disasmIced(bytes, ip, arch, maxInsns) {
  const iced = _icedModule;
  const bitness = arch==='x64' ? 64 : 32;
  const decoder = new iced.Decoder(bitness, bytes, { ip });
  const insns = [];
  const fmtr = new iced.Formatter(iced.FormatterSyntax.Intel);
  fmtr.uppercaseMnemonics = false;
  while (decoder.canDecode()) {
    if (maxInsns > 0 && insns.length >= maxInsns) break;
    const instr = decoder.decode();
    const output = new iced.StringOutput();
    fmtr.formatInstruction(instr, output);
    const text = output.toString().trim();
    const spaceIdx = text.indexOf(' ');
    const mnem = spaceIdx===-1 ? text : text.slice(0, spaceIdx);
    const ops  = spaceIdx===-1 ? ''   : text.slice(spaceIdx+1).trim();
    const byteLen = instr.length;
    const rawBytes = Array.from(bytes.subarray(instr.ip - ip, instr.ip - ip + byteLen));
    insns.push({
      address: instr.ip, size: byteLen, bytes: rawBytes,
      mnemonic: mnem, op_str: ops, category: classify(mnem),
      isCall: mnem.toLowerCase()==='call',
      isRet: mnem.toLowerCase().startsWith('ret'),
      isJmp: mnem.toLowerCase().startsWith('j'),
      branchTarget: instr.nearBranchTarget,
    });
  }
  return insns;
}

function _disasmHex(bytes, ip, maxInsns) {
  const insns = [];
  const limit = maxInsns > 0 ? Math.min(bytes.length, maxInsns*16) : bytes.length;
  for (let i = 0; i < limit; i += 16) {
    const chunk = Array.from(bytes.subarray(i, i+16));
    insns.push({ address:ip+i, size:chunk.length, bytes:chunk, mnemonic:'.byte', op_str:chunk.map(b=>'0x'+b.toString(16).padStart(2,'0')).join(', '), category:'data', isCall:false, isRet:false, isJmp:false });
  }
  return insns;
}

export function disassembleFunction(sectionBytes, sectionVaddr, startAddr, endAddr, arch) {
  const offset = startAddr - sectionVaddr;
  if (offset < 0 || offset >= sectionBytes.length) return { insns:[], detectedEnd:startAddr };
  const maxBytes = (endAddr > startAddr) ? (endAddr-startAddr) : Math.min(sectionBytes.length-offset, 65536);
  const chunk = sectionBytes.subarray(offset, offset+maxBytes);
  const allInsns = disassemble(chunk, startAddr, arch, 0);
  const insns = [];
  for (const ins of allInsns) {
    insns.push(ins);
    if (ins.isRet) break;
    if (ins.mnemonic.toLowerCase()==='jmp') break;
  }
  const detectedEnd = insns.length > 0 ? insns[insns.length-1].address + insns[insns.length-1].size : startAddr;
  return { insns, detectedEnd };
}

const REGS = new Set(['rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','r8','r9','r10','r11','r12','r13','r14','r15','eax','ebx','ecx','edx','esi','edi','esp','ebp','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d','ax','bx','cx','dx','si','di','sp','bp','al','bl','cl','dl','ah','bh','ch','dh','sil','dil','spl','bpl','xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7','ymm0','ymm1','ymm2','ymm3','rip','eip','x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x29','x30','w0','w1','w2','w3','sp','lr','pc','xzr','wzr']);

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function parseAddr(s) { s=s.trim(); if(/^0x[0-9a-fA-F]+$/.test(s))return parseInt(s,16); if(/^\d+$/.test(s))return parseInt(s,10); return null; }
function isReg(tok) { return REGS.has(tok.toLowerCase().replace(/^(byte|word|dword|qword|tbyte|xmmword|ymmword)\s+(ptr\s+)?/,'').trim()); }

export function highlightOperands(mnem, opStr, knownAddrs, stringMap) {
  if (!opStr) return '';
  const m = mnem.toLowerCase();
  if (m==='call'||m==='jmp'||m.startsWith('j')) {
    const addr = parseAddr(opStr);
    if (addr !== null && knownAddrs) {
      const name = knownAddrs.get(addr);
      if (name) return `<span class="${m==='call'?'op-call':'op-jmp'}" data-addr="0x${addr.toString(16)}">${escHtml(name)}</span>`;
    }
    return `<span class="op-jmp">${escHtml(opStr)}</span>`;
  }
  return opStr.split(',').map((tok, i) => {
    const t = tok.trim();
    const sep = i===0 ? '' : '<span class="op-sep">, </span>';
    if (t.includes('[')) {
      const addrMatch = t.match(/0x([0-9a-fA-F]+)/);
      if (addrMatch && stringMap) { const addr=parseInt(addrMatch[1],16); const str=stringMap.get(addr); if(str){const p=str.length>30?str.slice(0,30)+'…':str; return sep+`<span class="op-mem">${escHtml(t)}</span><span class="op-str"> ; "${escHtml(p)}"</span>`;} }
      return sep+`<span class="op-mem">${escHtml(t)}</span>`;
    }
    if (/^(0x[0-9a-fA-F]+|\d+)$/.test(t)) {
      const addr = parseAddr(t);
      if (addr !== null && knownAddrs) { const name=knownAddrs.get(addr); if(name) return sep+`<span class="op-call" data-addr="0x${addr.toString(16)}">${escHtml(name)}</span>`; }
      return sep+`<span class="op-imm">${escHtml(t)}</span>`;
    }
    if (isReg(t)) return sep+`<span class="op-reg">${escHtml(t)}</span>`;
    return sep+escHtml(t);
  }).join('');
}