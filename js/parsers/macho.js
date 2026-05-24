/**
 * Mach-O binary parser — macOS/iOS binaries
 * Supports 32-bit, 64-bit, and Fat (universal) binaries
 */

const MH_MAGIC    = 0xfeedface;
const MH_CIGAM    = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const FAT_MAGIC   = 0xcafebabe;
const FAT_CIGAM   = 0xbebafeca;

const LC = {
  SEGMENT         : 0x01,
  SEGMENT_64      : 0x19,
  SYMTAB          : 0x02,
  DYSYMTAB        : 0x0b,
  LOAD_DYLIB      : 0x0c,
  ID_DYLIB        : 0x0d,
  MAIN            : 0x80000028,
  FUNCTION_STARTS : 0x26,
};

export class MachOParser {
  constructor(buffer) {
    this.buf = buffer;
    this.dv  = new DataView(buffer);
    this.u8  = new Uint8Array(buffer);
  }

  parse() {
    const magic = this.dv.getUint32(0, false); // big-endian peek

    if (magic === FAT_MAGIC || magic === FAT_CIGAM) {
      this._parseFat();
    } else {
      this._parseSingle(0);
    }
    return this;
  }

  _parseFat() {
    const le = this.dv.getUint32(0, false) === FAT_CIGAM;
    const n  = this.dv.getUint32(4, !le);
    // Pick the first arch (usually x86_64 or arm64)
    const offset = this.dv.getUint32(8, !le);
    this._parseSingle(offset);
    this.isFat = true;
  }

  _parseSingle(base) {
    this._base = base;
    const magic = this.dv.getUint32(base, false);

    if (magic === MH_MAGIC || magic === MH_CIGAM) {
      this._64 = false;
      this._le = (magic === MH_CIGAM);
    } else if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) {
      this._64 = true;
      this._le = (magic === MH_CIGAM_64);
    } else {
      throw new Error('Not a Mach-O file');
    }

    this._parseHeader(base);
    this._parseLoadCommands(base);
  }

  _u8(o)  { return this.dv.getUint8(o); }
  _u16(o) { return this.dv.getUint16(o, this._le); }
  _u32(o) { return this.dv.getUint32(o, this._le); }
  _u64(o) {
    const lo = this.dv.getUint32(o, this._le);
    const hi = this.dv.getUint32(o+4, this._le);
    return this._le ? lo + hi * 4294967296 : hi + lo * 4294967296;
  }
  _addr(o) { return this._64 ? this._u64(o) : this._u32(o); }
  _cstr(off) {
    let end = off;
    while (end < this.u8.length && this.u8[end] !== 0) end++;
    return new TextDecoder().decode(this.u8.subarray(off, end));
  }

  _parseHeader(base) {
    this.cputype    = this._u32(base + 4);
    this.cpusubtype = this._u32(base + 8);
    this.filetype   = this._u32(base + 12);
    this.ncmds      = this._u32(base + 16);
    this.sizeofcmds = this._u32(base + 20);
    this.flags      = this._u32(base + 24);
  }

  _parseLoadCommands(base) {
    this.sections  = [];
    this.segments  = [];
    this.symbols   = [];
    this.imports   = [];
    this.exports   = [];
    this.entry     = 0;
    this._stroff   = 0;
    this._strsize  = 0;
    this._symoff   = 0;
    this._nsyms    = 0;

    const hdrSize = this._64 ? 32 : 28;
    let off = base + hdrSize;

    for (let i = 0; i < this.ncmds; i++) {
      const cmd     = this._u32(off);
      const cmdsize = this._u32(off + 4);

      switch (cmd) {
        case LC.SEGMENT:
        case LC.SEGMENT_64:
          this._parseSegment(off);
          break;
        case LC.SYMTAB:
          this._symoff  = this._u32(off + 8);
          this._nsyms   = this._u32(off + 12);
          this._stroff  = this._u32(off + 16);
          this._strsize = this._u32(off + 20);
          break;
        case LC.MAIN:
          this.entry = this._64 ? this._u64(off + 8) : this._u32(off + 8);
          break;
        case LC.FUNCTION_STARTS:
          this._funcStartsOff  = this._u32(off + 8);
          this._funcStartsSize = this._u32(off + 12);
          break;
        case LC.LOAD_DYLIB:
          const nameOff = this._u32(off + 8);
          this._dylibs = this._dylibs || [];
          this._dylibs.push(this._cstr(off + nameOff));
          break;
      }
      off += cmdsize;
    }

    if (this._symoff && this._nsyms) this._parseSymtab();
    if (this._funcStartsOff)         this._parseFunctionStarts();
  }

  _parseSegment(off) {
    const is64  = this._64;
    const nameBytes = this.u8.subarray(off + 8, off + 24);
    let nameEnd = nameBytes.indexOf(0);
    if (nameEnd === -1) nameEnd = 16;
    const name  = new TextDecoder().decode(nameBytes.subarray(0, nameEnd));

    const vmaddr   = this._addr(is64 ? off + 24 : off + 24);
    const vmsize   = this._addr(is64 ? off + 32 : off + 28);
    const fileoff  = this._addr(is64 ? off + 40 : off + 32);
    const filesize = this._addr(is64 ? off + 48 : off + 36);
    const nsects   = this._u32(is64 ? off + 64 : off + 48);

    const seg = { name, vmaddr, vmsize, fileoff, filesize };
    this.segments.push(seg);

    // Parse sections within segment
    const secBase = off + (is64 ? 72 : 56);
    const secSize = is64 ? 80 : 68;
    for (let i = 0; i < nsects; i++) {
      const sb = secBase + i * secSize;
      const snameBuf = this.u8.subarray(sb, sb + 16);
      let se = snameBuf.indexOf(0);
      if (se === -1) se = 16;
      const sname = new TextDecoder().decode(snameBuf.subarray(0, se));

      const s = {
        name    : sname,
        segment : name,
        addr    : this._addr(is64 ? sb + 32 : sb + 32),
        size    : this._addr(is64 ? sb + 40 : sb + 36),
        offset  : this._u32(is64 ? sb + 48 : sb + 40),
        flags   : this._u32(is64 ? sb + 64 : sb + 56),
      };
      this.sections.push(s);
    }
  }

  _parseSymtab() {
    const strData = this.u8.subarray(this._stroff, this._stroff + this._strsize);
    const nlSize  = this._64 ? 16 : 12;

    for (let i = 0; i < this._nsyms; i++) {
      const off = this._symoff + i * nlSize;
      const strx  = this._u32(off);
      const type  = this._u8(off + 4);
      const sect  = this._u8(off + 5);
      const desc  = this._u16(off + 6);
      const value = this._addr(off + 8);

      const N_STAB  = 0xe0;
      const N_TYPE  = 0x0e;
      const N_SECT  = 0x0e;
      const N_EXT   = 0x01;

      if (type & N_STAB) continue; // debug symbol
      if ((type & N_TYPE) !== N_SECT) continue;
      if (value === 0) continue;

      const name = strx < strData.length ? this._cstr(this._stroff + strx) : '';
      if (!name || name === '<redacted>') continue;

      const isExport = !!(type & N_EXT);
      this.symbols.push({ name, value, type, isExport });
    }
  }

  _parseFunctionStarts() {
    // LC_FUNCTION_STARTS is a ULEB128 encoded list of offsets from __TEXT
    const data = this.u8.subarray(this._funcStartsOff, this._funcStartsOff + this._funcStartsSize);
    const textSeg = this.segments.find(s => s.name === '__TEXT');
    if (!textSeg) return;

    let addr = textSeg.vmaddr;
    let i    = 0;
    this._funcStarts = [];

    while (i < data.length) {
      let delta = 0, shift = 0;
      while (i < data.length) {
        const b = data[i++];
        delta |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      if (delta === 0) break;
      addr += delta;
      this._funcStarts.push(addr);
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────

  getFunctions() {
    const seen = new Map();

    // From symbol table
    for (const sym of this.symbols) {
      const name = sym.name.replace(/^_+/, '') || `sub_${sym.value.toString(16)}`;
      if (!seen.has(sym.value)) {
        seen.set(sym.value, {
          name     : sym.name,
          address  : sym.value,
          size     : 0,
          end      : 0,
          isExport : sym.isExport,
          isEntry  : sym.value === this.entry,
        });
      }
    }

    // From LC_FUNCTION_STARTS (may reveal functions without symbols)
    if (this._funcStarts) {
      for (const addr of this._funcStarts) {
        if (!seen.has(addr)) {
          seen.set(addr, {
            name   : `sub_${addr.toString(16)}`,
            address: addr,
            size   : 0,
            end    : 0,
          });
        }
      }
    }

    return [...seen.values()].sort((a, b) => a.address - b.address);
  }

  getCodeSections() {
    return this.sections
      .filter(s => s.segment === '__TEXT' && s.name !== '__unwind_info' && s.size > 0)
      .map(s => ({
        name      : s.name,
        bytes     : this.u8.subarray(s.offset, s.offset + s.size),
        vaddr     : s.addr,
        fileOffset: s.offset,
        size      : s.size,
      }));
  }

  addrToOffset(addr) {
    for (const s of this.sections) {
      if (addr >= s.addr && addr < s.addr + s.size) {
        return s.offset + (addr - s.addr);
      }
    }
    return null;
  }

  getStrings(minLen = 5) {
    const strings = [];
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const searchSecs = this.sections.filter(s =>
      s.name === '__cstring' || s.name === '__const' || s.name === '__objc_methnames'
    );

    for (const sec of searchSecs) {
      const data  = this.u8.subarray(sec.offset, sec.offset + sec.size);
      let   start = -1, len = 0;
      for (let i = 0; i <= data.length; i++) {
        const c = i < data.length ? data[i] : 0;
        if (c >= 0x20 && c < 0x7f) { if (start === -1) start = i; len++; }
        else {
          if (c === 0 && start !== -1 && len >= minLen) {
            strings.push({
              value  : decoder.decode(data.subarray(start, i)),
              address: sec.addr + start,
              section: sec.name,
            });
          }
          start = -1; len = 0;
        }
      }
    }
    return strings;
  }

  getInfo() {
    const cputypes = {
      7:'x86', 0x1000007:'x86-64', 12:'ARM', 0x100000c:'ARM64',
      18:'PowerPC', 0x1000012:'PowerPC64',
    };
    const filetypes = { 1:'Object', 2:'Executable', 6:'DSO', 8:'Core', 10:'Dylinker' };
    return {
      format  : 'Mach-O',
      bits    : this._64 ? 64 : 32,
      endian  : this._le ? 'Little Endian' : 'Big Endian',
      machine : cputypes[this.cputype] || `0x${this.cputype.toString(16)}`,
      type    : filetypes[this.filetype] || 'Unknown',
      entry   : this.entry ? '0x' + this.entry.toString(16) : 'N/A',
      sections: this.sections.length,
      symbols : this.symbols.length,
    };
  }

  getArch() {
    switch (this.cputype) {
      case 0x1000007: return 'x64';
      case 7:         return 'x32';
      case 0x100000c: return 'arm64';
      case 12:        return 'arm';
      default:        return 'unknown';
    }
  }
}
