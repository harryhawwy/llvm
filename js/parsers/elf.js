const SHT = { NULL:0,PROGBITS:1,SYMTAB:2,STRTAB:3,RELA:4,NOBITS:8,DYNSYM:11 };
const STT = { FUNC:2 };
const STB = { LOCAL:0 };

export class ELFParser {
  constructor(buffer) { this.buf=buffer; this.dv=new DataView(buffer); this.u8=new Uint8Array(buffer); }
  parse() { this._parseMagic(); this._parseEhdr(); this._parseShdrs(); this._parseSymbols(); this._parseDynamic(); return this; }
  _le() { return this._endian===1; }
  _u8(o) { return this.dv.getUint8(o); }
  _u16(o) { return this.dv.getUint16(o,this._le()); }
  _u32(o) { return this.dv.getUint32(o,this._le()); }
  _u64(o) { const lo=this.dv.getUint32(o,this._le()),hi=this.dv.getUint32(o+4,this._le()); return this._le()?lo+hi*4294967296:hi+lo*4294967296; }
  _addr(o) { return this._64?this._u64(o):this._u32(o); }
  _cstr(base,off) { let end=off; while(end<base.length&&base[end]!==0)end++; return new TextDecoder().decode(base.subarray(off,end)); }
  _parseMagic() {
    const m=[0x7f,0x45,0x4c,0x46]; for(let i=0;i<4;i++) if(this._u8(i)!==m[i]) throw new Error('Not an ELF file');
    this._64=this._u8(4)===2; this._endian=this._u8(5); this.osabi=this._u8(7);
  }
  _parseEhdr() {
    this.elfType=this._u16(16); this.machine=this._u16(18); this.version=this._u32(20);
    if(this._64){this.entry=this._u64(24);this.phoff=this._u64(32);this.shoff=this._u64(40);this.flags=this._u32(48);this.ehsize=this._u16(52);this.phentsize=this._u16(54);this.phnum=this._u16(56);this.shentsize=this._u16(58);this.shnum=this._u16(60);this.shstrndx=this._u16(62);}
    else{this.entry=this._u32(24);this.phoff=this._u32(28);this.shoff=this._u32(32);this.flags=this._u32(36);this.ehsize=this._u16(40);this.phentsize=this._u16(42);this.phnum=this._u16(44);this.shentsize=this._u16(46);this.shnum=this._u16(48);this.shstrndx=this._u16(50);}
  }
  _parseShdrs() {
    this.sections=[];
    for(let i=0;i<this.shnum;i++){
      const base=this.shoff+i*this.shentsize;
      const s=this._64?{nameIdx:this._u32(base),type:this._u32(base+4),flags:this._u64(base+8),addr:this._u64(base+16),offset:this._u64(base+24),size:this._u64(base+32),link:this._u32(base+40),info:this._u32(base+44),entsize:this._u64(base+56)}:{nameIdx:this._u32(base),type:this._u32(base+4),flags:this._u32(base+8),addr:this._u32(base+12),offset:this._u32(base+16),size:this._u32(base+20),link:this._u32(base+24),info:this._u32(base+28),entsize:this._u32(base+36)};
      this.sections.push(s);
    }
    if(this.shstrndx<this.sections.length){const st=this.sections[this.shstrndx];const data=this.u8.subarray(st.offset,st.offset+st.size);for(const s of this.sections)s.name=this._cstr(data,s.nameIdx);}
    this._secByName={}; for(const s of this.sections)if(s.name)this._secByName[s.name]=s;
  }
  _parseSymbols() { this.symbols=this._readSymtab('.symtab','.strtab'); this.dynSymbols=this._readSymtab('.dynsym','.dynstr'); }
  _readSymtab(symName,strName) {
    const symSec=this._secByName[symName]; const strSec=this._secByName[strName];
    if(!symSec||!strSec)return[];
    const strData=this.u8.subarray(strSec.offset,strSec.offset+strSec.size);
    const entSize=this._64?24:16; const count=Math.floor(symSec.size/entSize); const syms=[];
    for(let i=0;i<count;i++){
      const base=symSec.offset+i*entSize;
      let sym;
      if(this._64){sym={name:this._cstr(strData,this._u32(base)),info:this._u8(base+4),other:this._u8(base+5),shndx:this._u16(base+6),value:this._u64(base+8),size:this._u64(base+16)};}
      else{sym={name:this._cstr(strData,this._u32(base)),value:this._u32(base+4),size:this._u32(base+8),info:this._u8(base+12),other:this._u8(base+13),shndx:this._u16(base+14)};}
      sym.type=sym.info&0xf; sym.binding=sym.info>>4; syms.push(sym);
    }
    return syms;
  }
  _parseDynamic() {
    this.imports=[]; this.exports=[];
    for(const sym of this.dynSymbols){if(!sym.name)continue;if(sym.shndx!==0&&sym.shndx!==0xfff1&&sym.value!==0)this.exports.push({name:sym.name,address:sym.value,size:sym.size});}
    for(const sym of this.dynSymbols){if(!sym.name)continue;if(sym.shndx===0&&sym.binding!==STB.LOCAL)this.imports.push({name:sym.name,address:0});}
    const plt=this._secByName['.plt']||this._secByName['.plt.sec'];
    if(plt){const entSize=16;const start=plt.addr+entSize;for(let i=0;i<this.imports.length;i++){this.imports[i].address=start+i*entSize;this.imports[i].plt=true;}}
  }
  getFunctions() {
    const all=[...this.symbols,...this.dynSymbols]; const seen=new Map();
    for(const sym of all){if(sym.type!==STT.FUNC||sym.value===0)continue;if(!seen.has(sym.value))seen.set(sym.value,{name:sym.name||`sub_${sym.value.toString(16)}`,address:sym.value,size:sym.size,end:sym.value+sym.size,isExport:this.exports.some(e=>e.address===sym.value),isEntry:sym.value===this.entry});}
    if(this.entry&&!seen.has(this.entry))seen.set(this.entry,{name:'_start',address:this.entry,size:0,end:0,isEntry:true,isExport:false});
    return[...seen.values()].sort((a,b)=>a.address-b.address);
  }
  getCodeSections() { const SHF_EXEC=4; return this.sections.filter(s=>(s.flags&SHF_EXEC)&&s.size>0&&s.type!==SHT.NOBITS).map(s=>({name:s.name,bytes:this.u8.subarray(s.offset,s.offset+s.size),vaddr:s.addr,fileOffset:s.offset,size:s.size})); }
  addrToOffset(addr) { for(const s of this.sections)if(addr>=s.addr&&addr<s.addr+s.size)return s.offset+(addr-s.addr); return null; }
  getStrings(minLen=5) {
    const strings=[]; const decoder=new TextDecoder('utf-8',{fatal:false});
    const searchSecs=this.sections.filter(s=>s.name&&(s.name==='.rodata'||s.name==='.data'||s.name.startsWith('.rodata')||s.name==='.cstring')&&s.size>0&&s.type!==SHT.NOBITS);
    for(const sec of searchSecs){const data=this.u8.subarray(sec.offset,sec.offset+sec.size);let start=-1,len=0;for(let i=0;i<=data.length;i++){const c=i<data.length?data[i]:0;if(c>=0x20&&c<0x7f){if(start===-1)start=i;len++;}else{if(c===0&&start!==-1&&len>=minLen)strings.push({value:decoder.decode(data.subarray(start,i)),address:sec.addr+start,offset:sec.offset+start,section:sec.name});start=-1;len=0;}}}
    return strings;
  }
  getInfo() {
    const machines={0x03:'i386',0x3e:'x86-64',0x28:'ARM',0xb7:'AArch64',0x08:'MIPS',0x14:'PowerPC',0x02:'SPARC'};
    const types={1:'Relocatable',2:'Executable',3:'Shared Object',4:'Core'};
    return{format:'ELF',bits:this._64?64:32,endian:this._le()?'Little Endian':'Big Endian',machine:machines[this.machine]||`0x${this.machine.toString(16)}`,type:types[this.elfType]||'Unknown',entry:'0x'+this.entry.toString(16),sections:this.sections.length,symbols:this.symbols.length+this.dynSymbols.length};
  }
  getArch() { switch(this.machine){case 0x3e:return'x64';case 0x03:return'x32';case 0xb7:return'arm64';case 0x28:return'arm';case 0x08:return'mips';default:return'unknown';} }
}