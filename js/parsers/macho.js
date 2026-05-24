const MH_MAGIC=0xfeedface,MH_CIGAM=0xcefaedfe,MH_MAGIC_64=0xfeedfacf,MH_CIGAM_64=0xcffaedfe,FAT_MAGIC=0xcafebabe,FAT_CIGAM=0xbebafeca;
const LC={SEGMENT:0x01,SEGMENT_64:0x19,SYMTAB:0x02,LOAD_DYLIB:0x0c,MAIN:0x80000028,FUNCTION_STARTS:0x26};

export class MachOParser {
  constructor(buffer){this.buf=buffer;this.dv=new DataView(buffer);this.u8=new Uint8Array(buffer);}
  parse(){const magic=this.dv.getUint32(0,false);if(magic===FAT_MAGIC||magic===FAT_CIGAM)this._parseFat();else this._parseSingle(0);return this;}
  _parseFat(){const le=this.dv.getUint32(0,false)===FAT_CIGAM;const offset=this.dv.getUint32(8,!le);this._parseSingle(offset);this.isFat=true;}
  _parseSingle(base){
    this._base=base;const magic=this.dv.getUint32(base,false);
    if(magic===MH_MAGIC||magic===MH_CIGAM){this._64=false;this._le=(magic===MH_CIGAM);}
    else if(magic===MH_MAGIC_64||magic===MH_CIGAM_64){this._64=true;this._le=(magic===MH_CIGAM_64);}
    else throw new Error('Not a Mach-O file');
    this._parseHeader(base);this._parseLoadCommands(base);
  }
  _u8(o){return this.dv.getUint8(o);}
  _u16(o){return this.dv.getUint16(o,this._le);}
  _u32(o){return this.dv.getUint32(o,this._le);}
  _u64(o){const lo=this.dv.getUint32(o,this._le),hi=this.dv.getUint32(o+4,this._le);return this._le?lo+hi*4294967296:hi+lo*4294967296;}
  _addr(o){return this._64?this._u64(o):this._u32(o);}
  _cstr(off){let end=off;while(end<this.u8.length&&this.u8[end]!==0)end++;return new TextDecoder().decode(this.u8.subarray(off,end));}
  _parseHeader(base){this.cputype=this._u32(base+4);this.cpusubtype=this._u32(base+8);this.filetype=this._u32(base+12);this.ncmds=this._u32(base+16);this.sizeofcmds=this._u32(base+20);this.flags=this._u32(base+24);}
  _parseLoadCommands(base){
    this.sections=[];this.segments=[];this.symbols=[];this.imports=[];this.exports=[];this.entry=0;
    this._stroff=0;this._strsize=0;this._symoff=0;this._nsyms=0;
    const hdrSize=this._64?32:28;let off=base+hdrSize;
    for(let i=0;i<this.ncmds;i++){
      const cmd=this._u32(off),cmdsize=this._u32(off+4);
      if(cmd===LC.SEGMENT||cmd===LC.SEGMENT_64)this._parseSegment(off);
      else if(cmd===LC.SYMTAB){this._symoff=this._u32(off+8);this._nsyms=this._u32(off+12);this._stroff=this._u32(off+16);this._strsize=this._u32(off+20);}
      else if(cmd===LC.MAIN){this.entry=this._64?this._u64(off+8):this._u32(off+8);}
      else if(cmd===LC.FUNCTION_STARTS){this._funcStartsOff=this._u32(off+8);this._funcStartsSize=this._u32(off+12);}
      off+=cmdsize;
    }
    if(this._symoff&&this._nsyms)this._parseSymtab();
    if(this._funcStartsOff)this._parseFunctionStarts();
  }
  _parseSegment(off){
    const is64=this._64;const nameBytes=this.u8.subarray(off+8,off+24);let ne=nameBytes.indexOf(0);if(ne===-1)ne=16;
    const name=new TextDecoder().decode(nameBytes.subarray(0,ne));
    const vmaddr=this._addr(off+24),vmsize=this._addr(is64?off+32:off+28),fileoff=this._addr(is64?off+40:off+32),filesize=this._addr(is64?off+48:off+36),nsects=this._u32(is64?off+64:off+48);
    this.segments.push({name,vmaddr,vmsize,fileoff,filesize});
    const secBase=off+(is64?72:56),secSize=is64?80:68;
    for(let i=0;i<nsects;i++){
      const sb=secBase+i*secSize;const snameBuf=this.u8.subarray(sb,sb+16);let se=snameBuf.indexOf(0);if(se===-1)se=16;
      const sname=new TextDecoder().decode(snameBuf.subarray(0,se));
      this.sections.push({name:sname,segment:name,addr:this._addr(is64?sb+32:sb+32),size:this._addr(is64?sb+40:sb+36),offset:this._u32(is64?sb+48:sb+40),flags:this._u32(is64?sb+64:sb+56)});
    }
  }
  _parseSymtab(){
    const strData=this.u8.subarray(this._stroff,this._stroff+this._strsize);const nlSize=this._64?16:12;
    for(let i=0;i<this._nsyms;i++){
      const off=this._symoff+i*nlSize;const strx=this._u32(off);const type=this._u8(off+4);const sect=this._u8(off+5);const value=this._addr(off+8);
      if(type&0xe0)continue;if((type&0x0e)!==0x0e)continue;if(value===0)continue;
      const name=strx<strData.length?this._cstr(this._stroff+strx):'';
      if(!name||name==='<redacted>')continue;
      this.symbols.push({name,value,type,isExport:!!(type&0x01)});
    }
  }
  _parseFunctionStarts(){
    const data=this.u8.subarray(this._funcStartsOff,this._funcStartsOff+this._funcStartsSize);
    const textSeg=this.segments.find(s=>s.name==='__TEXT');if(!textSeg)return;
    let addr=textSeg.vmaddr,i=0;this._funcStarts=[];
    while(i<data.length){let delta=0,shift=0;while(i<data.length){const b=data[i++];delta|=(b&0x7f)<<shift;shift+=7;if(!(b&0x80))break;}if(delta===0)break;addr+=delta;this._funcStarts.push(addr);}
  }
  getFunctions(){
    const seen=new Map();
    for(const sym of this.symbols){if(!seen.has(sym.value))seen.set(sym.value,{name:sym.name,address:sym.value,size:0,end:0,isExport:sym.isExport,isEntry:sym.value===this.entry});}
    if(this._funcStarts){for(const addr of this._funcStarts)if(!seen.has(addr))seen.set(addr,{name:`sub_${addr.toString(16)}`,address:addr,size:0,end:0});}
    return[...seen.values()].sort((a,b)=>a.address-b.address);
  }
  getCodeSections(){return this.sections.filter(s=>s.segment==='__TEXT'&&s.name!=='__unwind_info'&&s.size>0).map(s=>({name:s.name,bytes:this.u8.subarray(s.offset,s.offset+s.size),vaddr:s.addr,fileOffset:s.offset,size:s.size}));}
  addrToOffset(addr){for(const s of this.sections)if(addr>=s.addr&&addr<s.addr+s.size)return s.offset+(addr-s.addr);return null;}
  getStrings(minLen=5){
    const strings=[];const decoder=new TextDecoder('utf-8',{fatal:false});
    const searchSecs=this.sections.filter(s=>s.name==='__cstring'||s.name==='__const'||s.name==='__objc_methnames');
    for(const sec of searchSecs){const data=this.u8.subarray(sec.offset,sec.offset+sec.size);let start=-1,len=0;for(let i=0;i<=data.length;i++){const c=i<data.length?data[i]:0;if(c>=0x20&&c<0x7f){if(start===-1)start=i;len++;}else{if(c===0&&start!==-1&&len>=minLen)strings.push({value:decoder.decode(data.subarray(start,i)),address:sec.addr+start,section:sec.name});start=-1;len=0;}}}
    return strings;
  }
  getInfo(){const cputypes={7:'x86',0x1000007:'x86-64',12:'ARM',0x100000c:'ARM64',18:'PowerPC'};const filetypes={1:'Object',2:'Executable',6:'DSO',8:'Core'};return{format:'Mach-O',bits:this._64?64:32,endian:this._le?'Little Endian':'Big Endian',machine:cputypes[this.cputype]||`0x${this.cputype.toString(16)}`,type:filetypes[this.filetype]||'Unknown',entry:this.entry?'0x'+this.entry.toString(16):'N/A',sections:this.sections.length,symbols:this.symbols.length};}
  getArch(){switch(this.cputype){case 0x1000007:return'x64';case 7:return'x32';case 0x100000c:return'arm64';case 12:return'arm';default:return'unknown';}}
}