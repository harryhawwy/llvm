export class PEParser {
  constructor(buffer){this.buf=buffer;this.dv=new DataView(buffer);this.u8=new Uint8Array(buffer);}
  parse(){this._parseDosHeader();this._parsePEHeader();this._parseSections();this._parseExports();this._parseImports();return this;}
  _u8(o){return this.dv.getUint8(o);}
  _u16(o){return this.dv.getUint16(o,true);}
  _u32(o){return this.dv.getUint32(o,true);}
  _u64(o){return this.dv.getUint32(o,true)+this.dv.getUint32(o+4,true)*4294967296;}
  _cstr(off){let end=off;while(end<this.u8.length&&this.u8[end]!==0)end++;return new TextDecoder().decode(this.u8.subarray(off,end));}
  _parseDosHeader(){if(this._u16(0)!==0x5a4d)throw new Error('Not a PE file');this.peOffset=this._u32(0x3c);if(this._u32(this.peOffset)!==0x00004550)throw new Error('Not a PE file');}
  _parsePEHeader(){
    const pe=this.peOffset;
    this.machine=this._u16(pe+4);this.numSections=this._u16(pe+6);this.timestamp=this._u32(pe+8);this.optHeaderSz=this._u16(pe+20);this.chars=this._u16(pe+22);
    const oh=pe+24;this.magic=this._u16(oh);this._64=this.magic===0x20b;
    if(this._64){this.imageBase=this._u64(oh+24);this.sectionAlign=this._u32(oh+32);this.fileAlign=this._u32(oh+36);this.sizeOfImage=this._u32(oh+56);this.sizeOfHeaders=this._u32(oh+60);this.subsystem=this._u16(oh+68);this.entry=this._u32(oh+16)+this.imageBase;}
    else{this.imageBase=this._u32(oh+28);this.sectionAlign=this._u32(oh+32);this.fileAlign=this._u32(oh+36);this.sizeOfImage=this._u32(oh+56);this.sizeOfHeaders=this._u32(oh+60);this.subsystem=this._u16(oh+68);this.entry=this._u32(oh+16)+this.imageBase;}
    const ddBase=this._64?oh+112:oh+96;this.dataDirectories=[];for(let i=0;i<16;i++)this.dataDirectories.push({rva:this._u32(ddBase+i*8),size:this._u32(ddBase+i*8+4)});
    this.sectionTableOffset=pe+24+this.optHeaderSz;
  }
  _parseSections(){
    this.sections=[];
    for(let i=0;i<this.numSections;i++){
      const off=this.sectionTableOffset+i*40;
      const rawName=this.u8.subarray(off,off+8);let ne=rawName.indexOf(0);if(ne===-1)ne=8;
      const name=new TextDecoder().decode(rawName.subarray(0,ne));
      const s={name,vsize:this._u32(off+8),addr:this._u32(off+12)+this.imageBase,rva:this._u32(off+12),rawSize:this._u32(off+16),offset:this._u32(off+20),flags:this._u32(off+36)};
      s.executable=!!(s.flags&0x20000000);s.readable=!!(s.flags&0x40000000);s.writable=!!(s.flags&0x80000000);
      s.size=Math.min(s.vsize,s.rawSize);this.sections.push(s);
    }
  }
  _rvaToOffset(rva){for(const s of this.sections)if(rva>=s.rva&&rva<s.rva+s.vsize)return s.offset+(rva-s.rva);return null;}
  _rvaToAddr(rva){return rva+this.imageBase;}
  _parseExports(){
    this.exports=[];const dd=this.dataDirectories[0];if(!dd||dd.rva===0)return;
    const off=this._rvaToOffset(dd.rva);if(off===null)return;
    const numFuncs=this._u32(off+20),numNames=this._u32(off+24),funcRva=this._u32(off+28),nameRva=this._u32(off+32),ordRva=this._u32(off+36),ordBase=this._u32(off+16);
    const funcOff=this._rvaToOffset(funcRva),nameOff=this._rvaToOffset(nameRva),ordOff=this._rvaToOffset(ordRva);
    if(!funcOff||!nameOff||!ordOff)return;
    for(let i=0;i<numNames;i++){const namePtr=this._u32(nameOff+i*4);const name=this._cstr(this._rvaToOffset(namePtr)??0);const ordIdx=this._u16(ordOff+i*2);const funcPtr=this._u32(funcOff+ordIdx*4);this.exports.push({name,ordinal:ordIdx+ordBase,address:this._rvaToAddr(funcPtr)});}
  }
  _parseImports(){
    this.imports=[];const dd=this.dataDirectories[1];if(!dd||dd.rva===0)return;
    let off=this._rvaToOffset(dd.rva);if(off===null)return;
    while(true){
      const nameRva=this._u32(off+12),firstThunk=this._u32(off+16);
      if(nameRva===0&&firstThunk===0)break;
      const dllNameOff=this._rvaToOffset(nameRva);const dll=dllNameOff!==null?this._cstr(dllNameOff):'?';
      let thunkOff=this._rvaToOffset(firstThunk);const thunkSize=this._64?8:4;let addr=this._rvaToAddr(firstThunk);
      while(thunkOff!==null){const thunk=this._64?this._u64(thunkOff):this._u32(thunkOff);if(thunk===0)break;const highBit=this._64?0x8000000000000000:0x80000000;let name;if(thunk&highBit)name=`#${thunk&0xffff}`;else{const hintOff=this._rvaToOffset(thunk&(this._64?0x7fffffffffffffff:0x7fffffff));name=hintOff!==null?this._cstr(hintOff+2):'?';}this.imports.push({name,dll,address:addr});thunkOff+=thunkSize;addr+=thunkSize;}
      off+=20;
    }
  }
  getFunctions(){const funcs=[];for(const ex of this.exports)funcs.push({name:ex.name,address:ex.address,size:0,end:0,isExport:true});if(this.entry)funcs.push({name:'EntryPoint',address:this.entry,size:0,end:0,isEntry:true});return funcs.sort((a,b)=>a.address-b.address);}
  getCodeSections(){return this.sections.filter(s=>s.executable&&s.rawSize>0).map(s=>({name:s.name,bytes:this.u8.subarray(s.offset,s.offset+s.rawSize),vaddr:s.addr,fileOffset:s.offset,size:s.rawSize}));}
  addrToOffset(addr){for(const s of this.sections)if(addr>=s.addr&&addr<s.addr+s.vsize)return s.offset+(addr-s.addr);return null;}
  getStrings(minLen=5){
    const strings=[];const decoder=new TextDecoder('utf-8',{fatal:false});
    const searchSecs=this.sections.filter(s=>['.rdata','.data','.rsrc'].includes(s.name)&&s.rawSize>0);
    for(const sec of searchSecs){const data=this.u8.subarray(sec.offset,sec.offset+sec.rawSize);let start=-1,len=0;for(let i=0;i<=data.length;i++){const c=i<data.length?data[i]:0;if(c>=0x20&&c<0x7f){if(start===-1)start=i;len++;}else{if(c===0&&start!==-1&&len>=minLen)strings.push({value:decoder.decode(data.subarray(start,i)),address:sec.addr+start,section:sec.name});start=-1;len=0;}}}
    return strings;
  }
  getInfo(){const machines={0x14c:'i386',0x8664:'x86-64',0x1c0:'ARM',0xaa64:'ARM64'};const subsystems={1:'Native',2:'Windows GUI',3:'Windows CUI',14:'EFI App'};return{format:'PE',bits:this._64?64:32,endian:'Little Endian',machine:machines[this.machine]||`0x${this.machine.toString(16)}`,type:this.chars&0x2?'Executable':'DLL',entry:'0x'+this.entry.toString(16),imageBase:'0x'+this.imageBase.toString(16),sections:this.sections.length,subsystem:subsystems[this.subsystem]||`${this.subsystem}`};}
  getArch(){switch(this.machine){case 0x8664:return'x64';case 0x14c:return'x32';case 0xaa64:return'arm64';case 0x1c0:return'arm';default:return'unknown';}}
}