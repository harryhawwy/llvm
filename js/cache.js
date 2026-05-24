const DB_NAME = 'webdis-cache';
const DB_VERSION = 2;
const STORE = 'analyses';
let _db = null;

async function openDB() {
  if (_db) return _db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'hash' });
    };
    req.onsuccess = e => { _db = e.target.result; resolve(_db); };
    req.onerror = e => reject(e.target.error);
  });
}

export async function hashBuffer(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
}

export async function cacheStore(hash, data) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put({ hash, date: Date.now(), data: _serialize(data) });
    await new Promise((r,j) => { tx.oncomplete=r; tx.onerror=()=>j(tx.error); });
  } catch(e) { console.warn('[cache] store failed:', e); }
}

export async function cacheLoad(hash) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(hash);
    const result = await new Promise((r,j) => { req.onsuccess=()=>r(req.result); req.onerror=()=>j(req.error); });
    return result ? _deserialize(result.data) : null;
  } catch(e) { return null; }
}

export async function cacheClear() {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    await new Promise((r,j) => { tx.oncomplete=r; tx.onerror=()=>j(tx.error); });
  } catch(e) {}
}

function _serialize(a) {
  return {
    arch: a.arch,
    functions: a.functions.map(f => ({ name:f.name, address:f.address, size:f.size, end:f.end, isExport:f.isExport, isEntry:f.isEntry, sectionName:f.sectionName, insns:(f.insns||[]).map(i=>({address:i.address,size:i.size,bytes:i.bytes,mnemonic:i.mnemonic,op_str:i.op_str,category:i.category,isCall:i.isCall,isRet:i.isRet,isJmp:i.isJmp,branchTarget:i.branchTarget})) })),
    strings: a.strings.map(s => ({ value:s.value, address:s.address, section:s.section })),
    xrefsTo: [...a.xrefs._to.entries()],
    xrefsFrom: [...a.xrefs._from.entries()],
  };
}

function _deserialize(d) {
  const xrefs = { _to: new Map(d.xrefsTo), _from: new Map(d.xrefsFrom) };
  xrefs.xrefsTo = addr => xrefs._to.get(addr) || [];
  xrefs.xrefsFrom = addr => xrefs._from.get(addr) || [];
  xrefs.allTargets = () => xrefs._to;
  const stringMap = new Map();
  const addrNames = new Map();
  const functions = d.functions.map(f => { addrNames.set(f.address, f.name); return f; });
  for (const s of d.strings) stringMap.set(s.address, s.value);
  const funcMap = new Map();
  for (const f of functions) funcMap.set(f.address, f);
  return {
    arch: d.arch, functions, strings: d.strings, xrefs, funcMap, stringMap, addrNames,
    functionAt(addr) { if (funcMap.has(addr)) return funcMap.get(addr); for (const f of functions) if (addr>=f.address&&addr<f.end) return f; return null; },
    functionByName(name) { const l=name.toLowerCase(); return functions.find(f=>f.name.toLowerCase().includes(l)); },
  };
}