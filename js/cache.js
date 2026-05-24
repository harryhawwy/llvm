/**
 * IndexedDB-backed analysis cache
 * Key: SHA-256 hash of file contents
 * Value: serialized analysis result
 */

const DB_NAME    = 'webdis-cache';
const DB_VERSION = 2;
const STORE      = 'analyses';

let _db = null;

async function openDB() {
  if (_db) return _db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: 'hash' });
        store.createIndex('date', 'date', { unique: false });
      }
    };
    req.onsuccess = e => { _db = e.target.result; resolve(_db); };
    req.onerror   = e => reject(e.target.error);
  });
}

/** SHA-256 hash of an ArrayBuffer */
export async function hashBuffer(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
}

/** Store analysis result in cache */
export async function cacheStore(hash, data) {
  try {
    const db   = await openDB();
    const tx   = db.transaction(STORE, 'readwrite');
    const entry = {
      hash,
      date     : Date.now(),
      data     : _serialize(data),
    };
    tx.objectStore(STORE).put(entry);
    await txDone(tx);
  } catch (e) {
    console.warn('[cache] store failed:', e);
  }
}

/** Retrieve analysis result from cache (null if not found) */
export async function cacheLoad(hash) {
  try {
    const db  = await openDB();
    const tx  = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(hash);
    const result = await reqDone(req);
    if (!result) return null;
    return _deserialize(result.data);
  } catch (e) {
    console.warn('[cache] load failed:', e);
    return null;
  }
}

/** Remove all cached entries */
export async function cacheClear() {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    await txDone(tx);
    return true;
  } catch (e) {
    console.warn('[cache] clear failed:', e);
    return false;
  }
}

/** List cached entries (for debugging) */
export async function cacheList() {
  try {
    const db  = await openDB();
    const tx  = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).getAll();
    const all = await reqDone(req);
    return all.map(e => ({ hash: e.hash, date: new Date(e.date) }));
  } catch (e) {
    return [];
  }
}

// ── Serialization ─────────────────────────────────────────────────────────────
// We store only the parts that are expensive to recompute:
// functions (with insns as plain objects) + strings + xrefs

function _serialize(analysis) {
  return {
    arch     : analysis.arch,
    functions: analysis.functions.map(f => ({
      name    : f.name,
      address : f.address,
      size    : f.size,
      end     : f.end,
      isExport: f.isExport,
      isEntry : f.isEntry,
      sectionName: f.sectionName,
      insns   : f.insns ? f.insns.map(_serInsn) : [],
    })),
    strings: analysis.strings.map(s => ({
      value  : s.value,
      address: s.address,
      section: s.section,
    })),
    xrefsTo  : _mapToArr(analysis.xrefs._to),
    xrefsFrom: _mapToArr(analysis.xrefs._from),
    info     : analysis._info,
  };
}

function _serInsn(ins) {
  return {
    address : ins.address,
    size    : ins.size,
    bytes   : ins.bytes,
    mnemonic: ins.mnemonic,
    op_str  : ins.op_str,
    category: ins.category,
    isCall  : ins.isCall,
    isRet   : ins.isRet,
    isJmp   : ins.isJmp,
    branchTarget: ins.branchTarget,
  };
}

function _mapToArr(map) {
  const arr = [];
  for (const [k, v] of map) arr.push([k, v]);
  return arr;
}

function _deserialize(data) {
  // Import XrefDatabase lazily to avoid circular deps
  const xrefs = { _to: new Map(_arrToMap(data.xrefsTo)), _from: new Map(_arrToMap(data.xrefsFrom)) };
  xrefs.xrefsTo   = addr => xrefs._to.get(addr)   || [];
  xrefs.xrefsFrom = addr => xrefs._from.get(addr)  || [];
  xrefs.allTargets = () => xrefs._to;

  const stringMap = new Map();
  const addrNames = new Map();

  const functions = data.functions.map(f => {
    addrNames.set(f.address, f.name);
    return f;
  });
  for (const s of data.strings) stringMap.set(s.address, s.value);

  const funcMap = new Map();
  for (const f of functions) funcMap.set(f.address, f);

  return {
    arch     : data.arch,
    functions,
    strings  : data.strings,
    xrefs,
    funcMap,
    stringMap,
    addrNames,
    _info    : data.info,
    // Stubs for methods used by UI
    functionAt(addr) {
      if (funcMap.has(addr)) return funcMap.get(addr);
      for (const f of functions) if (addr >= f.address && addr < f.end) return f;
      return null;
    },
    functionByName(name) {
      const lower = name.toLowerCase();
      return functions.find(f => f.name.toLowerCase().includes(lower));
    },
  };
}

function _arrToMap(arr) {
  const out = new Map();
  for (const [k, v] of arr) out.set(k, v);
  return out;
}

// ── IDB helpers ───────────────────────────────────────────────────────────────
function txDone(tx) {
  return new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
}
function reqDone(req) {
  return new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
}
