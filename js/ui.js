import { highlightOperands } from './disasm/engine.js';

export function fmtAddr(addr, bits=64) { return '0x'+addr.toString(16).padStart(bits===64?16:8,'0'); }
export function fmtAddrShort(addr) { return '0x'+addr.toString(16); }

function escHtml(s) { if(typeof s!=='string')s=String(s); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtSize(n) { if(n>=1048576)return(n/1048576).toFixed(1)+' MB'; if(n>=1024)return(n/1024).toFixed(1)+' KB'; return n+' B'; }
export { fmtSize };

export function renderFunctionList(functions, onSelect) {
  const el = document.getElementById('tab-functions');
  if (!el) return;
  if (!functions || functions.length === 0) { el.innerHTML = '<div class="empty-state">No functions found</div>'; return; }
  const frag = document.createDocumentFragment();
  for (const f of functions) {
    const row = document.createElement('div');
    row.className = 'nav-item'; row.dataset.addr = f.address;
    const tags = [];
    if (f.isEntry) tags.push('<span class="ni-tag export">entry</span>');
    if (f.isExport) tags.push('<span class="ni-tag export">exp</span>');
    row.innerHTML = `<span class="ni-addr">${fmtAddrShort(f.address)}</span><span class="ni-name" title="${escHtml(f.name)}">${escHtml(f.name)}</span>${tags.join('')}${f.size?`<span class="ni-size">${f.size}b</span>`:''}` ;
    row.addEventListener('click', () => onSelect(f));
    frag.appendChild(row);
  }
  el.textContent = ''; el.appendChild(frag);
}

export function renderStringList(strings, onSelect) {
  const el = document.getElementById('tab-strings');
  if (!el) return;
  if (!strings || strings.length === 0) { el.innerHTML = '<div class="empty-state">No strings found</div>'; return; }
  const frag = document.createDocumentFragment();
  for (const s of strings) {
    const row = document.createElement('div');
    row.className = 'str-item';
    const preview = s.value.length > 60 ? s.value.slice(0, 60) + '…' : s.value;
    row.innerHTML = `<div class="str-val">"${escHtml(preview)}"</div><div class="str-meta">${fmtAddrShort(s.address)} &bull; ${escHtml(s.section||'')}</div>`;
    row.addEventListener('click', () => onSelect(s));
    frag.appendChild(row);
  }
  el.textContent = ''; el.appendChild(frag);
}

export function renderImportList(imports, onSelect) {
  const el = document.getElementById('tab-imports');
  if (!el) return;
  if (!imports || imports.length === 0) { el.innerHTML = '<div class="empty-state">No imports found</div>'; return; }
  const byDll = {};
  for (const imp of imports) { const dll = imp.dll||'unknown'; if (!byDll[dll]) byDll[dll]=[]; byDll[dll].push(imp); }
  const frag = document.createDocumentFragment();
  for (const [dll, items] of Object.entries(byDll)) {
    const hdr = document.createElement('div'); hdr.className='nav-group-header'; hdr.textContent=dll; frag.appendChild(hdr);
    for (const imp of items) {
      const row = document.createElement('div'); row.className='nav-item';
      row.innerHTML = `<span class="ni-addr">${imp.address?fmtAddrShort(imp.address):'—'}</span><span class="ni-name">${escHtml(imp.name)}</span><span class="ni-tag import">imp</span>`;
      if (imp.address && onSelect) row.addEventListener('click', () => onSelect(imp));
      frag.appendChild(row);
    }
  }
  el.textContent = ''; el.appendChild(frag);
}

export function renderSectionList(sections, onSelect) {
  const el = document.getElementById('tab-sections');
  if (!el) return;
  if (!sections || sections.length === 0) { el.innerHTML = '<div class="empty-state">No sections</div>'; return; }
  const frag = document.createDocumentFragment();
  for (const s of sections) {
    const row = document.createElement('div'); row.className='sec-item';
    const flags = [];
    if (s.executable) flags.push('X');
    if (s.readable || s.flags===undefined) flags.push('R');
    if (s.writable) flags.push('W');
    row.innerHTML = `<div class="sec-name">${escHtml(s.name||'?')}</div><div class="sec-info">${fmtAddrShort(s.addr||s.vaddr||0)} &bull; ${fmtSize(s.size)} ${flags.length?'&bull; '+flags.join(''):''}</div>`;
    row.addEventListener('click', () => onSelect && onSelect(s));
    frag.appendChild(row);
  }
  el.textContent = ''; el.appendChild(frag);
}

export class DisasmView {
  constructor(container) {
    this.el = container; this.analysis = null;
    this._selected = null; this._funcEls = new Map(); this._insnEls = new Map();
    this._showBytes = false; this._showComments = true; this._onSelect = null;
  }
  onSelect(cb) { this._onSelect = cb; return this; }
  setShowBytes(v) { this._showBytes = v; this.el.classList.toggle('show-bytes', v); }
  setShowComments(v) { this._showComments = v; this.el.querySelectorAll('.i-comment').forEach(c => { c.style.display = v ? '' : 'none'; }); }

  renderAll(analysis) {
    this.analysis = analysis; this._funcEls.clear(); this._insnEls.clear(); this.el.textContent = '';
    const frag = document.createDocumentFragment();
    for (const f of analysis.functions) { const block = this._renderFunction(f, analysis); this._funcEls.set(f.address, block); frag.appendChild(block); }
    this.el.appendChild(frag);
  }

  _renderFunction(f, analysis) {
    const block = document.createElement('div'); block.className='func-block'; block.dataset.funcAddr=f.address;
    const header = document.createElement('div'); header.className='func-header';
    const badges = [];
    if (f.isEntry) badges.push('<span class="fh-badge entry">entry</span>');
    if (f.isExport) badges.push('<span class="fh-badge export">export</span>');
    header.innerHTML = `<span class="fh-name">${escHtml(f.name)}</span><span class="fh-addr">${fmtAddr(f.address)}</span>${f.size?`<span class="fh-size">${f.size} bytes</span>`:''} ${badges.join('')}`;
    block.appendChild(header);
    const xrefTargets = analysis.xrefs.allTargets();
    for (const ins of (f.insns||[])) { const row=this._renderInsn(ins,f,analysis,xrefTargets); this._insnEls.set(ins.address,row); block.appendChild(row); }
    return block;
  }

  _renderInsn(ins, func, analysis, xrefTargets) {
    const row = document.createElement('div');
    row.className = `insn cat-${ins.category||'other'}`; row.dataset.addr = ins.address;
    if (ins.isCall) row.classList.add('is-call');
    if (ins.isRet) row.classList.add('is-ret');
    if (ins.isJmp && !ins.isCall) row.classList.add('is-jmp');
    if (xrefTargets.has(ins.address)) row.classList.add('xref-dest');
    const bytesHex = (ins.bytes||[]).map(b=>b.toString(16).padStart(2,'0')).join(' ');
    const opsHtml = highlightOperands(ins.mnemonic, ins.op_str, analysis.addrNames, analysis.stringMap);
    let comment = '';
    if (this._showComments) {
      const parts = [];
      if (ins.op_str) { const m=ins.op_str.match(/0x([0-9a-fA-F]+)/g); if(m){for(const h of m){const a=parseInt(h,16);const s=analysis.stringMap.get(a);if(s){parts.push(`"${s.length>40?s.slice(0,40)+'…':s}"`);break;}}} }
      const xto = analysis.xrefs.xrefsTo(ins.address);
      if (xto.length > 0) parts.push(`xref[${xto.length}]`);
      comment = parts.join(' ');
    }
    row.innerHTML = `<span class="i-addr">${fmtAddr(ins.address)}</span><span class="i-bytes">${escHtml(bytesHex)}</span><span class="i-mnem">${escHtml(ins.mnemonic)}</span><span class="i-ops">${opsHtml}</span>${comment?`<span class="i-comment">; ${escHtml(comment)}</span>`:''}` ;
    row.addEventListener('click', e => {
      if (this._selected) this._selected.classList.remove('selected');
      this._selected = row; row.classList.add('selected');
      if (this._onSelect) this._onSelect(ins.address, ins, func);
      const tgt = e.target.closest('[data-addr]');
      if (tgt && tgt !== row) { const dest=parseInt(tgt.dataset.addr,16); if(!isNaN(dest)) this.scrollToAddr(dest); }
    });
    return row;
  }

  scrollToAddr(addr) {
    const insnEl = this._insnEls.get(addr);
    if (insnEl) { insnEl.scrollIntoView({behavior:'smooth',block:'center'}); if(this._selected)this._selected.classList.remove('selected'); this._selected=insnEl; insnEl.classList.add('selected'); return true; }
    const funcEl = this._funcEls.get(addr);
    if (funcEl) { funcEl.scrollIntoView({behavior:'smooth',block:'start'}); return true; }
    return false;
  }

  highlightNavItem(addr) {
    document.querySelectorAll('#tab-functions .nav-item').forEach(el => { el.classList.toggle('active', parseInt(el.dataset.addr)===addr); });
  }
}

export function renderXrefs(addr, analysis, onNavigate) {
  const el = document.getElementById('tab-xrefs');
  if (!el) return;
  const xto = analysis.xrefs.xrefsTo(addr);
  const xfrom = analysis.xrefs.xrefsFrom(addr);
  if (xto.length === 0 && xfrom.length === 0) { el.innerHTML = '<div class="empty-state">No cross-references</div>'; return; }
  const frag = document.createDocumentFragment();
  if (xto.length > 0) {
    const hdr = document.createElement('div'); hdr.className='xref-section-header'; hdr.textContent=`References TO 0x${addr.toString(16)} (${xto.length})`; frag.appendChild(hdr);
    for (const x of xto) {
      const row = document.createElement('div'); row.className='xref-item';
      row.innerHTML = `<span class="xref-type xtype-${x.type}">${x.type.toUpperCase()}</span><span class="xref-addr">0x${x.from.toString(16)}</span><span class="xref-func"> in ${escHtml(x.func||'?')}</span>`;
      row.addEventListener('click', () => onNavigate && onNavigate(x.from)); frag.appendChild(row);
    }
  }
  if (xfrom.length > 0) {
    const hdr = document.createElement('div'); hdr.className='xref-section-header'; hdr.textContent=`References FROM 0x${addr.toString(16)} (${xfrom.length})`; frag.appendChild(hdr);
    for (const x of xfrom) {
      const row = document.createElement('div'); row.className='xref-item';
      row.innerHTML = `<span class="xref-type xtype-${x.type}">${x.type.toUpperCase()}</span><span class="xref-addr">0x${x.to.toString(16)}</span><span class="xref-func"> ${escHtml(analysis.addrNames.get(x.to)||'')}</span>`;
      row.addEventListener('click', () => onNavigate && onNavigate(x.to)); frag.appendChild(row);
    }
  }
  el.textContent = ''; el.appendChild(frag);
}

export function renderInfo(info, analysis) {
  const el = document.getElementById('tab-info');
  if (!el) return;
  const secs = [
    { title:'Binary', rows:info },
    { title:'Analysis', rows:{ 'Functions':analysis.functions.length, 'Strings':analysis.strings.length, 'XRefs':[...analysis.xrefs._to.values()].reduce((a,v)=>a+v.length,0) } },
  ];
  el.innerHTML = secs.map(s=>`<div class="info-section"><div class="info-title">${escHtml(s.title)}</div>${Object.entries(s.rows).map(([k,v])=>`<div class="info-row"><span class="info-key">${escHtml(String(k))}</span><span class="info-val">${escHtml(String(v))}</span></div>`).join('')}</div>`).join('');
}

export function renderHex(bytes, startAddr) {
  const el = document.getElementById('tab-hex');
  if (!el || !bytes) return;
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.subarray(i, i+16);
    const addr = '0x'+(startAddr+i).toString(16).padStart(16,'0');
    const hexPart = Array.from(chunk).map(b=>b.toString(16).padStart(2,'0')).join(' ');
    const ascii = Array.from(chunk).map(b=>(b>=0x20&&b<0x7f)?String.fromCharCode(b):'.').join('');
    lines.push(`<span class="hex-offset">${escHtml(addr)}</span>  <span class="hex-bytes">${escHtml(hexPart.padEnd(47))}</span>  <span class="hex-ascii">${escHtml(ascii)}</span>`);
  }
  el.innerHTML = `<div class="hex-view">${lines.join('\n')}</div>`;
}

export function initPanelTabs(panelId, bodyId) {
  const tabs = document.querySelectorAll(`#${panelId} .tab-btn`);
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active')); btn.classList.add('active');
      const tabName = btn.dataset.tab;
      document.querySelectorAll(`#${bodyId} .tab-content`).forEach(c => { c.classList.toggle('active', c.id===`tab-${tabName}`); });
    });
  });
}

export function initResizeHandles() {
  _makeResizable('leftResize','left-panel',260,150,500,'left');
  _makeResizable('rightResize','right-panel',280,150,600,'right');
}

function _makeResizable(handleId, panelId, defW, minW, maxW, side) {
  const handle = document.getElementById(handleId);
  const panel = document.getElementById(panelId);
  if (!handle || !panel) return;
  let startX, startW;
  handle.addEventListener('mousedown', e => {
    startX=e.clientX; startW=panel.offsetWidth;
    handle.classList.add('dragging'); document.body.style.cursor='col-resize'; document.body.style.userSelect='none';
    const onMove = mv => { const dx=side==='left'?mv.clientX-startX:startX-mv.clientX; panel.style.width=Math.max(minW,Math.min(maxW,startW+dx))+'px'; };
    const onUp = () => { handle.classList.remove('dragging'); document.body.style.cursor=''; document.body.style.userSelect=''; document.removeEventListener('mousemove',onMove); document.removeEventListener('mouseup',onUp); };
    document.addEventListener('mousemove',onMove); document.addEventListener('mouseup',onUp);
  });
}

export function setStatus(msg) { const el=document.getElementById('sb-cursor'); if(el) el.textContent=msg; }
export function setFileInfo(msg) { const el=document.getElementById('sb-file'); if(el) el.textContent=msg; }
export function setArchInfo(msg) { const el=document.getElementById('sb-arch'); if(el) el.textContent=msg; }
export function setProgress(msg) { const el=document.getElementById('sb-progress'); if(el) el.textContent=msg; }
export function showLoading(msg='Analyzing…', sub='') { document.getElementById('loading-overlay').hidden=false; document.getElementById('loading-text').textContent=msg; document.getElementById('loading-progress').textContent=sub; }
export function updateLoading(sub) { document.getElementById('loading-progress').textContent=sub; }
export function hideLoading() { document.getElementById('loading-overlay').hidden=true; }