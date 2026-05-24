/**
 * WebDis — main application controller
 */
import { ELFParser }   from './parsers/elf.js';
import { PEParser }    from './parsers/pe.js';
import { MachOParser } from './parsers/macho.js';
import { initDisassembler } from './disasm/engine.js';
import { BinaryAnalyzer }   from './analyzer.js';
import { hashBuffer, cacheStore, cacheLoad, cacheClear } from './cache.js';
import {
  DisasmView, renderFunctionList, renderStringList,
  renderImportList, renderSectionList, renderXrefs,
  renderInfo, renderHex,
  initPanelTabs, initResizeHandles,
  setStatus, setFileInfo, setArchInfo, setProgress,
  showLoading, updateLoading, hideLoading, fmtAddr,
} from './ui.js';

// ── App state ─────────────────────────────────────────────────────────────────
const state = {
  file     : null,
  parser   : null,
  analysis : null,
  arch     : 'auto',
};

// ── Elements ──────────────────────────────────────────────────────────────────
const fileInput    = document.getElementById('fileInput');
const btnOpen      = document.getElementById('btnOpen');
const btnRefresh   = document.getElementById('btnRefresh');
const btnClearCache= document.getElementById('btnClearCache');
const gotoInput    = document.getElementById('gotoInput');
const btnGoto      = document.getElementById('btnGoto');
const archSelect   = document.getElementById('archSelect');
const navSearch    = document.getElementById('navSearch');
const disasmView   = document.getElementById('disasm-view');
const funcLabel    = document.getElementById('funcLabel');
const showBytesChk = document.getElementById('showBytes');
const showCmtChk   = document.getElementById('showComments');
const dropOverlay  = document.getElementById('drop-overlay');

const view = new DisasmView(disasmView);

// ── Boot ──────────────────────────────────────────────────────────────────────

async function boot() {
  initPanelTabs('leftTabs',  'nav-body');
  initPanelTabs('rightTabs', 'right-body');
  initResizeHandles();
  initEventListeners();

  // Pre-load the disassembler engine in background
  setStatus('Loading disassembler engine…');
  try {
    await initDisassembler();
    setStatus('Ready — drop a binary or click Open');
  } catch (e) {
    setStatus('Ready (hex-only mode — disassembler unavailable)');
  }
}

// ── Event Listeners ───────────────────────────────────────────────────────────

function initEventListeners() {
  // File open
  btnOpen.addEventListener('click', () => fileInput.click());
  document.getElementById('welcomeOpen').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', e => {
    if (e.target.files[0]) openFile(e.target.files[0]);
  });

  // Drag & drop
  document.addEventListener('dragover', e => { e.preventDefault(); dropOverlay.hidden = false; });
  document.addEventListener('dragleave', e => {
    if (!e.relatedTarget) dropOverlay.hidden = true;
  });
  document.addEventListener('drop', e => {
    e.preventDefault();
    dropOverlay.hidden = true;
    const f = e.dataTransfer.files[0];
    if (f) openFile(f);
  });

  // Toolbar
  btnRefresh.addEventListener('click', () => {
    if (state.file) analyzeFile(state.file, state.parser, true);
  });
  btnClearCache.addEventListener('click', async () => {
    await cacheClear();
    setStatus('Cache cleared');
  });

  // Goto
  btnGoto.addEventListener('click', gotoAddress);
  gotoInput.addEventListener('keydown', e => { if (e.key === 'Enter') gotoAddress(); });

  // Arch override
  archSelect.addEventListener('change', () => {
    state.arch = archSelect.value;
    if (state.file && state.parser) analyzeFile(state.file, state.parser, true);
  });

  // Navigation search
  navSearch.addEventListener('input', () => {
    const term = navSearch.value.trim();
    const active = document.querySelector('#nav-body .tab-content.active');
    if (!active) return;
    active.querySelectorAll('.nav-item, .str-item, .sec-item').forEach(el => {
      const text = el.textContent.toLowerCase();
      el.style.display = term ? (text.includes(term.toLowerCase()) ? '' : 'none') : '';
    });
  });

  // Disasm toolbar toggles
  showBytesChk.addEventListener('change', () => view.setShowBytes(showBytesChk.checked));
  showCmtChk.addEventListener('change',   () => view.setShowComments(showCmtChk.checked));

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'o') { e.preventDefault(); fileInput.click(); }
    if ((e.ctrlKey || e.metaKey) && e.key === 'g') { e.preventDefault(); gotoInput.focus(); gotoInput.select(); }
    if (e.key === 'Escape') { gotoInput.blur(); }
  });
}

// ── File opening ──────────────────────────────────────────────────────────────

async function openFile(file) {
  state.file = file;
  setStatus(`Loading ${file.name}…`);
  setFileInfo(`${file.name} (${fmtFileSize(file.size)})`);

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch (e) {
    alert('Failed to read file: ' + e.message);
    return;
  }

  let parser;
  try {
    parser = detectFormat(buffer);
  } catch (e) {
    alert('Unsupported file format: ' + e.message);
    setStatus('Error: ' + e.message);
    return;
  }

  state.parser = parser;

  // Detect arch
  const detectedArch = parser.getArch();
  const arch = state.arch === 'auto' ? detectedArch : state.arch;
  archSelect.value = arch === 'unknown' ? 'auto' : arch;
  setArchInfo(detectedArch);

  await analyzeFile(file, parser, false, buffer);
}

/** Detect file format and return appropriate parser */
function detectFormat(buffer) {
  const u8 = new Uint8Array(buffer);
  const dv = new DataView(buffer);

  // ELF: magic 0x7f 'E' 'L' 'F'
  if (u8[0] === 0x7f && u8[1] === 0x45 && u8[2] === 0x4c && u8[3] === 0x46) {
    return new ELFParser(buffer).parse();
  }
  // PE: MZ header
  if (u8[0] === 0x4d && u8[1] === 0x5a) {
    return new PEParser(buffer).parse();
  }
  // Mach-O: multiple magics
  const magic = dv.getUint32(0, false);
  const MACHO_MAGICS = [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca];
  if (MACHO_MAGICS.includes(magic)) {
    return new MachOParser(buffer).parse();
  }

  throw new Error('Unrecognized format (expected ELF, PE, or Mach-O)');
}

// ── Analysis ──────────────────────────────────────────────────────────────────

async function analyzeFile(file, parser, forceRefresh = false, buffer = null) {
  if (!buffer && file) buffer = await file.arrayBuffer();

  showLoading('Analyzing binary…', 'Computing hash…');
  setStatus('Analyzing…');

  let analysis;
  const hash = await hashBuffer(buffer);

  if (!forceRefresh) {
    updateLoading('Checking cache…');
    const cached = await cacheLoad(hash);
    if (cached) {
      analysis = cached;
      setStatus(`Loaded from cache — ${analysis.functions.length} functions`);
      hideLoading();
      renderAnalysis(analysis, parser);
      return;
    }
  }

  // Determine architecture
  const detectedArch = parser.getArch();
  const arch = (state.arch === 'auto' || forceRefresh) ? detectedArch : state.arch;

  const analyzer = new BinaryAnalyzer(parser, arch);
  analyzer.onProgress((msg, pct) => {
    updateLoading(`${msg} (${pct}%)`);
    setProgress(`${pct}%`);
  });

  try {
    analysis = await analyzer.analyze();
    analysis.arch  = arch;
    analysis._info = parser.getInfo ? parser.getInfo() : {};
    await cacheStore(hash, analysis);
  } catch (e) {
    console.error('[analysis] failed:', e);
    alert('Analysis failed: ' + e.message);
    hideLoading();
    return;
  }

  setStatus(`Analysis complete — ${analysis.functions.length} functions, ${analysis.strings.length} strings`);
  setProgress('');
  hideLoading();
  state.analysis = analysis;

  renderAnalysis(analysis, parser);
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function renderAnalysis(analysis, parser) {
  state.analysis = analysis;

  // Navigation panels
  renderFunctionList(analysis.functions, f => navigateTo(f.address));
  renderStringList(analysis.strings,    s => navigateTo(s.address));
  renderImportList(parser.imports || [], imp => imp.address && navigateTo(imp.address));
  renderSectionList(parser.sections || [], s => navigateTo(s.addr || s.vaddr || 0));

  // Info panel
  if (parser.getInfo) {
    renderInfo(parser.getInfo(), analysis);
  }

  // Disassembly view
  // Show welcome screen gone
  const welcome = document.getElementById('welcome');
  if (welcome) welcome.remove();

  view.renderAll(analysis);
  view.onSelect((addr, ins, func) => {
    if (func) {
      funcLabel.textContent = func.name;
      view.highlightNavItem(func.address);
    }
    renderXrefs(addr, analysis, dest => navigateTo(dest));

    // Hex view: bytes around selected instruction
    const hexData = analysis.getBytesAt ? analysis.getBytesAt(addr, 256) : null;
    if (hexData) renderHex(hexData.bytes, hexData.vaddr);

    setStatus(`0x${addr.toString(16)} — ${ins.mnemonic} ${ins.op_str}`);
  });

  // Enable buttons
  btnRefresh.disabled = false;

  // Navigate to entry point
  const entry = analysis.functions.find(f => f.isEntry) || analysis.functions[0];
  if (entry) {
    setTimeout(() => navigateTo(entry.address), 100);
  }
}

// ── Navigation ────────────────────────────────────────────────────────────────

function navigateTo(addr) {
  if (!state.analysis) return;
  if (typeof addr === 'string') {
    addr = parseInt(addr, 16);
    if (isNaN(addr)) return;
  }
  const ok = view.scrollToAddr(addr);
  if (!ok) {
    setStatus(`Address 0x${addr.toString(16)} not in any disassembled function`);
  }

  // Highlight nav item for containing function
  const func = state.analysis.functionAt ? state.analysis.functionAt(addr) : null;
  if (func) {
    view.highlightNavItem(func.address);
    funcLabel.textContent = func.name;
  }
}

function gotoAddress() {
  const raw = gotoInput.value.trim();
  if (!raw || !state.analysis) return;

  // Try as function name
  const byName = state.analysis.functionByName ? state.analysis.functionByName(raw) : null;
  if (byName) { navigateTo(byName.address); return; }

  // Try as hex/decimal address
  const addr = raw.startsWith('0x') ? parseInt(raw, 16) : parseInt(raw);
  if (!isNaN(addr)) navigateTo(addr);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function fmtFileSize(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024)    return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

// ── Start ─────────────────────────────────────────────────────────────────────
boot();
