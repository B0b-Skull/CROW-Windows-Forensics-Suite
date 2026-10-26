// ============================================================================
// report.js - Windows System Analysis, Diagnostics, Security & Forensics
// Full Interactive Table Engine, Chart Renderer, Obsidian Viewer & Script Client
// ============================================================================

const TABLE_STATE = {};
let OBSIDIAN_NOTES_CACHE = [];
let SERVER_ONLINE = false;
let SELECTED_PS_PROFILE = 'AUTO'; // 'AUTO' (uses discovered local PS version), 'PS51', 'PS7', 'PSLegacy', or 'COMPARE'
let LIVE_TELEMETRY_ENABLED = true;
let LIVE_TELEMETRY_TIMER = null;
const LIVE_TELEMETRY_INTERVAL_MS = 3000;

document.addEventListener('DOMContentLoaded', async () => {
  initThemeMode();
  initTabs();
  await hydrateDashboardData();
  await refreshServerStatus();
  await loadObsidianVault();
  initLiveTelemetry();
});

function initThemeMode() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  updateThemeButtonLabel(isDark);
}

function updateThemeButtonLabel(isDark) {
  const btn = document.getElementById('btnThemeToggle');
  if (!btn) return;
  btn.innerHTML = isDark ? '&#9728;&#65039; Light Mode' : '&#127769; Dark Mode';
}

window.toggleThemeMode = function() {
  const isCurrentlyDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const nextDark = !isCurrentlyDark;
  if (nextDark) {
    document.documentElement.setAttribute('data-theme', 'dark');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }
  try {
    localStorage.setItem('forensic_theme_mode', nextDark ? 'dark' : 'light');
  } catch (e) {}
  updateThemeButtonLabel(nextDark);
  showToast(nextDark ? 'Switched to Dark View Mode' : 'Switched to Light View Mode');
};

// ----------------------------------------------------------------------------
// 0. Zero-Dependency Real-Time Hardware Telemetry Auto-Updater (PERF-02)
//    Works via BOTH /api/telemetry/live AND file:/// JSONP (live_telemetry.js)
// ----------------------------------------------------------------------------
function initLiveTelemetry() {
  // Seed initial values from master bundle immediately
  const fData = window.FORENSIC_DATA || {};
  const hw = (fData.Hardware && fData.Hardware.SystemOverview) || {};
  const perf = (fData.Performance && fData.Performance.LatestSnapshot) || {};
  const gpus = (fData.Hardware && fData.Hardware.GPUs) || [];
  const initVramMB = gpus.reduce((acc, g) => acc + (Number(g.DedicatedVRAM_Used_MB) || 0), 0);

  applyLiveTelemetryUpdate({
    TimeShort: 'Snapshot',
    CPU_Load_Percent: perf.CPU_Percent ?? 3,
    RAM_Used_GB: hw.UsedRAM_GB ?? 11.4,
    RAM_Total_GB: hw.TotalRAM_GB ?? 31.76,
    RAM_Used_Percent: hw.UsedRAM_Percent ?? perf.RAM_Used_Percent ?? 36,
    Commit_Used_GB: perf.Committed_MB ? Math.round((perf.Committed_MB / 1024) * 100) / 100 : 12.0,
    Commit_Limit_GB: perf.CommitLimit_MB ? Math.round((perf.CommitLimit_MB / 1024) * 100) / 100 : 36.5,
    Pool_Paged_MB: perf.PoolPaged_MB ?? 0,
    Pool_NonPaged_MB: perf.PoolNonPaged_MB ?? 0,
    GPU_Utilization_Percent: perf.GPU_Utilization_Percent ?? 8,
    GPU_3D_Percent: perf.GPU_3D_Percent ?? 8,
    GPU_Copy_Percent: 0,
    VRAM_Dedicated_MB: initVramMB || 620,
    VRAM_Shared_MB: 760,
    VRAM_TotalCommitted_MB: (initVramMB || 620) + 760
  });

  window.__onLiveTelemetry = function(sample) {
    if (sample && typeof sample === 'object') {
      applyLiveTelemetryUpdate(sample);
    }
  };

  startLiveTelemetryLoop();
  pollLiveTelemetry(false);
}

function startLiveTelemetryLoop() {
  if (LIVE_TELEMETRY_TIMER) clearInterval(LIVE_TELEMETRY_TIMER);
  if (!LIVE_TELEMETRY_ENABLED) return;
  LIVE_TELEMETRY_TIMER = setInterval(() => {
    if (LIVE_TELEMETRY_ENABLED) {
      pollLiveTelemetry(false);
    }
  }, LIVE_TELEMETRY_INTERVAL_MS);
}

window.toggleLiveTelemetry = function() {
  LIVE_TELEMETRY_ENABLED = !LIVE_TELEMETRY_ENABLED;
  const hdrBtn = document.getElementById('btnLiveTelemetry');
  const stripBtn = document.getElementById('btnLiveStripToggle');
  const dot = document.getElementById('livePulseDot');
  const badge = document.getElementById('liveStreamStatusBadge');

  if (LIVE_TELEMETRY_ENABLED) {
    if (hdrBtn) {
      hdrBtn.innerHTML = '&#128994; Live Telemetry: ON (3s)';
      hdrBtn.className = 'btn btn-teal';
    }
    if (stripBtn) stripBtn.textContent = 'Pause Stream';
    if (dot) dot.classList.remove('paused');
    if (badge) {
      badge.className = 'badge badge-success';
      badge.textContent = 'Auto-Updating (3s Interval)';
    }
    startLiveTelemetryLoop();
    pollLiveTelemetry(false);
    showToast('Live Hardware Telemetry Stream Resumed (3s interval)');
  } else {
    if (LIVE_TELEMETRY_TIMER) clearInterval(LIVE_TELEMETRY_TIMER);
    if (hdrBtn) {
      hdrBtn.innerHTML = '&#9208; Live Telemetry: PAUSED';
      hdrBtn.className = 'btn';
    }
    if (stripBtn) stripBtn.textContent = 'Resume Stream';
    if (dot) dot.classList.add('paused');
    if (badge) {
      badge.className = 'badge badge-neutral';
      badge.textContent = 'Stream Paused';
    }
    showToast('Live Hardware Telemetry Stream Paused');
  }
};

window.pollLiveTelemetry = async function(forceImmediateScript) {
  if (forceImmediateScript && SERVER_ONLINE) {
    try {
      const r = await executeScript('PERF-02', { MaxSamples: 1 });
      if (r && r.scriptOutputJson) {
        applyLiveTelemetryUpdate(r.scriptOutputJson);
        return;
      }
    } catch (e) {}
  }

  // 1. Try fast HTTP endpoint (/api/telemetry/live) when backend server is active
  if (SERVER_ONLINE || window.location.protocol.startsWith('http')) {
    try {
      const resp = await fetch('/api/telemetry/live?t=' + Date.now(), { cache: 'no-store' });
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.TimestampLocal) {
          SERVER_ONLINE = true;
          applyLiveTelemetryUpdate(data);
          return;
        }
      }
    } catch (e) {}
  }

  // 2. Zero-Server file:/// fallback: dynamically load Data/Performance/live_telemetry.js
  try {
    const oldTag = document.getElementById('__liveTelemetryScriptTag');
    if (oldTag && oldTag.parentNode) oldTag.parentNode.removeChild(oldTag);
    const s = document.createElement('script');
    s.id = '__liveTelemetryScriptTag';
    s.src = 'Data/Performance/live_telemetry.js?t=' + Date.now();
    s.async = true;
    document.body.appendChild(s);
  } catch (e) {}
};

function applyLiveTelemetryUpdate(s) {
  if (!s) return;
  const cpuPct = Math.min(100, Math.max(0, Number(s.CPU_Load_Percent ?? 0)));
  const ramUsed = Number(s.RAM_Used_GB ?? 0);
  const ramTot = Number(s.RAM_Total_GB ?? 31.76);
  const ramPct = Math.min(100, Math.max(0, Number(s.RAM_Used_Percent ?? (ramTot > 0 ? Math.round((ramUsed / ramTot) * 1000) / 10 : 0))));
  const gpuPct = Math.min(100, Math.max(0, Number(s.GPU_Utilization_Percent ?? 0)));
  const gpu3d = Number(s.GPU_3D_Percent ?? gpuPct);
  const gpuCopy = Number(s.GPU_Copy_Percent ?? 0);
  const vramDed = Number(s.VRAM_Dedicated_MB ?? 0);
  const vramShr = Number(s.VRAM_Shared_MB ?? 0);
  const vramCom = Number(s.VRAM_TotalCommitted_MB ?? (vramDed + vramShr));
  const vramPct = Math.min(100, Math.max(2, Math.round((vramCom / 8192) * 100)));

  setText('liveValCpu', `${cpuPct}%`);
  setText('liveSubCpu', `Active Processor Load (${s.TimeShort || 'Live'})`);
  const barCpu = document.getElementById('liveBarCpu');
  if (barCpu) {
    barCpu.style.width = `${cpuPct}%`;
    barCpu.className = `bar-fill ${cpuPct > 80 ? 'red' : (cpuPct > 55 ? 'amber' : 'blue')}`;
  }

  setText('liveValRam', `${ramUsed} / ${ramTot} GB (${ramPct}%)`);
  setText('liveSubRam', `Commit: ${s.Commit_Used_GB ?? 0}/${s.Commit_Limit_GB ?? 0} GB | NonPaged: ${s.Pool_NonPaged_MB ?? 0} MB`);
  const barRam = document.getElementById('liveBarRam');
  if (barRam) {
    barRam.style.width = `${ramPct}%`;
    barRam.className = `bar-fill ${ramPct > 85 ? 'red' : (ramPct > 70 ? 'amber' : 'teal')}`;
  }

  setText('liveValGpu', `${gpuPct}%`);
  setText('liveSubGpu', `3D Engine: ${gpu3d}% | Copy Engine: ${gpuCopy}%`);
  const barGpu = document.getElementById('liveBarGpu');
  if (barGpu) {
    barGpu.style.width = `${gpuPct}%`;
    barGpu.className = `bar-fill ${gpuPct > 85 ? 'red' : (gpuPct > 60 ? 'amber' : 'blue')}`;
  }

  setText('liveValVram', `${vramCom} MB`);
  setText('liveSubVram', `Dedicated: ${vramDed} MB | Shared: ${vramShr} MB`);
  const barVram = document.getElementById('liveBarVram');
  if (barVram) {
    barVram.style.width = `${vramPct}%`;
  }

  if (s.TimeShort && s.TimeShort !== 'Snapshot') {
    setText('liveStreamTimestamp', `Last Sample: ${s.TimeShort} \u2022 Native PowerShell WMI/CIM (Zero External Dependencies)`);
    const pBadge = document.getElementById('perfTimestampBadge');
    if (pBadge) {
      pBadge.className = 'badge badge-success';
      pBadge.textContent = `Live @ ${s.TimeShort}`;
    }
  }

  // Also keep the System Resource Utilization chart & Top Processes chart in View 1 synchronized in real time!
  const resChart = document.getElementById('chartSystemResources');
  if (resChart && s.TimeShort && s.TimeShort !== 'Snapshot') {
    const commitUsedMB = Math.round((Number(s.Commit_Used_GB || 0)) * 1024);
    const commitLimMB = Math.round((Number(s.Commit_Limit_GB || 32)) * 1024);
    const commitPct = commitLimMB > 0 ? Math.min(100, Math.round((commitUsedMB / commitLimMB) * 100)) : 0;
    resChart.innerHTML = `
      ${renderBarRow('CPU Load Percentage (Live)', `${cpuPct}%`, cpuPct, cpuPct > 80 ? 'red' : 'blue')}
      ${renderBarRow(`Physical RAM (${ramUsed} / ${ramTot} GB)`, `${ramPct}%`, ramPct, ramPct > 85 ? 'amber' : 'teal')}
      ${renderBarRow(`GPU Engine Utilization (3D: ${gpu3d}%)`, `${gpuPct}%`, gpuPct, gpuPct > 85 ? 'red' : 'blue')}
      ${renderBarRow(`GPU VRAM Committed (Ded: ${vramDed} MB | Shr: ${vramShr} MB)`, `${vramCom} MB`, vramPct, 'teal')}
      <div style="font-size:0.74rem; color:var(--text-muted); margin-top:0.5rem;">
        Commit Charge: <strong>${commitUsedMB} / ${commitLimMB} MB (${commitPct}%)</strong> | Paged Pool: <strong>${s.Pool_Paged_MB || 0} MB</strong> | Non-Paged Pool: <strong>${s.Pool_NonPaged_MB || 0} MB</strong>
      </div>
    `;
  }

  const topProcChart = document.getElementById('chartTopProcesses');
  if (topProcChart && Array.isArray(s.TopProcesses) && s.TopProcesses.length > 0) {
    const maxRam = Math.max(500, ...(s.TopProcesses.map(p => p.WorkingSetMB || 0)));
    topProcChart.innerHTML = s.TopProcesses.map(p => {
      const pct = Math.min(100, Math.round(((p.WorkingSetMB || 0) / maxRam) * 100));
      return renderBarRow(`${p.ProcessName} (PID ${p.PID})`, `${p.WorkingSetMB} MB | CPU: ${p.CPU_Seconds}s`, pct, 'teal');
    }).join('');
  }
}

// ----------------------------------------------------------------------------
// 1. Data Hydration & Persistent Table Preferences (Server Disk/SQLite + localStorage)
// ----------------------------------------------------------------------------
const TABLE_PREFS_STORAGE_KEY = 'crow_forensic_table_prefs_v2';
window.TABLE_PREFS_CACHE = { tables: {} };

function loadLocalTablePrefs() {
  try {
    const raw = localStorage.getItem(TABLE_PREFS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.tables === 'object') {
        window.TABLE_PREFS_CACHE = parsed;
      }
    }
  } catch (e) {}
}
loadLocalTablePrefs();

function mergeServerTablePrefs(serverPrefs) {
  if (!serverPrefs || typeof serverPrefs.tables !== 'object') return;
  if (!window.TABLE_PREFS_CACHE || typeof window.TABLE_PREFS_CACHE.tables !== 'object') {
    window.TABLE_PREFS_CACHE = { tables: {} };
  }
  // Server disk/SQLite preferences survive browser restarts and server restarts
  Object.keys(serverPrefs.tables).forEach(tblId => {
    window.TABLE_PREFS_CACHE.tables[tblId] = serverPrefs.tables[tblId];
  });
  try {
    localStorage.setItem(TABLE_PREFS_STORAGE_KEY, JSON.stringify(window.TABLE_PREFS_CACHE));
  } catch (e) {}
}

function getSavedTablePrefs(tableId) {
  if (!window.TABLE_PREFS_CACHE || !window.TABLE_PREFS_CACHE.tables) return null;
  return window.TABLE_PREFS_CACHE.tables[tableId] || null;
}

function persistTablePrefs(tableId) {
  const st = TABLE_STATE[tableId];
  if (!st) return;
  if (!window.TABLE_PREFS_CACHE || typeof window.TABLE_PREFS_CACHE.tables !== 'object') {
    window.TABLE_PREFS_CACHE = { tables: {} };
  }
  window.TABLE_PREFS_CACHE.tables[tableId] = {
    colOrder: (st.columns || []).map(c => c.key),
    hiddenCols: Array.from(st.hiddenCols || []),
    colWidths: st.colWidths || {}
  };
  try {
    localStorage.setItem(TABLE_PREFS_STORAGE_KEY, JSON.stringify(window.TABLE_PREFS_CACHE));
  } catch (e) {}

  if (SERVER_ONLINE || window.location.protocol.startsWith('http')) {
    fetch('/api/preferences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(window.TABLE_PREFS_CACHE)
    }).catch(() => {});
  }
}

async function hydrateDashboardData() {
  try {
    const resp = await fetch('/api/data', { cache: 'no-store' });
    if (resp.ok) {
      const liveMaster = await resp.json();
      if (liveMaster && Object.keys(liveMaster).length > 0) {
        window.FORENSIC_DATA = liveMaster;
        if (liveMaster.LegacyBaselineAudit) {
          window.DIAGNOSTIC_DATA = liveMaster.LegacyBaselineAudit;
        }
        if (liveMaster.UIPreferences) {
          mergeServerTablePrefs(liveMaster.UIPreferences);
        }
        SERVER_ONLINE = true;
      }
    }
  } catch (err) {
    // Running via file:/// protocol or backend offline; use window.FORENSIC_DATA from data.js
    SERVER_ONLINE = false;
  }

  renderAllViews();
}

function renderAllViews() {
  const fData = window.FORENSIC_DATA || {};
  const lData = window.DIAGNOSTIC_DATA || (fData.LegacyBaselineAudit) || {};

  renderHeaderAndOverview(fData, lData);
  renderProcessesAndServicesView(fData);
  renderNetworkActivityView(fData);
  renderWindowsEventsView(fData);
  renderBinaryIntegrityView(fData);
  renderSecurityFindingsView(fData);
  renderMemoryCrashView(fData);
  renderPowerShellVersionMatrix(fData);
  renderPhase2ReportsView(fData);
  renderRemediationAndLegacyView(fData, lData);
}

// ----------------------------------------------------------------------------
// 2. Tab Navigation
// ----------------------------------------------------------------------------
window.activateTab = function(targetId) {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');
  tabButtons.forEach(b => {
    if (b.getAttribute('data-target') === targetId) {
      b.classList.add('active');
    } else {
      b.classList.remove('active');
    }
  });
  tabPanels.forEach(p => {
    if (p.id === targetId) {
      p.classList.add('active');
    } else {
      p.classList.remove('active');
    }
  });
};

function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      window.activateTab(targetId);
    });
  });

  // Close column visibility dropdowns when clicking outside
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.col-vis-wrapper')) {
      document.querySelectorAll('.col-vis-menu.open').forEach(m => m.classList.remove('open'));
    }
  });
}

// ----------------------------------------------------------------------------
// 3. Universal Interactive Forensic Table Component
//    Supports: Auto/Manual Column Resizing, Column Visibility, Sorting,
//    Search, Severity/Threat Filter, Pagination, Copy Cell, Expand Details,
//    CSV Export, and Excel XLSX (SpreadsheetML) Export.
// ----------------------------------------------------------------------------
function renderColVisMenuHTML(tableId) {
  const st = TABLE_STATE[tableId];
  if (!st || !Array.isArray(st.columns)) return '';
  return `
    <div class="col-vis-menu-header">
      <span>&#8942;&#8942; Drag to reorder columns</span>
      <button class="col-order-btn" type="button" onclick="resetTableColumnPrefs('${tableId}', event)" title="Reset column order &amp; visibility to defaults">Reset</button>
    </div>
    ${st.columns.map((c, idx) => `
      <div class="col-vis-item"
           draggable="true"
           data-col-key="${c.key}"
           ondragstart="onColMenuDragStart(event, '${tableId}', '${c.key}')"
           ondragover="onColMenuDragOver(event)"
           ondragleave="onColMenuDragLeave(event)"
           ondrop="onColMenuDrop(event, '${tableId}', '${c.key}')"
           ondragend="onColMenuDragEnd(event)">
        <span class="col-drag-handle" title="Drag to reorder column">&#8942;&#8942;</span>
        <label class="col-vis-label-wrap">
          <input type="checkbox" ${!st.hiddenCols.has(c.key) ? 'checked' : ''} onchange="toggleColumnVisibility('${tableId}', '${c.key}', this.checked)">
          <span>${escapeHtml(c.label)}</span>
        </label>
        <div class="col-order-btns">
          <button class="col-order-btn" type="button" ${idx === 0 ? 'disabled' : ''} onclick="moveTableColumn('${tableId}', '${c.key}', -1, event)" title="Move column left/up">&#9650;</button>
          <button class="col-order-btn" type="button" ${idx === st.columns.length - 1 ? 'disabled' : ''} onclick="moveTableColumn('${tableId}', '${c.key}', 1, event)" title="Move column right/down">&#9660;</button>
        </div>
      </div>
    `).join('')}
  `;
}

function refreshColVisMenu(tableId) {
  const menu = document.getElementById(`${tableId}_colMenu`);
  if (menu) {
    menu.innerHTML = renderColVisMenuHTML(tableId);
  }
}

function applySavedColumnOrder(defaultCols, savedOrder) {
  if (!Array.isArray(savedOrder) || savedOrder.length === 0) {
    return defaultCols.slice();
  }
  const byKey = {};
  defaultCols.forEach(c => { byKey[c.key] = c; });
  const ordered = [];
  const seen = new Set();
  savedOrder.forEach(k => {
    if (byKey[k] && !seen.has(k)) {
      ordered.push(byKey[k]);
      seen.add(k);
    }
  });
  defaultCols.forEach(c => {
    if (!seen.has(c.key)) {
      ordered.push(c);
      seen.add(c.key);
    }
  });
  return ordered;
}

function renderForensicTable(containerId, config) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const tableId = config.tableId || `${containerId}_tbl`;
  const rows = Array.isArray(config.data) ? config.data : [];
  const defaultCols = (config.columns || []).slice();
  const savedPrefs = getSavedTablePrefs(tableId);

  if (!TABLE_STATE[tableId]) {
    TABLE_STATE[tableId] = {
      searchTerm: '',
      filterLevel: 'ALL',
      sortCol: config.defaultSortCol || null,
      sortAsc: config.defaultSortAsc !== undefined ? config.defaultSortAsc : true,
      pageSize: config.pageSize || 25,
      currentPage: 1,
      hiddenCols: new Set((savedPrefs && Array.isArray(savedPrefs.hiddenCols)) ? savedPrefs.hiddenCols : (config.defaultHiddenCols || [])),
      colWidths: (savedPrefs && savedPrefs.colWidths && typeof savedPrefs.colWidths === 'object') ? Object.assign({}, savedPrefs.colWidths) : {}
    };
  } else if (savedPrefs) {
    if (Array.isArray(savedPrefs.hiddenCols)) {
      TABLE_STATE[tableId].hiddenCols = new Set(savedPrefs.hiddenCols);
    }
    if (savedPrefs.colWidths && typeof savedPrefs.colWidths === 'object') {
      TABLE_STATE[tableId].colWidths = Object.assign({}, savedPrefs.colWidths);
    }
  }
  const st = TABLE_STATE[tableId];
  st.rawRows = rows;
  st.defaultColumns = defaultCols;
  st.defaultHiddenCols = config.defaultHiddenCols || [];
  st.columns = applySavedColumnOrder(defaultCols, savedPrefs ? savedPrefs.colOrder : null);
  st.title = config.title || 'Forensic Data Table';
  st.containerId = containerId;
  st.hasThreatFilter = config.hasThreatFilter || false;

  // Build wrapper HTML if not initialized
  container.innerHTML = `
    <div class="card table-card" id="${tableId}_card">
      <div class="table-toolbar">
        <div class="table-title">
          <span>${escapeHtml(st.title)}</span>
          <span class="badge badge-neutral" id="${tableId}_countBadge">${rows.length} records</span>
        </div>
        <div class="toolbar-controls">
          <input type="text" class="search-box" id="${tableId}_search" placeholder="Search all columns..." value="${escapeHtml(st.searchTerm)}">
          ${st.hasThreatFilter ? `
            <select class="select-box" id="${tableId}_filter" aria-label="Filter by Threat/Severity">
              <option value="ALL" ${st.filterLevel === 'ALL' ? 'selected' : ''}>All Levels</option>
              <option value="CRITICAL" ${st.filterLevel === 'CRITICAL' ? 'selected' : ''}>Critical Only</option>
              <option value="HIGH" ${st.filterLevel === 'HIGH' ? 'selected' : ''}>High &amp; Above</option>
              <option value="MEDIUM" ${st.filterLevel === 'MEDIUM' ? 'selected' : ''}>Medium &amp; Above</option>
              <option value="LOW" ${st.filterLevel === 'LOW' ? 'selected' : ''}>Low / Info</option>
            </select>
          ` : ''}
          <div class="col-vis-wrapper">
            <button class="btn btn-sm" type="button" onclick="toggleColVisMenu('${tableId}')">&#9776; Columns &#9662;</button>
            <div class="col-vis-menu" id="${tableId}_colMenu">
              ${renderColVisMenuHTML(tableId)}
            </div>
          </div>
          <button class="btn btn-sm" type="button" onclick="exportTableCSV('${tableId}')" title="Export filtered table to CSV">&#128196; CSV</button>
          <button class="btn btn-sm" type="button" onclick="exportTableXLSX('${tableId}')" title="Export filtered table to Excel SpreadsheetML (.xls)">&#128202; Excel (XLSX)</button>
        </div>
      </div>

      <div class="table-responsive" tabindex="0" role="region" aria-label="${escapeHtml(st.title)}">
        <table class="diag-table" id="${tableId}">
          <thead id="${tableId}_thead"></thead>
          <tbody id="${tableId}_tbody"></tbody>
        </table>
      </div>

      <div class="table-footer">
        <div id="${tableId}_pageInfo">Showing 0 of 0</div>
        <div class="pagination-controls">
          <span>Rows per page:</span>
          <select class="select-box" style="padding: 0.2rem 0.45rem;" onchange="changeTablePageSize('${tableId}', this.value)">
            <option value="25" ${st.pageSize === 25 ? 'selected' : ''}>25</option>
            <option value="50" ${st.pageSize === 50 ? 'selected' : ''}>50</option>
            <option value="100" ${st.pageSize === 100 ? 'selected' : ''}>100</option>
            <option value="999999" ${st.pageSize > 1000 ? 'selected' : ''}>All</option>
          </select>
          <button class="btn btn-sm" type="button" onclick="changeTablePage('${tableId}', -1)">&#9664; Prev</button>
          <span id="${tableId}_pageNum" style="padding: 0 0.4rem; font-weight: 600;">1 / 1</span>
          <button class="btn btn-sm" type="button" onclick="changeTablePage('${tableId}', 1)">Next &#9654;</button>
        </div>
      </div>
    </div>
  `;

  const searchInput = document.getElementById(`${tableId}_search`);
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      st.searchTerm = e.target.value;
      st.currentPage = 1;
      updateTableRows(tableId);
    });
  }

  const filterSelect = document.getElementById(`${tableId}_filter`);
  if (filterSelect) {
    filterSelect.addEventListener('change', (e) => {
      st.filterLevel = e.target.value;
      st.currentPage = 1;
      updateTableRows(tableId);
    });
  }

  updateTableHeaders(tableId);
  updateTableRows(tableId);
}

function getFilteredAndSortedRows(tableId) {
  const st = TABLE_STATE[tableId];
  if (!st) return [];
  const term = (st.searchTerm || '').toLowerCase().trim();
  const level = st.filterLevel || 'ALL';

  let filtered = st.rawRows.filter(row => {
    if (level !== 'ALL') {
      const rowSev = String(row.ThreatAssessment || row.RiskAssessment || row.Severity || row.IntegrityStatus || row.ExposureRisk || '').toUpperCase();
      if (level === 'CRITICAL' && !rowSev.includes('CRITICAL') && !rowSev.includes('INVALID') && !rowSev.includes('MISMATCH')) return false;
      if (level === 'HIGH' && !rowSev.includes('CRITICAL') && !rowSev.includes('HIGH') && !rowSev.includes('ERROR') && !rowSev.includes('INVALID')) return false;
      if (level === 'MEDIUM' && !rowSev.includes('CRITICAL') && !rowSev.includes('HIGH') && !rowSev.includes('MEDIUM') && !rowSev.includes('WARNING') && !rowSev.includes('UNSIGNED')) return false;
      if (level === 'LOW' && !rowSev.includes('LOW') && !rowSev.includes('INFO')) return false;
    }
    if (!term) return true;
    return Object.values(row).some(v => v !== null && v !== undefined && String(v).toLowerCase().includes(term));
  });

  if (st.sortCol) {
    const colKey = st.sortCol;
    const asc = st.sortAsc ? 1 : -1;
    filtered.sort((a, b) => {
      let va = a[colKey];
      let vb = b[colKey];
      if (va === null || va === undefined) va = '';
      if (vb === null || vb === undefined) vb = '';
      const na = Number(va);
      const nb = Number(vb);
      if (!isNaN(na) && !isNaN(nb) && va !== '' && vb !== '') {
        return (na - nb) * asc;
      }
      return String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: 'base' }) * asc;
    });
  }

  return filtered;
}

function updateTableHeaders(tableId) {
  const st = TABLE_STATE[tableId];
  const thead = document.getElementById(`${tableId}_thead`);
  if (!st || !thead) return;

  const visibleCols = st.columns.filter(c => !st.hiddenCols.has(c.key));
  thead.innerHTML = `
    <tr>
      <th style="width: 118px; min-width: 118px; text-align: center;">Inspect / VT</th>
      ${visibleCols.map(c => {
        const isSorted = st.sortCol === c.key;
        const arrow = isSorted ? (st.sortAsc ? '&#9650;' : '&#9660;') : '';
        const widthStyle = st.colWidths[c.key] ? `width: ${st.colWidths[c.key]}px; min-width: ${st.colWidths[c.key]}px;` : (c.width ? `min-width: ${c.width};` : '');
        return `
          <th data-col="${c.key}" style="${widthStyle}" onclick="handleHeaderSort('${tableId}', '${c.key}', event)">
            <span>${escapeHtml(c.label)}</span>
            <span class="sort-indicator">${arrow}</span>
            <div class="col-resizer" onmousedown="initColumnResize(event, '${tableId}', '${c.key}')"></div>
          </th>
        `;
      }).join('')}
    </tr>
  `;
}

function rowSupportsVirusTotal(row, tableId) {
  if (!row || typeof row !== 'object') return false;
  if (row.SHA256 && /^[A-Fa-f0-9]{64}$/.test(String(row.SHA256).trim())) return true;
  if (row.IsPublicRemoteIP && row.RemoteAddress) return true;
  const candidatePath = row.ServiceDll || row.DllPath || row.BinaryPath || row.TargetBinary || row.PathName || row.FullPath || '';
  if (candidatePath && candidatePath !== 'N/A' && candidatePath !== 'None' && candidatePath !== 'Unavailable') {
    return true;
  }
  return false;
}

function updateTableRows(tableId) {
  const st = TABLE_STATE[tableId];
  const tbody = document.getElementById(`${tableId}_tbody`);
  const countBadge = document.getElementById(`${tableId}_countBadge`);
  const pageInfo = document.getElementById(`${tableId}_pageInfo`);
  const pageNum = document.getElementById(`${tableId}_pageNum`);
  if (!st || !tbody) return;

  const filtered = getFilteredAndSortedRows(tableId);
  st.lastFiltered = filtered;
  if (countBadge) countBadge.textContent = `${filtered.length} records`;

  const totalPages = Math.max(1, Math.ceil(filtered.length / st.pageSize));
  if (st.currentPage > totalPages) st.currentPage = totalPages;

  const startIdx = (st.currentPage - 1) * st.pageSize;
  const pageSlice = filtered.slice(startIdx, startIdx + st.pageSize);
  const visibleCols = st.columns.filter(c => !st.hiddenCols.has(c.key));

  if (pageSlice.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${visibleCols.length + 1}" style="text-align: center; padding: 1.5rem; color: var(--text-muted);">No matching forensic records found.</td></tr>`;
  } else {
    tbody.innerHTML = pageSlice.map((row, idx) => {
      const globalIdx = startIdx + idx;
      const hasVt = rowSupportsVirusTotal(row, tableId);
      return `
        <tr>
          <td style="text-align: center; white-space: nowrap;">
            <div style="display: inline-flex; gap: 0.25rem; align-items: center;">
              <button class="btn btn-sm" type="button" onclick="openRowDetailModal('${tableId}', ${globalIdx})" title="Expand full forensic record">Details</button>
              ${hasVt ? `<button class="btn btn-teal btn-sm" type="button" style="padding: 0.2rem 0.45rem;" onclick="openRowVirusTotalAction('${tableId}', ${globalIdx})" title="Check Binary, Service, DLL, Driver, or IP on VirusTotal">&#128737; VT</button>` : ''}
            </div>
          </td>
          ${visibleCols.map(c => {
            const rawVal = row[c.key];
            const rendered = c.render ? c.render(rawVal, row) : escapeHtml(rawVal ?? '');
            const cellClass = `${c.mono ? 'mono-cell' : ''} ${c.wrap ? 'wrap-cell' : ''} cell-copy-hint`.trim();
            return `<td class="${cellClass}" title="Double-click to copy value: ${escapeHtml(String(rawVal ?? ''))}" ondblclick="copyToClipboard('${escapeJs(String(rawVal ?? ''))}')">${rendered}</td>`;
          }).join('')}
        </tr>
      `;
    }).join('');
  }

  if (pageInfo) {
    const from = filtered.length === 0 ? 0 : startIdx + 1;
    const to = Math.min(startIdx + st.pageSize, filtered.length);
    pageInfo.textContent = `Showing ${from}–${to} of ${filtered.length} records (Double-click any cell to copy value; drag column borders to resize)`;
  }
  if (pageNum) {
    pageNum.textContent = `${st.currentPage} / ${totalPages}`;
  }
}

window.handleHeaderSort = function(tableId, colKey, evt) {
  if (evt && evt.target && evt.target.classList.contains('col-resizer')) return;
  const st = TABLE_STATE[tableId];
  if (!st) return;
  if (st.sortCol === colKey) {
    st.sortAsc = !st.sortAsc;
  } else {
    st.sortCol = colKey;
    st.sortAsc = true;
  }
  updateTableHeaders(tableId);
  updateTableRows(tableId);
};

window.toggleColVisMenu = function(tableId) {
  const menu = document.getElementById(`${tableId}_colMenu`);
  if (menu) menu.classList.toggle('open');
};

window.toggleColumnVisibility = function(tableId, colKey, isVisible) {
  const st = TABLE_STATE[tableId];
  if (!st) return;
  if (isVisible) st.hiddenCols.delete(colKey);
  else st.hiddenCols.add(colKey);
  persistTablePrefs(tableId);
  updateTableHeaders(tableId);
  updateTableRows(tableId);
};

// Drag-and-Drop Column Reordering inside the Columns Dropdown Menu
let ACTIVE_DRAG_COL = { tableId: null, colKey: null };

window.onColMenuDragStart = function(evt, tableId, colKey) {
  ACTIVE_DRAG_COL = { tableId, colKey };
  const item = evt.currentTarget;
  if (item) item.classList.add('dragging');
  if (evt.dataTransfer) {
    evt.dataTransfer.effectAllowed = 'move';
    evt.dataTransfer.setData('text/plain', colKey);
  }
};

window.onColMenuDragOver = function(evt) {
  evt.preventDefault();
  if (evt.dataTransfer) evt.dataTransfer.dropEffect = 'move';
  const item = evt.currentTarget;
  if (item) item.classList.add('drag-over');
};

window.onColMenuDragLeave = function(evt) {
  const item = evt.currentTarget;
  if (item) item.classList.remove('drag-over');
};

window.onColMenuDragEnd = function(evt) {
  const item = evt.currentTarget;
  if (item) item.classList.remove('dragging', 'drag-over');
  document.querySelectorAll('.col-vis-item.drag-over, .col-vis-item.dragging').forEach(el => {
    el.classList.remove('drag-over', 'dragging');
  });
};

window.onColMenuDrop = function(evt, tableId, targetColKey) {
  evt.preventDefault();
  evt.stopPropagation();
  const item = evt.currentTarget;
  if (item) item.classList.remove('drag-over', 'dragging');

  const sourceColKey = (ACTIVE_DRAG_COL.tableId === tableId && ACTIVE_DRAG_COL.colKey)
    ? ACTIVE_DRAG_COL.colKey
    : (evt.dataTransfer ? evt.dataTransfer.getData('text/plain') : null);
  ACTIVE_DRAG_COL = { tableId: null, colKey: null };

  if (!sourceColKey || sourceColKey === targetColKey) return;
  const st = TABLE_STATE[tableId];
  if (!st || !Array.isArray(st.columns)) return;

  const fromIdx = st.columns.findIndex(c => c.key === sourceColKey);
  const toIdx = st.columns.findIndex(c => c.key === targetColKey);
  if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;

  const [moved] = st.columns.splice(fromIdx, 1);
  st.columns.splice(toIdx, 0, moved);

  persistTablePrefs(tableId);
  refreshColVisMenu(tableId);
  updateTableHeaders(tableId);
  updateTableRows(tableId);
};

window.moveTableColumn = function(tableId, colKey, delta, evt) {
  if (evt) {
    evt.preventDefault();
    evt.stopPropagation();
  }
  const st = TABLE_STATE[tableId];
  if (!st || !Array.isArray(st.columns)) return;
  const idx = st.columns.findIndex(c => c.key === colKey);
  const nextIdx = idx + delta;
  if (idx < 0 || nextIdx < 0 || nextIdx >= st.columns.length) return;

  const [moved] = st.columns.splice(idx, 1);
  st.columns.splice(nextIdx, 0, moved);

  persistTablePrefs(tableId);
  refreshColVisMenu(tableId);
  updateTableHeaders(tableId);
  updateTableRows(tableId);
};

window.resetTableColumnPrefs = function(tableId, evt) {
  if (evt) {
    evt.preventDefault();
    evt.stopPropagation();
  }
  const st = TABLE_STATE[tableId];
  if (!st) return;
  st.columns = (st.defaultColumns || []).slice();
  st.hiddenCols = new Set(st.defaultHiddenCols || []);
  st.colWidths = {};
  if (window.TABLE_PREFS_CACHE && window.TABLE_PREFS_CACHE.tables) {
    delete window.TABLE_PREFS_CACHE.tables[tableId];
  }
  persistTablePrefs(tableId);
  refreshColVisMenu(tableId);
  updateTableHeaders(tableId);
  updateTableRows(tableId);
  showToast('Column order and visibility restored to default');
};

window.changeTablePageSize = function(tableId, newSize) {
  const st = TABLE_STATE[tableId];
  if (!st) return;
  st.pageSize = parseInt(newSize, 10) || 25;
  st.currentPage = 1;
  updateTableRows(tableId);
};

window.changeTablePage = function(tableId, delta) {
  const st = TABLE_STATE[tableId];
  if (!st) return;
  const totalPages = Math.max(1, Math.ceil((st.lastFiltered || []).length / st.pageSize));
  const next = st.currentPage + delta;
  if (next >= 1 && next <= totalPages) {
    st.currentPage = next;
    updateTableRows(tableId);
  }
};

// Manual Drag-to-Resize Column Handler
window.initColumnResize = function(evt, tableId, colKey) {
  evt.stopPropagation();
  evt.preventDefault();
  const th = evt.target.closest('th');
  if (!th) return;
  const resizer = evt.target;
  resizer.classList.add('resizing');
  const startX = evt.pageX;
  const startWidth = th.offsetWidth;

  function onMouseMove(moveEvt) {
    const newWidth = Math.max(65, startWidth + (moveEvt.pageX - startX));
    th.style.width = `${newWidth}px`;
    th.style.minWidth = `${newWidth}px`;
    if (TABLE_STATE[tableId]) {
      TABLE_STATE[tableId].colWidths[colKey] = newWidth;
    }
  }

  function onMouseUp() {
    resizer.classList.remove('resizing');
    persistTablePrefs(tableId);
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  }

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};

// Build contextual plain-English explanation, recommended fix, and version-aware PowerShell command for any inspected record
function buildRowDiagnosticGuidance(row, tableId) {
  if (!row || typeof row !== 'object') return null;

  let explanation = row.Explanation || row.SuspectedCause || row.AnalysisSummary || row.WhyItLags || row.Reason || row.Notes || row.RiskNote || '';
  let recommendedFix = row.RecommendedAction || row.Recommendation || row.Verification || '';
  let cmdPS51 = '';
  let cmdPS7 = '';

  // Contextual synthesis for Process / Binary / Service / Event / Network rows
  if (!explanation && row.SignatureStatus) {
    if (String(row.SignatureStatus).toUpperCase().includes('NOTSIGNED') || String(row.SignatureStatus).toUpperCase().includes('UNSIGNED')) {
      explanation = `The binary "${row.ProcessName || row.FileName || row.Name || 'target'}" does not carry an embedded Authenticode signature or Windows Catalog signature. While common for open-source or developer utilities, unsigned binaries in user-writable paths warrant publisher & hash verification.`;
      recommendedFix = `Verify the binary SHA-256 hash (${row.SHA256 || 'see below'}) and inspect its Authenticode certificate status and parent process.`;
    } else if (String(row.SignatureStatus).toUpperCase().includes('VALID')) {
      explanation = `This binary carries a cryptographically valid Authenticode signature (${row.Publisher || 'trusted publisher'}).`;
      recommendedFix = `No remediation required unless behavior or command-line arguments appear anomalous.`;
    }
  }

  if (!explanation && row.EventId) {
    explanation = `Windows Event ID ${row.EventId} logged by provider "${row.ProviderName || 'System'}" in channel "${row.Channel || 'Application/System'}".`;
    recommendedFix = `Inspect the full event payload below and correlate timestamps with active processes or crash dumps.`;
  }

  if (row.BinaryPath || row.FullPath) {
    const targetPath = row.BinaryPath || row.FullPath;
    cmdPS51 = `Get-AuthenticodeSignature -FilePath "${targetPath}" | Format-List *; Get-FileHash -Path "${targetPath}" -Algorithm SHA256`;
    cmdPS7 = `Get-AuthenticodeSignature -FilePath "${targetPath}" | Format-List *; Get-FileHash -Path "${targetPath}" -Algorithm SHA256`;
  } else if (row.PID && Number(row.PID) > 0) {
    cmdPS51 = `Get-CimInstance Win32_Process -Filter "ProcessId = ${row.PID}" | Select-Object ProcessId,Name,ParentProcessId,ExecutablePath,CommandLine`;
    cmdPS7 = `Get-CimInstance Win32_Process -Filter "ProcessId = ${row.PID}" | Select-Object ProcessId,Name,ParentProcessId,ExecutablePath,CommandLine`;
  } else if (row.EventId && row.Channel) {
    cmdPS51 = `Get-WinEvent -FilterHashtable @{LogName="${row.Channel}"; Id=${row.EventId}} -MaxEvents 10 | Format-List TimeCreated,Id,LevelDisplayName,Message`;
    cmdPS7 = `Get-WinEvent -FilterHashtable @{LogName="${row.Channel}"; Id=${row.EventId}} -MaxEvents 10 | Format-List TimeCreated,Id,LevelDisplayName,Message`;
  } else if (row.Name && tableId === 'tblServices') {
    cmdPS51 = `Get-CimInstance Win32_Service -Filter "Name='${row.Name}'" | Select-Object Name,DisplayName,State,StartMode,StartName,PathName`;
    cmdPS7 = `Get-CimInstance Win32_Service -Filter "Name='${row.Name}'" | Select-Object Name,DisplayName,State,StartMode,StartName,PathName`;
  }

  if (!explanation && !recommendedFix && !cmdPS51) return null;
  return { explanation, recommendedFix, cmdPS51, cmdPS7 };
}

function extractVirusTotalTargetFromRow(row) {
  if (!row || typeof row !== 'object') return null;
  const sha256 = (row.SHA256 && /^[A-Fa-f0-9]{64}$/.test(String(row.SHA256).trim())) ? String(row.SHA256).trim().toUpperCase() : '';
  // Prefer ServiceDll if present on svchost service rows, then DllPath, BinaryPath, TargetBinary, PathName, FullPath
  let targetPath = '';
  const candidates = [row.ServiceDll, row.DllPath, row.BinaryPath, row.TargetBinary, row.PathName, row.FullPath];
  for (const c of candidates) {
    if (c && typeof c === 'string' && c !== 'N/A' && c !== 'None' && c !== 'Unavailable') {
      targetPath = c.trim();
      break;
    }
  }
  const entityName = row.ProcessName || row.FileName || row.DisplayName || row.Name || row.HandlerName || row.EntryName || 'Target Binary/Module';
  const isPublicIp = Boolean(row.IsPublicRemoteIP && row.RemoteAddress);
  return {
    entityName,
    targetPath,
    sha256,
    signatureStatus: row.SignatureStatus || row.IntegrityStatus || 'Unknown',
    publisher: row.Publisher || row.CompanyName || row.Company || 'Unknown',
    isPublicIp,
    remoteIp: row.RemoteAddress || '',
    country: row.Country || '',
    asnOrg: row.ASN_Organization || '',
    reverseDns: row.ReverseDNS || ''
  };
}

window.openRowVirusTotalAction = async function(tableId, rowIndex) {
  const st = TABLE_STATE[tableId];
  if (!st || !st.lastFiltered || !st.lastFiltered[rowIndex]) return;
  const row = st.lastFiltered[rowIndex];
  const info = extractVirusTotalTargetFromRow(row);
  if (!info) return;

  // If this is a public network IP row without a binary SHA-256 or if tableId is tblNetTCP
  if (tableId === 'tblNetTCP' && info.isPublicIp) {
    showIpThreatIntelModal(info, row);
    return;
  }

  // If SHA256 is already available on the row, show the VirusTotal modal immediately (with option to run deep INT-03 API/hash check)
  if (info.sha256) {
    showVirusTotalModal({
      EntityName: info.entityName,
      ResolvedFilePath: info.targetPath || 'In-Memory / System Binary',
      TargetPathInput: info.targetPath || '',
      SHA256: info.sha256,
      SignatureStatus: info.signatureStatus,
      Publisher: info.publisher,
      VirusTotal_GUI_URL: `https://www.virustotal.com/gui/file/${info.sha256}`,
      HybridAnalysis_URL: `https://www.hybrid-analysis.com/search?query=${info.sha256}`,
      MicrosoftSubmit_URL: 'https://www.microsoft.com/en-us/wdsi/filesubmission',
      VT_API_Status: 'Ready — Click "Open on VirusTotal.com" or "Run Deep Hash & API Scan (INT-03)" below',
      Explanation: `Cryptographic SHA-256 hash (${info.sha256}) is ready for instant reputation lookup. Looking up by SHA-256 hash on VirusTotal verifies multi-engine AV detections without uploading sensitive local binaries.`,
      RecommendedFix: `Click "Open Report on VirusTotal.com" to inspect detections across 70+ security vendors, or click "Compute All Hashes & Query VT API (INT-03)" to inspect SHA-1/MD5/PE headers via PowerShell.`
    });
    return;
  }

  // Otherwise (e.g., Service, DLL, Driver, or Registry Autorun where SHA-256 wasn't pre-computed yet), run INT-03 live!
  if (info.targetPath) {
    await runLiveVirusTotalScript(info.targetPath, '', info.entityName);
  }
};

window.triggerManualVirusTotalLookup = async function() {
  const pathEl = document.getElementById('inputVtTargetPath');
  const shaEl = document.getElementById('inputVtSha256');
  const targetPath = pathEl ? pathEl.value.trim() : '';
  const sha256 = shaEl ? shaEl.value.trim() : '';

  if (!targetPath && !sha256) {
    showToast('Enter a file/DLL/driver path (e.g. C:\\Windows\\System32\\ntoskrnl.exe) or a 64-character SHA-256 hash.');
    return;
  }
  await runLiveVirusTotalScript(targetPath, sha256, '');
};

window.runLiveVirusTotalScript = async function(targetPath, sha256 = '', entityName = '') {
  const params = {};
  if (targetPath) params.TargetPath = targetPath;
  if (sha256) params.SHA256 = sha256;
  if (entityName) params.EntityName = entityName;

  const res = await executeScript('INT-03', params);
  if (res && res.scriptOutputJson) {
    const out = res.scriptOutputJson;
    if (out.Status === 'FileNotFoundOrNoHash') {
      showDiagnosticIssueModal({
        hasIssue: true,
        severity: 'warning',
        title: `Unable to Resolve File or Hash (${entityName || targetPath || sha256})`,
        explanation: out.Explanation,
        recommendedFix: out.RecommendedFix,
        commandPS51: out.Command_PS51,
        commandPS7: out.Command_PS7
      });
      return;
    }
    showVirusTotalModal(out);
  } else if (!SERVER_ONLINE && sha256 && /^[A-Fa-f0-9]{64}$/.test(sha256)) {
    // Offline fallback when a valid SHA-256 hash was provided
    showVirusTotalModal({
      EntityName: entityName || 'SHA-256 Hash Lookup',
      ResolvedFilePath: targetPath || 'Hash-Only Lookup',
      SHA256: sha256.toUpperCase(),
      SignatureStatus: 'Offline Mode',
      Publisher: 'Check via PowerShell or VirusTotal',
      VirusTotal_GUI_URL: `https://www.virustotal.com/gui/file/${sha256.toUpperCase()}`,
      HybridAnalysis_URL: `https://www.hybrid-analysis.com/search?query=${sha256.toUpperCase()}`,
      VT_API_Status: 'Offline Snapshot Mode — Direct Browser Lookup Ready'
    });
  }
};

function showIpThreatIntelModal(info, row) {
  const modal = document.getElementById('detailModalBackdrop');
  const title = document.getElementById('detailModalTitle');
  const body = document.getElementById('detailModalBody');
  const copyBtn = document.getElementById('detailModalCopyBtn');
  if (!modal || !title || !body) return;

  const ip = info.remoteIp;
  const vtIpUrl = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
  const abuseUrl = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
  const shodanUrl = `https://www.shodan.io/host/${encodeURIComponent(ip)}`;

  title.textContent = `External IP Threat Intelligence & VirusTotal Lookup (${ip})`;
  if (copyBtn) copyBtn.onclick = () => copyToClipboard(JSON.stringify(row, null, 2));

  body.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:0.9rem;">
      <div class="card" style="padding:0.95rem 1.1rem; margin-bottom:0; border-left:4px solid var(--accent-teal);">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.5rem;">
          <div>
            <span class="badge badge-info">Remote Public IP: ${escapeHtml(ip)}</span>
            <span class="badge badge-neutral">Process: ${escapeHtml(info.entityName)} (PID ${escapeHtml(String(row.PID || ''))})</span>
          </div>
          <span class="badge badge-success">${escapeHtml(info.country)} &bull; ${escapeHtml(info.asnOrg)}</span>
        </div>
        <p style="font-size:0.82rem; color:var(--text-secondary); margin-bottom:0.75rem;">
          Inspect multi-engine reputation, passive DNS resolutions, downloaded communicating samples, and abuse reports for <strong>${escapeHtml(ip)}</strong> (${escapeHtml(info.reverseDns || 'No PTR')}):
        </p>
        <div style="display:flex; gap:0.55rem; flex-wrap:wrap;">
          <a class="btn btn-teal" href="${escapeHtml(vtIpUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#128737; Open IP Report on VirusTotal.com &#8599;
          </a>
          <a class="btn btn-primary" href="${escapeHtml(abuseUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#128680; Check AbuseIPDB &#8599;
          </a>
          <a class="btn" href="${escapeHtml(shodanUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#128269; Check Shodan.io &#8599;
          </a>
          ${info.targetPath ? `
            <button class="btn" onclick="runLiveVirusTotalScript('${escapeJs(info.targetPath)}', '', '${escapeJs(info.entityName)}')">
              &#128737; Check Owning Process Binary (${escapeHtml(info.entityName)}) on VirusTotal
            </button>
          ` : ''}
        </div>
      </div>
    </div>
  `;
  modal.classList.add('open');
}

window.showVirusTotalModal = function(vt) {
  const modal = document.getElementById('detailModalBackdrop');
  const title = document.getElementById('detailModalTitle');
  const body = document.getElementById('detailModalBody');
  const copyBtn = document.getElementById('detailModalCopyBtn');
  if (!modal || !title || !body || !vt) return;

  const psEnv = getDiscoveredPowerShellEnv(window.FORENSIC_DATA || {});
  const sha256 = vt.SHA256 || '';
  const vtUrl = vt.VirusTotal_GUI_URL || (sha256 ? `https://www.virustotal.com/gui/file/${sha256}` : 'https://www.virustotal.com');
  const hybridUrl = vt.HybridAnalysis_URL || (sha256 ? `https://www.hybrid-analysis.com/search?query=${sha256}` : 'https://www.hybrid-analysis.com');
  const msUrl = vt.MicrosoftSubmit_URL || 'https://www.microsoft.com/en-us/wdsi/filesubmission';
  const rawPath = vt.ResolvedFilePath && vt.ResolvedFilePath !== 'Hash-Only Lookup' && vt.ResolvedFilePath !== 'In-Memory / System Binary'
    ? vt.ResolvedFilePath
    : (vt.TargetPathInput || '');

  const cmdPS51 = vt.Command_PS51 || (rawPath
    ? `Get-FileHash -Path "${rawPath}" -Algorithm SHA256; Get-AuthenticodeSignature -FilePath "${rawPath}"; Start-Process "${vtUrl}"`
    : `Start-Process "${vtUrl}"`);
  const cmdPS7 = vt.Command_PS7 || cmdPS51;
  const activeCmd = psEnv.DetectedProfile === 'PS7' ? cmdPS7 : cmdPS51;

  title.textContent = `VirusTotal & Binary Threat Intelligence: ${vt.EntityName || 'Target Binary'}`;
  if (copyBtn) copyBtn.onclick = () => copyToClipboard(JSON.stringify(vt, null, 2));

  const hasApiStats = vt.VT_MaliciousDetections !== null && vt.VT_MaliciousDetections !== undefined;
  const apiBannerClass = hasApiStats
    ? (vt.VT_MaliciousDetections > 0 ? 'critical' : 'info')
    : 'info';

  body.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:0.9rem;">
      <div class="alert-banner ${apiBannerClass}" style="margin-bottom:0;">
        <div style="font-size:1.35rem;">&#128737;</div>
        <div style="flex:1;">
          <h3>${escapeHtml(vt.EntityName || 'Binary / DLL')} &mdash; ${ renderAssessmentBadge(vt.SignatureStatus || 'Unknown') }</h3>
          <p style="margin-bottom:0.35rem;">
            <strong>SHA-256:</strong> <code style="user-select:all;">${escapeHtml(sha256)}</code>
            <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem; margin-left:0.4rem;" onclick="copyToClipboard('${escapeJs(sha256)}')">Copy SHA-256</button>
          </p>
          <p style="margin-bottom:0.35rem;"><strong>Resolved File Path:</strong> <code>${escapeHtml(vt.ResolvedFilePath || vt.TargetPathInput || 'N/A')}</code></p>
          <p style="margin-bottom:0.35rem;"><strong>Signer / Publisher:</strong> ${escapeHtml(vt.Publisher || 'Unknown')} ${vt.FileVersion ? `| <strong>Version:</strong> ${escapeHtml(vt.FileVersion)}` : ''}</p>
          <p style="margin-bottom:0;"><strong>VirusTotal Status:</strong> ${escapeHtml(vt.VT_API_Status || 'Ready for Lookup')} ${hasApiStats ? `| <strong>Detections:</strong> ${vt.VT_MaliciousDetections} / ${vt.VT_TotalEngines} Malicious (${escapeHtml(vt.VT_ThreatLabel || '')})` : ''}</p>
        </div>
      </div>

      <div class="card" style="padding:0.9rem 1rem; margin-bottom:0; border-left:4px solid var(--accent-teal);">
        <h4 style="font-size:0.9rem; font-weight:700; margin-bottom:0.45rem;">One-Click External Threat Intelligence Actions (Privacy-Safe Hash Lookup)</h4>
        <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.65rem;">
          <a class="btn btn-teal" href="${escapeHtml(vtUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#127760; Open SHA-256 Report on VirusTotal.com &#8599;
          </a>
          <a class="btn btn-primary" href="${escapeHtml(hybridUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#128300; Search Hybrid-Analysis (Falcon Sandbox) &#8599;
          </a>
          <a class="btn" href="${escapeHtml(msUrl)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#128737; Microsoft Security Intelligence Submission &#8599;
          </a>
          ${rawPath ? `
            <button class="btn" onclick="runLiveVirusTotalScript('${escapeJs(rawPath)}', '${escapeJs(sha256)}', '${escapeJs(vt.EntityName || '')}')">
              &#9889; Compute SHA-1/MD5/PE &amp; Query VT API (INT-03)
            </button>
          ` : ''}
        </div>
        ${vt.Explanation ? `<p style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.3rem;"><strong>Analysis Note:</strong> ${escapeHtml(vt.Explanation)}</p>` : ''}
        ${vt.RecommendedFix ? `<p style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.5rem;"><strong>Recommended Action:</strong> ${escapeHtml(vt.RecommendedFix)}</p>` : ''}

        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.73rem; font-weight:600; margin-bottom:0.2rem;">
            <span>Local PowerShell Command (${escapeHtml(psEnv.DetectedProfileLabel)}):</span>
            <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(activeCmd)}')">Copy Command</button>
          </div>
          <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap; word-break:break-all;">${escapeHtml(activeCmd)}</pre>
        </div>
      </div>

      ${(vt.SHA1 || vt.MD5 || vt.OriginalFilename) ? `
        <div class="kv-grid">
          ${Object.entries(vt).map(([k, v]) => {
            const formatted = (typeof v === 'object' && v !== null) ? JSON.stringify(v, null, 2) : String(v ?? 'N/A');
            return `
              <div class="kv-key">${escapeHtml(k)}</div>
              <div class="kv-val" onclick="copyToClipboard('${escapeJs(formatted)}')" title="Click to copy">${escapeHtml(formatted)}</div>
            `;
          }).join('')}
        </div>
      ` : ''}
    </div>
  `;
  modal.classList.add('open');
};

// Expandable Row Details Modal
window.openRowDetailModal = function(tableId, rowIndex) {
  const st = TABLE_STATE[tableId];
  if (!st || !st.lastFiltered || !st.lastFiltered[rowIndex]) return;
  const row = st.lastFiltered[rowIndex];
  const modal = document.getElementById('detailModalBackdrop');
  const title = document.getElementById('detailModalTitle');
  const body = document.getElementById('detailModalBody');
  const copyBtn = document.getElementById('detailModalCopyBtn');

  title.textContent = `${st.title} — Record Inspection`;
  copyBtn.onclick = () => copyToClipboard(JSON.stringify(row, null, 2));

  const psEnv = getDiscoveredPowerShellEnv(window.FORENSIC_DATA || {});
  const guidance = buildRowDiagnosticGuidance(row, tableId);
  const activeCmd = guidance ? (psEnv.DetectedProfile === 'PS7' ? guidance.cmdPS7 : guidance.cmdPS51) : '';
  const hasVt = rowSupportsVirusTotal(row, tableId);
  const vtInfo = hasVt ? extractVirusTotalTargetFromRow(row) : null;

  const vtQuickBarHtml = vtInfo ? `
    <div class="card" style="padding:0.75rem 1rem; margin-bottom:0.85rem; border-left:4px solid var(--accent-blue); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
      <div>
        <strong style="font-size:0.85rem;">&#128737; VirusTotal &amp; Threat Intelligence Lookup</strong>
        <div style="font-size:0.75rem; color:var(--text-secondary);">
          ${vtInfo.sha256 ? `SHA-256: <code>${escapeHtml(vtInfo.sha256.slice(0, 24))}...</code>` : (vtInfo.targetPath ? `Target: <code>${escapeHtml(vtInfo.targetPath)}</code>` : `Remote IP: <code>${escapeHtml(vtInfo.remoteIp)}</code>`)}
        </div>
      </div>
      <div style="display:flex; gap:0.45rem; flex-wrap:wrap;">
        ${vtInfo.sha256 ? `
          <a class="btn btn-teal btn-sm" href="https://www.virustotal.com/gui/file/${encodeURIComponent(vtInfo.sha256)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;">
            &#127760; Open on VirusTotal.com &#8599;
          </a>
        ` : ''}
        <button class="btn btn-primary btn-sm" onclick="openRowVirusTotalAction('${tableId}', ${rowIndex})">
          &#128737; ${vtInfo.sha256 ? 'Full VirusTotal &amp; Sandbox Panel' : 'Compute Hash &amp; Check VirusTotal (INT-03)'}
        </button>
      </div>
    </div>
  ` : '';

  const guidanceHtml = guidance ? `
    <div class="card" style="padding:0.85rem 1rem; margin-bottom:1rem; border-left:4px solid var(--accent-teal);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
        <strong style="font-size:0.88rem;">Diagnostic Context &amp; Recommended Action</strong>
        <span class="badge badge-info">Local PS: v${escapeHtml(psEnv.ActiveVersion)} (${escapeHtml(psEnv.PSEdition)})</span>
      </div>
      ${guidance.explanation ? `<p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.35rem;"><strong>Explanation:</strong> ${escapeHtml(guidance.explanation)}</p>` : ''}
      ${guidance.recommendedFix ? `<p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.45rem;"><strong>Recommended Action / Verification:</strong> ${escapeHtml(guidance.recommendedFix)}</p>` : ''}
      ${activeCmd ? `
        <div style="margin-top:0.35rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; color:var(--text-muted); margin-bottom:0.2rem;">
            <span>Verification Command (${escapeHtml(psEnv.DetectedProfileLabel)}):</span>
            <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(activeCmd)}')">Copy Command</button>
          </div>
          <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap; word-break:break-all;">${escapeHtml(activeCmd)}</pre>
        </div>
      ` : ''}
    </div>
  ` : '';

  body.innerHTML = `
    ${vtQuickBarHtml}
    ${guidanceHtml}
    <div class="kv-grid">
      ${Object.entries(row).map(([k, v]) => {
        const formatted = (typeof v === 'object' && v !== null) ? JSON.stringify(v, null, 2) : String(v ?? 'N/A');
        return `
          <div class="kv-key">${escapeHtml(k)}</div>
          <div class="kv-val" onclick="copyToClipboard('${escapeJs(formatted)}')" title="Click to copy">${escapeHtml(formatted)}</div>
        `;
      }).join('')}
    </div>
  `;
  modal.classList.add('open');
};

window.closeDetailModal = function() {
  const modal = document.getElementById('detailModalBackdrop');
  if (modal) modal.classList.remove('open');
};

// CSV & Excel SpreadsheetML Export Functions
window.exportTableCSV = function(tableId) {
  const st = TABLE_STATE[tableId];
  if (!st || !st.lastFiltered) return;
  const cols = st.columns.filter(c => !st.hiddenCols.has(c.key));
  const header = cols.map(c => `"${String(c.label).replace(/"/g, '""')}"`).join(',');
  const lines = st.lastFiltered.map(row => {
    return cols.map(c => {
      const val = row[c.key] ?? '';
      return `"${String(val).replace(/"/g, '""')}"`;
    }).join(',');
  });
  const csvContent = '\uFEFF' + [header, ...lines].join('\r\n');
  downloadBlob(csvContent, `${tableId}_${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.csv`, 'text/csv;charset=utf-8;');
  showToast(`Exported ${st.lastFiltered.length} rows to CSV.`);
};

window.exportTableXLSX = function(tableId) {
  const st = TABLE_STATE[tableId];
  if (!st || !st.lastFiltered) return;
  const cols = st.columns.filter(c => !st.hiddenCols.has(c.key));

  // Generate Microsoft Excel 2003+ XML SpreadsheetML Workbook
  let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<?mso-application progid="Excel.Sheet"?>\n`;
  xml += `<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">\n`;
  xml += `  <Styles>\n    <Style ss:ID="Header"><Font ss:Bold="1"/><Interior ss:Color="#E2E8F0" ss:Pattern="Solid"/></Style>\n  </Styles>\n`;
  xml += `  <Worksheet ss:Name="ForensicExport">\n    <Table>\n`;
  xml += `      <Row ss:StyleID="Header">` + cols.map(c => `<Cell><Data ss:Type="String">${escapeXml(c.label)}</Data></Cell>`).join('') + `</Row>\n`;

  st.lastFiltered.forEach(row => {
    xml += `      <Row>` + cols.map(c => {
      const v = row[c.key] ?? '';
      const isNum = typeof v === 'number' && !isNaN(v);
      return `<Cell><Data ss:Type="${isNum ? 'Number' : 'String'}">${escapeXml(String(v))}</Data></Cell>`;
    }).join('') + `</Row>\n`;
  });

  xml += `    </Table>\n  </Worksheet>\n</Workbook>`;
  downloadBlob(xml, `${tableId}_${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.xls`, 'application/vnd.ms-excel');
  showToast(`Exported ${st.lastFiltered.length} rows to Excel Spreadsheet.`);
};

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ----------------------------------------------------------------------------
// 4. Badge Render Helpers
// ----------------------------------------------------------------------------
function renderAssessmentBadge(val) {
  const s = String(val || 'Unknown');
  const up = s.toUpperCase();
  let cls = 'badge-neutral';
  if (up.includes('CRITICAL') || up.includes('INVALID') || up.includes('MISMATCH')) cls = 'badge-critical';
  else if (up.includes('HIGH') || up.includes('ERROR') || up.includes('SEVERE')) cls = 'badge-high';
  else if (up.includes('MEDIUM') || up.includes('WARNING') || up.includes('MODERATE') || up.includes('UNSIGNED') || up.includes('NOTSIGNED')) cls = 'badge-warning';
  else if (up.includes('VERIFIED') || up.includes('VALID') || up.includes('MATCH') || up.includes('KERNELTRUSTED') || up.includes('RUNNING') || up.includes('OK')) cls = 'badge-success';
  else if (up.includes('LOW') || up.includes('INFO')) cls = 'badge-low';
  return `<span class="badge ${cls}">${escapeHtml(s)}</span>`;
}

// ----------------------------------------------------------------------------
// 5. View Renderers (1 to 10)
// ----------------------------------------------------------------------------

// VIEW 1: SYSTEM OVERVIEW & CHARTS
function renderHeaderAndOverview(fData, lData) {
  const hw = (fData.Hardware && fData.Hardware.SystemOverview) || (lData.SystemSummary) || {};
  const perf = (fData.Performance && fData.Performance.LatestSnapshot) || {};
  const corrSum = (fData.CorrelatedEntities && fData.CorrelatedEntities.Summary) || {};
  const netSum = (fData.Network && fData.Network.Summary) || {};
  const intSum = (fData.BinaryIntegrity && fData.BinaryIntegrity.Summary) || {};
  const secSum = (fData.SecurityFindings && fData.SecurityFindings.SummaryCounts) || {};
  const memSum = (fData.MemoryForensics && fData.MemoryForensics.Summary) || {};
  const evtSum = (fData.Events && fData.Events.SeveritySummary) || {};

  // Update Navigation Tab Counts
  setText('badgeCountProcs', corrSum.TotalCorrelatedProcesses || 0);
  setText('badgeCountNet', netSum.TotalTCPConnections || 0);
  setText('badgeCountEvents', ((fData.Events && fData.Events.Events) || []).length);
  setText('badgeCountIntegrity', intSum.TotalVerifiedBinaries || 0);
  setText('badgeCountSecurity', secSum.TotalFindings || 0);
  setText('badgeCountMemory', memSum.TotalDumpFilesOnDisk || 0);

  // Header Meta Chips & Footer Hostname
  const demoHost = (typeof window !== 'undefined' && window.location && window.location.search) ? new URLSearchParams(window.location.search).get('demoHost') : null;
  const hostDisplay = demoHost || hw.ComputerName || 'Local Windows Host';
  const psEnv = getDiscoveredPowerShellEnv(fData);
  setText('footerHostName', hostDisplay);
  const headerMeta = document.getElementById('headerMeta');
  if (headerMeta) {
    headerMeta.innerHTML = `
      <div class="meta-chip"><span>Host:</span> <strong>${escapeHtml(hostDisplay)}</strong></div>
      <div class="meta-chip"><span>OS Build:</span> <strong>${escapeHtml(hw.OSBuild || 'N/A')}</strong></div>
      <div class="meta-chip" title="Discovered Local PowerShell Runtime (${escapeHtml(psEnv.DetectedProfileLabel)})"><span>PowerShell:</span> <strong>v${escapeHtml(psEnv.ActiveVersion)} (${escapeHtml(psEnv.PSEdition)})</strong></div>
      <div class="meta-chip"><span>Uptime:</span> <strong>${escapeHtml(hw.UptimeFormatted || (hw.UptimeHours ? hw.UptimeHours + 'h' : 'N/A'))}</strong></div>
      <div class="meta-chip"><span>Engine:</span> <strong style="color:${SERVER_ONLINE ? 'var(--status-success)' : 'var(--status-warning)'};">${SERVER_ONLINE ? 'Live Script API Online' : 'Snapshot Mode'}</strong></div>
    `;
  }

  const incSum = (fData.Incidents && fData.Incidents.SummaryCounts) || {};
  const diagFindings = (fData.Incidents && fData.Incidents.DiagnosticFindings) || [];
  const tdrCount = memSum.RecentTDRKernelEvents ?? incSum.DisplayBrowserEvents ?? 0;
  const expCount = incSum.ExplorerRelatedEvents ?? 0;
  const hasStabilityAlerts = (tdrCount > 0 || expCount > 0);

  // Dynamic Incident Summary Banner
  const incBanner = document.getElementById('incidentSummaryBanner');
  const incContent = document.getElementById('incidentSummaryContent');
  if (incBanner && incContent) {
    incBanner.className = `alert-banner ${hasStabilityAlerts ? 'critical' : 'info'}`;
    if (diagFindings.length > 0) {
      incContent.innerHTML = `
        <h3>Automated System Stability &amp; Incident Forensic Diagnosis (<code>INC-01</code>)</h3>
        ${diagFindings.map(df => `
          <p style="margin-bottom: 0.45rem;">
            <strong>${escapeHtml(df.Incident)} [${escapeHtml(df.Confidence)}]:</strong>
            ${escapeHtml(df.SuspectedCause)} <em>Evidence:</em> ${escapeHtml(df.Evidence)}
          </p>
        `).join('')}
      `;
    } else {
      incContent.innerHTML = `
        <h3>Automated System Stability &amp; Incident Forensic Diagnosis (<code>INC-01</code>)</h3>
        <p>Display/GPU Events: <strong>${tdrCount}</strong> &bull; Shell/Explorer Events: <strong>${expCount}</strong> &bull; Crash Dumps on Disk: <strong>${memSum.TotalDumpFilesOnDisk || 0}</strong>. Run <code>INC-01</code> or <code>CORE-01</code> to refresh detailed incident findings.</p>
      `;
    }
  }

  // KPI Cards
  const kpiContainer = document.getElementById('kpiContainer');
  if (kpiContainer) {
    kpiContainer.innerHTML = `
      <div class="card kpi-card ${hasStabilityAlerts ? 'kpi-critical' : 'kpi-success'}">
        <div class="kpi-header"><span class="kpi-title">System Stability Triage</span><span class="badge ${hasStabilityAlerts ? 'badge-critical' : 'badge-success'}">${hasStabilityAlerts ? 'Events Found' : 'Healthy'}</span></div>
        <div class="kpi-value">${tdrCount} GPU TDRs / ${expCount} Shell Events</div>
        <div class="kpi-desc">${memSum.TotalDumpFilesOnDisk || 0} crash dumps on disk &bull; ${incSum.WERReports || 0} WER reports &bull; ${incSum.ApplicationErrorEvents || 0} App error/hang records.</div>
      </div>
      <div class="card kpi-card kpi-info">
        <div class="kpi-header"><span class="kpi-title">Correlated Processes</span><span class="badge badge-info">Entity Engine</span></div>
        <div class="kpi-value">${corrSum.TotalCorrelatedProcesses || 0} Processes</div>
        <div class="kpi-desc">${corrSum.WithActiveServices || 0} hosting services &bull; ${corrSum.WithNetworkEndpoints || 0} active network sockets &bull; ${corrSum.WithRegistryPersistence || 0} autorun keys.</div>
      </div>
      <div class="card kpi-card kpi-success">
        <div class="kpi-header"><span class="kpi-title">Binary Integrity</span><span class="badge badge-success">Authenticode</span></div>
        <div class="kpi-value">${intSum.VerifiedValidCount || 0} / ${intSum.TotalVerifiedBinaries || 0} Verified</div>
        <div class="kpi-desc">${intSum.BaselineMatchCount || 0} core OS baseline matches &bull; ${intSum.UnsignedCount || 0} unsigned third-party binaries &bull; ${intSum.InvalidSignatureCount || 0} invalid.</div>
      </div>
      <div class="card kpi-card kpi-warning">
        <div class="kpi-header"><span class="kpi-title">Security &amp; Network</span><span class="badge badge-warning">Audit</span></div>
        <div class="kpi-value">${secSum.TotalFindings || 0} Findings / ${netSum.PublicRemoteIPCount || 0} Public IPs</div>
        <div class="kpi-desc">Defender RTP: ${(fData.SecurityFindings && fData.SecurityFindings.DefenderStatus && fData.SecurityFindings.DefenderStatus.RealTimeProtectionEnabled) ? 'Active' : 'Check Status'} &bull; ${netSum.EstablishedTCPCount || 0} established TCP connections enriched.</div>
      </div>
    `;
  }

  // Crash Dump & BugCheck Detection Display on System Overview (Links to Analysis Tab)
  const overviewCrashEl = document.getElementById('overviewCrashDetectionCard');
  if (overviewCrashEl) {
    const memObj = fData.MemoryForensics || {};
    const latestCrash = memObj.LatestCrashAnalysis || null;
    const crashHist = Array.isArray(memObj.SystemCrashHistory) ? memObj.SystemCrashHistory : [];
    const dumpInv = Array.isArray(memObj.DumpInventory) ? memObj.DumpInventory : [];
    const memDmpRow = dumpInv.find(d => d.FileName === 'MEMORY.DMP');
    const bugCheckCnt = memSum.ConfirmedBugCheckCount ?? crashHist.filter(c => c.IsBugCheck).length;
    const rebootCnt = memSum.TotalUnexpectedReboots ?? crashHist.length;

    if (latestCrash) {
      const isBc = Boolean(latestCrash.IsBugCheck);
      overviewCrashEl.innerHTML = `
        <div class="card" style="border-left: 4px solid ${isBc ? 'var(--status-critical)' : 'var(--status-warning)'}; cursor: pointer; transition: transform 0.15s ease, box-shadow 0.15s ease;" onclick="activateTab('tab-memory'); window.scrollTo({top: 0, behavior: 'smooth'});" title="Click to open the Analysis tab and inspect the full decoded BugCheck &amp; Crash Root-Cause Report">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem;">
            <div style="flex: 1; min-width: 280px;">
              <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.4rem;">
                <span class="badge ${isBc ? 'badge-critical' : 'badge-warning'}">${isBc ? 'SYSTEM BUGCHECK DETECTED' : 'UNEXPECTED SYSTEM REBOOT'}</span>
                <span class="badge badge-info">Stop Code: ${escapeHtml(latestCrash.StopCodeHex)} (${escapeHtml(latestCrash.StopCodeName)})</span>
                <span class="badge badge-neutral">Crash Reboot: ${escapeHtml(latestCrash.RebootTimestampLocal)}</span>
                ${memDmpRow ? `<span class="badge badge-warning">MEMORY.DMP: ${escapeHtml(String(memDmpRow.Size_MB))} MB (Modified ${escapeHtml(memDmpRow.ModifiedLocal)})</span>` : ''}
              </div>
              <h3 style="font-size: 1rem; font-weight: 800; margin-bottom: 0.35rem;">
                Crash Dump &amp; Kernel BugCheck Detection: <code>${escapeHtml(latestCrash.StopCodeName)}</code> (${escapeHtml(latestCrash.StopCodeHex)})
              </h3>
              <p style="font-size: 0.82rem; color: var(--text-secondary); margin-bottom: 0.35rem; line-height: 1.5;">
                <strong>Decoded Parameter 1:</strong> <code>${escapeHtml(latestCrash.Parameter1)}</code><br>
                <strong>Correlated Pre-Crash Trigger:</strong> ${escapeHtml(latestCrash.PreCrashTriggerSummary)}<br>
                <strong>Dump Creation Status:</strong> ${escapeHtml(latestCrash.DumpCreationStatus)}
              </p>
              <div style="font-size: 0.76rem; color: var(--text-muted);">
                <strong>Inventory Summary:</strong> ${bugCheckCnt} Confirmed BugCheck(s) &bull; ${rebootCnt} Unexpected Reboot(s) (Kernel-Power 41) &bull; ${dumpInv.length} Physical Dump Files on Disk (${memSum.ExplorerDumpsCount || 0} Explorer, ${memSum.RecentTDRKernelEvents || 0} GPU TDR Events)
              </div>
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 0.5rem; justify-content: center;">
              <button class="btn btn-primary" type="button" onclick="event.stopPropagation(); activateTab('tab-memory'); window.scrollTo({top: 0, behavior: 'smooth'});">
                &#128269; Open Full Crash Analysis &rarr;
              </button>
              <button class="btn btn-sm" type="button" onclick="event.stopPropagation(); executeScript('MEM-01');">
                &#8635; Re-Scan Crash Logs (MEM-01)
              </button>
            </div>
          </div>
        </div>
      `;
    } else {
      overviewCrashEl.innerHTML = `
        <div class="card" style="border-left: 4px solid var(--accent-teal); cursor: pointer;" onclick="activateTab('tab-memory'); window.scrollTo({top: 0, behavior: 'smooth'});">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
            <div>
              <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                <span class="badge badge-info">CRASH DUMP &amp; BUGCHECK MONITOR</span>
                <span class="badge badge-neutral">${dumpInv.length} Dump Files Inventoried</span>
              </div>
              <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.2rem;">System Crash &amp; Memory Dump Forensics</h3>
              <p style="font-size: 0.8rem; color: var(--text-secondary); margin: 0;">Click to open the <strong>Analysis</strong> view and run <code>MEM-01</code> to decode Kernel BugChecks and inspect crash dumps.</p>
            </div>
            <button class="btn btn-primary btn-sm" type="button" onclick="event.stopPropagation(); activateTab('tab-memory');">&#128269; Open Analysis Page &rarr;</button>
          </div>
        </div>
      `;
    }
  }

  // Charts
  const resChart = document.getElementById('chartSystemResources');
  if (resChart) {
    const cpuPct = perf.CPU_Percent ?? 0;
    const ramPct = hw.UsedRAM_Percent ?? perf.RAM_Used_Percent ?? 0;
    const gpus = (fData.Hardware && fData.Hardware.GPUs) || [];
    const vramMB = gpus.reduce((acc, g) => acc + (Number(g.DedicatedVRAM_Used_MB) || 0), 0);
    const commitMB = perf.Committed_MB || 0;
    const commitLim = perf.CommitLimit_MB || 32768;
    const commitPct = Math.min(100, Math.round((commitMB / commitLim) * 100));

    resChart.innerHTML = `
      ${renderBarRow('CPU Load Percentage', `${cpuPct}%`, cpuPct, cpuPct > 80 ? 'red' : 'blue')}
      ${renderBarRow(`Physical RAM (${hw.UsedRAM_GB || 0} / ${hw.TotalRAM_GB || 31.8} GB)`, `${ramPct}%`, ramPct, ramPct > 85 ? 'amber' : 'teal')}
      ${renderBarRow(`System Commit Charge (${commitMB} / ${commitLim} MB)`, `${commitPct}%`, commitPct, 'blue')}
      ${renderBarRow(`Dedicated GPU VRAM Used`, `${vramMB} MB`, Math.min(100, Math.round((vramMB / 8192) * 100)), 'teal')}
      <div style="font-size:0.74rem; color:var(--text-muted); margin-top:0.5rem;">
        Disk I/O: Read <strong>${perf.Disk_Read_KBps || 0} KB/s</strong> (${perf.Disk_AvgSecPerRead_ms || 0} ms) | Write <strong>${perf.Disk_Write_KBps || 0} KB/s</strong> (${perf.Disk_AvgSecPerWrite_ms || 0} ms) | Page Faults: <strong>${perf.PageFaultsPerSec || 0}/s</strong>
      </div>
    `;
  }

  const topProcChart = document.getElementById('chartTopProcesses');
  if (topProcChart && fData.Performance && fData.Performance.TopProcessesByRAM) {
    const top6 = fData.Performance.TopProcessesByRAM.slice(0, 6);
    const maxRam = Math.max(500, ...(top6.map(p => p.WorkingSet_MB || 0)));
    topProcChart.innerHTML = top6.map(p => {
      const pct = Math.min(100, Math.round(((p.WorkingSet_MB || 0) / maxRam) * 100));
      const gpuNote = p.GPU_Dedicated_MB > 0 ? ` | GPU: ${p.GPU_Dedicated_MB} MB` : '';
      return renderBarRow(`${p.ProcessName} (PID ${p.PID})`, `${p.WorkingSet_MB} MB${gpuNote}`, pct, 'teal');
    }).join('');
  }

  const secChart = document.getElementById('chartSecurityDistribution');
  if (secChart) {
    secChart.innerHTML = `
      ${renderBarRow('Verified System & Process Signatures', `${intSum.VerifiedValidCount || 0} binaries`, Math.min(100, ((intSum.VerifiedValidCount || 0) / Math.max(1, intSum.TotalVerifiedBinaries || 1)) * 100), 'teal')}
      ${renderBarRow('Event Log Errors (7-Day Multi-Channel)', `${evtSum.Error || 0} events`, Math.min(100, (evtSum.Error || 0)), 'red')}
      ${renderBarRow('Event Log Warnings (7-Day Multi-Channel)', `${evtSum.Warning || 0} events`, Math.min(100, (evtSum.Warning || 0)), 'amber')}
      ${renderBarRow('Security & Persistence Findings', `${secSum.TotalFindings || 0} findings`, Math.min(100, (secSum.TotalFindings || 0) * 6), 'blue')}
    `;
  }

  // Hardware & Security Specs Grid
  const specsGrid = document.getElementById('specsGrid');
  if (specsGrid && fData.Hardware) {
    const h = fData.Hardware;
    const cpu0 = (h.CPUs && h.CPUs[0]) || {};
    const mb = h.MotherboardAndBIOS || {};
    const ps = h.PlatformSecurity || {};
    const gpus = (h.GPUs || []).map(g => `${g.Name} (Driver ${g.DriverVersion}, ${g.DriverDate})`).join(' | ');

    specsGrid.innerHTML = `
      <div class="spec-item"><div class="spec-label">Operating System</div><div class="spec-val">${escapeHtml(hw.OSName)} (Build ${escapeHtml(hw.OSBuild)})</div></div>
      <div class="spec-item"><div class="spec-label">Processor (CPU)</div><div class="spec-val">${escapeHtml(cpu0.Name || hw.CPU)} (${cpu0.PhysicalCores || 8}C / ${cpu0.LogicalProcessors || 16}T)</div></div>
      <div class="spec-item"><div class="spec-label">CPU Thermal Sensor</div><div class="spec-val">${escapeHtml(String(cpu0.Temperature_C || 'Unavailable'))} ${typeof cpu0.Temperature_C === 'number' ? '&deg;C' : ''}</div></div>
      <div class="spec-item"><div class="spec-label">Installed Memory (RAM)</div><div class="spec-val">${hw.UsedRAM_GB} GB Used / ${hw.TotalRAM_GB} GB (${hw.UsedRAM_Percent}%)</div></div>
      <div class="spec-item"><div class="spec-label">Display GPUs</div><div class="spec-val">${escapeHtml(gpus)}</div></div>
      <div class="spec-item"><div class="spec-label">Motherboard &amp; BIOS</div><div class="spec-val">${escapeHtml(mb.BoardManufacturer || '')} ${escapeHtml(mb.BoardProduct || '')} &bull; BIOS ${escapeHtml(mb.BIOSVersion || '')} (${escapeHtml(mb.BIOSReleaseDate || '')})</div></div>
      <div class="spec-item"><div class="spec-label">Secure Boot &amp; TPM</div><div class="spec-val">SecureBoot: ${escapeHtml(ps.SecureBoot)} &bull; TPM: ${escapeHtml(ps.TPM)}</div></div>
      <div class="spec-item"><div class="spec-label">VBS / DeviceGuard &amp; BitLocker</div><div class="spec-val">VBS: ${escapeHtml(ps.VirtualizationBasedSecurity)} &bull; BitLocker: ${escapeHtml(ps.BitLocker_OSDrive)}</div></div>
      <div class="spec-item"><div class="spec-label">Discovered PowerShell Runtime</div><div class="spec-val">v${escapeHtml(psEnv.ActiveVersion)} (${escapeHtml(psEnv.PSEdition)}) &bull; PS7 Installed: ${psEnv.PowerShell7_Installed ? 'Yes (' + escapeHtml(psEnv.PowerShell7_Version) + ')' : 'No'} &bull; CLR: ${escapeHtml(psEnv.CLRVersion)}</div></div>
    `;
  }

  // Storage Table
  if (fData.Hardware && fData.Hardware.LogicalVolumes) {
    renderForensicTable('tableContainerStorage', {
      tableId: 'tblStorage',
      title: 'Storage Volumes & Physical Disk Health (HW-01)',
      pageSize: 25,
      data: fData.Hardware.LogicalVolumes,
      columns: [
        { key: 'DriveLetter', label: 'Drive', mono: true },
        { key: 'VolumeName', label: 'Label' },
        { key: 'FileSystem', label: 'Filesystem' },
        { key: 'Size_GB', label: 'Capacity (GB)' },
        { key: 'Used_GB', label: 'Used (GB)' },
        { key: 'Free_GB', label: 'Free (GB)' },
        { key: 'Used_Percent', label: 'Usage %', render: v => `${v}%` },
        { key: 'VolumeSerial', label: 'Volume Serial', mono: true }
      ]
    });
  }

  // Network Adapters Table
  if (fData.Hardware && fData.Hardware.NetworkAdapters) {
    renderForensicTable('tableContainerAdapters', {
      tableId: 'tblAdapters',
      title: 'Network Interfaces, Drivers & Byte Counters (HW-01)',
      pageSize: 25,
      data: fData.Hardware.NetworkAdapters,
      columns: [
        { key: 'Name', label: 'Adapter Name' },
        { key: 'InterfaceDescription', label: 'Hardware Description' },
        { key: 'Status', label: 'Status', render: renderAssessmentBadge },
        { key: 'MacAddress', label: 'MAC Address', mono: true },
        { key: 'IPv4Addresses', label: 'IPv4 Address', mono: true },
        { key: 'LinkSpeed', label: 'Link Speed' },
        { key: 'Received_MB', label: 'Rx (MB)' },
        { key: 'Sent_MB', label: 'Tx (MB)' },
        { key: 'DriverVersion', label: 'Driver Version', mono: true }
      ]
    });
  }
}

// VIEW 2: PROCESSES, SERVICES & DRIVERS
function renderProcessesAndServicesView(fData) {
  const entities = (fData.CorrelatedEntities && fData.CorrelatedEntities.Entities) || [];
  renderForensicTable('tableContainerCorrelatedProcs', {
    tableId: 'tblCorrelatedProcs',
    title: 'Correlated Process Entities (Threat, Risk, PID, PPID, Hash, Signature, Services, Registry & Network)',
    pageSize: 25,
    hasThreatFilter: true,
    defaultSortCol: 'WorkingSet_MB',
    defaultSortAsc: false,
    data: entities,
    columns: [
      { key: 'ThreatAssessment', label: 'Threat Assessment', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk Assessment', render: renderAssessmentBadge },
      { key: 'ProcessName', label: 'Process Name' },
      { key: 'PID', label: 'PID', mono: true },
      { key: 'PPID', label: 'PPID', mono: true },
      { key: 'ParentProcess', label: 'Parent Process' },
      { key: 'WorkingSet_MB', label: 'RAM (MB)' },
      { key: 'CPU_Seconds', label: 'CPU (s)' },
      { key: 'GPU_Dedicated_MB', label: 'GPU (MB)' },
      { key: 'SignatureStatus', label: 'Signature', render: renderAssessmentBadge },
      { key: 'Publisher', label: 'Publisher' },
      { key: 'SHA256', label: 'SHA-256 Hash', mono: true },
      { key: 'Services', label: 'Associated Services' },
      { key: 'Registry', label: 'Registry Persistence' },
      { key: 'Network', label: 'Network Endpoints' },
      { key: 'BinaryPath', label: 'Binary Path', mono: true },
      { key: 'CommandLine', label: 'Command Line', mono: true },
      { key: 'UserAndSID', label: 'User / SID' },
      { key: 'StartTime', label: 'Start Time', mono: true }
    ]
  });

  const svcs = (fData.Services && fData.Services.Services) || [];
  renderForensicTable('tableContainerServices', {
    tableId: 'tblServices',
    title: 'Windows Services Inventory & Hosting Process Cross-Reference (SVC-01)',
    pageSize: 25,
    data: svcs,
    columns: [
      { key: 'Name', label: 'Service Name', mono: true },
      { key: 'DisplayName', label: 'Display Name' },
      { key: 'State', label: 'State', render: renderAssessmentBadge },
      { key: 'StartMode', label: 'Start Mode' },
      { key: 'ProcessId', label: 'PID', mono: true },
      { key: 'HostProcessName', label: 'Host Process' },
      { key: 'StartName', label: 'Service Account' },
      { key: 'ServiceDll', label: 'ServiceDll (svchost)', mono: true },
      { key: 'PathName', label: 'Binary Path / Command', mono: true }
    ]
  });

  const drvs = (fData.Drivers && fData.Drivers.Drivers) || [];
  renderForensicTable('tableContainerDrivers', {
    tableId: 'tblDrivers',
    title: 'Kernel & File-System Drivers Inventory (DRV-01)',
    pageSize: 25,
    data: drvs,
    columns: [
      { key: 'Name', label: 'Driver Name', mono: true },
      { key: 'DisplayName', label: 'Display Name' },
      { key: 'State', label: 'State', render: renderAssessmentBadge },
      { key: 'StartMode', label: 'Start Mode' },
      { key: 'ServiceType', label: 'Type' },
      { key: 'CompanyName', label: 'Publisher / Company' },
      { key: 'SignatureStatus', label: 'Signature', render: renderAssessmentBadge },
      { key: 'PathName', label: 'Driver Binary Path', mono: true },
      { key: 'SHA256', label: 'SHA-256 (Third-Party)', mono: true }
    ]
  });
}

// VIEW 3: NETWORK ACTIVITY & EXTERNAL IP INTELLIGENCE
function renderNetworkActivityView(fData) {
  const net = fData.Network || {};
  const tcp = net.TCPConnections || [];
  const udp = net.UDPEndpoints || [];
  const dns = net.DNSCacheSample || [];

  // Network Charts
  const stateChart = document.getElementById('chartNetworkStates');
  if (stateChart && net.Summary) {
    const s = net.Summary;
    stateChart.innerHTML = `
      ${renderBarRow('Established TCP Connections', `${s.EstablishedTCPCount || 0} sockets`, Math.min(100, (s.EstablishedTCPCount || 0) * 2), 'teal')}
      ${renderBarRow('Listening TCP Ports (Inbound Surface)', `${s.ListeningTCPCount || 0} sockets`, Math.min(100, (s.ListeningTCPCount || 0) * 2), 'blue')}
      ${renderBarRow('Unique Public Remote IP Addresses', `${s.PublicRemoteIPCount || 0} IPs`, Math.min(100, (s.PublicRemoteIPCount || 0) * 3), 'amber')}
      ${renderBarRow('Bound UDP Endpoints', `${s.TotalUDPEndpoints || 0} sockets`, Math.min(100, (s.TotalUDPEndpoints || 0)), 'blue')}
    `;
  }

  const countryChart = document.getElementById('chartNetworkCountries');
  if (countryChart) {
    const pubConns = tcp.filter(c => c.IsPublicRemoteIP);
    const byOrg = {};
    pubConns.forEach(c => {
      const k = `${c.Country} — ${c.ASN_Organization}`;
      byOrg[k] = (byOrg[k] || 0) + 1;
    });
    const sortedOrgs = Object.entries(byOrg).sort((a,b) => b[1] - a[1]).slice(0, 5);
    countryChart.innerHTML = sortedOrgs.length > 0
      ? sortedOrgs.map(([label, cnt]) => renderBarRow(label, `${cnt} conn`, Math.min(100, cnt * 15), 'teal')).join('')
      : '<div style="color:var(--text-muted); font-size:0.8rem;">No active external public TCP connections at snapshot time.</div>';
  }

  renderForensicTable('tableContainerNetTCP', {
    tableId: 'tblNetTCP',
    title: 'Active TCP Connections, Listening Sockets, Durations & WHOIS/ASN Intelligence (NET-01 / NET-02)',
    pageSize: 25,
    hasThreatFilter: true,
    data: tcp,
    columns: [
      { key: 'State', label: 'State', render: renderAssessmentBadge },
      { key: 'ProcessName', label: 'Process' },
      { key: 'PID', label: 'PID', mono: true },
      { key: 'LocalAddress', label: 'Local IP', mono: true },
      { key: 'LocalPort', label: 'Local Port', mono: true },
      { key: 'RemoteAddress', label: 'Remote IP', mono: true },
      { key: 'RemotePort', label: 'Remote Port', mono: true },
      { key: 'Country', label: 'Country (GeoIP)' },
      { key: 'ASN_Organization', label: 'ASN & Organization (WHOIS/RDAP)' },
      { key: 'ReverseDNS', label: 'Reverse DNS (PTR)', mono: true },
      { key: 'ConnectionDuration', label: 'Duration', mono: true },
      { key: 'ConnectionStartTime', label: 'Socket Created', mono: true },
      { key: 'RelatedServices', label: 'Related Services' },
      { key: 'ExposureRisk', label: 'Exposure Assessment', render: renderAssessmentBadge },
      { key: 'BinaryPath', label: 'Binary Path', mono: true }
    ]
  });

  renderForensicTable('tableContainerNetUDP', {
    tableId: 'tblNetUDP',
    title: 'Bound UDP Endpoints & Owning Processes (NET-01)',
    pageSize: 25,
    data: udp,
    columns: [
      { key: 'Protocol', label: 'Protocol' },
      { key: 'LocalAddress', label: 'Bind Address', mono: true },
      { key: 'LocalPort', label: 'Local Port', mono: true },
      { key: 'ProcessName', label: 'Owning Process' },
      { key: 'PID', label: 'PID', mono: true },
      { key: 'RelatedServices', label: 'Related Services' },
      { key: 'CreationTime', label: 'Creation Timestamp', mono: true },
      { key: 'BinaryPath', label: 'Binary Path', mono: true }
    ]
  });

  renderForensicTable('tableContainerDNSCache', {
    tableId: 'tblDNSCache',
    title: 'Local DNS Client Resolver Cache Sample (NET-01)',
    pageSize: 25,
    data: dns,
    columns: [
      { key: 'Entry', label: 'Queried Domain', mono: true },
      { key: 'RecordName', label: 'Record Name', mono: true },
      { key: 'RecordType', label: 'Type' },
      { key: 'Data', label: 'Resolved IP / Target', mono: true },
      { key: 'TTL_Sec', label: 'TTL (s)' }
    ]
  });
}

// VIEW 4: WINDOWS EVENTS & INCIDENT TIMELINES
function renderWindowsEventsView(fData) {
  const evts = fData.Events || {};
  const inc = fData.Incidents || {};

  const chChart = document.getElementById('chartEventChannels');
  if (chChart && evts.ChannelStatus) {
    chChart.innerHTML = evts.ChannelStatus.map(ch => {
      const pct = Math.min(100, Math.round((ch.EventsPulled / 60) * 100));
      return renderBarRow(`${ch.Channel} (${ch.Status})`, `${ch.EventsPulled} events`, pct, ch.EventsPulled > 0 ? 'blue' : 'amber');
    }).join('');
  }

  const clChart = document.getElementById('chartEventClusters');
  if (clChart && evts.EventClusters) {
    const top5 = evts.EventClusters.slice(0, 5);
    clChart.innerHTML = top5.map(c => {
      const pct = Math.min(100, c.Occurrences * 3);
      return renderBarRow(`[${c.Channel}] Event ${c.EventId} (${c.ProviderName})`, `${c.Occurrences}x`, pct, c.Severity === 'Error' || c.Severity === 'Critical' ? 'red' : 'amber');
    }).join('');
  }

  const superTl = (fData.SuperTimeline && fData.SuperTimeline.TimelineEntries) || [];
  renderForensicTable('tableContainerSuperTimeline', {
    tableId: 'tblSuperTimeline',
    title: 'Unified Chronological Forensic Super-Timeline: Processes, Network Sockets, Events, Crash Dumps, Tasks & PS 4104 (UTIL-04)',
    pageSize: 25,
    hasThreatFilter: true,
    data: superTl,
    columns: [
      { key: 'TimestampLocal', label: 'Local Timestamp', mono: true },
      { key: 'TimestampUtc', label: 'UTC Timestamp', mono: true },
      { key: 'ArtifactType', label: 'Artifact Type' },
      { key: 'SourceModule', label: 'Source', mono: true },
      { key: 'EntityOrEvent', label: 'Entity / Event' },
      { key: 'PID_Or_RecordId', label: 'PID / Record ID', mono: true },
      { key: 'SeverityOrThreat', label: 'Severity / Threat', render: renderAssessmentBadge },
      { key: 'Summary', label: 'Chronological Event Summary', wrap: true },
      { key: 'BinaryPath', label: 'Binary Path', mono: true }
    ]
  });

  renderForensicTable('tableContainerIncidentEvents', {
    tableId: 'tblIncidentEvents',
    title: 'Incident A (GPU TDR 141 / Browser) & Incident B (Explorer Crash/Hang) Forensic Event Log Evidence (INC-01)',
    pageSize: 25,
    data: inc.ApplicationEvents || [],
    columns: [
      { key: 'TimeCreatedLocal', label: 'Local Timestamp', mono: true },
      { key: 'TimeCreatedUtc', label: 'UTC Timestamp', mono: true },
      { key: 'EventId', label: 'Event ID', mono: true },
      { key: 'Level', label: 'Level', render: renderAssessmentBadge },
      { key: 'ProviderName', label: 'Provider' },
      { key: 'IsExplorerRelated', label: 'Explorer Incident B', render: v => v ? '<span class="badge badge-critical">Explorer Match</span>' : '<span class="badge badge-neutral">No</span>' },
      { key: 'IsDisplayOrBrowserRelated', label: 'GPU/Browser Incident A', render: v => v ? '<span class="badge badge-warning">GPU/TDR/Browser</span>' : '<span class="badge badge-neutral">No</span>' },
      { key: 'RecordId', label: 'Record ID', mono: true },
      { key: 'Message', label: 'Event Payload / Problem Signature', wrap: true }
    ]
  });

  renderForensicTable('tableContainerEventClusters', {
    tableId: 'tblEventClusters',
    title: 'Repeated Error & Warning Event Clusters Across Channels (EVT-01)',
    pageSize: 25,
    hasThreatFilter: true,
    data: evts.EventClusters || [],
    columns: [
      { key: 'Channel', label: 'Channel' },
      { key: 'ProviderName', label: 'Provider' },
      { key: 'EventId', label: 'Event ID', mono: true },
      { key: 'Severity', label: 'Severity', render: renderAssessmentBadge },
      { key: 'Occurrences', label: 'Count' },
      { key: 'FirstSeenLocal', label: 'First Seen', mono: true },
      { key: 'LastSeenLocal', label: 'Last Seen', mono: true },
      { key: 'SampleMessage', label: 'Sample Message', wrap: true }
    ]
  });

  renderForensicTable('tableContainerAllEvents', {
    tableId: 'tblAllEvents',
    title: 'All Collected Multi-Channel Windows Event Records (EVT-01)',
    pageSize: 25,
    hasThreatFilter: true,
    data: evts.Events || [],
    columns: [
      { key: 'TimeCreatedLocal', label: 'Local Timestamp', mono: true },
      { key: 'Channel', label: 'Channel' },
      { key: 'EventId', label: 'Event ID', mono: true },
      { key: 'Severity', label: 'Severity', render: renderAssessmentBadge },
      { key: 'ProviderName', label: 'Provider' },
      { key: 'ProcessId', label: 'PID', mono: true },
      { key: 'RecordId', label: 'Record ID', mono: true },
      { key: 'Message', label: 'Event Message', wrap: true }
    ]
  });
}

// VIEW 5: SYSTEM BINARY INTEGRITY
function renderBinaryIntegrityView(fData) {
  const bins = (fData.BinaryIntegrity && fData.BinaryIntegrity.Binaries) || [];
  renderForensicTable('tableContainerBinaryIntegrity', {
    tableId: 'tblBinaryIntegrity',
    title: 'System32 & Active Process Binary Integrity Verification (SHA-256, Authenticode, Microsoft Publisher & Baseline)',
    pageSize: 25,
    hasThreatFilter: true,
    data: bins,
    columns: [
      { key: 'FileName', label: 'Binary Name', mono: true },
      { key: 'IntegrityStatus', label: 'Integrity Status (Section 7)', render: renderAssessmentBadge },
      { key: 'SignatureStatus', label: 'Authenticode', render: renderAssessmentBadge },
      { key: 'SignatureType', label: 'Sig Type' },
      { key: 'Publisher', label: 'Signer / Publisher' },
      { key: 'IsMicrosoftSigned', label: 'Microsoft Signed', render: v => v ? '<span class="badge badge-success">Yes (Microsoft)</span>' : '<span class="badge badge-neutral">Third-Party</span>' },
      { key: 'BaselineComparison', label: 'Baseline Match', render: renderAssessmentBadge },
      { key: 'SHA256', label: 'SHA-256 Hash', mono: true },
      { key: 'FileVersion', label: 'Version', mono: true },
      { key: 'RelatedProcesses', label: 'Active Processes' },
      { key: 'RelatedServices', label: 'Related Services' },
      { key: 'ThreatAssessment', label: 'Threat', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk', render: renderAssessmentBadge },
      { key: 'BinaryPath', label: 'Full Path', mono: true },
      { key: 'Notes', label: 'Verification Notes', wrap: true }
    ]
  });
}

// VIEW 6: SECURITY FINDINGS, PERSISTENCE & SHELL EXTENSIONS
function renderSecurityFindingsView(fData) {
  const findings = (fData.SecurityFindings && fData.SecurityFindings.Findings) || [];
  renderForensicTable('tableContainerSecurityFindings', {
    tableId: 'tblSecurityFindings',
    title: 'Deterministic Security, Persistence & Attack Surface Findings (MAL-01)',
    pageSize: 25,
    hasThreatFilter: true,
    data: findings,
    columns: [
      { key: 'FindingId', label: 'ID', mono: true },
      { key: 'Title', label: 'Finding Title' },
      { key: 'Category', label: 'Category' },
      { key: 'ThreatAssessment', label: 'Threat Assessment', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk Assessment', render: renderAssessmentBadge },
      { key: 'Confidence', label: 'Confidence' },
      { key: 'AffectedAsset', label: 'Affected Asset', mono: true },
      { key: 'DetectionRule', label: 'Detection Rule', mono: true },
      { key: 'Evidence', label: 'Observable Evidence', wrap: true },
      { key: 'RecommendedAction', label: 'Recommended Action', wrap: true },
      { key: 'FalsePositiveConsiderations', label: 'False-Positive Context', wrap: true }
    ]
  });

  const deepPers = fData.DeepPersistence || {};
  renderForensicTable('tableContainerScheduledTasks', {
    tableId: 'tblScheduledTasks',
    title: 'Scheduled Tasks Persistence & Binary Authenticode Audit (MAL-02)',
    pageSize: 25,
    hasThreatFilter: true,
    data: deepPers.ScheduledTasks || [],
    columns: [
      { key: 'TaskName', label: 'Task Name' },
      { key: 'TaskPath', label: 'Task Folder', mono: true },
      { key: 'State', label: 'State', render: renderAssessmentBadge },
      { key: 'RunAsUser', label: 'Run As Principal' },
      { key: 'RunLevel', label: 'Privilege Level' },
      { key: 'SignatureStatus', label: 'Authenticode', render: renderAssessmentBadge },
      { key: 'Publisher', label: 'Publisher / Signer' },
      { key: 'ThreatAssessment', label: 'Threat', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk', render: renderAssessmentBadge },
      { key: 'ExecuteCommand', label: 'Executable', mono: true },
      { key: 'Arguments', label: 'Arguments', mono: true },
      { key: 'LastRunTime', label: 'Last Run', mono: true },
      { key: 'LastTaskResult', label: 'Last Exit Code', mono: true },
      { key: 'SHA256', label: 'SHA-256 Hash', mono: true }
    ]
  });

  renderForensicTable('tableContainerPowerShellScriptBlocks', {
    tableId: 'tblPowerShellScriptBlocks',
    title: 'PowerShell Event ID 4104 / 4103 ScriptBlock & Obfuscation Audit (MAL-02)',
    pageSize: 25,
    hasThreatFilter: true,
    data: deepPers.PowerShellScriptLogs || [],
    columns: [
      { key: 'TimeCreatedLocal', label: 'Local Timestamp', mono: true },
      { key: 'Channel', label: 'Log Channel' },
      { key: 'EventId', label: 'Event ID', mono: true },
      { key: 'ProcessId', label: 'PID', mono: true },
      { key: 'DetectedPatterns', label: 'Heuristic Pattern Match' },
      { key: 'ThreatAssessment', label: 'Threat', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk', render: renderAssessmentBadge },
      { key: 'ScriptBlockPreview', label: 'Decoded ScriptBlock Transcript Preview', wrap: true },
      { key: 'RecommendedAction', label: 'Recommended Action', wrap: true }
    ]
  });

  renderForensicTable('tableContainerBitsJobs', {
    tableId: 'tblBitsJobs',
    title: 'Background Intelligent Transfer Service (BITS) Jobs Queue Audit (MAL-02)',
    pageSize: 25,
    hasThreatFilter: true,
    data: deepPers.BitsTransferJobs || [],
    columns: [
      { key: 'DisplayName', label: 'BITS Job Name' },
      { key: 'JobState', label: 'Job State', render: renderAssessmentBadge },
      { key: 'TransferType', label: 'Transfer Type' },
      { key: 'OwnerAccount', label: 'Owner Account' },
      { key: 'Priority', label: 'Priority' },
      { key: 'BytesTransferred', label: 'Bytes Transferred' },
      { key: 'CreationTime', label: 'Created Timestamp', mono: true },
      { key: 'ThreatAssessment', label: 'Threat', render: renderAssessmentBadge },
      { key: 'TransferFiles', label: 'Remote URL -> Local Destination Path', wrap: true }
    ]
  });

  const regEntries = (fData.Registry && fData.Registry.Entries) || [];
  renderForensicTable('tableContainerRegistryPersistence', {
    tableId: 'tblRegistryPersistence',
    title: 'Registry Autorun, Winlogon Core & IFEO Debugger Persistence Inventory (REG-01)',
    pageSize: 25,
    data: regEntries,
    columns: [
      { key: 'Category', label: 'Category' },
      { key: 'Scope', label: 'Registry Scope' },
      { key: 'EntryName', label: 'Entry Name', mono: true },
      { key: 'ValueData', label: 'Configured Command / Value', mono: true },
      { key: 'TargetBinary', label: 'Target Executable', mono: true },
      { key: 'RiskNote', label: 'Forensic Assessment' },
      { key: 'RegistryKey', label: 'Full Registry Path', mono: true }
    ]
  });

  const shellExts = (fData.Incidents && fData.Incidents.ShellContextHandlers) || [];
  renderForensicTable('tableContainerShellExtensions', {
    tableId: 'tblShellExtensions',
    title: 'Registered Explorer Shell Context Menu Handlers (Incident B Audit - INC-01)',
    pageSize: 25,
    data: shellExts,
    columns: [
      { key: 'HandlerName', label: 'Handler Name' },
      { key: 'CLSID', label: 'COM CLSID', mono: true },
      { key: 'Company', label: 'Publisher / Vendor' },
      { key: 'DllPath', label: 'InprocServer32 DLL Path', mono: true },
      { key: 'Scope', label: 'Registry Scope', mono: true }
    ]
  });
}

// VIEW 7: FULL SYSTEM CRASH ROOT-CAUSE ANALYSIS & MEMORY FORENSICS
function renderMemoryCrashView(fData) {
  const mem = fData.MemoryForensics || {};
  const latest = mem.LatestCrashAnalysis || null;
  const hostCfg = mem.HostCrashConfiguration || {};
  const dirStatus = Array.isArray(mem.DirectoryAccessStatus) ? mem.DirectoryAccessStatus : [];
  const sysCrashes = Array.isArray(mem.SystemCrashHistory) ? mem.SystemCrashHistory : [];
  const isAdmin = Boolean(mem.IsElevatedAdmin);

  const rcaContainer = document.getElementById('crashRootCauseEngineContainer');
  if (rcaContainer) {
    const dimmsHtml = Array.isArray(hostCfg.PhysicalMemoryModules) && hostCfg.PhysicalMemoryModules.length > 0
      ? hostCfg.PhysicalMemoryModules.map(d => `<div style="font-size:0.78rem; font-family:'JetBrains Mono',monospace;">&bull; ${escapeHtml(d.Summary)}</div>`).join('')
      : '<div style="font-size:0.78rem; color:var(--text-muted);">Physical DIMM inventory unavailable</div>';

    const disksHtml = Array.isArray(hostCfg.StorageDisks) && hostCfg.StorageDisks.length > 0
      ? hostCfg.StorageDisks.map(d => `<span class="badge ${String(d.HealthStatus).toUpperCase() === 'HEALTHY' ? 'badge-success' : 'badge-critical'}" style="margin-right:0.35rem;">${escapeHtml(d.FriendlyName)} (${escapeHtml(String(d.Size_GB))} GB): ${escapeHtml(d.HealthStatus)} / ${escapeHtml(d.OperationalStatus)}</span>`).join('')
      : '';

    const dirBadgesHtml = dirStatus.map(ds => `
      <span class="badge ${ds.Accessible ? 'badge-success' : 'badge-warning'}" title="${escapeHtml(ds.StatusMessage)}" style="margin-right:0.35rem; margin-bottom:0.25rem;">
        ${escapeHtml(ds.Category)}: ${ds.FilesFound} file(s) ${ds.Accessible ? '(Accessible)' : '(Admin Required for Raw Folder)'}
      </span>
    `).join('');

    const preCrashRowsHtml = (latest && Array.isArray(latest.PreCrashTimeline) && latest.PreCrashTimeline.length > 0)
      ? latest.PreCrashTimeline.slice(0, 8).map(pe => `
          <tr>
            <td class="mono-cell" style="white-space:nowrap;">${escapeHtml(pe.TimeLocal)}</td>
            <td class="mono-cell">${escapeHtml(String(pe.EventId))}</td>
            <td>${renderAssessmentBadge(pe.Level)}</td>
            <td>${escapeHtml(pe.ProviderName)}</td>
            <td class="mono-cell">${escapeHtml(String(pe.RecordId))}</td>
            <td class="wrap-cell">${escapeHtml(pe.Message)}</td>
          </tr>
        `).join('')
      : `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:0.75rem;">No abnormal driver/update events recorded in the 30-minute pre-crash window.</td></tr>`;

    const remStepsHtml = (latest && Array.isArray(latest.RemediationSteps) && latest.RemediationSteps.length > 0)
      ? latest.RemediationSteps.map(step => `<li style="margin-bottom:0.35rem; font-size:0.82rem; color:var(--text-secondary); line-height:1.5;">${escapeHtml(step)}</li>`).join('')
      : '';

    rcaContainer.innerHTML = `
      <!-- Elevation & Non-Admin Capability Notice -->
      <div class="alert-banner ${isAdmin ? 'info' : 'warning'}" style="margin-bottom: 1.15rem;">
        <div style="font-size: 1.35rem; line-height: 1;">${isAdmin ? '&#9989;' : '&#128274;'}</div>
        <div style="flex: 1;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.3rem;">
            <h3 style="margin:0;">Collection Privilege Mode: ${isAdmin ? 'Administrator (Elevated Full Dump Byte Access)' : 'Standard User (Non-Admin Event &amp; XML Correlation Active)'}</h3>
            <span class="badge ${isAdmin ? 'badge-success' : 'badge-info'}">100% BugCheck XML Decoder Active</span>
          </div>
          <p style="margin-bottom: 0.45rem; font-size: 0.81rem;">
            ${escapeHtml(mem.ElevationNote || 'The Kernel BugCheck & Pre-Crash Event Correlation Engine decodes Kernel-Power Event 41 XML, volmgr Event 161, FilterManager, and MEMORY.DMP metadata even without Administrator elevation.')}
          </p>
          <div style="display:flex; flex-wrap:wrap; align-items:center; gap:0.4rem;">
            ${dirBadgesHtml}
          </div>
        </div>
      </div>

      ${latest ? `
        <!-- Automated Full System Crash Root-Cause Analysis Card -->
        <div class="card" style="border-left: 5px solid ${latest.IsBugCheck ? 'var(--status-critical)' : 'var(--status-warning)'}; margin-bottom: 0;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:1rem; margin-bottom:1rem; padding-bottom:0.85rem; border-bottom:1px solid var(--border-light);">
            <div>
              <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.4rem;">
                <span class="badge ${latest.IsBugCheck ? 'badge-critical' : 'badge-warning'}">${latest.IsBugCheck ? 'CONFIRMED KERNEL BUGCHECK' : 'UNEXPECTED KERNEL REBOOT'}</span>
                <span class="badge badge-info">Stop Code: ${escapeHtml(latest.StopCodeHex)} (${escapeHtml(String(latest.BugcheckCodeDec))})</span>
                <span class="badge badge-neutral">Kernel-Power Event 41 (RecordId ${escapeHtml(String(latest.KernelPowerRecordId))})</span>
                <span class="badge badge-neutral">Reboot Time: ${escapeHtml(latest.RebootTimestampLocal)}</span>
              </div>
              <h3 style="font-size:1.15rem; font-weight:800; margin-bottom:0.25rem;">
                Latest System Crash Root-Cause Analysis: <code>${escapeHtml(latest.StopCodeName)}</code> (${escapeHtml(latest.StopCodeHex)})
              </h3>
              <div style="font-size:0.82rem; color:var(--text-secondary);">
                <strong>Faulting Subsystem:</strong> ${escapeHtml(latest.Subsystem)} &bull;
                <strong>Faulting Component:</strong> <code>${escapeHtml(latest.FaultingComponent)}</code>
              </div>
            </div>
            <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
              <button class="btn btn-sm" type="button" onclick="copyToClipboard(JSON.stringify(window.FORENSIC_DATA.MemoryForensics.LatestCrashAnalysis, null, 2))">&#128203; Copy Crash JSON</button>
              <button class="btn btn-primary btn-sm" type="button" onclick="executeScript('MEM-01')">&#8635; Re-Verify Crash Logs</button>
            </div>
          </div>

          <!-- Decoded 64-Bit BugCheck Parameters Grid -->
          <h4 style="font-size:0.88rem; font-weight:700; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.55rem;">
            1. Decoded 64-Bit Kernel BugCheck Parameters (<code>Microsoft-Windows-Kernel-Power</code> Event ID 41 XML)
          </h4>
          <div class="specs-grid" style="grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); margin-bottom:1.1rem;">
            <div class="spec-item" style="border-left:3px solid var(--status-critical);">
              <div class="spec-label">BugcheckParameter1 (Primary Error / NTSTATUS)</div>
              <div class="spec-val" style="font-family:'JetBrains Mono',monospace; font-size:0.79rem; word-break:break-word;">${escapeHtml(latest.Parameter1)}</div>
            </div>
            <div class="spec-item" style="border-left:3px solid var(--accent-blue);">
              <div class="spec-label">BugcheckParameter2 (Size / Secondary Context)</div>
              <div class="spec-val" style="font-family:'JetBrains Mono',monospace; font-size:0.79rem; word-break:break-word;">${escapeHtml(latest.Parameter2)}</div>
            </div>
            <div class="spec-item" style="border-left:3px solid var(--accent-teal);">
              <div class="spec-label">BugcheckParameter3 (Source Buffer / Context VA)</div>
              <div class="spec-val" style="font-family:'JetBrains Mono',monospace; font-size:0.79rem; word-break:break-word;">${escapeHtml(latest.Parameter3)}</div>
            </div>
            <div class="spec-item" style="border-left:3px solid var(--accent-teal);">
              <div class="spec-label">BugcheckParameter4 (Kernel Destination Buffer VA)</div>
              <div class="spec-val" style="font-family:'JetBrains Mono',monospace; font-size:0.79rem; word-break:break-word;">${escapeHtml(latest.Parameter4)}</div>
            </div>
          </div>

          <!-- Automated Root Cause & Pre-Crash Correlation -->
          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap:1rem; margin-bottom:1.1rem;">
            <div style="padding:0.9rem 1rem; background:var(--bg-subtle); border:1px solid var(--border-light); border-radius:var(--radius-md);">
              <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.4rem; color:var(--status-critical);">2. Automated Root-Cause Determination</h4>
              <p style="font-size:0.82rem; color:var(--text-secondary); line-height:1.55; margin-bottom:0.6rem;">
                ${escapeHtml(latest.RootCauseAnalysis)}
              </p>
              <div style="font-size:0.79rem; color:var(--text-secondary); padding-top:0.5rem; border-top:1px dashed var(--border-light);">
                <strong>Correlated Pre-Crash Trigger (30m Window):</strong> ${escapeHtml(latest.PreCrashTriggerSummary)}<br>
                <strong>Dump Creation &amp; Pagefile Status:</strong> ${escapeHtml(latest.DumpCreationStatus)}
              </div>
            </div>

            <div style="padding:0.9rem 1rem; background:var(--bg-subtle); border:1px solid var(--border-light); border-radius:var(--radius-md);">
              <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.4rem; color:var(--accent-blue);">3. Host RAM, MemCompression &amp; Pagefile Telemetry</h4>
              <div style="font-size:0.8rem; color:var(--text-secondary); line-height:1.55; margin-bottom:0.5rem;">
                &bull; <strong>Windows Memory Compression (<code>MemCompression</code>):</strong> <span class="badge ${hostCfg.MemoryCompressionEnabled ? 'badge-warning' : 'badge-neutral'}">${hostCfg.MemoryCompressionEnabled ? 'Enabled (Active in RAM)' : 'Disabled'}</span><br>
                &bull; <strong>CrashControl Dump Mode:</strong> <code>${escapeHtml(hostCfg.CrashDumpType || '7 (Automatic)')}</code><br>
                &bull; <strong>Pagefile Allocation vs. Physical RAM:</strong> <code>${escapeHtml(String(hostCfg.TotalPagefileAllocated_MB || 0))} MB</code> Pagefile / <code>${escapeHtml(String(hostCfg.TotalPhysicalRAM_MB || 0))} MB</code> Physical RAM<br>
                &bull; <strong>CPU Firmware Thermal/Power Throttling (Event 37):</strong> <code>${escapeHtml(String(hostCfg.RecentThermalThrottleCount ?? 0))}</code> recent warning(s) | <strong>WHEA Errors:</strong> <code>${escapeHtml(String(hostCfg.RecentWHEAHardwareErrors ?? 0))}</code>
              </div>
              <div style="margin-bottom:0.45rem;">
                <strong style="font-size:0.76rem; text-transform:uppercase; color:var(--text-muted);">Installed Physical Memory (DIMMs):</strong>
                ${dimmsHtml}
              </div>
              <div>${disksHtml}</div>
            </div>
          </div>

          <!-- 30-Minute Pre-Crash Activity Timeline Table -->
          <h4 style="font-size:0.88rem; font-weight:700; text-transform:uppercase; color:var(--text-secondary); margin-bottom:0.5rem;">
            4. Reconstructed 30-Minute Pre-Crash Kernel &amp; System Activity Timeline
          </h4>
          <div class="table-responsive" style="margin-bottom:1.1rem; max-height:260px; overflow-y:auto;">
            <table class="diag-table">
              <thead>
                <tr>
                  <th>Pre-Crash Timestamp</th>
                  <th>Event ID</th>
                  <th>Level</th>
                  <th>Provider</th>
                  <th>Record ID</th>
                  <th>Pre-Crash Activity / Driver / Update Payload</th>
                </tr>
              </thead>
              <tbody>
                ${preCrashRowsHtml}
              </tbody>
            </table>
          </div>

          <!-- Actionable Verification & Remediation Playbook -->
          <div style="padding:0.9rem 1rem; background:var(--bg-subtle); border:1px solid var(--border-light); border-left:4px solid var(--accent-teal); border-radius:var(--radius-md);">
            <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.4rem;">5. Recommended Verification &amp; Crash Prevention Playbook</h4>
            <ul style="margin:0 0 0.75rem 1.15rem; padding:0;">
              ${remStepsHtml}
            </ul>
            <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
              <button class="btn btn-sm" type="button" onclick="copyToClipboard('mdsched.exe')">&#128203; Copy: mdsched.exe (RAM Diagnostic)</button>
              <button class="btn btn-sm" type="button" onclick="copyToClipboard('Disable-MMAgent -MemoryCompression')">&#128203; Copy: Disable-MMAgent -MemoryCompression (Admin PS)</button>
              <button class="btn btn-sm" type="button" onclick="copyToClipboard('& \"$env:ProgramFiles\\\\Windows Defender\\\\MpCmdRun.exe\" -SignatureUpdate -MMPC')">&#128203; Copy: Reset Defender KB4052623 Update Loop</button>
            </div>
          </div>
        </div>
      ` : ''}
    `;
  }

  // System Kernel Crash & Unexpected Reboot History Table
  renderForensicTable('tableContainerSystemCrashes', {
    tableId: 'tblSystemCrashes',
    title: 'System Kernel Crash & Unexpected Reboot History (Kernel-Power Event 41 / BugCheck / volmgr Correlation)',
    pageSize: 10,
    hasThreatFilter: true,
    data: sysCrashes,
    columns: [
      { key: 'RebootTimestampLocal', label: 'Crash / Reboot Timestamp', mono: true },
      { key: 'StopCodeHex', label: 'Stop Code (Hex)', mono: true },
      { key: 'StopCodeName', label: 'BugCheck Symbolic Name', mono: true },
      { key: 'RiskAssessment', label: 'Severity / Risk', render: renderAssessmentBadge },
      { key: 'Parameter1', label: 'Decoded Parameter 1 (NTSTATUS / Subtype)', wrap: true },
      { key: 'Parameter2', label: 'Decoded Parameter 2', mono: true },
      { key: 'PreCrashTriggerSummary', label: 'Correlated Pre-Crash Activity (30m Window)', wrap: true },
      { key: 'DumpCreationStatus', label: 'volmgr / Dump Creation Status', wrap: true },
      { key: 'RootCauseAnalysis', label: 'Automated Root-Cause Analysis', wrap: true },
      { key: 'KernelPowerRecordId', label: 'Event Record ID', mono: true }
    ]
  });

  // Physical Crash Dump & Minidump File Inventory (Sorted by ModifiedLocal Descending so MEMORY.DMP is #1)
  renderForensicTable('tableContainerCrashDumps', {
    tableId: 'tblCrashDumps',
    title: 'Windows Crash Dump & Minidump File Inventory (Sorted by Last Modified / Crash Timestamp - MEM-01)',
    pageSize: 25,
    defaultSortCol: 'ModifiedLocal',
    defaultSortAsc: false,
    data: mem.DumpInventory || [],
    columns: [
      { key: 'ModifiedLocal', label: 'Last Modified (Crash Time)', mono: true },
      { key: 'FileName', label: 'Dump File Name', mono: true },
      { key: 'Category', label: 'Dump Category' },
      { key: 'RiskAssessment', label: 'Risk', render: renderAssessmentBadge },
      { key: 'ExceptionCode', label: 'Correlated BugCheck / Exception', mono: true },
      { key: 'FaultingModule', label: 'Faulting Module / Component', mono: true },
      { key: 'Size_MB', label: 'Size (MB)' },
      { key: 'AnalysisSummary', label: 'Forensic Triage & Event Correlation Summary', wrap: true },
      { key: 'HeaderValidation', label: 'Header Signature', render: renderAssessmentBadge },
      { key: 'TargetProcess', label: 'Process / Target' },
      { key: 'CreatedLocal', label: 'Initial File Created', mono: true },
      { key: 'SHA256', label: 'SHA-256 Hash', mono: true },
      { key: 'FullPath', label: 'Full File Path', mono: true }
    ]
  });

  renderForensicTable('tableContainerTdrEvents', {
    tableId: 'tblTdrEvents',
    title: 'GPU Timeout Detection & Recovery (LiveKernelEvent P1: 141 WATCHDOG) Timeline (Incident A)',
    pageSize: 25,
    data: mem.GPUTDRKernelEvents || [],
    columns: [
      { key: 'TimestampLocal', label: 'Local Timestamp', mono: true },
      { key: 'TimestampUtc', label: 'UTC Timestamp', mono: true },
      { key: 'RecordId', label: 'WER Record ID', mono: true },
      { key: 'EventName', label: 'Kernel Event Signature' },
      { key: 'DumpFileReferenced', label: 'Kernel Dump Referenced', mono: true },
      { key: 'StatusOnDisk', label: 'Artifact Retention Status' }
    ]
  });
}

// ----------------------------------------------------------------------------
// PowerShell Environment Discovery & Version-Specific Command Helper
// ----------------------------------------------------------------------------
function getDiscoveredPowerShellEnv(fData) {
  const hw = (fData && fData.Hardware) || {};
  const env = hw.PowerShellEnvironment || {};
  const defaultCommands = [
    {
      OperationId: 'PS-CMD-EVENTS',
      Category: 'Event Log Forensics',
      Operation: 'Query Recent Critical & Error System Events',
      ActiveLocalCommand: 'Get-WinEvent -FilterHashtable @{LogName="System","Application"; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue',
      Command_PS51: 'Get-WinEvent -FilterHashtable @{LogName="System","Application"; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue',
      Command_PS7: 'Get-WinEvent -FilterHashtable @{LogName="System","Application"; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -ErrorAction SilentlyContinue',
      Command_PSLegacy: 'Get-EventLog -LogName System -EntryType Error -Newest 100',
      VersionNotes: 'Get-EventLog was removed in PowerShell 7+ (Core). Get-WinEvent -FilterHashtable is compatible with both Windows PowerShell 5.1 and PowerShell 7+ and performs server-side XML filtering.'
    },
    {
      OperationId: 'PS-CMD-NET',
      Category: 'Network Forensics',
      Operation: 'Enumerate Active TCP Sockets with Owning Process & Service',
      ActiveLocalCommand: 'Get-NetTCPConnection -State Established,Listen | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}',
      Command_PS51: 'Get-NetTCPConnection -State Established,Listen | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}',
      Command_PS7: 'Get-NetTCPConnection -State Established,Listen | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}',
      Command_PSLegacy: 'netstat -ano -p tcp',
      VersionNotes: 'Get-NetTCPConnection (NetTCPIP CDXML module) is native in Windows PowerShell 5.1 and PowerShell 7+ on Windows 10/11. Legacy PS 2.0/3.0 on older OS builds requires netstat -ano.'
    },
    {
      OperationId: 'PS-CMD-HASH-SIG',
      Category: 'Binary Integrity',
      Operation: 'Verify SHA-256 Hash & Authenticode Signature of Running Executables',
      ActiveLocalCommand: 'Get-Process | Where-Object {$_.Path} | Select-Object -Unique Name,Path | ForEach-Object { [PSCustomObject]@{Name=$_.Name; SHA256=(Get-FileHash $_.Path -Algorithm SHA256).Hash; Signature=(Get-AuthenticodeSignature $_.Path).Status} }',
      Command_PS51: 'Get-Process | Where-Object {$_.Path} | Select-Object -Unique Name,Path | ForEach-Object { [PSCustomObject]@{Name=$_.Name; SHA256=(Get-FileHash $_.Path -Algorithm SHA256).Hash; Signature=(Get-AuthenticodeSignature $_.Path).Status} }',
      Command_PS7: 'Get-Process | Where-Object {$_.Path} | Select-Object -Unique Name,Path | ForEach-Object -Parallel { [PSCustomObject]@{Name=$_.Name; SHA256=(Get-FileHash $_.Path -Algorithm SHA256).Hash; Signature=(Get-AuthenticodeSignature $_.Path).Status} } -ThrottleLimit 8',
      Command_PSLegacy: 'certutil -hashfile C:\\Windows\\System32\\ntoskrnl.exe SHA256',
      VersionNotes: 'PowerShell 7+ supports native ForEach-Object -Parallel -ThrottleLimit 8 for multi-threaded hashing, whereas Windows PowerShell 5.1 uses sequential ForEach-Object or [runspacefactory]::CreateRunspacePool.'
    },
    {
      OperationId: 'PS-CMD-CIM-WMI',
      Category: 'Hardware & OS Inventory',
      Operation: 'Query WMI / CIM Hardware & Operating System Telemetry',
      ActiveLocalCommand: 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,FreePhysicalMemory',
      Command_PS51: 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,FreePhysicalMemory',
      Command_PS7: 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,FreePhysicalMemory',
      Command_PSLegacy: 'Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,FreePhysicalMemory',
      VersionNotes: 'Get-WmiObject (DCOM) was deprecated in PS 5.1 and completely removed in PowerShell 7+. All scripts in this platform use Get-CimInstance (WSMan/MI API) for full PS 5.1 & PS 7+ compatibility.'
    },
    {
      OperationId: 'PS-CMD-HTTP-INTEL',
      Category: 'External IP Intelligence',
      Operation: 'Query Public IP RDAP / ASN Threat Intelligence over HTTPS',
      ActiveLocalCommand: '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri "https://ipwho.is/8.8.8.8" -UseBasicParsing -TimeoutSec 5',
      Command_PS51: '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri "https://ipwho.is/8.8.8.8" -UseBasicParsing -TimeoutSec 5',
      Command_PS7: 'Invoke-RestMethod -Uri "https://ipwho.is/8.8.8.8" -TimeoutSec 5',
      Command_PSLegacy: '(New-Object System.Net.WebClient).DownloadString("https://ipwho.is/8.8.8.8")',
      VersionNotes: 'Windows PowerShell 5.1 requires -UseBasicParsing (to avoid IE DOM dependency) and explicit TLS 1.2 activation via [Net.ServicePointManager]. In PowerShell 7+, -UseBasicParsing is deprecated/default and TLS 1.2/1.3 is enabled natively.'
    },
    {
      OperationId: 'PS-CMD-APPX',
      Category: 'System Debloat & Packages',
      Operation: 'Audit or Remove Provisioned Consumer Appx Bloatware',
      ActiveLocalCommand: 'Get-AppxPackage -Name "Clipchamp.Clipchamp" | Select-Object Name,PackageFullName,Version',
      Command_PS51: 'Get-AppxPackage -Name "Clipchamp.Clipchamp" | Select-Object Name,PackageFullName,Version',
      Command_PS7: 'Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue; Get-AppxPackage -Name "Clipchamp.Clipchamp" | Select-Object Name,PackageFullName,Version',
      Command_PSLegacy: 'dism /Online /Get-ProvisionedAppxPackages',
      VersionNotes: 'On certain Windows 10/11 builds, the Appx module is compiled against .NET Framework Desktop and requires Import-Module Appx -UseWindowsPowerShell when invoked from PowerShell 7+.'
    },
    {
      OperationId: 'PS-CMD-OBSIDIAN-SYNC',
      Category: 'Knowledge Base & Reporting',
      Operation: 'Synchronize Forensic Findings to Local Obsidian Markdown Vault',
      ActiveLocalCommand: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Utilities\\Sync-ObsidianVault.ps1"',
      Command_PS51: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Utilities\\Sync-ObsidianVault.ps1"',
      Command_PS7: 'pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Utilities\\Sync-ObsidianVault.ps1"',
      Command_PSLegacy: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Utilities\\Sync-ObsidianVault.ps1"',
      VersionNotes: 'Sync-ObsidianVault.ps1 is written in pure 7-bit ASCII without smart-quotes or version-locked cmdlets so it executes identically under both powershell.exe (5.1) and pwsh.exe (7+).'
    },
    {
      OperationId: 'PS-CMD-REMEDIATION-ELEVATED',
      Category: 'Controlled Remediation',
      Operation: 'Execute Authorized System Modification with UAC Administrator Elevation',
      ActiveLocalCommand: 'Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\\Scripts\\Remediation\\Invoke-AuthorizedRemediation.ps1`" -ActionId REM-GPU-01_TdrDelayIncrease -ExecuteRemediation -ConfirmationToken AUTHORIZE-CHANGE"',
      Command_PS51: 'Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\\Scripts\\Remediation\\Invoke-AuthorizedRemediation.ps1`" -ActionId REM-GPU-01_TdrDelayIncrease -ExecuteRemediation -ConfirmationToken AUTHORIZE-CHANGE"',
      Command_PS7: 'Start-Process pwsh.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\\Scripts\\Remediation\\Invoke-AuthorizedRemediation.ps1`" -ActionId REM-GPU-01_TdrDelayIncrease -ExecuteRemediation -ConfirmationToken AUTHORIZE-CHANGE"',
      Command_PSLegacy: 'Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\\Scripts\\Remediation\\Invoke-AuthorizedRemediation.ps1`" -ActionId REM-GPU-01_TdrDelayIncrease -ExecuteRemediation -ConfirmationToken AUTHORIZE-CHANGE"',
      VersionNotes: 'HKLM registry keys (such as GPU TdrDelay) and Windows Service Control Manager modifications require an elevated Administrator token (-Verb RunAs).'
    }
  ];

  return {
    ActiveVersion: env.ActiveVersion || '5.1.26100.7019',
    MajorVersion: env.MajorVersion || 5,
    MinorVersion: env.MinorVersion ?? 1,
    PSEdition: env.PSEdition || 'Desktop',
    CLRVersion: env.CLRVersion || '4.0.30319.42000',
    DetectedProfile: env.DetectedProfile || 'PS51',
    DetectedProfileLabel: env.DetectedProfileLabel || 'Windows PowerShell 5.1 (Desktop Edition - powershell.exe)',
    WindowsPowerShell51_Installed: env.WindowsPowerShell51_Installed !== false,
    WindowsPowerShell51_Path: env.WindowsPowerShell51_Path || 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    PowerShell7_Installed: Boolean(env.PowerShell7_Installed),
    PowerShell7_Path: env.PowerShell7_Path || 'Not Installed (Using Windows PowerShell 5.1)',
    PowerShell7_Version: env.PowerShell7_Version || 'Not Installed',
    ExecutionPolicies: Array.isArray(env.ExecutionPolicies) && env.ExecutionPolicies.length > 0
      ? env.ExecutionPolicies
      : [
          { Scope: 'MachinePolicy', ExecutionPolicy: 'Undefined' },
          { Scope: 'UserPolicy', ExecutionPolicy: 'Undefined' },
          { Scope: 'Process', ExecutionPolicy: 'Bypass' },
          { Scope: 'CurrentUser', ExecutionPolicy: 'RemoteSigned' },
          { Scope: 'LocalMachine', ExecutionPolicy: 'RemoteSigned' }
        ],
    CompatibilityGuarantee: env.CompatibilityGuarantee || 'All 21 platform scripts are engineered to execute natively on Windows PowerShell 5.1 (Desktop) and PowerShell 7+ (Core) with version-adaptive cmdlets and pure ASCII source encoding.',
    VersionSpecificCommands: Array.isArray(env.VersionSpecificCommands) && env.VersionSpecificCommands.length > 0
      ? env.VersionSpecificCommands
      : defaultCommands
  };
}

function getEffectivePSProfile(psEnv) {
  if (SELECTED_PS_PROFILE === 'AUTO') {
    return psEnv.DetectedProfile || 'PS51';
  }
  return SELECTED_PS_PROFILE;
}

function getCommandForProfile(item, profileKey) {
  if (profileKey === 'PS7') return item.Command_PS7 || item.ActiveLocalCommand || item.Command_PS51;
  if (profileKey === 'PSLegacy') return item.Command_PSLegacy || item.Command_PS51;
  return item.Command_PS51 || item.ActiveLocalCommand;
}

window.setPowerShellCommandProfile = function(profile) {
  SELECTED_PS_PROFILE = profile;
  const fData = window.FORENSIC_DATA || {};
  const lData = window.DIAGNOSTIC_DATA || (fData.LegacyBaselineAudit) || {};
  renderPowerShellVersionMatrix(fData);
  renderRemediationAndLegacyView(fData, lData);
  const labelMap = {
    AUTO: 'Auto-Detected Local System PowerShell',
    PS51: 'Windows PowerShell 5.1 (Desktop - powershell.exe)',
    PS7: 'PowerShell 7+ (Core - pwsh.exe)',
    PSLegacy: 'Legacy PowerShell 3.0 / 4.0 (WMI / netsh Fallback)',
    COMPARE: 'Side-by-Side All PowerShell Versions Comparison'
  };
  showToast(`Switched PowerShell syntax display to: ${labelMap[profile] || profile}`);
};

function renderPowerShellVersionMatrix(fData) {
  const container = document.getElementById('psVersionMatrixCard');
  if (!container) return;

  const psEnv = getDiscoveredPowerShellEnv(fData);
  const effectiveProfile = getEffectivePSProfile(psEnv);
  const isCompare = SELECTED_PS_PROFILE === 'COMPARE';

  const policiesHtml = (psEnv.ExecutionPolicies || []).map(p =>
    `<span class="badge badge-neutral" style="margin-right:0.35rem;">${escapeHtml(p.Scope)}: <strong>${escapeHtml(p.ExecutionPolicy)}</strong></span>`
  ).join('');

  const profileBadgeLabel = effectiveProfile === 'PS7'
    ? 'PowerShell 7+ (Core - pwsh.exe)'
    : (effectiveProfile === 'PSLegacy'
        ? 'Legacy PowerShell 3.0/4.0 (WMI / netsh)'
        : 'Windows PowerShell 5.1 (Desktop - powershell.exe)');

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:1rem; margin-bottom:0.9rem;">
      <div>
        <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.3rem;">
          <span class="badge badge-success">Discovered Local PowerShell: v${escapeHtml(psEnv.ActiveVersion)} (${escapeHtml(psEnv.PSEdition)})</span>
          <span class="badge badge-info">Active Profile: ${escapeHtml(psEnv.DetectedProfile)}</span>
          <span class="badge ${psEnv.PowerShell7_Installed ? 'badge-success' : 'badge-neutral'}">PowerShell 7+ (pwsh.exe): ${psEnv.PowerShell7_Installed ? 'Installed (' + escapeHtml(psEnv.PowerShell7_Version) + ')' : 'Not Installed'}</span>
        </div>
        <h3 style="font-size:1rem; font-weight:700; margin-bottom:0.25rem;">Local PowerShell Version Discovery &amp; Multi-Version Command Compatibility Matrix</h3>
        <p style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.45rem;">
          ${escapeHtml(psEnv.CompatibilityGuarantee)} Commands below automatically match your discovered local PowerShell version (<code>v${escapeHtml(psEnv.ActiveVersion)}</code>), or you can switch versions to inspect unique cmdlets for <strong>PS 5.1 Desktop</strong>, <strong>PS 7+ Core</strong>, and <strong>Legacy PS 3.0/4.0</strong>.
        </p>
        <div style="font-size:0.75rem; color:var(--text-muted);">
          <strong>Discovered ExecutionPolicy Scopes:</strong> ${policiesHtml}
        </div>
      </div>
      <div style="display:flex; flex-wrap:wrap; gap:0.4rem; align-items:center;">
        <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'AUTO' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('AUTO')">
          &#9989; Auto-Detected Local (v${escapeHtml(psEnv.ActiveVersion)})
        </button>
        <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PS51' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PS51')">
          PS 5.1 Desktop (powershell.exe)
        </button>
        <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PS7' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PS7')">
          PS 7+ Core (pwsh.exe)
        </button>
        <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PSLegacy' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PSLegacy')">
          Legacy PS 3.0/4.0
        </button>
        <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'COMPARE' ? 'btn-teal' : ''}" onclick="setPowerShellCommandProfile('COMPARE')">
          &#8644; Compare All Versions
        </button>
      </div>
    </div>

    <div class="scripts-grid" style="grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 0.85rem;">
      ${(psEnv.VersionSpecificCommands || []).map(cmd => {
        const activeCmd = getCommandForProfile(cmd, effectiveProfile);
        return `
          <div class="card" style="padding:0.85rem 1rem; margin-bottom:0; border:1px solid var(--border-light);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
              <span class="badge badge-info">${escapeHtml(cmd.Category)}</span>
              <span class="badge badge-neutral">${isCompare ? 'All Versions Side-by-Side' : escapeHtml(profileBadgeLabel)}</span>
            </div>
            <h4 style="font-size:0.88rem; font-weight:700; margin-bottom:0.3rem;">${escapeHtml(cmd.Operation)}</h4>
            <p style="font-size:0.76rem; color:var(--text-secondary); margin-bottom:0.55rem;">
              <strong>Version Compatibility Note:</strong> ${escapeHtml(cmd.VersionNotes)}
            </p>
            ${isCompare ? `
              <div style="display:flex; flex-direction:column; gap:0.45rem;">
                <div>
                  <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; font-weight:600; margin-bottom:0.15rem;">
                    <span>Windows PowerShell 5.1 (Desktop)${psEnv.DetectedProfile === 'PS51' ? ' [Discovered Local]' : ''}</span>
                    <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(cmd.Command_PS51)}')">Copy PS 5.1</button>
                  </div>
                  <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap;">${escapeHtml(cmd.Command_PS51)}</pre>
                </div>
                <div>
                  <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; font-weight:600; margin-bottom:0.15rem;">
                    <span>PowerShell 7+ (Core - pwsh.exe)${psEnv.DetectedProfile === 'PS7' ? ' [Discovered Local]' : ''}</span>
                    <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(cmd.Command_PS7)}')">Copy PS 7+</button>
                  </div>
                  <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap;">${escapeHtml(cmd.Command_PS7)}</pre>
                </div>
                <div>
                  <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; font-weight:600; margin-bottom:0.15rem;">
                    <span>Legacy PowerShell 3.0 / 4.0 (WMI / netsh Fallback)</span>
                    <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(cmd.Command_PSLegacy)}')">Copy Legacy</button>
                  </div>
                  <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap;">${escapeHtml(cmd.Command_PSLegacy)}</pre>
                </div>
              </div>
            ` : `
              <div class="code-block" style="margin:0; padding:0.55rem 0.7rem; display:flex; justify-content:space-between; align-items:center; gap:0.75rem;">
                <span style="font-size:0.74rem; word-break:break-all; white-space:pre-wrap;">${escapeHtml(activeCmd)}</span>
                <button class="btn btn-sm" style="flex-shrink:0;" onclick="copyToClipboard('${escapeJs(activeCmd)}')">Copy Cmd</button>
              </div>
            `}
          </div>
        `;
      }).join('')}
    </div>
  `;
}

// VIEW 8: SCRIPT EXECUTION CENTER
async function refreshServerStatus() {
  try {
    const resp = await fetch('/api/status', { cache: 'no-store' });
    if (!resp.ok) return;
    const statusData = await resp.json();
    SERVER_ONLINE = true;

    const scripts = (statusData.registry && statusData.registry.Scripts) || [];
    setText('badgeCountScripts', scripts.length);
    renderScriptCatalog(scripts);

    const history = statusData.executionHistory || [];
    renderForensicTable('tableContainerScriptHistory', {
      tableId: 'tblScriptHistory',
      title: 'SQLite Operational Audit Log: Script Execution History (Data\\forensic_workstation.db)',
      pageSize: 25,
      data: history,
      columns: [
        { key: 'id', label: 'Run #', mono: true },
        { key: 'script_id', label: 'Script ID', mono: true },
        { key: 'script_name', label: 'Script Name' },
        { key: 'status', label: 'Status', render: renderAssessmentBadge },
        { key: 'duration_sec', label: 'Duration (s)' },
        { key: 'started_at_utc', label: 'Started (UTC)', mono: true },
        { key: 'parameters_json', label: 'Parameters', mono: true },
        { key: 'output_preview', label: 'Console Output Preview', wrap: true }
      ]
    });
  } catch (err) {
    // Fallback static catalog if viewing via file:///
    renderFallbackScriptCatalog();
  }
}

function renderScriptCatalog(scripts) {
  const grid = document.getElementById('scriptCatalogGrid');
  if (!grid) return;

  grid.innerHTML = scripts.map(s => `
    <div class="script-card">
      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.45rem;">
          <span class="badge ${s.IsReadOnly ? 'badge-info' : 'badge-warning'}">${escapeHtml(s.ScriptId)} &bull; ${escapeHtml(s.Category)}</span>
          <span class="badge badge-neutral">${s.IsReadOnly ? 'Read-Only' : 'Authorized Action'}</span>
        </div>
        <h3 style="font-size: 0.92rem; font-weight: 700; margin-bottom: 0.3rem;">${escapeHtml(s.Name)}</h3>
        <p style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${escapeHtml(s.Description)}</p>
        <div class="mono-cell" style="font-size: 0.72rem; margin-bottom: 0.75rem; word-break: break-all;">Path: ${escapeHtml(s.ScriptPath)}</div>
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-light); padding-top: 0.65rem;">
        <span style="font-size: 0.72rem; color: var(--text-muted);">Timeout: ${s.TimeoutSeconds}s | Priv: ${escapeHtml(s.PrivilegeLevel)}</span>
        <button class="btn ${s.IsReadOnly ? 'btn-primary' : 'btn-teal'} btn-sm" onclick="executeScript('${escapeJs(s.ScriptId)}')">
          &#9654; Execute Script
        </button>
      </div>
    </div>
  `).join('');
}

function renderFallbackScriptCatalog() {
  const fData = window.FORENSIC_DATA || {};
  const runs = fData.ScriptRunSummary || [];
  const grid = document.getElementById('scriptCatalogGrid');
  if (!grid) return;
  grid.innerHTML = runs.map(r => `
    <div class="script-card">
      <div>
        <span class="badge badge-info">${escapeHtml(r.ScriptId)}</span>
        <div class="mono-cell" style="margin-top:0.4rem;">${escapeHtml(r.ScriptPath)}</div>
      </div>
      <div style="margin-top:0.65rem; display:flex; justify-content:space-between;">
        <span>Last Run: ${r.DurationSec}s (${escapeHtml(r.Status)})</span>
        <button class="btn btn-primary btn-sm" onclick="executeScript('${escapeJs(r.ScriptId)}')">&#9654; Execute</button>
      </div>
    </div>
  `).join('');
}

// VIEW 9: INVESTIGATION REPORTS & OBSIDIAN VAULT
function renderPhase2ReportsView(fData) {
  const inc = (fData && fData.Incidents) || {};
  const dynamicRows = Array.isArray(inc.DiagnosticFindings) ? inc.DiagnosticFindings : [];

  renderForensicTable('tableContainerPhase2Report', {
    tableId: 'tblPhase2Report',
    title: 'Automated System Stability & Incident Diagnostic Findings (INC-01)',
    pageSize: 10,
    data: dynamicRows,
    columns: [
      { key: 'Incident', label: 'Incident / Subsystem', wrap: true },
      { key: 'SuspectedCause', label: 'Suspected Cause (Evidence-Supported)', wrap: true },
      { key: 'Evidence', label: 'Supporting Forensic Evidence', wrap: true },
      { key: 'Confidence', label: 'Confidence', render: renderAssessmentBadge },
      { key: 'ThreatAssessment', label: 'Threat Assessment', render: renderAssessmentBadge },
      { key: 'RiskAssessment', label: 'Risk Assessment', render: renderAssessmentBadge },
      { key: 'RecommendedAction', label: 'Recommended Safe Action', wrap: true },
      { key: 'Verification', label: 'Verification Procedure', wrap: true }
    ]
  });
}

function populateVaultFromNotes(notes) {
  const sidebar = document.getElementById('vaultSidebarList');
  const viewer = document.getElementById('vaultNoteViewer');
  if (!sidebar || !viewer) return false;
  if (!Array.isArray(notes) || notes.length === 0) return false;

  OBSIDIAN_NOTES_CACHE = notes;
  sidebar.innerHTML = OBSIDIAN_NOTES_CACHE.map((n, idx) => `
    <button class="vault-note-btn ${idx === 0 ? 'active' : ''}" onclick="selectVaultNote(${idx}, this)">
      <div style="font-weight:600;">${escapeHtml(n.fileName)}</div>
      <div style="font-size:0.68rem; color:var(--text-muted);">${escapeHtml(n.folder)} &bull; ${((n.sizeBytes || 0) / 1024).toFixed(1)} KB</div>
    </button>
  `).join('');
  viewer.textContent = OBSIDIAN_NOTES_CACHE[0].content || '';
  return true;
}

async function loadObsidianVault() {
  const sidebar = document.getElementById('vaultSidebarList');
  const viewer = document.getElementById('vaultNoteViewer');
  if (!sidebar || !viewer) return;

  try {
    const resp = await fetch('/api/obsidian', { cache: 'no-store' });
    if (resp.ok) {
      const data = await resp.json();
      if (populateVaultFromNotes(data.notes || [])) {
        return;
      }
    }
  } catch (e) {}

  // Offline / Snapshot fallback using bundled ObsidianNotes inside window.FORENSIC_DATA
  const fData = window.FORENSIC_DATA || {};
  if (populateVaultFromNotes(fData.ObsidianNotes || [])) {
    return;
  }

  sidebar.innerHTML = `<div style="padding:0.5rem; font-size:0.78rem; color:var(--text-muted);">No Obsidian Vault notes found yet. Click <strong>Sync Obsidian Vault</strong> or run <code>powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Scripts\\Utilities\\Sync-ObsidianVault.ps1</code> to generate the Markdown knowledge base.</div>`;
}

window.selectVaultNote = function(idx, btnEl) {
  document.querySelectorAll('.vault-note-btn').forEach(b => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  const viewer = document.getElementById('vaultNoteViewer');
  if (viewer && OBSIDIAN_NOTES_CACHE[idx]) {
    viewer.textContent = OBSIDIAN_NOTES_CACHE[idx].content;
  }
};

// VIEW 10: REMEDIATION & PRESERVED BASELINE AUDIT
function renderRemediationAndLegacyView(fData, lData) {
  const psEnv = getDiscoveredPowerShellEnv(fData);
  const effectiveProfile = getEffectivePSProfile(psEnv);
  const profileBadgeLabel = effectiveProfile === 'PS7'
    ? 'PowerShell 7+ (Core - pwsh.exe)'
    : (effectiveProfile === 'PSLegacy'
        ? 'Legacy PowerShell 3.0/4.0'
        : 'Windows PowerShell 5.1 (Desktop - powershell.exe)');

  const remSelectorBar = document.getElementById('remVersionSelectorBar');
  if (remSelectorBar) {
    remSelectorBar.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.75rem;">
        <div>
          <div style="display:flex; align-items:center; gap:0.45rem; margin-bottom:0.2rem;">
            <span class="badge badge-success">Discovered Local PowerShell: v${escapeHtml(psEnv.ActiveVersion)} (${escapeHtml(psEnv.PSEdition)})</span>
            <span class="badge badge-info">Displaying Commands For: ${escapeHtml(profileBadgeLabel)}</span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-secondary);">
            All remediation &amp; optimization commands below are tailored to your discovered PowerShell version. Switch profiles to copy commands for another PowerShell version:
          </div>
        </div>
        <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
          <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'AUTO' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('AUTO')">
            &#9989; Auto-Detected Local (v${escapeHtml(psEnv.ActiveVersion)})
          </button>
          <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PS51' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PS51')">
            PS 5.1 Desktop
          </button>
          <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PS7' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PS7')">
            PS 7+ Core (pwsh)
          </button>
          <button class="btn btn-sm ${SELECTED_PS_PROFILE === 'PSLegacy' ? 'btn-primary' : ''}" onclick="setPowerShellCommandProfile('PSLegacy')">
            Legacy PS 3.0/4.0
          </button>
        </div>
      </div>
    `;
  }

  const remActions = [
    {
      ActionId: 'REM-EXP-01_ExplorerSeparateProcess',
      Title: 'Isolate File Explorer Windows in a Separate Process (SeparateProcess = 1)',
      Target: 'Shell Stability (Explorer.exe Crash/Hang Isolation)',
      Privilege: 'Standard User (HKCU)',
      Risk: 'Low (Reversible)',
      IssueExplanation: 'By default, Windows runs the desktop taskbar and all File Explorer folder windows inside a single explorer.exe process. If a third-party shell extension or corrupt media file hangs while generating thumbnails, the entire desktop shell freezes.',
      RecommendedFix: 'Enable SeparateProcess = 1 under HKCU Explorer Advanced settings so folder windows run in an isolated worker process. Does not require Administrator rights.',
      Command_PS51: 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "SeparateProcess" -Value 1 -Type DWord',
      Command_PS7: 'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" -Name "SeparateProcess" -Value 1 -Type DWord',
      Command_PSLegacy: 'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v SeparateProcess /t REG_DWORD /d 1 /f'
    },
    {
      ActionId: 'REM-GPU-01_TdrDelayIncrease',
      Title: 'Increase Windows GPU Watchdog Timeout (TdrDelay = 8s)',
      Target: 'Display / Browser GPU TDR Stability (LiveKernelEvent 141)',
      Privilege: 'Administrator (HKLM)',
      Risk: 'Low-Medium (Reversible, Takes Effect on Reboot)',
      IssueExplanation: 'Windows DirectX Graphics Kernel resets the GPU driver (LiveKernelEvent 141) if a GPU preemption packet takes longer than 2 seconds. Hybrid iGPU/dGPU power transitions or heavy WebGL/CUDA workloads can exceed 2s and cause brief black screens.',
      RecommendedFix: 'Set TdrDelay = 8 (seconds) in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers and reboot. Requires Administrator elevation.',
      Command_PS51: 'Start-Process powershell.exe -Verb RunAs -ArgumentList \'-NoProfile -Command "Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers -Name TdrDelay -Value 8 -Type DWord"\'',
      Command_PS7: 'Start-Process pwsh.exe -Verb RunAs -ArgumentList \'-NoProfile -Command "Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers -Name TdrDelay -Value 8 -Type DWord"\'',
      Command_PSLegacy: 'reg.exe add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 8 /f'
    },
    {
      ActionId: 'REM-SHUT-01_ReduceServiceKillTimeout',
      Title: 'Enable AutoEndTasks for Clean User Session Shutdown',
      Target: 'Shutdown / Restart Responsiveness',
      Privilege: 'Standard User (HKCU)',
      Risk: 'Low (Reversible)',
      IssueExplanation: 'During logoff or restart, background tray utilities or hidden windows that fail to respond to WM_QUERYENDSESSION can block the user session shutdown sequence and trigger Event 7043.',
      RecommendedFix: 'Set AutoEndTasks = "1" under HKCU:\\Control Panel\\Desktop so unresponsive background user tasks close cleanly during shutdown.',
      Command_PS51: 'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "AutoEndTasks" -Value "1" -Type String',
      Command_PS7: 'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "AutoEndTasks" -Value "1" -Type String',
      Command_PSLegacy: 'reg.exe add "HKCU\\Control Panel\\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f'
    },
    {
      ActionId: 'REM-NET-01_SetRustDeskManual',
      Title: 'Set Remote Desktop Service (RustDesk) StartupType to Manual',
      Target: 'Security Audit Flag (Active Remote Control Service)',
      Privilege: 'Administrator (SCM)',
      Risk: 'Low (Reversible)',
      IssueExplanation: 'Persistent third-party remote control services running as LocalSystem maintain an always-on remote administration listener across reboots, increasing workstation attack surface.',
      RecommendedFix: 'Set the RustDesk service StartupType to Manual so it only runs when explicitly started by the user. Requires Administrator elevation (safe no-op if RustDesk is not installed).',
      Command_PS51: 'Start-Process powershell.exe -Verb RunAs -ArgumentList \'-NoProfile -Command "Get-Service -Name RustDesk -ErrorAction SilentlyContinue | Set-Service -StartupType Manual"\'',
      Command_PS7: 'Start-Process pwsh.exe -Verb RunAs -ArgumentList \'-NoProfile -Command "Get-Service -Name RustDesk -ErrorAction SilentlyContinue | Set-Service -StartupType Manual"\'',
      Command_PSLegacy: 'sc.exe config RustDesk start= demand'
    }
  ];

  const remContainer = document.getElementById('remediationCardsContainer');
  if (remContainer) {
    remContainer.innerHTML = remActions.map(a => {
      const cmdForVersion = getCommandForProfile(a, effectiveProfile);
      return `
        <div class="script-card" style="border-left: 4px solid var(--accent-blue);">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
              <span class="badge badge-info">${escapeHtml(a.Target)}</span>
              <span class="badge badge-neutral">${escapeHtml(a.Privilege)}</span>
            </div>
            <h3 style="font-size:0.95rem; font-weight:700; margin-bottom:0.35rem;">${escapeHtml(a.Title)}</h3>
            <p style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.4rem;">
              <strong>Issue Explanation:</strong> ${escapeHtml(a.IssueExplanation)}
            </p>
            <p style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.55rem;">
              <strong>Recommended Fix:</strong> ${escapeHtml(a.RecommendedFix)}
            </p>
            <div style="margin-bottom:0.65rem;">
              <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.71rem; color:var(--text-muted); margin-bottom:0.2rem;">
                <span>Command (${escapeHtml(profileBadgeLabel)}):</span>
                <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem;" onclick="copyToClipboard('${escapeJs(cmdForVersion)}')">Copy Command</button>
              </div>
              <pre class="code-block" style="margin:0; padding:0.45rem 0.6rem; font-size:0.72rem; white-space:pre-wrap; word-break:break-all;">${escapeHtml(cmdForVersion)}</pre>
            </div>
          </div>
          <div style="border-top:1px solid var(--border-light); padding-top:0.65rem;">
            <label style="display:flex; align-items:center; gap:0.4rem; font-size:0.76rem; color:var(--text-secondary); margin-bottom:0.5rem; cursor:pointer;">
              <input type="checkbox" id="authChk_${a.ActionId}">
              <span>I explicitly authorize applying this system modification</span>
            </label>
            <div style="display:flex; gap:0.5rem; justify-content:flex-end;">
              <button class="btn btn-sm" onclick="runRemediationAction('${a.ActionId}', false)">&#128269; Dry-Run Preview</button>
              <button class="btn btn-primary btn-sm" onclick="runRemediationAction('${a.ActionId}', true)">&#9889; Authorize &amp; Execute</button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Preserved Legacy Baseline Tables (Logon Lag, Shutdown Delay, Resource Bloat, Action Plan)
  const legacyCard = document.getElementById('legacyBaselineCard');
  const hasLegacy = Boolean(lData && (lData.LogonLagDetails || lData.ResourceBloatAnalysis || (lData.ActionPlan && lData.ActionPlan.length > 0)));
  if (legacyCard) {
    legacyCard.style.display = hasLegacy ? 'block' : 'none';
  }
  if (lData && lData.LogonLagDetails && lData.LogonLagDetails.HighImpactItems) {
    renderForensicTable('tableContainerLegacyLogon', {
      tableId: 'tblLegacyLogon',
      title: 'Preserved Baseline: High-Impact Startup Applications (Logon Lag Analysis)',
      pageSize: 25,
      data: lData.LogonLagDetails.HighImpactItems,
      columns: [
        { key: 'Name', label: 'Application' },
        { key: 'Source', label: 'Startup Source' },
        { key: 'Impact', label: 'Impact', render: renderAssessmentBadge },
        { key: 'DelaySec', label: 'Est. Delay', mono: true },
        { key: 'WhyItLags', label: 'Root Cause Analysis', wrap: true },
        { key: 'Recommendation', label: 'Recommended Action', wrap: true }
      ]
    });
  }

  if (lData && lData.ResourceBloatAnalysis && lData.ResourceBloatAnalysis.NonEssentialServices) {
    renderForensicTable('tableContainerLegacyBloat', {
      tableId: 'tblLegacyBloat',
      title: 'Preserved Baseline: Non-Essential Services Safe to Set to Manual',
      pageSize: 25,
      data: lData.ResourceBloatAnalysis.NonEssentialServices,
      columns: [
        { key: 'Name', label: 'Service Name', mono: true },
        { key: 'DisplayName', label: 'Display Name' },
        { key: 'StartMode', label: 'Start Mode' },
        { key: 'Action', label: 'Recommended Action', render: renderAssessmentBadge },
        { key: 'Reason', label: 'Justification', wrap: true }
      ]
    });
  }

  const steps = (lData && lData.ActionPlan) || [];
  const actionContainer = document.getElementById('actionPlanContainer');
  if (actionContainer && steps.length > 0) {
    actionContainer.innerHTML = steps.map(s => {
      // Adapt command per selected PowerShell version (e.g., Step 2 Appx removal uses -UseWindowsPowerShell in PS 7+)
      let adaptedCmd = s.Command || '';
      let versionNote = 'Compatible with both Windows PowerShell 5.1 and PowerShell 7+.';
      if (adaptedCmd.includes('Get-AppxPackage')) {
        versionNote = 'In PowerShell 7+, Import-Module Appx -UseWindowsPowerShell ensures the Desktop Appx cmdlets load cleanly on all Windows 10/11 builds.';
        if (effectiveProfile === 'PS7') {
          adaptedCmd = `Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue; ${s.Command}`;
        } else if (effectiveProfile === 'PSLegacy') {
          adaptedCmd = `powershell.exe -NoProfile -Command "${s.Command}"`;
        }
      } else if (adaptedCmd.includes('Set-Service') && effectiveProfile === 'PSLegacy') {
        versionNote = 'Requires an elevated Administrator PowerShell prompt to modify Service Control Manager startup types.';
      }
      return `
        <div class="card" style="padding:0.85rem 1rem; margin-bottom:0.65rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.3rem;">
            <strong>Step ${s.Step}: ${escapeHtml(s.Target)} &mdash; ${escapeHtml(s.Action)}</strong>
            <div style="display:flex; gap:0.4rem;">
              <span class="badge badge-info">${escapeHtml(profileBadgeLabel)}</span>
              <span class="badge badge-success">Risk: ${escapeHtml(s.Risk)}</span>
            </div>
          </div>
          <div style="font-size:0.75rem; color:var(--text-secondary); margin-bottom:0.4rem;">
            <strong>PowerShell Compatibility Note:</strong> ${escapeHtml(versionNote)}
          </div>
          <div class="code-block" style="display:flex; justify-content:space-between; align-items:center; gap:1rem;">
            <span style="white-space:pre-wrap; word-break:break-all;">${escapeHtml(adaptedCmd)}</span>
            <button class="btn btn-sm" style="flex-shrink:0;" onclick="copyToClipboard('${escapeJs(adaptedCmd)}')">Copy Command</button>
          </div>
        </div>
      `;
    }).join('');
  }
}

// ----------------------------------------------------------------------------
// 6. Centralized Script Execution, Diagnostic Issue Explanation & Action Handlers
// ----------------------------------------------------------------------------
function renderDiagnosticIssueBannerAndModal(diag, openModal = true) {
  const banner = document.getElementById('scriptDiagnosticBanner');
  if (banner && diag && diag.hasIssue) {
    const sevClass = diag.severity === 'warning' ? 'warning' : (diag.severity === 'info' ? 'info' : 'critical');
    banner.style.display = 'block';
    banner.innerHTML = `
      <div class="alert-banner ${sevClass}" style="margin-bottom:0;">
        <div style="font-size:1.35rem; line-height:1;">&#9888;</div>
        <div style="flex:1;">
          <h3>${escapeHtml(diag.title || 'Script Execution Diagnostic Notice')}</h3>
          <p style="margin-bottom:0.35rem;"><strong>Issue Explanation:</strong> ${escapeHtml(diag.explanation || '')}</p>
          <p style="margin-bottom:0.5rem;"><strong>Recommended Fix:</strong> ${escapeHtml(diag.recommendedFix || '')}</p>
          <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
            ${diag.commandPS51 ? `<button class="btn btn-sm" onclick="copyToClipboard('${escapeJs(diag.commandPS51)}')">Copy PS 5.1 Fix Command</button>` : ''}
            ${diag.commandPS7 ? `<button class="btn btn-sm" onclick="copyToClipboard('${escapeJs(diag.commandPS7)}')">Copy PS 7+ Fix Command</button>` : ''}
            <button class="btn btn-primary btn-sm" onclick='showDiagnosticIssueModal(${ JSON.stringify(diag).replace(/'/g, "&#39;") })'>View Full Explanation &amp; Fix</button>
          </div>
        </div>
      </div>
    `;
  } else if (banner) {
    banner.style.display = 'none';
    banner.innerHTML = '';
  }

  if (openModal && diag && diag.hasIssue) {
    showDiagnosticIssueModal(diag);
  }
}

window.showDiagnosticIssueModal = function(diag) {
  const modal = document.getElementById('detailModalBackdrop');
  const title = document.getElementById('detailModalTitle');
  const body = document.getElementById('detailModalBody');
  const copyBtn = document.getElementById('detailModalCopyBtn');
  if (!modal || !title || !body) return;

  const psEnv = getDiscoveredPowerShellEnv(window.FORENSIC_DATA || {});
  title.textContent = diag.title || 'Diagnostic Issue Explanation & Recommended Fix';
  if (copyBtn) {
    copyBtn.onclick = () => copyToClipboard(JSON.stringify(diag, null, 2));
  }

  body.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:0.9rem;">
      <div class="alert-banner ${diag.severity === 'warning' ? 'warning' : 'critical'}" style="margin-bottom:0;">
        <div style="font-size:1.3rem;">&#9888;</div>
        <div>
          <h3>Why This Happened (Plain-English Explanation)</h3>
          <p>${escapeHtml(diag.explanation || 'An error or privilege restriction occurred while running the script.')}</p>
        </div>
      </div>

      <div class="card" style="padding:0.9rem 1rem; margin-bottom:0; border-left:4px solid var(--accent-teal);">
        <h4 style="font-size:0.92rem; font-weight:700; margin-bottom:0.35rem;">Recommended Steps to Fix</h4>
        <p style="font-size:0.82rem; color:var(--text-secondary); margin-bottom:0.65rem;">
          ${escapeHtml(diag.recommendedFix || 'Run the appropriate PowerShell command below to resolve or verify this operation.')}
        </p>

        ${diag.commandPS51 ? `
          <div style="margin-bottom:0.6rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; font-weight:600; margin-bottom:0.2rem;">
              <span>Windows PowerShell 5.1 (Desktop - powershell.exe) ${psEnv.DetectedProfile === 'PS51' ? '&bull; [Discovered on This System]' : ''}</span>
              <button class="btn btn-primary btn-sm" onclick="copyToClipboard('${escapeJs(diag.commandPS51)}')">Copy PS 5.1 Command</button>
            </div>
            <pre class="code-block" style="margin:0; white-space:pre-wrap; word-break:break-all;">${escapeHtml(diag.commandPS51)}</pre>
          </div>
        ` : ''}

        ${diag.commandPS7 ? `
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; font-weight:600; margin-bottom:0.2rem;">
              <span>PowerShell 7+ (Core - pwsh.exe) ${psEnv.DetectedProfile === 'PS7' ? '&bull; [Discovered on This System]' : ''}</span>
              <button class="btn btn-teal btn-sm" onclick="copyToClipboard('${escapeJs(diag.commandPS7)}')">Copy PS 7+ Command</button>
            </div>
            <pre class="code-block" style="margin:0; white-space:pre-wrap; word-break:break-all;">${escapeHtml(diag.commandPS7)}</pre>
          </div>
        ` : ''}
      </div>

      ${diag.technicalDetails ? `
        <div>
          <div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); margin-bottom:0.25rem;">Technical Diagnostic Output (Logs\\script_execution.log):</div>
          <pre class="code-block" style="margin:0; max-height:180px; overflow-y:auto; white-space:pre-wrap; font-size:0.73rem;">${escapeHtml(diag.technicalDetails)}</pre>
        </div>
      ` : ''}
    </div>
  `;
  modal.classList.add('open');
};

window.executeScript = async function(scriptId, parameters = {}) {
  const bar = document.getElementById('jobStatusBar');
  const titleEl = document.getElementById('jobStatusTitle');
  const detailEl = document.getElementById('jobStatusDetail');
  const consoleEl = document.getElementById('scriptConsoleOutput');

  if (bar) {
    bar.classList.add('active');
    if (titleEl) titleEl.textContent = `Running Approved PowerShell Script: ${scriptId}`;
    if (detailEl) detailEl.textContent = `Parameters: ${JSON.stringify(parameters)}`;
  }

  try {
    const resp = await fetch('/api/scripts/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scriptId, parameters })
    });
    const res = await resp.json();

    if (!resp.ok) {
      const errDiag = {
        hasIssue: true,
        severity: 'error',
        title: `Script Execution Blocked or Rejected (${scriptId} - HTTP ${resp.status})`,
        explanation: res.error || `The backend script controller rejected the request with HTTP status ${resp.status}.`,
        recommendedFix: resp.status === 409
          ? 'Another forensic script is currently running. Wait for it to finish or click "Cancel Job" in the top progress bar before starting a new script.'
          : 'Verify that the script ID and parameters match Config\\script_registry.json.',
        commandPS51: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Core\\Invoke-FullSystemSnapshot.ps1" -QuickMode`,
        commandPS7: `pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Core\\Invoke-FullSystemSnapshot.ps1" -QuickMode`,
        technicalDetails: JSON.stringify(res, null, 2)
      };
      if (consoleEl) consoleEl.textContent = `ERROR (${resp.status}):\n${JSON.stringify(res, null, 2)}`;
      renderDiagnosticIssueBannerAndModal(errDiag, true);
      showToast(errDiag.title);
      return res;
    }

    if (consoleEl) {
      const previewObj = res.scriptOutputJson || { stdout: res.stdout };
      consoleEl.textContent = `// Script: ${res.scriptId} (${res.scriptName})\n// Status: ${res.status} | Duration: ${res.durationSec}s\n\n` +
        JSON.stringify(previewObj, null, 2);
    }

    if (res.masterData) {
      window.FORENSIC_DATA = res.masterData;
      renderAllViews();
    }
    await refreshServerStatus();

    if (scriptId === 'UTIL-01' || scriptId === 'CORE-01') {
      await loadObsidianVault();
    }

    // Check if backend or script reported any diagnostic issue / elevation requirement
    if (res.diagnostics && res.diagnostics.hasIssue) {
      renderDiagnosticIssueBannerAndModal(res.diagnostics, true);
      showToast(`${res.diagnostics.title} — see explanation & fix modal`);
      return res;
    } else {
      renderDiagnosticIssueBannerAndModal(null, false);
    }

    // If user clicked Sync Obsidian Vault (UTIL-01), navigate to Tab 9 (Investigation Reports & Vault) and show clear confirmation
    if (scriptId === 'UTIL-01') {
      window.activateTab('tab-reports');
      const notesCount = (res.scriptOutputJson && res.scriptOutputJson.NotesGenerated) || OBSIDIAN_NOTES_CACHE.length || 4;
      showToast(`Obsidian Vault synchronized (${notesCount} Markdown reports updated in ObsidianVault)`);
      const vaultCard = document.getElementById('vaultSidebarList');
      if (vaultCard) vaultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return res;
    }

    showToast(`Completed ${scriptId} (${res.scriptName || ''}) in ${res.durationSec}s`);
    return res;
  } catch (err) {
    // Offline mode (file:// or backend server stopped)
    if (scriptId === 'UTIL-01') {
      await loadObsidianVault();
      window.activateTab('tab-reports');
    }
    const offlineDiag = {
      hasIssue: true,
      severity: 'warning',
      title: `Local Script Engine Offline (Viewing Static Snapshot Mode)`,
      explanation: `You clicked to execute PowerShell script "${scriptId}", but the dashboard is currently open in offline Snapshot Mode (or the local Python backend server on 127.0.0.1:8765 is not running). Browsers cannot spawn PowerShell processes directly from a static file:// page without the local backend service.`,
      recommendedFix: `Launch the dashboard via "Run-ForensicAnalysis.cmd" or "Start-Dashboard.cmd" (which starts Dashboard\\Backend\\server.py on http://127.0.0.1:8765), OR run the script directly in PowerShell using the command below:`,
      commandPS51: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Start-Dashboard.cmd"`,
      commandPS7: `pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\\Scripts\\Core\\Invoke-FullSystemSnapshot.ps1" -QuickMode`,
      technicalDetails: String(err && err.message ? err.message : err)
    };
    renderDiagnosticIssueBannerAndModal(offlineDiag, true);
    showToast('Local Script Engine offline — opened instructions & PowerShell commands');
    return null;
  } finally {
    if (bar) bar.classList.remove('active');
  }
};

window.cancelActiveScript = async function() {
  try {
    await fetch('/api/scripts/cancel', { method: 'POST', body: '{}' });
    showToast('Requested job cancellation.');
  } catch (e) {}
};

window.triggerProcessMiniDump = function() {
  const pidInput = document.getElementById('inputDumpPid');
  const reasonInput = document.getElementById('inputDumpReason');
  const pid = parseInt(pidInput ? pidInput.value : '', 10);
  if (!pid || pid <= 4) {
    showToast('Please enter a valid user-mode Target PID (> 4). Protected kernel PIDs (0, 4) cannot be dumped via user-mode MiniDumpWriteDump.');
    return;
  }
  const reason = (reasonInput && reasonInput.value) ? reasonInput.value : 'Manual Triage via Dashboard';
  executeScript('MEM-02', { TargetPID: pid, Reason: reason });
};

window.runRemediationAction = async function(actionId, executeLive) {
  if (executeLive) {
    const chk = document.getElementById(`authChk_${actionId}`);
    if (!chk || !chk.checked) {
      showToast('Please check the explicit authorization box on the card before executing a system modification.');
      return;
    }
  }

  const res = await executeScript('REM-01', executeLive ? {
    ActionId: actionId,
    ExecuteRemediation: true,
    ConfirmationToken: 'AUTHORIZE-CHANGE'
  } : {
    ActionId: actionId
  });

  // If executeScript already opened the diagnostic modal for an issue/elevation requirement, don't overwrite it
  if (!res || (res.diagnostics && res.diagnostics.hasIssue)) {
    return;
  }

  const out = res.scriptOutputJson || {};
  const modal = document.getElementById('detailModalBackdrop');
  const title = document.getElementById('detailModalTitle');
  const body = document.getElementById('detailModalBody');
  if (modal && title && body) {
    title.textContent = executeLive
      ? `Remediation Execution Result: ${out.Title || actionId} (${out.Status || res.status})`
      : `Read-Only Dry-Run Preview: ${out.Title || actionId}`;
    body.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:0.85rem;">
        <div class="alert-banner ${out.Status === 'Applied' ? 'info' : 'warning'}" style="margin-bottom:0;">
          <div style="font-size:1.25rem;">${out.Status === 'Applied' ? '&#9989;' : '&#128269;'}</div>
          <div>
            <h3>Status: ${escapeHtml(out.Status || res.status)}</h3>
            <p>${escapeHtml(out.Explanation || out.DryRunNotice || '')}</p>
            ${out.RecommendedFix ? `<p style="margin-top:0.35rem;"><strong>Verification / Next Step:</strong> ${escapeHtml(out.RecommendedFix)}</p>` : ''}
          </div>
        </div>
        ${out.Command_PS51 ? `
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; font-weight:600; margin-bottom:0.2rem;">
              <span>Windows PowerShell 5.1 (Desktop) Command:</span>
              <button class="btn btn-sm" onclick="copyToClipboard('${escapeJs(out.Command_PS51)}')">Copy PS 5.1</button>
            </div>
            <pre class="code-block" style="margin:0; white-space:pre-wrap;">${escapeHtml(out.Command_PS51)}</pre>
          </div>
        ` : ''}
        ${out.Command_PS7 ? `
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; font-weight:600; margin-bottom:0.2rem;">
              <span>PowerShell 7+ (Core - pwsh.exe) Command:</span>
              <button class="btn btn-sm" onclick="copyToClipboard('${escapeJs(out.Command_PS7)}')">Copy PS 7+</button>
            </div>
            <pre class="code-block" style="margin:0; white-space:pre-wrap;">${escapeHtml(out.Command_PS7)}</pre>
          </div>
        ` : ''}
        <div>
          <div style="font-size:0.75rem; font-weight:600; color:var(--text-muted); margin-bottom:0.2rem;">Full Structured Output:</div>
          <pre class="code-block" style="margin:0; white-space:pre-wrap;">${escapeHtml(JSON.stringify(out, null, 2))}</pre>
        </div>
      </div>
    `;
    modal.classList.add('open');
  }
};

window.copyBrowserSnippet = async function() {
  try {
    const resp = await fetch('/Data/Investigations/browser_diagnostics_snippet.js', { cache: 'no-store' });
    if (resp.ok) {
      const txt = await resp.text();
      copyToClipboard(txt);
      return;
    }
  } catch (e) {}
  showToast('Run UTIL-03 or open Data\\Investigations\\browser_diagnostics_snippet.js');
};

window.exportPortableHtmlReport = async function() {
  const fData = window.FORENSIC_DATA || {};
  const host = ((fData.Hardware && fData.Hardware.SystemOverview && fData.Hardware.SystemOverview.ComputerName) || 'WindowsHost').replace(/[^a-zA-Z0-9_-]/g, '');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const dlFileName = `ForensicReport_${host}_${stamp}.html`;

  if (SERVER_ONLINE) {
    const res = await executeScript('UTIL-05');
    if (res && res.scriptOutputJson && res.scriptOutputJson.Status === 'Success') {
      const m = res.scriptOutputJson;
      try {
        const htmlResp = await fetch(m.RelativeDownloadUrl || '/Reports/Executive/Portable_Forensic_Report_Latest.html', { cache: 'no-store' });
        if (htmlResp.ok) {
          const bundledHtml = await htmlResp.text();
          downloadBlob(bundledHtml, dlFileName, 'text/html;charset=utf-8;');
        }
      } catch (e) {}

      const modal = document.getElementById('detailModalBackdrop');
      const title = document.getElementById('detailModalTitle');
      const body = document.getElementById('detailModalBody');
      if (modal && title && body) {
        title.textContent = `Single-File Portable Executive HTML Report Ready (${m.FileSize_KB} KB)`;
        body.innerHTML = `
          <div style="display:flex; flex-direction:column; gap:0.85rem;">
            <div class="alert-banner info" style="margin-bottom:0;">
              <div style="font-size:1.35rem;">&#128230;</div>
              <div>
                <h3>Portable Single-File HTML Report Compiled &amp; Downloaded</h3>
                <p style="margin-bottom:0.35rem;">${escapeHtml(m.Explanation || '')}</p>
                <p style="margin-bottom:0.35rem;"><strong>Saved on Disk:</strong> <code>${escapeHtml(m.TimestampedReportPath || m.LatestReportHtmlPath)}</code></p>
                <p style="margin-bottom:0;">
                  <strong>SHA-256 Tamper-Evident Integrity Hash:</strong> <code>${escapeHtml(m.SHA256)}</code>
                  <button class="btn btn-sm" style="padding:0.1rem 0.45rem; font-size:0.68rem; margin-left:0.4rem;" onclick="copyToClipboard('${escapeJs(m.SHA256)}')">Copy SHA-256</button>
                </p>
              </div>
            </div>
            <div class="card" style="padding:0.85rem 1rem; margin-bottom:0; border-left:4px solid var(--accent-teal);">
              <strong>Next Steps for System Administrators:</strong>
              <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.25rem; margin-bottom:0;">
                ${escapeHtml(m.RecommendedFix || '')}
              </p>
            </div>
          </div>
        `;
        modal.classList.add('open');
      }
      return;
    }
  }

  // Offline / fallback client-side single-file HTML synthesis
  const snapshotHtml = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
  downloadBlob(snapshotHtml, dlFileName, 'text/html;charset=utf-8;');
  showToast(`Downloaded portable HTML snapshot (${dlFileName})`);
};

// ----------------------------------------------------------------------------
// 7. Utility Helpers
// ----------------------------------------------------------------------------
function renderBarRow(label, rightValue, percent, colorClass = 'blue') {
  const safePct = Math.max(2, Math.min(100, Math.round(Number(percent) || 0)));
  return `
    <div class="bar-row">
      <div class="bar-label-line">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(rightValue)}</strong>
      </div>
      <div class="bar-track">
        <div class="bar-fill ${colorClass}" style="width: ${safePct}%;"></div>
      </div>
    </div>
  `;
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(val);
}

function showToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.style.display = 'block';
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    toast.style.display = 'none';
  }, 3000);
}

window.copyToClipboard = function(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard!')).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
};

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    showToast('Copied to clipboard!');
  } catch (e) {}
  document.body.removeChild(ta);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeXml(str) {
  return escapeHtml(str).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

function escapeJs(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '');
}
