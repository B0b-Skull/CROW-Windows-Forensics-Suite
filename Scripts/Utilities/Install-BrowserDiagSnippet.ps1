<#
.SYNOPSIS
    Browser Frontend GPU/DOM/WebSocket Diagnostic Snippet Generator (UTIL-03)
.DESCRIPTION
    Generates an optional, read-only JavaScript diagnostic observer snippet
    that can be pasted into Chrome/Edge DevTools Console or loaded as a
    Userscript on any web application tab experiencing visual blanking or drops.
    Captures WebGL/GPU context losses, DOM body blanking/replacement, WebSocket
    disconnects/reconnects, visibility state changes, and unhandled JS errors
    with high-precision local & UTC timestamps for correlation with Windows Event Logs.
#>
param(
    [string]$OutputPath = ""
)

$baseDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $baseDir "Data\Investigations\browser_diagnostics_snippet.js" }

$jsSnippet = @'
// ============================================================================
// Read-Only Browser GPU, WebSocket & DOM Stability Diagnostic Monitor (UTIL-03)
// Purpose: Correlate browser visual blanking / white-flashes with Windows GPU
//          TDR (LiveKernelEvent 141 / Event 4101) vs. WebSocket disconnects
//          or Frontend DOM container replacement.
// Usage:   Paste into Chrome/Edge DevTools Console (F12) on the target tab.
//          Call window.exportBrowserDiagLogs() anytime to download JSON logs.
// ============================================================================
(function() {
  if (window.__FORENSIC_BROWSER_DIAG_ACTIVE__) {
    console.info('[BROWSER-DIAG] Monitor already active. Existing logs:', window.__FORENSIC_BROWSER_DIAG_LOGS__.length);
    return;
  }
  window.__FORENSIC_BROWSER_DIAG_ACTIVE__ = true;
  window.__FORENSIC_BROWSER_DIAG_LOGS__ = JSON.parse(localStorage.getItem('FORENSIC_BROWSER_DIAG_LOGS') || '[]');

  function recordEvent(category, severity, details) {
    const now = new Date();
    const entry = {
      id: window.__FORENSIC_BROWSER_DIAG_LOGS__.length + 1,
      timestampUtc: now.toISOString(),
      timestampLocal: now.toLocaleString(),
      category: category,
      severity: severity,
      url: window.location.href,
      memoryUsedMB: (performance && performance.memory) ? Math.round(performance.memory.usedJSHeapSize / 1048576) : null,
      details: details
    };
    window.__FORENSIC_BROWSER_DIAG_LOGS__.push(entry);
    if (window.__FORENSIC_BROWSER_DIAG_LOGS__.length > 500) window.__FORENSIC_BROWSER_DIAG_LOGS__.shift();
    try { localStorage.setItem('FORENSIC_BROWSER_DIAG_LOGS', JSON.stringify(window.__FORENSIC_BROWSER_DIAG_LOGS__)); } catch (e) {}
    console.warn(`[BROWSER-DIAG][${entry.timestampLocal}][${category}]`, details);
  }

  // 1. Detect GPU / WebGL Context Loss (Correlates with Windows LiveKernelEvent 141 TDR)
  window.addEventListener('webglcontextlost', (e) => {
    recordEvent('GPU_WEBGL_CONTEXT_LOST', 'CRITICAL', {
      message: 'WebGL context lost (Browser GPU process reset or Windows TDR Event 141)',
      targetTag: e.target ? e.target.tagName : 'Unknown'
    });
  }, true);

  window.addEventListener('webglcontextrestored', (e) => {
    recordEvent('GPU_WEBGL_CONTEXT_RESTORED', 'WARNING', {
      message: 'WebGL context restored after reset'
    });
  }, true);

  // 2. Detect DOM Body / Root Container Replacement or Whiteout
  let lastChildCount = document.body ? document.body.children.length : 0;
  const domObserver = new MutationObserver(() => {
    const curCount = document.body ? document.body.children.length : 0;
    const rootApp = document.getElementById('root') || document.getElementById('app') || document.querySelector('.stApp');
    if (curCount === 0 || (rootApp && rootApp.innerHTML.trim() === '')) {
      recordEvent('DOM_VIEWPORT_BLANKED', 'HIGH', {
        message: 'Root container or document.body became empty during re-render',
        previousChildCount: lastChildCount,
        currentChildCount: curCount
      });
    }
    lastChildCount = curCount;
  });
  if (document.body) {
    domObserver.observe(document.body, { childList: true, subtree: false });
  }

  // 3. Intercept WebSocket Disconnections & Reconnections
  const OrigWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const ws = protocols ? new OrigWebSocket(url, protocols) : new OrigWebSocket(url);
    recordEvent('WEBSOCKET_OPENING', 'INFO', { url: String(url) });
    ws.addEventListener('close', (evt) => {
      recordEvent('WEBSOCKET_CLOSED', 'HIGH', {
        url: String(url),
        code: evt.code,
        reason: evt.reason || 'None',
        wasClean: evt.wasClean
      });
    });
    ws.addEventListener('error', () => {
      recordEvent('WEBSOCKET_ERROR', 'HIGH', { url: String(url) });
    });
    return ws;
  };
  window.WebSocket.prototype = OrigWebSocket.prototype;
  Object.assign(window.WebSocket, OrigWebSocket);

  // 4. Unhandled JS Exceptions & Promise Rejections
  window.addEventListener('error', (evt) => {
    recordEvent('JS_UNHANDLED_ERROR', 'HIGH', {
      message: evt.message,
      filename: evt.filename,
      lineno: evt.lineno,
      colno: evt.colno
    });
  });

  window.addEventListener('unhandledrejection', (evt) => {
    recordEvent('PROMISE_REJECTION', 'MEDIUM', {
      reason: String(evt.reason)
    });
  });

  // 5. Page Visibility & Reload Tracking
  document.addEventListener('visibilitychange', () => {
    recordEvent('VISIBILITY_CHANGE', 'INFO', { state: document.visibilityState });
  });

  window.exportBrowserDiagLogs = function() {
    const blob = new Blob([JSON.stringify(window.__FORENSIC_BROWSER_DIAG_LOGS__, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `browser_diag_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
  };

  recordEvent('MONITOR_INITIALIZED', 'INFO', { note: 'Browser Diagnostic Monitor attached (Read-Only)' });
})();
'@

$outDir = Split-Path -Path $OutputPath -Parent
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$jsSnippet | Set-Content -Path $OutputPath -Encoding UTF8

$result = [PSCustomObject]@{
    ScriptId         = "UTIL-03"
    ScriptName       = "Install-BrowserDiagSnippet.ps1"
    GeneratedAtLocal = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    SnippetPath      = $OutputPath
    Status           = "Ready"
    Instructions     = "Open the target web application in Chrome/Edge, press F12 -> Console, paste the contents of browser_diagnostics_snippet.js, and call exportBrowserDiagLogs() to export collected events."
}
$result | ConvertTo-Json -Depth 4
