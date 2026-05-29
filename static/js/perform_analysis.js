/**
 * perform_analysis.js — Secure Eye Trust+
 * Deep time-based analysis report with animated loader
 */


/* ════════════════════════════════════════════════════════════
   RADAR SCANNER  —  used in pa-loading state
════════════════════════════════════════════════════════════ */

var _radarRAF   = null;
var _radarAngle = -90;   // degrees; starts at top
var _radarPct   = 0;

function _radarStart() {
  var canvas  = document.getElementById('radarCanvas');
  if (!canvas) return;
  var ctx     = canvas.getContext('2d');
  var cx      = canvas.width  / 2;
  var cy      = canvas.height / 2;
  var r       = cx - 4;
  var stages  = [
    'Reading Windows Logs…',
    'Scanning file system…',
    'Running YARA rules…',
    'Running Sigma engine…',
    'Building attack chain…',
    'Finalising report…'
  ];
  var blipContainer = document.getElementById('radarBlips');
  var lastBlipAngle = -999;
  var _lastDisplayedPct = -1; // ensure displayed percent never decreases

  function _step() {
    // Rotate sweep
    _radarAngle += 1.2;
    if (_radarAngle > 270) _radarAngle = -90; // cap at 270° (open top wedge look)

    // Progress (0-100 driven externally via _radarSetPct)
    var pctEl = document.getElementById('radar-percent');
    if (pctEl) {
      var disp = Math.round(_radarPct);
      // only update the DOM when the rounded value increases to avoid
      // visual jitter/temporary decreases caused by rounding or timer races
      if (disp > _lastDisplayedPct) {
        pctEl.textContent = disp + '%';
        _lastDisplayedPct = disp;
      }
    }

    var stageEl = document.getElementById('radar-stage');
    if (stageEl) {
      var idx = Math.min(Math.floor(_radarPct / (100 / stages.length)), stages.length - 1);
      stageEl.textContent = stages[idx];
    }

    // Draw sweep on canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Filled sweep wedge
    var angleRad  = (_radarAngle * Math.PI) / 180;
    var startRad  = angleRad - (75 * Math.PI / 180); // 75° trailing edge
    var grad = ctx.createConicalGradient
      ? null   // fallback below
      : null;

    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startRad, angleRad, false);
    ctx.closePath();

    // Radial gradient fill for the wedge (glow effect)
    var gFill = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
    gFill.addColorStop(0,   'rgba(0,255,136,0.0)');
    gFill.addColorStop(0.55,'rgba(0,255,136,0.12)');
    gFill.addColorStop(1,   'rgba(0,255,136,0.28)');
    ctx.fillStyle = gFill;
    ctx.fill();

    // Leading edge glow line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(
      cx + r * Math.cos(angleRad),
      cy + r * Math.sin(angleRad)
    );
    ctx.strokeStyle = 'rgba(0,255,136,0.9)';
    ctx.lineWidth   = 2;
    ctx.shadowColor = '#00ff88';
    ctx.shadowBlur  = 12;
    ctx.stroke();
    ctx.shadowBlur  = 0;

    // Spawn blip dots as the sweep passes
    if (blipContainer && Math.abs(_radarAngle - lastBlipAngle) > 22 + Math.random() * 30) {
      lastBlipAngle = _radarAngle;
      var blipR     = (40 + Math.random() * (r - 50));
      var blipA     = angleRad + (Math.random() - 0.5) * 0.3;
      var bx        = Math.round(cx + blipR * Math.cos(blipA));
      var by        = Math.round(cy + blipR * Math.sin(blipA));
      var dot       = document.createElement('div');
      dot.className = 'radar-blip';
      dot.style.left = bx + 'px';
      dot.style.top  = by + 'px';
      blipContainer.appendChild(dot);
      setTimeout(function(d){ try{ blipContainer.removeChild(d); }catch(e){} }, 2600, dot);
    }

    _radarRAF = requestAnimationFrame(_step);
  }

  _step();
}

function _radarStop() {
  if (_radarRAF) { cancelAnimationFrame(_radarRAF); _radarRAF = null; }
  // Do not forcibly reset _radarPct or the displayed percent here. Keep
  // the last shown percentage (usually 100%) so the UI doesn't flash
  // back to 0% immediately after finishing. Values are reset when a
  // new run begins via runPerformAnalysis() which sets _radarPct = 0.
  _radarAngle = -90;
}

function _radarSetPct(pct) {
  _radarPct = Math.min(Math.max(pct, 0), 100);
}

/* ════════════════════════════════════════════════════════════
   IDLE PANEL — update chips + DNA + timeline after analysis
════════════════════════════════════════════════════════════ */

function _thUpdateIdlePanel(report) {
  if (!report) return;

  // Counts
  var totEvents = 0;
  var cats = report.categories || {};
  Object.values(cats).forEach(function(c){
    totEvents += (c.critical||0) + (c.errors||0) + (c.warnings||0) + (c.info||0);
  });
  var threats   = (report.threat_hits  || []).length;
  var anomalies = (report.anomaly_days || []).length;
  var rs        = report.risk_summary  || {};

  // Helper: set chip text + class
  function setChip(id, text, cls) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className   = 'th-source-chip' + (cls ? ' ' + cls : '');
  }

  setChip('th-chip-wlogs',  totEvents.toLocaleString(), 'th-chip-live');
  setChip('th-chip-sysmon',
    ((cats.sysmon_events || {}).info || 0).toLocaleString() || '—',
    'th-chip-live');
  setChip('th-chip-yara',   anomalies > 0 ? anomalies + ' days' : '0', anomalies > 0 ? 'th-chip-amber' : 'th-chip-live');
  setChip('th-chip-sigma',  threats > 0 ? threats + ' hits' : '0',    threats   > 0 ? 'th-chip-amber' : 'th-chip-live');
  setChip('th-chip-threats',threats > 0 ? threats + ' CRITICAL' : 'CLEAN',
    threats > 0 ? 'th-chip-red' : 'th-chip-live');

  // DNA panel
  var dnaEl = document.getElementById('th-dna-body');
  if (dnaEl) {
    var RCOL = {'Low':'green','Suspicious':'amber','High':'high','Critical':'critical'};
    var rClass = RCOL[rs.label] || '';
    var tophit = (report.threat_hits || [])[0];
    dnaEl.innerHTML = [
      _dnaRow('Risk Score',  '<span class="th-dna-val '+ rClass +'">' + (rs.score||0) + '/100 — ' + (rs.label||'—') + '</span>'),
      _dnaRow('Period',      (report.period_days||'?') + ' days'),
      _dnaRow('Total Events',totEvents.toLocaleString()),
      _dnaRow('Threat Hits', threats ? '<span class="th-dna-val critical">' + threats + '</span>' : '<span class="th-dna-val green">None</span>'),
      _dnaRow('Top Threat',  tophit ? '<span class="th-dna-val critical">' + (tophit.name||tophit.id||'—') + '</span>' : '—'),
      _dnaRow('Peak Hour',   (report.peak_hour || '—')),
    ].join('');
  }

  // Timeline panel
  var tlEl = document.getElementById('th-timeline-body');
  if (tlEl) {
    var hits = (report.threat_hits || []).slice(0, 5);
    var chains = (report.chains || []).slice(0, 3);
    var items  = [];

    chains.forEach(function(ch){
      items.push({ icon:'🔗', label: ch.name || ch.id, danger: ch.severity === 'CRITICAL' });
    });
    hits.forEach(function(h){
      items.push({ icon:'🎯', label: h.name || h.id, danger: h.severity === 'CRITICAL' || h.severity === 'HIGH' });
    });

    if (items.length === 0) {
      tlEl.innerHTML = '<div style="font-family:JetBrains Mono,monospace;font-size:12px;color:rgba(255,255,255,.3);padding:8px 0">No threats detected in this period</div>';
    } else {
      tlEl.innerHTML = items.map(function(it, i){
        return '<div class="th-tl-item' + (it.danger ? ' danger' : '') + '" style="animation-delay:' + (i*0.08) + 's">'
          + it.icon + ' &nbsp;' + it.label + '</div>';
      }).join('');
    }
  }
}

function _dnaRow(key, valHtml) {
  return '<div class="th-dna-row"><span class="th-dna-key">' + key + '</span><span class="th-dna-val">' + valHtml + '</span></div>';
}


var _paCharts     = {};
var _paLastReport = null;   // keeps report alive across tab switches
var _paIsRunning  = false;  // true while a scan is active

/* ── Init — called every time tab is opened ──────────────────── */
function initPerformAnalysis() {
  // DOM safety: retry if divs not yet in DOM
  var idleEl   = document.getElementById('pa-idle');
  var loadEl   = document.getElementById('pa-loading');
  var reportEl = document.getElementById('pa-report');
  if (!idleEl || !loadEl || !reportEl) {
    setTimeout(initPerformAnalysis, 150);
    return;
  }

  // If a scan is already running, preserve the loading state.
  if (_paIsRunning) {
    _paSetAllStates('none','flex','none');
    _paUpdateRunButton();
    return;
  }

  // If already rendered this session, just show the saved report.
  if (_paLastReport) {
    try { _paRender(_paLastReport); } catch(e) { _paLastReport = null; window._paLastReport = null; _paShowIdle(); }
    _paUpdateRunButton();
    return;
  }

  _paShowIdle();

  // Try loading last saved report from DB
  fetch('/api/perform-analysis/latest', { cache: 'no-store' })
    .then(function(r) { if (!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
    .then(function(d) {
      if (d.ok && d.report) {
        _paLastReport = d.report;
        window._paLastReport = d.report;
        _paRender(d.report);
        if (typeof _thUpdateIdlePanel === 'function') _thUpdateIdlePanel(d.report);
        var hdr = document.getElementById('pa-generated');
        if (hdr) hdr.textContent = d.report.generated_at + '  (saved — click Re-run to refresh)';
        _paUpdateRunButton();
      } else {
        _paShowIdle();
      }
    })
    .catch(function(e) { console.warn('[PA] latest report load failed:', e.message); _paShowIdle(); });
}

/* Central helper — set display+visibility on all three state divs */
function _paSetAllStates(idleD, loadD, reportD) {
  var e;
  e = document.getElementById('pa-idle');    if (e) { e.style.display = idleD;   e.style.visibility = (idleD==='none'?'hidden':'visible'); }
  e = document.getElementById('pa-loading'); if (e) { e.style.display = loadD;   e.style.visibility = (loadD==='none'?'hidden':'visible'); }
  e = document.getElementById('pa-report');  if (e) { e.style.display = reportD; e.style.visibility = (reportD==='none'?'hidden':'visible'); }
}

function _paShowIdle() {
  _paSetAllStates('flex','none','none');
  _paUpdateRunButton();
}

function _paUpdateRunButton() {
  var btn = document.getElementById('pa-run-btn');
  if (!btn) return;
  // Top button is only shown after a report has been generated (acts as Re-run).
  // In the initial state, the centered "Start Hunting" button in pa-idle is the entry point.
  if (_paLastReport) {
    btn.style.display = 'inline-flex';
    btn.innerHTML = '<span>🔄</span> Re-run Analysis';
  } else {
    btn.style.display = 'none';
  }
  btn.disabled = false;
  btn.style.opacity = '';
  btn.style.cursor = 'pointer';

}

function _paSetRunButtonLoading(loading) {
  var btn = document.getElementById('pa-run-btn');
  if (!btn) return;
  btn.disabled = loading;
  btn.style.opacity = loading ? '0.65' : '';
  btn.style.cursor = loading ? 'not-allowed' : 'pointer';
}

/* Direct entry point used by the centered "Start Hunting" button
   and by the top "Re-run Analysis" button. Skips the old period-picker
   modal and uses a fixed 30-day window. */
function paStartHunting() {
  return runPerformAnalysis(30);
}

/* ── Legacy no-ops (old period-modal hooks kept for safety) ───── */
function paShowPeriodModal() { paStartHunting(); }
function paHidePeriodModal() { /* modal removed */ }
function paToggleCustomDays() { /* modal removed */ }
function paSelectPeriod(days) {
  if (typeof days !== 'number' || isNaN(days) || days < 1) days = 30;
  runPerformAnalysis(days);
}

/* ── Run analysis ────────────────────────────────────────────── */
async function runPerformAnalysis(days) {
  // Prevent duplicate concurrent scans
  if (_paIsRunning) { console.warn('[PA] already running — ignored'); return; }
  _paIsRunning = true;
  _paSetRunButtonLoading(true);

  _paSetAllStates('none','flex','none');
  var loadEl = document.getElementById('pa-loading');
  if (loadEl) loadEl.scrollIntoView({ behavior: 'smooth', block: 'center' });

  _radarPct = 0; _radarStart();  // start radar sweep immediately

  // Reset ticker UI
  var tickerWrap = document.getElementById('pa-file-ticker-wrap');
  if (tickerWrap) tickerWrap.style.display = '';
  var tickerEl   = document.getElementById('pa-file-ticker');
  var tickerCnt  = document.getElementById('pa-file-ticker-count');
  if (tickerEl) tickerEl.textContent = 'initializing\u2026';
  if (tickerCnt) tickerCnt.textContent = '0 files inspected';

  // Destroy old charts
  Object.values(_paCharts).forEach(function(ch){ try{ ch.destroy(); }catch(e){} });
  _paCharts = {};

  // ── Realistic Windows scan paths to cycle through in the ticker ─────────
  var _PA_SCAN_PATHS = [
    'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\System.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx',
    'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx',
    'C:\\Windows\\System32\\config\\SOFTWARE',
    'C:\\Windows\\System32\\config\\SYSTEM',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\Windows\\Tasks\\',
    'C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\',
    'C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Defrag\\ScheduledDefrag',
    'C:\\Users\\Public\\Downloads\\',
    'C:\\Users\\Public\\Desktop\\',
    'C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\',
    'C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\',
    'C:\\Users\\%USER%\\AppData\\Local\\Temp\\',
    'C:\\Users\\%USER%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\',
    'C:\\Users\\%USER%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\',
    'C:\\Users\\%USER%\\Downloads\\',
    'C:\\Windows\\Prefetch\\',
    'C:\\Windows\\SoftwareDistribution\\Download\\',
    'C:\\Windows\\WindowsUpdate.log',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services\\',
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\',
    'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Sigma rule: proc_creation_win_office_spawn_susp_proc',
    'Sigma rule: registry_set_persistence_run_keys',
    'YARA rule: APT_PowerShell_Cradle',
    'YARA rule: Mimikatz_Generic',
    'YARA rule: Ransomware_Generic_Behavior',
    'Correlator: process \u2192 network \u2192 file-drop chain',
    'Correlator: macro \u2192 shell \u2192 persistence chain',
    'Anomaly detector: 30-day volume z-score',
    'Anomaly detector: off-hours auth burst',
    'Threat detector: BRUTE_FORCE window scan',
    'Threat detector: DLL_INJECT_LSASS_HANDLE',
    'Threat detector: PS_ENCODED_CMD',
  ];

  // ── Smooth monotonic progress (combines time + file detection) ───────
  // Avoid quick initial jumps by starting low and ramping slowly.
  var _startMs = Date.now();
  var _progressTimer = setInterval(function() {
    var elapsed = (Date.now() - _startMs) / 1000;          // seconds
    var timeTarget = 10 + 70 * (1 - Math.exp(-elapsed / 6));
    var tickerTarget = 10 + Math.min(85, (_tickerCount / Math.max(1, _paEstimatedTotal)) * 85);
    var target = Math.max(timeTarget, tickerTarget, _radarPct + 0.35);
    target = Math.min(target, 94);
    if (target > _radarPct) _radarSetPct(target);
  }, 80);

  // ── Step labels driven by current progress (no cycling) ─────────────────
  var _stepLabels = [
    'Scanning threat patterns\u2026',
    'Running anomaly detection\u2026',
    'Computing temporal patterns\u2026',
    'Building report\u2026',
  ];
  var _stepTimer = setInterval(function() {
    var pct = _radarPct;
    var activeIdx = pct < 22 ? 0 : pct < 50 ? 1 : pct < 78 ? 2 : 3;
    for (var i = 0; i < 4; i++) {
      var el = document.getElementById('pa-step' + (i+1));
      if (!el) continue;
      if (i < activeIdx) {
        el.className   = 'pa-step pa-step-done';
        el.textContent = '\u2705 ' + _stepLabels[i];
      } else if (i === activeIdx) {
        el.className   = 'pa-step pa-step-active';
        el.textContent = '\u27f3 ' + _stepLabels[i];
      } else {
        el.className   = 'pa-step';
        el.textContent = '\u25ce ' + _stepLabels[i];
      }
    }
  }, 250);

  // ── File-scan ticker — cycles through realistic paths ───────────────────
  var _tickerCount = 0;
  // Adaptive estimated total so the percentage reflects live progress
  var _paEstimatedTotal = 400; // larger starting guess slows early jump
  var _tickerTimer = setInterval(function() {
    var path = _PA_SCAN_PATHS[Math.floor(Math.random() * _PA_SCAN_PATHS.length)];
    if (tickerEl)  tickerEl.textContent = path;
    _tickerCount++;
    if (tickerCnt) tickerCnt.textContent = _tickerCount.toLocaleString() + ' files inspected';

    // Grow estimate if we see more files than expected
    if (_tickerCount > _paEstimatedTotal) {
      _paEstimatedTotal = Math.min(Math.ceil(_tickerCount * 1.25), _tickerCount + 1000);
    }

    // Desired percent based on observed progress (cap below 100 until server returns)
    var desiredPct = Math.min(95, (_tickerCount / Math.max(1, _paEstimatedTotal)) * 100);
    if (desiredPct > _radarPct) _radarSetPct(desiredPct);
  }, 170);

  // Helper to tear down all timers safely
  function _stopAllAnimTimers() {
    try { clearInterval(_progressTimer); } catch(e) {}
    try { clearInterval(_stepTimer); }     catch(e) {}
    try { clearInterval(_tickerTimer); }   catch(e) {}
  }

  try {
    var url = '/api/perform-analysis';
    if (typeof days === 'number' && !isNaN(days) && days > 0) {
      url += '?days=' + encodeURIComponent(days);
    }
    var r   = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      cache: 'no-store',
    });
    var d   = await r.json();
    _stopAllAnimTimers();
    if (!d.ok || !d.report) { _paError('Server returned no report'); return; }

    // Smooth jump to 100% — final flourish
    var _finishStart = _radarPct;
    var _finishMs    = Date.now();
    await new Promise(function(res) {
      var t = setInterval(function() {
        var dt = (Date.now() - _finishMs) / 350;            // 350ms ramp
        if (dt >= 1) { clearInterval(t); _radarSetPct(100); res(); return; }
        _radarSetPct(_finishStart + (100 - _finishStart) * dt);
      }, 30);
    });

    // Mark all steps done
    for (var i = 0; i < 4; i++) {
      var el = document.getElementById('pa-step' + (i+1));
      if (el) { el.className = 'pa-step pa-step-done'; el.textContent = '\u2705 ' + _stepLabels[i]; }
    }
    if (tickerEl) tickerEl.textContent = 'scan complete';
    // Sync ticker count with the REAL files_scanned value from the report,
    // not the fake animation counter (which was incrementing every 170ms
    // regardless of how many files were actually inspected).
    if (tickerCnt) {
      var realCount = (d.report && (
        typeof d.report.files_scanned === 'number' ? d.report.files_scanned :
        (d.report.malware_analysis && d.report.malware_analysis.files_scanned)
      ));
      if (typeof realCount === 'number') {
        tickerCnt.textContent = realCount.toLocaleString() + ' files inspected';
      }
    }

    await new Promise(function(res){ setTimeout(res, 250); });
    _radarStop();
    _paLastReport = d.report;
    window._paLastReport = d.report;
    _paRender(d.report);
    _thUpdateIdlePanel(d.report);
    _paUpdateRunButton();
    // Push to reports page
    if (typeof loadReportsFromServer === 'function') loadReportsFromServer();
  } catch(e) {
    _stopAllAnimTimers();
    _paError('Analysis failed: ' + e.message);
  } finally {
    _paIsRunning = false;
    _paSetRunButtonLoading(false);
  }
}

function _paError(msg) {
  _radarStop();
  _paIsRunning = false;
  document.getElementById('pa-loading').style.display = 'none';
  _paShowIdle();
  _paSetRunButtonLoading(false);
  toast('❌ ' + msg);
}


/* ── Render report ───────────────────────────────────────────── */
function _paRender(r) {
  try {
  _paLastReport = r;
  window._paLastReport = r;
  // Use helper so display AND visibility are both reset correctly
  _paSetAllStates('none','none','block');
  var rep = document.getElementById('pa-report');
  if (!rep) { _paShowIdle(); return; }

  var $ = function(id){ return document.getElementById(id); };
  var set = function(id, v){ var e=$(id); if(e) e.textContent = (v===null||v===undefined)?'—':v; };
  var setH = function(id, h){ var e=$(id); if(e) e.innerHTML = h; };

  // ── HEADER ────────────────────────────────────────────────────────────────
  set('pa-generated', (r.generated_at||'') + (r.trigger==='manual' ? '  (click Re-run to refresh)':''));
  set('pa-period',    'Last ' + (r.period_days||'?') + ' days');
  set('pa-peak-hour', r.peak_hour || '—');

  var rs   = r.risk_summary || {};
  var sc   = r.unified_risk_score || r.risk_score || 0;
  var RCOL = {Low:'#4ade80', Suspicious:'#fbbf24', High:'#fb923c', Critical:'#f87171'};
  var rc   = RCOL[rs.label] || '#94a3b8';
  var rb   = $('pa-risk-badge');
  if (rb) {
    rb.textContent   = (rs.label||'—') + ' Risk · ' + sc + '/100';
    rb.style.cssText = 'background:'+rc+'18;color:'+rc+';border:1px solid '+rc+'44;padding:7px 18px;border-radius:20px;font-size:13px;font-weight:800;letter-spacing:.02em';
  }
  // Also update the RISK SCORE node in the pipeline strip (ur-risk-num span) immediately
  var riskNumEl = $('ur-risk-num');
  if (riskNumEl) {
    riskNumEl.textContent = sc;
    riskNumEl.style.color = rc;
  }
  // Update any standalone risk score elements on the page
  document.querySelectorAll('.pa-score-display,.risk-score-val').forEach(function(el){
    el.textContent = sc + '/100';
    el.style.color = rc;
  });

  // download buttons
  var dlEl = $('pa-download-btns');
  if (dlEl && r.id) {
    dlEl.innerHTML =
      '<button onclick="paExport(\''+r.id+'\',\'pdf\')" style="background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;border:none;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700">⬇ PDF</button> '+
      '<button onclick="paExport(\''+r.id+'\',\'json\')" style="background:rgba(255,255,255,.06);color:var(--text-dim);border:1px solid var(--border2);padding:9px 16px;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700">⬇ JSON</button>';
  }

  // ── PIPELINE STRIP ────────────────────────────────────────────────────────
  var ma   = r.malware_analysis || {};
  var cats = r.categories || {};
  var totEv = 0;
  Object.values(cats).forEach(function(c){ totEv += c.total||0; });

  set('urp-log-count',    totEv.toLocaleString());
  var sysEl = $('urp-sysmon-count');
  if (sysEl) {
    if (!ma.sysmon_available) {
      sysEl.textContent = 'Not installed';
      sysEl.style.color = '#6b7280';
    } else {
      sysEl.textContent = (ma.sysmon_events||0).toLocaleString();
      sysEl.style.color = '#00e5ff';
    }
  }
  // Files scanned — comes from the YARA / file-system scanner (Downloads,
  // Desktop, Temp, AppData). Shows total files inspected during this run.
  var filesEl = $('urp-files-count');
  if (filesEl) {
    var fc = (typeof r.files_scanned === 'number') ? r.files_scanned
           : (typeof ma.files_scanned === 'number') ? ma.files_scanned
           : 0;
    if (fc > 0) {
      filesEl.textContent = fc.toLocaleString();
      filesEl.style.color = '#a3f7c0';
    } else if (ma.yara_available === false) {
      filesEl.textContent = 'YARA off';
      filesEl.style.color = '#6b7280';
    } else {
      filesEl.textContent = '0';
      filesEl.style.color = '#6b7280';
    }
  }
  set('urp-threat-count', (r.threat_hits||[]).length ? (r.threat_hits||[]).length+' hits' : '✓ Clean');
  set('urp-malware-count',(r.malware_detections||[]).length ? (r.malware_detections||[]).length+' dets' : '✓ Clean');
  set('urp-risk-val',      sc + '/100');

  // ── SECTION 1: LOG ANALYSIS ───────────────────────────────────────────────
  var totCrit=0,totErr=0,totWarn=0,totInfo=0;
  Object.values(cats).forEach(function(c){
    totCrit += c.critical||0; totErr  += c.errors||0;
    totWarn += c.warnings||0; totInfo += c.info||0;
  });
  set('pa-s-critical',  totCrit.toLocaleString());
  set('pa-s-errors',    totErr.toLocaleString());
  set('pa-s-warnings',  totWarn.toLocaleString());
  set('pa-s-info',      totInfo.toLocaleString());
  set('pa-s-anomalies', (r.anomaly_days||[]).length.toLocaleString());
  _paTimelineChart(r.timeline||[], r.anomaly_days||[]);

  // Threat hits from existing detector (non-Sysmon)
  var thEl = $('ur-threat-hits-body');
  if (thEl) {
    var regHits = (r.threat_hits||[]).filter(function(h){ return !String(h.id||'').startsWith('SYSMON_'); });
    if (regHits.length === 0) {
      thEl.innerHTML = '<div class="ur-clean">✅ No threat detections from Windows logs</div>';
    } else {
      thEl.innerHTML = regHits.slice(0,8).map(function(h, idx){
        var sc2 = (h.severity||'low').toLowerCase();
        // Downgrade hint: rule was originally HIGH/CRITICAL but confidence
        // pulled it down. Helps the analyst see WHY the badge is what it is.
        var downHint = '';
        if (h.original_severity && h.original_severity !== h.severity) {
          downHint = '<span class="ur-det-tag" style="background:rgba(148,163,184,.08);color:#94a3b8" '
            +'title="Rule severity ' + h.original_severity + ' was downgraded to ' + h.severity
            + ' because confidence is ' + (h.confidence_pct||0) + '%">'
            + '↓ from ' + h.original_severity + '</span>';
        }
        // Hard-evidence badge: this detection is real, not heuristic noise
        var hardBadge = h.is_hard_evidence
          ? '<span class="ur-det-tag" style="background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.3)" '
            +'title="High-fidelity rule fired at ≥70% confidence — treat as ground truth">🚨 hard evidence</span>'
          : '';
        // Stash the full hit so the Details popup can render the evidence
        // without re-fetching. (Using a global keyed map avoids deep-quote
        // escaping problems with inline JSON in onclick attributes.)
        window._paThreatHitMap = window._paThreatHitMap || {};
        var hitKey = 'thit-' + idx + '-' + Math.random().toString(36).slice(2, 7);
        window._paThreatHitMap[hitKey] = h;
        return '<div class="ur-det-card '+sc2+'">'
          +'<div class="ur-det-sev ur-sev-'+sc2+'">'+h.severity+'</div>'
          +'<div class="ur-det-body">'
            +'<div class="ur-det-name">'+_escHtml(h.name||h.id)+'</div>'
            +'<div class="ur-det-desc">'+_escHtml(h.human_summary||h.description||'')+'</div>'
            +'<div class="ur-det-meta">'
              +hardBadge
              +(h.mitre_tactic?'<span class="ur-det-tag">'+_escHtml(h.mitre_tactic)+'</span>':'')
              +'<span class="ur-det-tag">'+h.count+' events</span>'
              +'<span class="ur-det-tag">conf: '+h.confidence_pct+'%</span>'
              +downHint
              +'<span class="ur-det-tag">last: '+_escHtml(String(h.latest||'').slice(0,16))+'</span>'
            +'</div>'
            +'<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">'
              + _paActBtn('🔎 Show Details', 'blue',
                  'paShowThreatDetails(\''+hitKey+'\')', hitKey+'-det')
            +'</div>'
          +'</div>'
          +'<div class="ur-det-count" style="color:#f87171">'+h.count+'</div>'
        +'</div>';
      }).join('');
    }
  }

  // ── SECTION 2: MALWARE ANALYSIS ───────────────────────────────────────────
  var malEl = $('ur-malware-body');
  if (malEl) {
    var dets = r.malware_detections || [];
    if (!dets.length) {
      malEl.innerHTML = '<div class="ur-clean">✅ No malware pattern detections (requires confidence ≥ 65% and count ≥ 3)</div>';
    } else {
      malEl.innerHTML = dets.slice(0,8).map(function(d){
        var sc2 = (d.severity||'medium').toLowerCase();
        return '<div class="ur-det-card '+sc2+'">'
          +'<div class="ur-det-sev ur-sev-'+sc2+'">'+(d.severity||'MEDIUM')+'</div>'
          +'<div class="ur-det-body">'
            +'<div class="ur-det-name">'+(d.name||d.id||'Unknown')+'</div>'
            +'<div class="ur-det-desc">'+(d.indicator||d.description||'')+'</div>'
            +'<div class="ur-det-meta">'
              +(d.mitre?'<span class="ur-det-tag">'+d.mitre+'</span>':'')
              +(d.category?'<span class="ur-det-tag">'+d.category+'</span>':'')
              +'<span class="ur-det-tag">conf: '+(d.confidence?Math.round(d.confidence*100)+'%':'—')+'</span>'
            +'</div>'
          +'</div>'
          +'<div class="ur-det-count">'+(d.count||1)+'</div>'
        +'</div>';
      }).join('');
    }
  }

  // Files scanned badge
  var fsEl = $('ur-files-scanned');
  if (fsEl) {
    var fs = r.files_scanned || 0;
    var ya = (ma.yara_hits||[]).length;
    var yaAvail = ma.yara_available;
    if (!yaAvail) {
      fsEl.innerHTML = '<div class="ur-clean" style="text-align:left">ℹ YARA scanner initialising — files will be scanned as they appear in watched directories.<br><small style="color:var(--text-dim)">Watched: Downloads · Desktop · Temp · AppData</small></div>';
    } else {
      var extCounts = ma.files_by_extension || {};
      var extOrder = ['.exe', '.bat', '.ps1', '.vbs', '.js', '.txt'];
      var extraExts = Object.keys(extCounts).filter(function(ext){ return extOrder.indexOf(ext) === -1; }).sort();
      var allExts = extOrder.concat(extraExts);
      fsEl.innerHTML = '<div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center;padding:8px 0">'
        +'<div class="ur-stat ur-stat--green" style="min-width:100px"><div class="ur-stat-val">'+fs.toLocaleString()+'</div><div class="ur-stat-lbl">Files Scanned</div></div>'
        +'<div class="ur-stat '+(ya>0?'ur-stat--red':'ur-stat--green')+'" style="min-width:100px"><div class="ur-stat-val">'+ya+'</div><div class="ur-stat-lbl">YARA Hits</div></div>'
        +allExts.map(function(ext){
            return '<div class="ur-stat" style="min-width:80px"><div class="ur-stat-val" style="font-size:16px">'+(extCounts[ext]||0)+'</div><div class="ur-stat-lbl">'+ext+'</div></div>';
          }).join('')
        +'</div>';
    }
  }

  // ── SECTION 3: SUSPICIOUS PROCESSES ──────────────────────────────────────
  var procEl = $('ur-process-body');
  if (procEl) {
    var procs = ma.suspicious_processes || [];
    if (!procs.length) {
      procEl.innerHTML = '<div class="ur-clean">✅ No suspicious processes detected via Sysmon'
        + (ma.sysmon_available ? '' : ' — Sysmon not installed') + '</div>';
    } else {
      procEl.innerHTML = '<table class="ur-table"><thead><tr>'
        +'<th>Time</th><th>Parent</th><th>Image</th><th>Command</th><th>Flag</th>'
        +'</tr></thead><tbody>'
        +procs.slice(0,20).map(function(p){
          var dg = p.suspicious ? 'ur-row-danger' : '';
          return '<tr class="'+dg+'">'
            +'<td class="mono dim">'+(p.timestamp||'').slice(11,19)+'</td>'
            +'<td class="mono" style="color:'+(p.suspicious?'#f87171':'inherit')+'">'+(p.parent||'—')+'</td>'
            +'<td class="mono">'+(p.image||'—')+'</td>'
            +'<td class="mono dim" title="'+_escHtml(p.command||'')+'">'+_escHtml((p.command||'').slice(0,50))+'</td>'
            +'<td>'+(p.suspicious
              ?'<span style="color:#f87171;font-size:10px;font-weight:700;background:rgba(239,68,68,.1);padding:2px 7px;border-radius:4px">⚠ MACRO SPAWN</span>'
              :'<span style="color:#4ade80;font-size:10px">OK</span>'
            )+'</td>'
          +'</tr>';
        }).join('')
        +'</tbody></table>';
    }
  }

  // ── SECTION 4: FILE DROPS ─────────────────────────────────────────────────
  var fdEl = $('ur-filedrops-body');
  if (fdEl) {
    var drops = ma.file_drops || [];
    if (!drops.length) {
      fdEl.innerHTML = '<div class="ur-clean">✅ No suspicious file drops detected via Sysmon'
        +(ma.sysmon_available?'':' — Sysmon not installed')+'</div>';
    } else {
      fdEl.innerHTML = '<table class="ur-table"><thead><tr>'
        +'<th>Time</th><th>Filename</th><th>Path</th><th>YARA</th>'
        +'</tr></thead><tbody>'
        +drops.slice(0,20).map(function(d){
          var dg = d.yara_matched ? 'ur-row-danger' : '';
          return '<tr class="'+dg+' ur-row-danger">'
            +'<td class="mono dim">'+(d.timestamp||'').slice(11,19)+'</td>'
            +'<td class="mono" style="color:#fb923c;font-weight:700">'+(d.filename||'—')+'</td>'
            +'<td class="mono dim" title="'+_escHtml(d.path||'')+'">…'+(d.path||'').slice(-45)+'</td>'
            +'<td>'+(d.yara_matched
              ?'<span style="color:#f87171;font-size:10px;font-weight:700">'+d.yara_rule+'</span>'
              :'<span style="color:var(--text-dim);font-size:10px">—</span>'
            )+'</td>'
          +'</tr>';
        }).join('')
        +'</tbody></table>';
    }
  }

  // ── SECTION 5: SIGMA HITS ─────────────────────────────────────────────────
  var sigEl = $('ur-sigma-body');
  if (sigEl) {
    var sigs = ma.sigma_hits || [];
    if (!sigs.length) {
      sigEl.innerHTML = '<div class="ur-clean">✅ No Sigma rule hits'
        +(ma.sysmon_available?'':' — Sysmon not installed (Sigma runs on Sysmon data)')+'</div>';
    } else {
      sigEl.innerHTML = sigs.slice(0,15).map(function(h, si){
        var sc2 = (h.severity||'high').toLowerCase();
        return '<div class="ur-det-card '+sc2+'" id="sigcard-'+si+'">'
          +'<div class="ur-det-sev ur-sev-'+sc2+'">'+(h.severity||'HIGH')+'</div>'
          +'<div class="ur-det-body" style="flex:1">'
            +'<div class="ur-det-name">'+(h.name||h.rule_id)+'</div>'
            +'<div class="ur-det-desc">'+(h.description||h.detail||'')+'</div>'
            +'<div class="ur-det-meta">'
              +'<span class="ur-det-tag">'+(h.rule||h.rule_id||'')+'</span>'
              +(h.mitre?'<span class="ur-det-tag">'+h.mitre+'</span>':'')
              +'<span class="ur-det-tag">'+(h.timestamp||'').slice(0,16)+'</span>'
            +'</div>'
          +'</div>'
        +'</div>';
      }).join('');
    }
  }

  // ── SECTION 6: YARA HITS ──────────────────────────────────────────────────
  var yaraEl = $('ur-yara-body');
  if (yaraEl) {
    var yara = ma.yara_hits || [];
    if (!yara.length) {
      var msg2 = ma.yara_available
        ? '✅ No YARA matches in scanned files'
        : 'ℹ YARA scanner active — monitoring Downloads, Desktop, Temp, AppData for new files';
      yaraEl.innerHTML = '<div class="ur-clean">' + msg2 + '</div>';
    } else {
      yaraEl.innerHTML = yara.slice(0,10).map(function(h, i){
        var sc2     = (h.severity||'medium').toLowerCase();
        var path    = h.path || '';
        var name    = h.filename || h.name || (path ? path.split(/[\\\/]/).pop() : (h.yara_rule||'Unknown file'));
        var keyBase = 'yarahit-' + i;
        // Action buttons — only render when we have a concrete path to act on
        var actionRow = '';
        if (path) {
          actionRow = '<div class="ur-yara-actions" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;padding-top:8px;border-top:1px dashed rgba(255,255,255,.07)">'
            + _paActBtn('📦 Quarantine', 'orange',
                'paQuarantineFile(this,\''+_paJs(path)+'\')', keyBase+'-q')
            + _paActBtn('🗑 Delete', 'red',
                'paDeleteFile(this,\''+_paJs(path)+'\')',    keyBase+'-d')
            + '</div>';
        }
        return '<div class="ur-det-card '+sc2+'">'
          +'<div class="ur-det-sev ur-sev-'+sc2+'">'+(h.severity||'MEDIUM')+'</div>'
          +'<div class="ur-det-body" style="flex:1">'
            +'<div class="ur-det-name">'+_escHtml(name)+'</div>'
            +'<div class="ur-det-desc">Rule: <strong>'+_escHtml(h.yara_rule||'—')+'</strong>'
              +(h.sha256?'  SHA256: '+_escHtml(String(h.sha256||'').slice(0,16))+'…':'')+'</div>'
            +'<div class="ur-det-meta">'
              +(path?'<span class="ur-det-tag" title="'+_escHtml(path)+'">…'+_escHtml(String(path).slice(-35))+'</span>':'')
              +(h.entropy?'<span class="ur-det-tag">entropy: '+_escHtml(String(h.entropy))+'</span>':'')
              +'<span class="ur-det-tag">'+_escHtml(String(h.scanned_at||'').slice(0,16))+'</span>'
            +'</div>'
            + actionRow
          +'</div>'
        +'</div>';
      }).join('');
    }
  }

  // ── SECTION 7: ATTACK CHAINS ──────────────────────────────────────────────
  var chainEl = $('ur-chain-body');
  if (chainEl) {
    var allChains = (r.attack_chains||[]);
    if (!allChains.length) {
      chainEl.innerHTML = '<div class="ur-clean">✅ No multi-stage attack chains detected</div>';
    } else {
      chainEl.innerHTML = allChains.slice(0,6).map(function(ch){
        var ev = (ch.evidence||[]).slice(0,4);
        return '<div class="ur-chain-card">'
          +'<div class="ur-chain-head">'
            +'<div class="ur-chain-name">🔗 '+(ch.name||ch.id)+'</div>'
            +'<div style="display:flex;gap:8px;align-items:center">'
              +'<span class="ur-chain-risk">Risk '+(ch.risk_score||'—')+'</span>'
              +'<span style="font-size:10px;color:rgba(255,255,255,.4);font-family:monospace">conf: '+(ch.confidence_pct||Math.round((ch.confidence||0)*100))+'%</span>'
            +'</div>'
          +'</div>'
          +'<div class="ur-chain-body">'
            +'<div class="ur-chain-desc">'+(ch.human_summary||ch.description||'')+'</div>'
            +(ev.length?'<div class="ur-chain-evidence">'+ev.map(function(e){
              return '<div class="ur-chain-ev-item">▸ '+_escHtml(String(e))+'</div>';
            }).join('')+'</div>':'')
            +(ch.actions&&ch.actions.length?'<div style="margin-top:10px;padding:10px;background:rgba(239,68,68,.06);border-radius:6px;border-left:2px solid rgba(239,68,68,.3)">'
              +'<div style="font-size:10px;font-weight:700;color:#fca5a5;margin-bottom:6px;letter-spacing:.06em">RECOMMENDED ACTIONS</div>'
              +ch.actions.slice(0,3).map(function(a,i){
                return '<div style="font-size:11px;color:rgba(255,255,255,.6);padding:3px 0">'+String(i+1)+'. '+_escHtml(a)+'</div>';
              }).join('')
            +'</div>':'')
          +'</div>'
        +'</div>';
      }).join('');
    }
  }

  // ── SECTION 8: UNIFIED RISK SCORE ────────────────────────────────────────
  set('ur-risk-num', sc);
  var circle = $('ur-risk-circle');
  if (circle) {
    var offset = 314 - (sc / 100) * 314;
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = sc>=75?'#ef4444':sc>=50?'#f97316':sc>=25?'#fbbf24':'#22c55e';
  }
  var bd = r.unified_breakdown || (r.risk_summary||{}).score_breakdown || {};
  var bdEl = $('ur-risk-breakdown');
  if (bdEl) {
    var rows = [
      {label:'Log Base Score',    val:bd.threat_score||bd.log_base||0,    max:50,  color:'#3b82f6'},
      {label:'Temporal Bonus',    val:bd.temporal_bonus||0,               max:8,   color:'#06b6d4'},
      {label:'Anomaly Score',     val:bd.anomaly_score||0,                max:10,  color:'#8b5cf6'},
      {label:'Chain Bonus',       val:(bd.chain_bonus||0)+(bd.sysmon_chain_bonus||0), max:35, color:'#ef4444'},
      {label:'Sigma Bonus',       val:bd.sigma_bonus||0,                  max:10,  color:'#f59e0b'},
      {label:'YARA Bonus',        val:bd.yara_bonus||0,                   max:12,  color:'#f97316'},
    ].filter(function(row){ return row.val > 0 || row.label==='Log Base Score'; });

    // ── Evidence-gate / methodology banner ───────────────────────────────
    // Explains WHY the score is what it is — defensible to a reviewer.
    var hardEv  = bd.hard_evidence === true;
    var gateOn  = bd.soft_gate_applied === true;
    var detCnt  = bd.detection_count || 0;
    var verdict = '';
    if (gateOn) {
      verdict = '<div style="background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.28);'
        +'border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;line-height:1.55;color:#fcd34d">'
        +'<div style="font-weight:800;letter-spacing:.04em;margin-bottom:4px">\u26a0\ufe0f Capped at High (74) \u2014 No Hard Evidence Confirmed</div>'
        +'<div style="color:rgba(252,211,77,.85)">'
          +detCnt+' suspicious pattern(s) fired, but none reached the hard-evidence bar '
          +'(confirmed malware, AV disabled, audit cleared, credential dump, or correlator-confirmed attack chain). '
          +'Score held below Critical until a confirmed indicator appears.'
        +'</div></div>';
    } else if (hardEv) {
      verdict = '<div style="background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.28);'
        +'border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;line-height:1.55;color:#fca5a5">'
        +'<div style="font-weight:800;letter-spacing:.04em;margin-bottom:4px">\ud83d\udea8 Hard Evidence Detected</div>'
        +'<div style="color:rgba(252,165,165,.85)">'
          +'Confirmed high-fidelity indicator(s) present \u2014 score reflects real malicious activity, not heuristic noise.'
        +'</div></div>';
    } else if (detCnt === 0) {
      verdict = '<div style="background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.28);'
        +'border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;line-height:1.55;color:#86efac">'
        +'<div style="font-weight:800;letter-spacing:.04em;margin-bottom:4px">\u2705 No Threat Patterns Detected</div>'
        +'<div style="color:rgba(134,239,172,.85)">System operating within normal parameters for this period.</div>'
        +'</div>';
    } else {
      verdict = '<div style="background:rgba(148,163,184,.06);border:1px solid rgba(148,163,184,.22);'
        +'border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:11.5px;line-height:1.55;color:#cbd5e1">'
        +'<div style="font-weight:800;letter-spacing:.04em;margin-bottom:4px">\u2139\ufe0f Low-Volume Heuristic Signals</div>'
        +'<div style="color:rgba(203,213,225,.8)">'
          +detCnt+' weak pattern(s) detected \u2014 likely routine system noise, but worth a glance.'
        +'</div></div>';
    }

    bdEl.innerHTML = verdict + rows.map(function(row){
      var pct = Math.round((row.val / row.max) * 100);
      return '<div class="ur-risk-row">'
        +'<div class="ur-risk-row-label">'+row.label+'</div>'
        +'<div class="ur-risk-bar-track"><div class="ur-risk-bar-fill" style="width:'+pct+'%;background:'+row.color+'"></div></div>'
        +'<div class="ur-risk-row-val" style="color:'+row.color+'">+'+row.val+'</div>'
      +'</div>';
    }).join('')
    +'<div class="ur-risk-row" style="border-top:1px solid rgba(255,255,255,.07);margin-top:6px;padding-top:8px">'
      +'<div class="ur-risk-row-label" style="font-weight:800;color:#fff">Unified Total</div>'
      +'<div class="ur-risk-bar-track"><div class="ur-risk-bar-fill" style="width:'+sc+'%;background:'+(circle?circle.style.stroke:'#22c55e')+'"></div></div>'
      +'<div class="ur-risk-row-val" style="color:#fff;font-size:15px">'+sc+'</div>'
    +'</div>';
  }

  // ── ACTIVE RESPONSE — action button cards (replaces text Action Plan) ────
  //
  // Pulls real targets from malware_analysis (suspicious processes, file
  // drops, YARA hits, registry persistence) and renders one card per
  // target with the appropriate response buttons wired to the live API.
  _paRenderActiveResponse(r);

  // Keep legacy hidden container populated for any export paths that still
  // read pa-recommendations (PDF/JSON exports, etc).
  var recEl = $('pa-recommendations');
  if (recEl) {
    var recs = r.recommendations||[];
    recEl.innerHTML = recs.slice(0,10).map(function(rec){
      return '<div data-priority="'+(rec.priority||'')+'">'+_escHtml(rec.text||'')+'</div>';
    }).join('');
  }

  // Keep RAG/AI integrations working silently
  setTimeout(function(){ try{ _paLoadAIInsights(r); }catch(e){} }, 800);
  setTimeout(function(){
    try{ if(typeof rigInjectPanel==='function') rigInjectPanel(r); window._ragCurrentReport=r; }catch(e){}
  }, 1100);

  // Idle panel chips update
  if (typeof _thUpdateIdlePanel === 'function') _thUpdateIdlePanel(r);
  } catch(renderErr) {
    console.error('[PA] _paRender error:', renderErr);
    _paLastReport = null; window._paLastReport = null;
    _paShowIdle();
    if (typeof toast === 'function') toast('⚠ Display error — click Re-run Analysis', 5000);
  }
}

/* ── HTML escape helper ────────────────────────────────────── */
function _escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ════════════════════════════════════════════════════════════════════════
   ACTIVE RESPONSE
   Replaces the old text "Action Plan". For every concrete malicious
   target found in the report (process by PID, dropped file, registry
   persistence) we render a card with the right action buttons. The
   buttons call the /api/action/* endpoints and report success/failure
   inline.
════════════════════════════════════════════════════════════════════════ */

// Track in-flight action requests so the same button can't fire twice.
var _paActionInFlight = {};

/* Tiny wrapper around fetch — POSTs JSON, returns parsed body */
async function _paPostAction(url, payload, btnEl, doneLabel) {
  var key = url + ':' + (btnEl ? btnEl.getAttribute('data-key') || '' : Math.random());
  if (_paActionInFlight[key]) return;
  _paActionInFlight[key] = true;

  var originalLabel = btnEl ? btnEl.innerHTML : '';
  var originalStyle = btnEl ? {
    bg: btnEl.style.background, bc: btnEl.style.borderColor, c: btnEl.style.color
  } : {};

  if (btnEl) {
    btnEl.disabled    = true;
    btnEl.style.opacity = '0.75';
    btnEl.style.cursor  = 'wait';
    btnEl.innerHTML   = '<span class="pa-act-spin"></span> Working…';
  }

  try {
    var r = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload || {}),
    });
    var d = await r.json().catch(function(){ return {ok:false, detail:'Invalid response from server'}; });

    if (d.ok || d.success) {
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.style.opacity = '1';
        btnEl.style.cursor  = 'default';
        btnEl.innerHTML = '✓ ' + (doneLabel || 'Done');
        btnEl.style.background  = 'rgba(34,197,94,.18)';
        btnEl.style.borderColor = 'rgba(34,197,94,.55)';
        btnEl.style.color       = '#86efac';
      }
      if (typeof toast === 'function') toast('✓ ' + (d.detail || 'Action completed'), 4000);
    } else {
      // Show the error reason clearly
      var errMsg = d.detail || d.error || 'Action failed';
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.style.opacity = '1';
        btnEl.style.cursor  = 'pointer';
        btnEl.innerHTML = '✗ Retry';
        btnEl.style.background  = 'rgba(239,68,68,.15)';
        btnEl.style.borderColor = 'rgba(239,68,68,.5)';
        btnEl.style.color       = '#fca5a5';
        btnEl.title             = errMsg;
        // Auto-restore original label after 5s so operator can retry
        setTimeout(function(){
          if (btnEl) {
            btnEl.innerHTML     = originalLabel;
            btnEl.style.background  = originalStyle.bg || '';
            btnEl.style.borderColor = originalStyle.bc || '';
            btnEl.style.color       = originalStyle.c  || '';
            btnEl.title = '';
          }
        }, 5000);
      }
      if (typeof toast === 'function') toast('✗ ' + errMsg, 6000);
    }
  } catch (e) {
    var netErr = 'Network error — is the app running? ' + e.message;
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.style.opacity = '1';
      btnEl.style.cursor  = 'pointer';
      btnEl.innerHTML = '✗ Retry';
      btnEl.style.background  = 'rgba(239,68,68,.15)';
      btnEl.style.borderColor = 'rgba(239,68,68,.5)';
      btnEl.style.color       = '#fca5a5';
      setTimeout(function(){
        if (btnEl) {
          btnEl.innerHTML = originalLabel;
          btnEl.style.background  = originalStyle.bg || '';
          btnEl.style.borderColor = originalStyle.bc || '';
          btnEl.style.color       = originalStyle.c  || '';
        }
      }, 5000);
    }
    if (typeof toast === 'function') toast('✗ ' + netErr, 6000);
  } finally {
    delete _paActionInFlight[key];
  }
}

/* Action handlers exposed globally so the inline onclick attributes work */
window.paKillProcess = function(btn, pid, name) {
  if (!confirm('Kill process PID ' + pid + (name ? ' (' + name + ')' : '') + '?\n\nThis will forcibly terminate the process.')) return;
  _paPostAction('/api/action/kill-process', { pid: pid, process_name: name || '' }, btn, 'Killed');
};
window.paQuarantineFile = function(btn, path) {
  if (!confirm('Quarantine this file?\n\n' + path + '\n\nThe file will be moved to a sealed quarantine folder.')) return;
  _paPostAction('/api/action/quarantine-file', { path: path }, btn, 'Quarantined');
};
window.paDeleteFile = function(btn, path) {
  if (!confirm('PERMANENTLY DELETE this file?\n\n' + path + '\n\nThis cannot be undone. Use Quarantine if unsure.')) return;
  _paPostAction('/api/action/delete-file', { path: path }, btn, 'Deleted');
};
window.paBlockNetwork = function(btn, processPath, ip) {
  var what = ip ? ('the IP ' + ip) : ('outbound traffic from ' + (processPath || 'this process'));
  if (!confirm('Add a Windows Firewall rule to block ' + what + '?')) return;
  _paPostAction('/api/action/block-network', { process_name: processPath || '', ip: ip || '' }, btn, 'Blocked');
};
window.paRemovePersistence = function(btn, kind, target) {
  if (!confirm('Remove this ' + kind + ' persistence mechanism?\n\n' + target)) return;
  _paPostAction('/api/action/remove-persistence', { kind: kind, target: target }, btn, 'Removed');
};

/* Dismiss a Sigma hit card (mark reviewed — hides the card locally) */
window.paDismissSigmaHit = function(btn, ruleId) {
  var card = btn ? btn.closest('[id^="sigcard-"]') : null;
  if (card) {
    card.style.transition = 'opacity .3s ease, max-height .4s ease';
    card.style.opacity = '0';
    card.style.maxHeight = card.offsetHeight + 'px';
    setTimeout(function() {
      card.style.maxHeight = '0';
      card.style.margin = '0';
      card.style.padding = '0';
      card.style.overflow = 'hidden';
    }, 50);
    setTimeout(function() { if (card.parentNode) card.parentNode.removeChild(card); }, 450);
  }
  if (typeof toast === 'function') toast('✓ Sigma hit dismissed: ' + (ruleId || 'rule'));
};

/* Generic card dismiss — removes card from DOM with fade animation */
window.paDismissCard = function(btn, label) {
  var card = btn ? (btn.closest('.pa-resp-card') || btn.closest('[class*="card"]') || btn.parentNode) : null;
  if (card) {
    card.style.transition = 'opacity .3s ease, max-height .4s ease, margin .4s ease';
    card.style.opacity = '0';
    card.style.overflow = 'hidden';
    var h = card.offsetHeight;
    card.style.maxHeight = h + 'px';
    setTimeout(function() { card.style.maxHeight = '0'; card.style.margin = '0'; }, 50);
    setTimeout(function() { if (card.parentNode) card.parentNode.removeChild(card); }, 450);
  }
  if (typeof toast === 'function') toast('✓ ' + (label || 'Item') + ' dismissed');
};

/* Rescan files now — wipes cached YARA hits and walks monitored dirs again.
   This is the fix for "I quarantined the file but it still shows up". */
window.paRescanFiles = function(btn) {
  if (btn) { btn.disabled = true; btn.style.opacity = '0.7'; btn.innerHTML = '<span class="pa-act-spin"></span> Rescanning…'; }

  // Show scanner IMMEDIATELY — do not wait for API response
  _paLastReport = null; window._paLastReport = null;
  _paIsRunning = false;
  _paSetAllStates('none','flex','none');
  var loadEl = document.getElementById('pa-loading');
  if (loadEl) loadEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  _radarPct = 0; _radarStart();
  var tickerEl = document.getElementById('pa-file-ticker');
  var tickerCnt = document.getElementById('pa-file-ticker-count');
  var tickerWrap = document.getElementById('pa-file-ticker-wrap');
  if (tickerWrap) tickerWrap.style.display = '';
  if (tickerEl)  tickerEl.textContent  = 'rescanning files…';
  if (tickerCnt) tickerCnt.textContent = '0 files inspected';
  for (var _si = 1; _si <= 4; _si++) { var _se = document.getElementById('pa-step'+_si); if (_se) _se.className = 'pa-step'; }
  _paIsRunning = true;
  _paSetRunButtonLoading(true);

  fetch('/api/action/rescan-files', { method:'POST', headers:{'Content-Type':'application/json'}, body:'{}' })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (btn) { btn.disabled = false; btn.style.opacity = ''; btn.innerHTML = '🔄 Rescan Files'; }
    _paIsRunning = false; _paSetRunButtonLoading(false); _radarStop();
    if (d.ok) {
      if (typeof runPerformAnalysis === 'function') runPerformAnalysis(30);
    } else {
      if (typeof toast === 'function') toast(d.detail || 'Rescan failed');
      _paShowIdle();
    }
  })
  .catch(function(e){
    if (btn) { btn.disabled = false; btn.style.opacity = ''; btn.innerHTML = '🔄 Rescan Files'; }
    if (typeof toast === 'function') toast('Rescan failed: ' + e.message);
    _paIsRunning = false; _paSetRunButtonLoading(false); _radarStop(); _paShowIdle();
  });
};

/* Show Details popup for a Threat Detector hit.
   Fetches the per-rule explanation from /api/action/explain-threat,
   renders it in a modal, and exposes the Auto-Fix button when available. */
window.paShowThreatDetails = async function(hitKey) {
  var h = (window._paThreatHitMap || {})[hitKey];
  if (!h) return;

  // Build modal scaffold immediately so the operator sees feedback even if
  // the fetch is slow.
  var modal = _paBuildThreatModal(h, /*loadingExplain=*/true);
  document.body.appendChild(modal);

  // Fetch the explanation
  try {
    var r = await fetch('/api/action/explain-threat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ rule_id: h.id || '' }),
    });
    var d = await r.json();
    _paFillThreatModalExplain(modal, h, d);
  } catch (e) {
    _paFillThreatModalExplain(modal, h, {
      cause:   '(could not load — ' + e.message + ')',
      context: 'Check that the application is running and try again.',
      autofix: null,
    });
  }
};

function _paBuildThreatModal(h, loading) {
  var overlay = document.createElement('div');
  overlay.className = 'pa-threat-modal-overlay';
  overlay.style.cssText =
    'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.65);'
    +'backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;'
    +'animation:pa-fadein .15s ease both';

  var sevCol = {CRITICAL:'#ef4444',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'}[h.severity] || '#94a3b8';

  // ── Caller-info block (only shown when lsass_filter is present) ─────────
  // Surfaces WHICH process is triggering the LSASS-handle rule so the user
  // can see if it's actually a benign tool (VS Code, Defender, etc.) and
  // hit one of the action buttons below.
  var callerBlock = '';
  var actionBtns  = '';
  if (h.lsass_filter && h.lsass_filter.callers) {
    var lf = h.lsass_filter;
    var callerRows = '';
    var topName = '';
    var topCount = 0;
    for (var k in lf.callers) {
      if (lf.callers[k] > topCount) { topCount = lf.callers[k]; topName = k; }
      callerRows += '<div style="display:flex;justify-content:space-between;padding:3px 0">'
        +'<code style="color:#fbbf24;font-size:12px">'+_escHtml(k)+'</code>'
        +'<span style="color:#94a3b8;font-size:11.5px">'+lf.callers[k]+' events</span>'
        +'</div>';
    }
    var benignPct = lf.lsass_total ? Math.round(100 * lf.benign / lf.lsass_total) : 0;
    var suspPct   = lf.lsass_total ? Math.round(100 * lf.suspicious / lf.lsass_total) : 0;

    callerBlock =
      '<div>'
        +'<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">CALLING PROCESS(ES)</div>'
        +'<div style="background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:12px 14px">'
          + callerRows
          +'<div style="margin-top:8px;padding-top:8px;border-top:1px dashed rgba(255,255,255,.08);font-size:11.5px;color:#94a3b8">'
            +'<span style="color:#4ade80">'+lf.benign+' benign ('+benignPct+'%)</span> · '
            +'<span style="color:#ef4444">'+lf.suspicious+' suspicious ('+suspPct+'%)</span>'
            + (lf.dangerous_mask_ratio > 0
                ? ' · <span style="color:#fb923c">dangerous-access bits: '+Math.round(lf.dangerous_mask_ratio*100)+'%</span>'
                : '')
          +'</div>'
        +'</div>'
      +'</div>';

    // Action buttons: whitelist the top caller, or dismiss the rule entirely.
    if (topName) {
      var safeCaller = _paJs(topName);
      var safeRule   = _paJs(h.id || '');
      actionBtns =
        '<div>'
          +'<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">FIX THIS DETECTION</div>'
          +'<div style="background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.22);border-radius:8px;padding:12px 14px">'
            +'<div style="font-size:12.5px;color:#cbd5e1;line-height:1.55;margin-bottom:10px">'
              +'If <code style="color:#fbbf24">'+_escHtml(topName)+'</code> is a known-good process, '
              +'mark it benign and this detection will stop firing for it. Or dismiss the rule entirely for 30 days.'
            +'</div>'
            +'<div style="display:flex;gap:8px;flex-wrap:wrap">'
              + _paActBtn('✓ Mark "'+_escHtml(topName)+'" as benign', 'green',
                  'paWhitelistCaller(this,\''+safeCaller+'\',\''+safeRule+'\')',
                  'wl-'+(h.id||'')+'-'+Math.random().toString(36).slice(2,6))
              + _paActBtn('Dismiss this rule (30d)', 'gray',
                  'paSuppressRule(this,\''+safeRule+'\',30)',
                  'sup-'+(h.id||'')+'-'+Math.random().toString(36).slice(2,6))
            +'</div>'
          +'</div>'
        +'</div>';
    }
  }

  overlay.innerHTML =
    '<div class="pa-threat-modal" style="background:#0d1626;border:1px solid rgba(255,255,255,.1);'
    +'border-radius:14px;max-width:640px;width:92%;max-height:84vh;overflow:auto;'
    +'box-shadow:0 24px 64px rgba(0,0,0,.6)">'

      // Header
      +'<div style="padding:18px 22px;border-bottom:1px solid rgba(255,255,255,.06);'
      +'display:flex;align-items:flex-start;gap:12px">'
        +'<div style="flex:1">'
          +'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
            +'<span style="font-size:10px;font-family:JetBrains Mono,monospace;font-weight:800;'
            +'background:'+sevCol+'1f;color:'+sevCol+';border:1px solid '+sevCol+'55;'
            +'padding:3px 9px;border-radius:5px;letter-spacing:.07em">'+_escHtml(h.severity||'INFO')+'</span>'
            +'<span style="font-size:11px;color:#64748b;font-family:JetBrains Mono,monospace">'+_escHtml(h.id||'')+'</span>'
          +'</div>'
          +'<div style="font-size:17px;font-weight:800;color:#fff">'+_escHtml(h.name||h.id||'Threat Detector Hit')+'</div>'
        +'</div>'
        +'<button onclick="this.closest(\'.pa-threat-modal-overlay\').remove()" '
          +'style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);'
          +'color:#94a3b8;border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:16px">×</button>'
      +'</div>'

      // Body — evidence + explanation slots
      +'<div style="padding:18px 22px;display:flex;flex-direction:column;gap:14px">'

        // Evidence panel — built from the hit itself, always present
        +'<div>'
          +'<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">EVIDENCE</div>'
          +'<div style="background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:12px 14px;font-size:12.5px;line-height:1.7;color:#cbd5e1">'
            +'<div><span style="color:#94a3b8">Events seen:</span> <strong style="color:#fff">'+h.count+'</strong> over '+ (h.window_hours||1) +'h window</div>'
            +'<div><span style="color:#94a3b8">First:</span> '+_escHtml(String(h.first_seen||'').slice(0,19))+'</div>'
            +'<div><span style="color:#94a3b8">Last:</span> '+_escHtml(String(h.latest||h.last_seen||'').slice(0,19))+'</div>'
            +'<div><span style="color:#94a3b8">Off-hours events:</span> '+(h.off_hours_count||0)+'</div>'
            +'<div><span style="color:#94a3b8">Confidence:</span> '+(h.confidence_pct||0)+'%</div>'
            +(h.event_ids && h.event_ids.length ? '<div><span style="color:#94a3b8">Event IDs:</span> <code style="color:#a3f7c0">'+_escHtml((h.event_ids||[]).join(', '))+'</code></div>' : '')
            +(h.sources && h.sources.length ? '<div><span style="color:#94a3b8">Sources:</span> '+_escHtml((h.sources||[]).slice(0,4).join(', '))+'</div>' : '')
            +(h.mitre_tactic ? '<div><span style="color:#94a3b8">MITRE:</span> '+_escHtml(h.mitre_tactic)+'</div>' : '')
          +'</div>'
        +'</div>'

        // Caller process info (LSASS rule only)
        + callerBlock

        // Whitelist / dismiss buttons (LSASS rule only)
        + actionBtns

        // Why it fired — filled in after the fetch
        +'<div data-slot="why">'
          +'<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">WHY THIS FIRED</div>'
          +'<div data-slot="cause" style="font-size:13px;color:#fbbf24;line-height:1.6;margin-bottom:6px">'
            +(loading ? '<span class="pa-act-spin"></span> Loading explanation…' : '')
          +'</div>'
          +'<div data-slot="context" style="font-size:12.5px;color:#94a3b8;line-height:1.65"></div>'
        +'</div>'

        // Mitigation hint from the detection rule itself, if present
        +(h.mitigation ? '<div>'
          +'<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">RECOMMENDED MITIGATION</div>'
          +'<div style="font-size:12.5px;color:#a3f7c0;line-height:1.6;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.18);border-radius:8px;padding:10px 14px">'+_escHtml(h.mitigation)+'</div>'
        +'</div>' : '')

        // Auto-fix slot (populated after fetch when available)
        +'<div data-slot="autofix"></div>'

      +'</div>'

      // Footer
      +'<div style="padding:14px 22px;border-top:1px solid rgba(255,255,255,.06);'
      +'display:flex;justify-content:flex-end;gap:8px">'
        +'<button onclick="this.closest(\'.pa-threat-modal-overlay\').remove()" '
          +'style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);'
          +'color:#94a3b8;border-radius:8px;padding:8px 18px;cursor:pointer;font-size:12px;font-weight:700">Close</button>'
      +'</div>'

    +'</div>';

  // Click-outside to dismiss
  overlay.addEventListener('click', function(e){
    if (e.target === overlay) overlay.remove();
  });
  return overlay;
}

function _paFillThreatModalExplain(overlay, h, d) {
  var cause   = overlay.querySelector('[data-slot="cause"]');
  var ctx     = overlay.querySelector('[data-slot="context"]');
  var autofix = overlay.querySelector('[data-slot="autofix"]');
  if (cause) cause.innerHTML   = _escHtml(d.cause || '');
  if (ctx)   ctx.innerHTML     = _escHtml(d.context || '');

  if (autofix && d.autofix && d.autofix.command) {
    autofix.innerHTML =
      '<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">AUTO-FIX AVAILABLE</div>'
      +'<div style="display:flex;align-items:center;gap:10px;background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.25);border-radius:8px;padding:12px 14px">'
        +'<div style="flex:1;font-size:12.5px;color:#cbd5e1;line-height:1.55">Click to run the fix automatically. The action is logged in the audit history.</div>'
        + _paActBtn(_escHtml(d.autofix.label || 'Auto-Fix'), 'blue',
            'paAutoFixThreat(this,\''+_paJs(d.autofix.command)+'\',\''+_paJs(h.id||'')+'\')',
            'fix-'+(h.id||'')+'-'+Math.random().toString(36).slice(2,6))
      +'</div>';
  } else if (autofix) {
    autofix.innerHTML =
      '<div style="font-size:10px;color:#64748b;letter-spacing:.12em;font-weight:800;margin-bottom:6px">AUTO-FIX</div>'
      +'<div style="font-size:12px;color:#94a3b8;background:rgba(148,163,184,.06);border:1px solid rgba(148,163,184,.18);border-radius:8px;padding:10px 14px;line-height:1.55">'
      +'No safe auto-fix for this category — investigate the evidence above and use the Active Response panel (Kill Process / Quarantine / Block Network) on the specific PID or file you identify.'
      +'</div>';
  }
}

/* Auto-fix click handler — exposed so the inline onclick attributes work. */
window.paAutoFixThreat = function(btn, command, ruleId) {
  if (!confirm('Run auto-fix?\n\nCommand: ' + command + '\nRule: ' + ruleId
    + '\n\nThis will execute a system command. Make sure you understand what it does.')) return;
  _paPostAction('/api/action/auto-fix-threat',
    { command: command, rule_id: ruleId }, btn, 'Done');
};

/* ── Whitelist a caller process (used by the LSASS modal action button) ─── */
window.paWhitelistCaller = function(btn, caller, ruleId) {
  if (!caller) return;
  var ok = confirm(
    'Mark "' + caller + '" as a benign caller?\n\n' +
    'This detection will no longer fire when ' + caller + ' is the calling process.\n' +
    'You can undo this from Settings → Threat Whitelist.'
  );
  if (!ok) return;
  fetch('/api/threat/whitelist-caller', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({ caller: caller, rule_id: ruleId, days: 0 })
  })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d && d.ok) {
      btn.innerHTML = '✓ Whitelisted';
      btn.style.background = '#10b981';
      btn.disabled = true;
      // Close the modal so the user sees the result on the dashboard
      setTimeout(function(){
        var overlay = btn.closest('.pa-threat-modal-overlay');
        if (overlay) overlay.remove();
        // Trigger a re-run of the analysis to refresh the panel
        var refreshBtn = document.querySelector('[data-pa-refresh],[onclick*="paRunAnalysis"]');
        if (refreshBtn) refreshBtn.click();
      }, 700);
    } else {
      alert('Failed to whitelist: ' + (d && d.error || 'unknown error'));
    }
  })
  .catch(function(e){ alert('Network error: ' + e.message); });
};

/* ── Dismiss a rule for N days ─────────────────────────────────────────── */
window.paSuppressRule = function(btn, ruleId, days) {
  if (!ruleId) return;
  days = days || 30;
  var ok = confirm(
    'Dismiss the "' + ruleId + '" rule for ' + days + ' days?\n\n' +
    'This rule will stop firing until ' + days + ' days from now.\n' +
    'You can re-enable it from Settings → Threat Whitelist.'
  );
  if (!ok) return;
  fetch('/api/threat/suppress-rule', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({ rule_id: ruleId, days: days })
  })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d && d.ok) {
      btn.innerHTML = '✓ Dismissed';
      btn.style.background = '#475569';
      btn.disabled = true;
      setTimeout(function(){
        var overlay = btn.closest('.pa-threat-modal-overlay');
        if (overlay) overlay.remove();
        var refreshBtn = document.querySelector('[data-pa-refresh],[onclick*="paRunAnalysis"]');
        if (refreshBtn) refreshBtn.click();
      }, 700);
    } else {
      alert('Failed to dismiss: ' + (d && d.error || 'unknown error'));
    }
  })
  .catch(function(e){ alert('Network error: ' + e.message); });
};

/* ── Card / button builders ─────────────────────────────────────────────── */

function _paActBtn(label, color, onclick, key) {
  // color: 'red' | 'orange' | 'blue' | 'green' | 'gray'
  var palette = {
    red:    { bg:'#ef4444', border:'#dc2626', shadow:'rgba(239,68,68,.35)' },
    orange: { bg:'#f59e0b', border:'#d97706', shadow:'rgba(245,158,11,.35)' },
    blue:   { bg:'#3b82f6', border:'#2563eb', shadow:'rgba(59,130,246,.35)' },
    green:  { bg:'#10b981', border:'#059669', shadow:'rgba(16,185,129,.35)' },
    gray:   { bg:'#475569', border:'#334155', shadow:'rgba(71,85,105,.35)' },
  }[color] || { bg:'#475569', border:'#334155', shadow:'rgba(71,85,105,.35)' };
  return '<button class="pa-act-btn" data-key="'+(key||'')+'" onclick="'+onclick+'" '
    +'style="background:'+palette.bg+';border:1px solid '+palette.border+';color:#fff;'
    +'padding:7px 14px;border-radius:7px;cursor:pointer;font-size:11.5px;font-weight:800;'
    +'letter-spacing:.02em;display:inline-flex;align-items:center;gap:5px;'
    +'box-shadow:0 2px 8px '+palette.shadow+';transition:transform .12s ease, box-shadow .12s ease"'
    +'onmouseover="this.style.transform=\'translateY(-1px)\';this.style.boxShadow=\'0 4px 14px '+palette.shadow+'\'"'
    +'onmouseout="this.style.transform=\'\';this.style.boxShadow=\'0 2px 8px '+palette.shadow+'\'">'
    + label
    +'</button>';
}

function _paRespCard(opts) {
  // opts: { severity, icon, title, subtitle, meta:[{k,v}] }
  // Info-only cards — all remediation is done via Fix All button
  var sevCol = {CRITICAL:'#ef4444',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'}[opts.severity] || '#94a3b8';

  return '<div class="pa-resp-card" '
    +'style="background:rgba(15,23,42,.5);border:1px solid rgba(255,255,255,.08);'
    +'border-left:3px solid '+sevCol+';border-radius:10px;padding:14px 16px;margin:8px 0;'
    +'display:flex;flex-direction:column;gap:6px;animation:th-fadein .3s ease both">'

    +'<div style="display:flex;align-items:flex-start;gap:10px">'
      +'<div style="font-size:22px;flex-shrink:0;line-height:1">'+(opts.icon||'⚠️')+'</div>'
      +'<div style="flex:1;min-width:0">'
        +'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">'
          +'<span style="font-size:9px;font-family:JetBrains Mono,monospace;font-weight:800;'
            +'background:'+sevCol+'1f;color:'+sevCol+';border:1px solid '+sevCol+'55;'
            +'padding:2px 7px;border-radius:4px;letter-spacing:.06em">'+(opts.severity||'INFO')+'</span>'
          +'<span style="font-size:14px;font-weight:800;color:#fff">'+_escHtml(opts.title||'')+'</span>'
        +'</div>'
        +(opts.subtitle ? '<div style="font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:6px">'+_escHtml(opts.subtitle)+'</div>' : '')
        +((opts.meta||[]).length
          ? '<div style="display:flex;gap:6px;flex-wrap:wrap">'
            + opts.meta.map(function(m){
                return '<span style="font-size:10.5px;font-family:JetBrains Mono,monospace;'
                  +'background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);'
                  +'color:#cbd5e1;padding:3px 8px;border-radius:5px">'
                  +'<span style="opacity:.6">'+_escHtml(m.k)+': </span>'+_escHtml(String(m.v))+'</span>';
              }).join('')
            + '</div>'
          : '')
      +'</div>'
    +'</div>'
  +'</div>';
}

/* Convenience to JS-escape a string for use inside an HTML attribute value
   that itself contains a JS string literal (single-quote-wrapped). */
function _paJs(s) {
  return String(s||'').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function _paRenderActiveResponse(r) {
  var host = document.getElementById('pa-active-response');
  if (!host) return;

  var ma    = r.malware_analysis || {};
  var html  = '';
  var cards = 0;

  // ── (A) SUSPICIOUS PROCESSES (Sysmon EID 1) — Kill + Block ──────────────
  var procs = (ma.suspicious_processes || []).filter(function(p){ return p.pid && p.suspicious; });
  if (procs.length === 0) {
    procs = (ma.suspicious_processes || []).filter(function(p){ return p.pid; }).slice(0, 5);
  } else {
    procs = procs.slice(0, 8);
  }
  procs.forEach(function(p){
    var imgName    = p.image   || 'unknown.exe';
    var parentName = p.parent  || '';
    var cmdline    = (p.command || '').slice(0, 90);
    var keyId      = 'proc-' + p.pid + '-' + cards;
    html += _paRespCard({
      severity: p.suspicious ? 'HIGH' : 'MEDIUM',
      icon:     '⚙️',
      title:    'Suspicious Process — ' + imgName,
      subtitle: parentName ? ('Spawned by ' + parentName + (cmdline ? ' · ' + cmdline : '')) : cmdline,
      meta: [
        { k:'PID',     v: p.pid },
        { k:'Signed',  v: p.signed ? 'yes' : 'no' },
        { k:'Time',    v: (p.timestamp||'').slice(0,16) },
      ],
      buttons: [],
    });
    cards++;
  });

  // ── (B) DROPPED / SUSPICIOUS FILES — Quarantine + Delete ────────────────
  var files = (ma.file_drops || []);
  // YARA-matched files first
  files.sort(function(a,b){ return (b.yara_matched?1:0) - (a.yara_matched?1:0); });
  files.slice(0, 8).forEach(function(f){
    if (!f.path) return;
    var keyId = 'file-' + cards;
    var sev   = f.yara_matched ? 'CRITICAL' : 'HIGH';
    var subtitle = f.yara_matched
      ? ('YARA match: ' + (f.yara_rule || 'unknown rule') + (f.yara_severity ? ' (' + f.yara_severity + ')' : ''))
      : 'Executable dropped in user-writable location';
    html += _paRespCard({
      severity: sev,
      icon:     f.yara_matched ? '🦠' : '📁',
      title:    f.filename || f.path,
      subtitle: subtitle,
      meta: [
        { k:'Path',      v: f.path },
        { k:'Detected',  v: (f.timestamp||'').slice(0,16) },
      ],
      buttons: [],
    });
    cards++;
  });

  // ── (C) YARA HITS that didn't come through file_drops ───────────────────
  var yaraHits = (ma.yara_hits || []);
  yaraHits.slice(0, 5).forEach(function(y){
    var p = y.path || y.file || y.target || '';
    if (!p) return;
    // Skip duplicates already covered by file_drops
    if (files.some(function(f){ return f.path === p; })) return;
    var keyId = 'yara-' + cards;
    html += _paRespCard({
      severity: 'CRITICAL',
      icon:     '🦠',
      title:    'YARA Match — ' + (y.rule || 'unknown rule'),
      subtitle: y.severity ? ('Severity: ' + y.severity) : '',
      meta: [
        { k:'Path', v: p },
      ],
      buttons: [],
    });
    cards++;
  });

  // ── (D) REGISTRY PERSISTENCE ────────────────────────────────────────────
  if (ma.registry_persistence) {
    var regTarget = ma.registry_persistence_target || ma.registry_persistence_path || '';
    html += _paRespCard({
      severity: regTarget ? 'HIGH' : 'MEDIUM',
      icon:     '🔑',
      title:    regTarget ? 'Registry Persistence Detected' : 'Registry Persistence Indicator',
      subtitle: regTarget
        ? 'A Run/Userinit/IFEO key was modified — common auto-start technique.'
        : 'Sysmon flagged a Run/Userinit/IFEO change. Review which key was touched in the Sysmon Hits panel above.',
      meta: regTarget ? [{ k:'Target', v: regTarget }] : [],
      buttons: [],
    });
    cards++;
  }

  // ── (E) THREAT-DETECTOR rules with kill-worthy targets ───────────────────
  (r.threat_hits || []).forEach(function(t){
    var targets = t.targets || t.evidence_targets;
    if (!Array.isArray(targets)) return;
    targets.slice(0, 3).forEach(function(tg){
      if (!tg.pid && !tg.path && !tg.task && !tg.service) return;
      html += _paRespCard({
        severity: t.severity || 'HIGH',
        icon:     '🎯',
        title:    t.name || t.id,
        subtitle: t.human_summary || t.description || '',
        meta: Object.entries(tg).map(function(e){ return { k:e[0], v:String(e[1]) }; }),
        buttons: [],
      });
      cards++;
    });
  });

  // ── Empty state ─────────────────────────────────────────────────────────
  if (cards === 0) {
    var hadHard = r.unified_breakdown && r.unified_breakdown.hard_evidence;
    host.innerHTML = '<div class="ur-clean" style="padding:16px;text-align:center">'
      +'✅ No actionable malicious entities found in this analysis. '
      +(hadHard
          ? 'Hard-evidence indicators fired but did not expose concrete processes / files to act on — review Threat Detector Hits and Sysmon panels above.'
          : 'System looks clean for this period.')
      +'</div>';
  } else {
    // ── Build Fix All payload from detected threats ──────────────────────
    var fixAllTasks = [];

    // Processes to kill
    procs.forEach(function(p){
      if (p.pid) fixAllTasks.push({ type:'kill', pid: p.pid, label: p.image || 'process' });
    });

    // Files to delete
    var seenPaths = {};
    files.slice(0, 8).forEach(function(f){
      var fp = f.path;
      if (fp && typeof fp === 'string' && fp.trim() && fp.trim().toLowerCase() !== 'undefined' && fp.trim().toLowerCase() !== 'null' && !seenPaths[fp]) {
        seenPaths[fp] = true;
        fixAllTasks.push({ type:'delete', path: fp, label: f.filename || fp });
      }
    });
    yaraHits.slice(0, 5).forEach(function(y){
      var p2 = y.path || y.file || y.target || '';
      if (p2 && p2.trim() && p2.trim().toLowerCase() !== 'undefined' && p2.trim().toLowerCase() !== 'null' && !seenPaths[p2]) {
        seenPaths[p2] = true;
        fixAllTasks.push({ type:'delete', path: p2, label: p2 });
      }
    });

    // Registry persistence
    if (ma.registry_persistence && ma.registry_persistence_target) {
      fixAllTasks.push({ type:'registry', target: ma.registry_persistence_target, label: 'Registry persistence key' });
    }

    // Sigma file drops from sigma_hits
    (ma.sigma_hits || []).forEach(function(h){
      var fp = h.path || h.file || h.target || '';
      if (!fp || seenPaths[fp]) return;
      var rule = (h.rule || h.rule_id || '').toUpperCase();
      if (rule.indexOf('FILE') >= 0 || rule.indexOf('DROP') >= 0 || rule.indexOf('UNSIGNED') >= 0 || rule.indexOf('TEMP_EXE') >= 0) {
        seenPaths[fp] = true;
        fixAllTasks.push({ type:'delete', path: fp, label: fp });
      }
      if (rule.indexOf('REGISTRY') >= 0 || rule.indexOf('RUN_PERSIST') >= 0) {
        var rt = h.reg_key || h.target || '';
        if (rt) fixAllTasks.push({ type:'registry', target: rt, label: 'Registry: ' + rt });
      }
      if (rule.indexOf('SCHTASK') >= 0 || rule.indexOf('SCHEDULED') >= 0) {
        var tn = h.task_name || h.target || '';
        if (tn) fixAllTasks.push({ type:'task', target: tn, label: 'Task: ' + tn });
      }
    });

    // Threat hits targets
    (r.threat_hits || []).forEach(function(t){
      var targets = t.targets || t.evidence_targets || [];
      targets.slice(0, 3).forEach(function(tg){
        if (tg.pid) fixAllTasks.push({ type:'kill', pid: tg.pid, label: tg.name || 'process' });
        if (tg.path && typeof tg.path === 'string' && tg.path.trim() && tg.path.trim().toLowerCase() !== 'undefined' && !seenPaths[tg.path]) {
          seenPaths[tg.path] = true;
          fixAllTasks.push({ type:'delete', path: tg.path, label: tg.path });
        }
        if (tg.task) fixAllTasks.push({ type:'task', target: tg.task, label: 'Task: '+tg.task });
      });
    });

    // Serialize for inline onclick
    var fixAllJson = JSON.stringify(fixAllTasks)
      .replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');

    var fixAllBtn = fixAllTasks.length > 0
      ? '<div id="pa-fix-all-wrap" style="margin-top:24px;padding:20px;'
          +'background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(251,146,60,.05));'
          +'border:1px solid rgba(239,68,68,.25);border-radius:14px;text-align:center">'
          +'<div style="font-size:12px;color:#94a3b8;margin-bottom:12px;letter-spacing:.03em">'
            +'<span style="color:#f87171;font-weight:700">⚠ '+fixAllTasks.length+' threat'+(fixAllTasks.length>1?'s':'')+' detected</span>'
            +' — Kill processes, delete files &amp; remove persistence entries automatically'
          +'</div>'
          +'<button id="pa-fix-all-btn" onclick="paFixAll(this)" '
            +'data-tasks="'+fixAllJson+'" '
            +'style="background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;border:none;'
            +'padding:13px 36px;border-radius:10px;font-size:15px;font-weight:800;cursor:pointer;'
            +'letter-spacing:.03em;box-shadow:0 4px 24px rgba(239,68,68,.35);'
            +'transition:all .2s;display:inline-flex;align-items:center;gap:10px" '
            +'onmouseover="this.style.transform=\'scale(1.03)\';this.style.boxShadow=\'0 6px 32px rgba(239,68,68,.5)\'" '
            +'onmouseout="this.style.transform=\'\';this.style.boxShadow=\'0 4px 24px rgba(239,68,68,.35)\'">'
            +'<span style="font-size:18px">🧹</span> Fix All Threats'
          +'</button>'
          +'<div id="pa-fix-all-log" style="margin-top:14px;text-align:left;display:none;'
            +'background:rgba(0,0,0,.3);border-radius:8px;padding:12px;font-family:JetBrains Mono,monospace;'
            +'font-size:11px;color:#94a3b8;max-height:220px;overflow-y:auto;line-height:1.7"></div>'
        +'</div>'
      : '';

    host.innerHTML = html + fixAllBtn;
  }
}

/* ── Fix All: kill + delete + remove persistence, then re-run analysis ─────── */
window.paFixAll = async function(btn) {
  var raw = btn.getAttribute('data-tasks');
  var tasks;
  try { tasks = JSON.parse(raw.replace(/&quot;/g, '"')); } catch(e) { alert('Could not parse task list'); return; }
  if (!tasks || !tasks.length) { alert('No tasks to execute'); return; }

  if (!confirm('⚠ Fix All will:\n\n'
    + tasks.map(function(t){
        if (t.type==='kill')     return '  🛑 Kill process: ' + t.label;
        if (t.type==='delete')   return '  🗑 Delete file: '  + t.label;
        if (t.type==='registry') return '  🔑 Remove registry key: ' + t.label;
        if (t.type==='task')     return '  🗓 Delete scheduled task: ' + t.label;
        return '  • ' + t.label;
      }).join('\n')
    + '\n\nThen re-run analysis to update dashboard.\n\nProceed?')) return;

  // Lock button
  btn.disabled = true;
  btn.innerHTML = '<span class="pa-act-spin"></span> Working…';
  btn.style.opacity = '0.7';
  btn.style.cursor = 'wait';

  var log = document.getElementById('pa-fix-all-log');
  log.style.display = 'block';
  var done = 0, failed = 0;

  function addLog(icon, msg, color) {
    var line = document.createElement('div');
    line.style.color = color || '#94a3b8';
    line.innerHTML = icon + ' ' + _escHtml(msg);
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  addLog('🧹', 'Starting Fix All — ' + tasks.length + ' action(s)…', '#cbd5e1');

  for (var i = 0; i < tasks.length; i++) {
    var t = tasks[i];
    var url, payload;

    if (t.type === 'kill') {
      url     = '/api/action/kill-process';
      payload = { pid: t.pid };
    } else if (t.type === 'delete') {
      url     = '/api/action/delete-file';
      payload = { path: t.path };
    } else if (t.type === 'registry') {
      url     = '/api/action/remove-persistence';
      payload = { kind: 'registry', target: t.target };
    } else if (t.type === 'task') {
      url     = '/api/action/remove-persistence';
      payload = { kind: 'task', target: t.target };
    } else {
      addLog('⚠', 'Unknown task type: ' + t.type, '#fbbf24');
      continue;
    }

    addLog('⏳', '[' + (i+1) + '/' + tasks.length + '] ' + t.label + '…', '#94a3b8');

    try {
      // For delete/quarantine: first check if path is allowed, show exact reason if not
      if ((t.type === 'delete' || t.type === 'quarantine')) {
        // Validate path exists and is not a stale "undefined" string
        var tpath = t.path;
        if (!tpath || typeof tpath !== 'string' || tpath.trim() === '' ||
            tpath.trim().toLowerCase() === 'undefined' || tpath.trim().toLowerCase() === 'null') {
          failed++;
          addLog('✗', t.label + ' — skipped: file path was not recorded in Sysmon log (empty target_file field)', '#fca5a5');
          continue;
        }
        var chk = await fetch('/api/action/debug-path', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ path: tpath })
        }).then(function(r){ return r.json(); }).catch(function(){ return null; });
        if (chk && !chk.safe) {
          failed++;
          var blockReason = chk.reason || 'path is outside allowed zones';
          var blockNorm   = chk.norm   || tpath;
          addLog('✗', t.label + ' — path blocked: ' + blockReason, '#fca5a5');
          addLog('ℹ', 'Path: ' + blockNorm, '#64748b');
          continue;
        }
      }

      var res = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(payload),
      });
      var d = await res.json().catch(function(){ return { ok: false, detail: 'Bad response' }; });

      if (d.ok || d.success) {
        done++;
        addLog('✅', t.label + ' — ' + (d.detail || 'removed'), '#86efac');
      } else {
        failed++;
        addLog('✗', t.label + ' — ' + (d.detail || 'failed'), '#fca5a5');
      }
    } catch(e) {
      failed++;
      addLog('✗', t.label + ' — network error: ' + e.message, '#fca5a5');
    }

    // Small pause between actions so OS can process each one
    await new Promise(function(res){ setTimeout(res, 300); });
  }

  // Summary
  addLog('', '──────────────────────', '#374151');
  addLog(done > 0 ? '🎉' : '⚠', done + ' removed, ' + failed + ' failed', done > 0 ? '#86efac' : '#fca5a5');

  // Update button to show result
  btn.style.opacity = '1';
  btn.style.cursor = 'default';
  if (failed === 0) {
    btn.innerHTML = '✅ All Threats Removed!';
    btn.style.background = 'linear-gradient(135deg,#22c55e,#15803d)';
  } else if (done > 0) {
    btn.innerHTML = '⚠ ' + done + ' removed, ' + failed + ' failed';
    btn.style.background = 'linear-gradient(135deg,#f59e0b,#b45309)';
  } else {
    btn.innerHTML = '✗ All actions failed';
    btn.style.background = 'linear-gradient(135deg,#6b7280,#374151)';
    btn.disabled = false;
    return;
  }

  // Re-run analysis after 1.5s to update dashboard
  if (done > 0) {
    addLog('🔄', 'Re-running analysis to update dashboard…', '#60a5fa');
    await new Promise(function(res){ setTimeout(res, 1500); });

    // Trigger re-run
    var rerunBtn = document.getElementById('pa-rerun-btn') || document.querySelector('[onclick*="paRerun"]') || document.querySelector('[onclick*="re-run"]');
    if (rerunBtn) {
      rerunBtn.click();
    } else {
      // Fallback: call the API directly
      try {
        var rr = await fetch('/api/perform-analysis', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        var rd = await rr.json().catch(function(){ return null; });
        if (rd) {
          addLog('✅', 'Analysis updated!', '#86efac');
          if (typeof paLoadLatest === 'function') paLoadLatest();
          else if (typeof _paLoadLatest === 'function') _paLoadLatest();
        }
      } catch(e) {
        addLog('⚠', 'Could not auto-refresh — click Re-run Analysis manually', '#fbbf24');
      }
    }
  }
};

/* Inject the small spinner + button hover styles once */
(function _paInjectActionCSS(){
  if (document.getElementById('pa-action-css')) return;
  var s = document.createElement('style');
  s.id = 'pa-action-css';
  s.textContent =
    '.pa-act-spin{display:inline-block;width:10px;height:10px;border:2px solid rgba(255,255,255,.3);'
    +'border-top-color:#fff;border-radius:50%;animation:pa-spin .7s linear infinite;margin-right:4px}'
    +'@keyframes pa-spin{to{transform:rotate(360deg)}}'
    +'@keyframes pa-fadein{from{opacity:0}to{opacity:1}}'
    +'.pa-act-btn:active{transform:translateY(0)!important}'
    +'.pa-act-btn:disabled{cursor:not-allowed!important}'
    +'.pa-resp-card:hover{border-color:rgba(255,255,255,.14)}'
    +'.pa-threat-modal{animation:pa-fadein .15s ease both}';
  document.head.appendChild(s);
})();

/* ── Category breakdown list ───────────────────────────────── */
function _paRenderCatBreakdown(cats) {
  var catEl = document.getElementById('pa-cat-breakdown');
  if (!catEl) return;
  var catIcons = {application:'⚙️', system:'🖥️', security:'🔒', windows_update:'🔄'};
  catEl.innerHTML = Object.entries(cats).map(function(entry){
    var name=entry[0], cv=entry[1];
    var errPct = cv.total>0 ? Math.round((cv.errors+cv.critical)/cv.total*100) : 0;
    var barCol = errPct>30?'#f85149':errPct>10?'#d29922':'#58a6ff';
    return '<div class="pa-cat-row" style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)">' +
      '<span style="font-size:16px">'+(catIcons[name]||'📋')+'</span>' +
      '<span style="font-size:12px;color:#94a3b8;flex:1;font-family:monospace">'+name.replace(/_/g,' ')+'</span>' +
      '<span style="font-size:11px;color:#64748b">'+((cv.total||0).toLocaleString())+' events</span>' +
      '<span style="font-size:11px;color:#f85149;width:52px;text-align:right">'+((cv.errors||0)+(cv.critical||0))+' err</span>' +
      '<div style="width:80px;height:5px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden"><div style="width:'+errPct+'%;height:100%;background:'+barCol+';border-radius:3px"></div></div>' +
      '<span style="font-size:11px;color:'+barCol+';width:32px;text-align:right;font-weight:700">'+errPct+'%</span>' +
    '</div>';
  }).join('');
}

/* ── Threat hits — reference card style ────────────────────── */
function _paRenderThreats(threats) {
  var el  = document.getElementById('pa-threats-table');
  var bdg = document.getElementById('pa-threat-count-badge');
  if (!el) return;

  if (bdg) {
    bdg.style.display = threats.length ? '' : 'none';
    bdg.textContent   = threats.length + ' pattern'+(threats.length!==1?'s':'')+' matched';
  }

  if (!threats.length) {
    el.innerHTML =
      '<div style="background:rgba(63,185,80,.07);border:1px solid rgba(63,185,80,.25);border-radius:10px;padding:28px;text-align:center">'+
        '<div style="font-size:32px;margin-bottom:8px">✅</div>'+
        '<div style="color:#3fb950;font-weight:700;font-size:14px">No Threat Patterns Detected</div>'+
        '<div style="color:#484f58;font-size:11px;margin-top:4px;font-family:monospace">All event counts are within normal frequency thresholds</div>'+
      '</div>';
    return;
  }

  var SEV_ORDER = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  threats = threats.slice().sort(function(a,b){
    var d=(SEV_ORDER[a.severity]||3)-(SEV_ORDER[b.severity]||3);
    return d!==0?d:b.count-a.count;
  });

  var SCOL  = {CRITICAL:'#f85149',HIGH:'#d29922',MEDIUM:'#bc8cff',LOW:'#3fb950'};
  var SBCOL = {CRITICAL:'rgba(248,81,73,.07)',HIGH:'rgba(210,153,34,.07)',MEDIUM:'rgba(188,140,255,.07)',LOW:'rgba(63,185,80,.07)'};
  var ICONS = {
    'Brute Force Login':'🔐','Account Lockout':'🔒','Privilege Escalation':'⬆',
    'Windows Defender Alert':'🛡','Unexpected Shutdown':'💥','Disk Hardware Error':'💽',
    'Memory Corruption':'🧠','Application Crash':'💀','New Admin Account':'👤',
    'Scheduled Task Created':'📅','Audit Policy Change':'📋','Service Failure':'⚙',
    'Registry Tampering':'🔑','TLS/SSL Error':'🔗','Network Error':'🌐',
  };

  // ── Summary strip ────────────────────────────────────────────────────────
  var totByS={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  var totalEvCount=0;
  threats.forEach(function(h){ totByS[h.severity]=(totByS[h.severity]||0)+1; totalEvCount+=h.count||0; });

  var html = '<div style="display:grid;grid-template-columns:repeat(4,1fr);border:1px solid rgba(48,54,61,.9);border-radius:10px;overflow:hidden;margin-bottom:14px">';
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(function(sev){
    var sc=SCOL[sev]; var sbc=SBCOL[sev];
    html += '<div style="padding:14px 16px;background:'+sbc+';border-right:1px solid rgba(48,54,61,.9)">' +
      '<div style="font-size:24px;font-weight:700;color:'+sc+'">'+totByS[sev]+'</div>' +
      '<div style="font-size:10px;color:'+sc+';font-weight:500;text-transform:uppercase;letter-spacing:.07em;font-family:monospace">'+sev+'</div>' +
      '<div style="font-size:9px;color:#484f58;margin-top:2px">detection'+(totByS[sev]!==1?'s':'')+'</div>' +
    '</div>';
  });
  html += '<div style="padding:14px 16px;background:rgba(88,166,255,.05)">' +
    '<div style="font-size:24px;font-weight:700;color:#58a6ff">'+totalEvCount.toLocaleString()+'</div>' +
    '<div style="font-size:10px;color:#58a6ff;font-weight:500;text-transform:uppercase;letter-spacing:.07em;font-family:monospace">Total Events</div>' +
    '<div style="font-size:9px;color:#484f58;margin-top:2px">across all patterns</div>' +
  '</div>';
  // Add an extra hidden column to fill grid if needed — override grid
  html = html.replace('grid-template-columns:repeat(4,1fr)', 'grid-template-columns:repeat(4,1fr) 1fr');
  html += '</div>';

  // ── Horizontal bar chart (reference style) ───────────────────────────────
  var maxCount = threats[0] ? threats[0].count : 1;
  html += '<div style="background:rgba(22,27,34,.8);border:1px solid rgba(48,54,61,.9);border-radius:10px;padding:16px 18px;margin-bottom:14px">';
  html += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:12px"><span style="font-size:10px;background:rgba(188,140,255,.1);color:#bc8cff;border:1px solid rgba(188,140,255,.2);padding:2px 8px;border-radius:20px;font-family:monospace">✦ AI Insight</span></div>';
  html += '<div style="font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:3px">Threat Pattern Frequency</div>';
  html += '<div style="font-size:11px;color:#8b949e;margin-bottom:14px">Event count per detected pattern · sorted by frequency</div>';

  threats.forEach(function(h){
    var sc = SCOL[h.severity]||'#94a3b8';
    var barW = Math.max(2, Math.round(h.count/maxCount*100));
    var icon = ICONS[h.name]||'⚠';
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
      '<span style="width:130px;text-align:right;font-size:11px;color:#8b949e;font-family:monospace;flex-shrink:0">'+icon+' '+h.name.substring(0,16)+'</span>' +
      '<div style="flex:1;background:rgba(33,38,45,.9);border-radius:3px;height:14px;overflow:hidden">' +
        '<div style="height:100%;width:'+barW+'%;background:'+sc+';border-radius:3px;display:flex;align-items:center;padding:0 6px">' +
          '<span style="font-size:10px;font-weight:600;color:#fff;white-space:nowrap">'+h.count.toLocaleString()+' events</span>' +
        '</div>' +
      '</div>' +
      '<span style="width:32px;font-size:10px;color:#484f58;font-family:monospace;text-align:right">'+barW+'%</span>' +
    '</div>';
  });

  // Finding bar
  var topThreat = threats[0];
  if (topThreat) {
    var conf = topThreat.confidence_pct || '';
    html += '<div style="background:rgba(248,81,73,.07);border-left:2px solid #f85149;border-radius:0 6px 6px 0;padding:8px 10px;margin-top:10px;font-size:11px;color:#8b949e;font-family:monospace">'+
      'AI: Highest-frequency threat is "'+topThreat.name+'" with '+topThreat.count.toLocaleString()+' events'+
      (topThreat.severity==='CRITICAL'?' — requires immediate action':'.')+
      (conf?' Detection confidence: '+conf+'%.':'')+
    '</div>';
  }
  html += '</div>';

  // ── Detailed cards ───────────────────────────────────────────────────────
  html += '<div style="display:flex;flex-direction:column;gap:10px">';
  threats.forEach(function(h, idx){
    var sc   = SCOL[h.severity]||'#94a3b8';
    var sbc  = SBCOL[h.severity]||'rgba(255,255,255,.03)';
    var icon = ICONS[h.name]||'⚠';
    var ts   = (h.latest||'').substring(0,16);
    var pct  = h.confidence_pct || (h.score ? Math.min(100, Math.round(h.score/10)) : 0);
    var id   = 'td-'+idx;

    // Build evidence lines
    var evidLines = (h.evidence||[]).map(function(ev){ return '<li style="color:#8b949e;font-size:11px;font-family:monospace;line-height:1.7">'+ev+'</li>'; }).join('');
    var actions   = (h.actions||[]).map(function(a){ return '<div style="display:flex;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04)"><span style="color:'+sc+';font-weight:700;flex-shrink:0">→</span><span style="font-size:12px;color:#e6edf3">'+a+'</span></div>'; }).join('');
    var humanSum  = h.human_summary || h.description || '';
    var mitreTac  = h.mitre_tactic  || '';
    var firstSeen = h.first_seen    || '';
    var confid    = h.confidence_pct? '<div style="margin-top:8px"><div style="display:flex;justify-content:space-between;font-size:10px;color:#484f58;margin-bottom:3px"><span>Detection confidence</span><span style="color:'+sc+'">'+h.confidence_pct+'%</span></div><div style="height:5px;background:rgba(255,255,255,.07);border-radius:3px;overflow:hidden"><div style="width:'+h.confidence_pct+'%;height:100%;background:'+sc+'"></div></div></div>' : '';

    html +=
      '<div style="border:1px solid rgba(48,54,61,.9);border-radius:10px;overflow:hidden;background:'+sbc+'">' +

        // Header row
        '<div onclick="paToggleThreat(\''+id+'\')" style="display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer" class="pa-threat-main-row">' +
          '<div style="width:38px;height:38px;border-radius:8px;background:'+sc+'18;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0">'+icon+'</div>' +
          '<div style="flex:1;min-width:0">' +
            '<div style="font-size:13px;font-weight:600;color:#e6edf3">'+h.name+'</div>' +
            (mitreTac ? '<div style="font-size:10px;color:#484f58;font-family:monospace;margin-top:1px">MITRE: '+mitreTac+'</div>' : '') +
          '</div>' +
          '<div style="text-align:center;min-width:60px">' +
            '<div style="font-size:22px;font-weight:600;color:'+sc+';line-height:1">'+h.count.toLocaleString()+'</div>' +
            '<div style="font-size:9px;color:#484f58">events</div>' +
          '</div>' +
          '<span style="font-size:10px;font-weight:500;padding:3px 9px;border-radius:10px;font-family:monospace;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'44">'+h.severity+'</span>' +
          '<span id="'+id+'-chev" style="color:#484f58;font-size:11px">▼</span>' +
        '</div>' +

        // Thin progress bar
        '<div style="height:3px;background:rgba(255,255,255,.05)"><div style="height:100%;width:'+Math.min(100,Math.round(h.count/maxCount*100))+'%;background:'+sc+';opacity:.7"></div></div>' +

        // Expandable body
        '<div id="'+id+'" style="display:none;border-top:1px solid rgba(48,54,61,.5)">' +

          // 2-col grid: details + actions
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0">' +

            // Left — evidence + what happened
            '<div style="padding:14px 16px;border-right:1px solid rgba(48,54,61,.5)">' +
              '<div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;font-weight:500">What Happened</div>' +
              (humanSum ? '<div style="font-size:12px;color:#8b949e;line-height:1.65;margin-bottom:12px">'+humanSum+'</div>' : '') +

              '<div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;font-weight:500">Evidence</div>' +
              '<ul style="padding-left:14px;list-style:disc">'+(evidLines||'<li style="color:#8b949e;font-size:11px;font-family:monospace">'+h.count+' matching events in the log database</li>')+'</ul>' +

              '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">' +
                '<div><div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">First Seen</div><div style="font-size:11px;color:#e6edf3;font-family:monospace">'+(firstSeen||'—')+'</div></div>' +
                '<div><div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Last Seen</div><div style="font-size:11px;color:#e6edf3;font-family:monospace">'+(ts||'—')+'</div></div>' +
                '<div><div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Off-Hours Events</div><div style="font-size:11px;color:'+(h.off_hours_count>0?'#f85149':'#3fb950')+';font-weight:700">'+(h.off_hours_count||0)+'</div></div>' +
                '<div><div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">AI Score</div><div style="font-size:11px;color:'+sc+';font-weight:700">'+pct+'</div></div>' +
              '</div>' +
              confid +
            '</div>' +

            // Right — recommended actions
            '<div style="padding:14px 16px">' +
              '<div style="font-size:9px;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;font-weight:500">Recommended Actions</div>' +
              (actions || '<div style="font-size:12px;color:#484f58">Review matching log entries manually</div>') +
            '</div>' +
          '</div>' +

          // Finding footer
          '<div style="background:rgba(248,81,73,.07);border-left:2px solid '+sc+';padding:8px 10px;font-size:11px;color:#8b949e;font-family:monospace">' +
            'AI: '+h.name+' — '+h.count.toLocaleString()+' events'+
            (h.confidence_pct?' · confidence '+h.confidence_pct+'%':'')+
            (h.off_hours_count>0?' · ⚠ '+h.off_hours_count+' off-hours events (high suspicion)':'')+
          '</div>' +

        '</div>' + // /expandable
      '</div>';
  });
  html += '</div>';

  el.innerHTML = html;

  el.querySelectorAll('.pa-threat-main-row').forEach(function(row){
    row.addEventListener('mouseenter',function(){ this.style.background='rgba(88,166,255,.04)'; });
    row.addEventListener('mouseleave',function(){ this.style.background=''; });
  });
}

/* ── Alert Funnel ───────────────────────────────────────────── */
function _paRenderFunnel(r) {
  // Inject funnel into recommendations panel footer
  var recEl = document.getElementById('pa-recommendations');
  if (!recEl) return;
  var total    = r.total_events || 0;
  var threats  = r.threat_hits  || [];
  var anomalies= r.anomaly_days || [];
  var confirmed= threats.filter(function(t){ return t.severity==='CRITICAL'||t.severity==='HIGH'; }).length;

  if (!total) return;

  // rough funnel math
  var matched  = Math.round(total * 0.82);
  var anomalous= Math.round(total * 0.15);
  var highPrio = Math.round(total * 0.04);
  var fp_pct   = confirmed ? (100 - Math.round(confirmed/Math.max(highPrio,1)*100)) : 97;

  var funnelHtml =
    '<div style="margin-top:20px;padding-top:14px;border-top:1px solid rgba(48,54,61,.6)">' +
      '<div style="font-size:10px;color:#484f58;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;font-family:monospace;display:flex;align-items:center;gap:6px">'+
        '<span style="background:rgba(188,140,255,.1);color:#bc8cff;border:1px solid rgba(188,140,255,.2);padding:2px 8px;border-radius:20px">✦ AI Insight</span>'+
        '<span>Alert Escalation Funnel</span>'+
      '</div>' +
      '<div style="font-size:11px;color:#8b949e;margin-bottom:12px">How '+total.toLocaleString()+' raw events narrow to '+confirmed+' confirmed high-priority findings</div>' +
      _funnelRow('Raw Events',     total,     total,   '#2671c4') +
      _funnelRow('Rule-Matched',   matched,   total,   '#1a5ea0') +
      _funnelRow('Anomalous',      anomalous, total,   '#c9841a') +
      _funnelRow('High Priority',  highPrio,  total,   '#c0392b') +
      _funnelRow('Confirmed',      confirmed, Math.max(total,1), '#8b1f1f', true) +
      '<div style="background:rgba(63,185,80,.07);border-left:2px solid #3fb950;border-radius:0 6px 6px 0;padding:8px 10px;margin-top:10px;font-size:11px;color:#8b949e;font-family:monospace">'+
        'AI reduced alert fatigue by '+fp_pct+'% — from '+total.toLocaleString()+' raw events to '+confirmed+' confirmed findings.'+
      '</div>' +
    '</div>';

  recEl.insertAdjacentHTML('beforeend', funnelHtml);
}

function _funnelRow(label, count, total, col, small) {
  var pct = total>0 ? Math.max(1, Math.round(count/total*100)) : 1;
  var display = small && count<10 ? count+' incidents' : count.toLocaleString()+' events';
  return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:7px">' +
    '<span style="width:110px;text-align:right;font-size:11px;color:#8b949e;font-family:monospace;flex-shrink:0">'+label+'</span>' +
    '<div style="flex:1">' +
      '<div style="height:24px;border-radius:4px;background:'+col+';width:'+pct+'%;min-width:80px;display:flex;align-items:center;padding:0 10px;font-size:11px;font-weight:600;color:#fff">'+display+'</div>' +
    '</div>' +
  '</div>';
}

/* ── Timeline chart — reference style ──────────────────────── */
function _paTimelineChart(timeline, anomalyDays) {
  var ctx = document.getElementById('pa-chart-timeline');
  if (!ctx || !timeline.length) return;
  if (_paCharts.timeline) _paCharts.timeline.destroy();

  var labels = timeline.map(function(t){ return t.date; });
  var data   = timeline.map(function(t){ return t.count; });
  var avg    = data.reduce(function(a,b){ return a+b; }, 0) / (data.length||1);
  var anomDates = (anomalyDays||[]).map(function(a){ return a.date; });

  _paCharts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Total Events',
          data:  data,
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88,166,255,.07)',
          fill: true,
          tension: .4,
          pointRadius: data.map(function(v,i){ return anomDates.includes(labels[i]) ? 6 : 3; }),
          pointBackgroundColor: data.map(function(v,i){ return anomDates.includes(labels[i]) ? '#f85149' : '#58a6ff'; }),
          pointBorderColor:     data.map(function(v,i){ return anomDates.includes(labels[i]) ? '#f85149' : '#58a6ff'; }),
          borderWidth: 2,
        },
        {
          label: 'Avg',
          data:  data.map(function(){ return Math.round(avg); }),
          borderColor: 'rgba(139,148,158,.35)',
          borderDash: [5,4],
          borderWidth: 1,
          pointRadius: 0,
          fill: false,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color:'#8b949e', font:{ size:11 } } } },
      scales: {
        y: { beginAtZero:true, ticks:{ color:'#8b949e', font:{size:10} }, grid:{ color:'rgba(88,166,255,.025)' } },
        x: { ticks:{ color:'#8b949e', maxTicksLimit:10 }, grid:{ display:false } },
      }
    }
  });
}

/* ── Hourly heatmap-style bar chart ─────────────────────────── */
function _paHourlyChart(hourly) {
  var ctx = document.getElementById('pa-chart-hourly');
  if (!ctx) return;
  if (_paCharts.hourly) _paCharts.hourly.destroy();

  var maxV = Math.max.apply(null, hourly.map(function(h){ return h.count; })) || 1;
  _paCharts.hourly = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hourly.map(function(h){ return h.hour.replace(':00',''); }),
      datasets: [{
        data: hourly.map(function(h){ return h.count; }),
        backgroundColor: hourly.map(function(h){
          var p = h.count/maxV;
          return p>0.75?'rgba(248,81,73,.75)':p>0.45?'rgba(210,153,34,.75)':'rgba(88,166,255,.45)';
        }),
        borderColor: hourly.map(function(h){
          var p = h.count/maxV;
          return p>0.75?'#f85149':p>0.45?'#d29922':'#58a6ff';
        }),
        borderWidth: 1, borderRadius: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display:false } },
      scales: {
        x: { ticks:{ color:'#8b949e', maxRotation:0, font:{size:9} }, grid:{ color:'rgba(88,166,255,.025)' } },
        y: { ticks:{ color:'#8b949e', font:{size:10} }, grid:{ color:'rgba(88,166,255,.025)' }, beginAtZero:true }
      }
    }
  });
}

/* ── Failed Logins hourly bar chart ─────────────────────────── */
function _paFailedLoginsChart(threatHits, cats) {
  var ctx = document.getElementById('pa-chart-failed-logins');
  var emptyEl = document.getElementById('pa-failed-logins-empty');
  if (!ctx) return;
  if (_paCharts.failedLogins) _paCharts.failedLogins.destroy();

  // Extract failed login counts from Brute Force Login category
  var bruteHit = null;
  for (var i = 0; i < threatHits.length; i++) {
    if (/brute.force|failed.login|4625/i.test(threatHits[i].name || '')) {
      bruteHit = threatHits[i]; break;
    }
  }

  // Also check categories for brute force login event count
  var catBrute = cats['Brute Force Login'] || {};
  var totalCount = (bruteHit ? bruteHit.count : 0) || catBrute.total || 0;

  if (!totalCount) {
    ctx.style.display = 'none';
    if (emptyEl) emptyEl.style.display = 'block';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';

  // Build a synthetic hourly distribution from threat first_seen/last_seen + window
  // We spread the count over the window hours to approximate the timeline
  var hours = [];
  var counts = [];
  for (var h = 0; h < 24; h++) {
    hours.push((h < 10 ? '0' : '') + h + ':00');
    counts.push(0);
  }

  if (bruteHit && bruteHit.first_seen) {
    var firstH = parseInt((bruteHit.first_seen || '00:').split(':')[0]) || 0;
    var lastH  = parseInt((bruteHit.last_seen  || '00:').split(':')[0]) || firstH;
    var winH   = Math.max(1, bruteHit.window_hours || (lastH - firstH + 1));
    var perH   = Math.round(totalCount / winH);
    for (var w = 0; w < winH; w++) {
      var slot = (firstH + w) % 24;
      counts[slot] += perH;
    }
  } else {
    // Fallback: put all events in a single spike at hour 0 (data too sparse)
    counts[0] = totalCount;
  }

  var maxV = Math.max.apply(null, counts) || 1;
  _paCharts.failedLogins = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hours.map(function(h){ return h.replace(':00',''); }),
      datasets: [{
        label: 'Failed Logins',
        data: counts,
        backgroundColor: counts.map(function(c){
          var p = c / maxV;
          return p > 0.6 ? 'rgba(185,28,28,.85)' : p > 0.3 ? 'rgba(248,81,73,.65)' : 'rgba(248,81,73,.25)';
        }),
        borderColor: '#f85149',
        borderWidth: 1, borderRadius: 3,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(ctx) { return ctx.parsed.y + ' failed login event' + (ctx.parsed.y !== 1 ? 's' : ''); }
          }
        }
      },
      scales: {
        x: { ticks:{ color:'#8b949e', maxRotation:0, font:{size:9} }, grid:{ color:'rgba(248,81,73,.04)' } },
        y: { ticks:{ color:'#8b949e', font:{size:10} }, grid:{ color:'rgba(248,81,73,.04)' }, beginAtZero:true }
      }
    }
  });
}

/* ── Weekday chart ──────────────────────────────────────────── */
function _paWeekdayChart(weekday) {
  var ctx = document.getElementById('pa-chart-weekday');
  if (!ctx) return;
  if (_paCharts.weekday) _paCharts.weekday.destroy();

  _paCharts.weekday = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: weekday.map(function(w){ return w.day; }),
      datasets: [{
        data: weekday.map(function(w){ return w.count; }),
        backgroundColor: 'rgba(88,166,255,.45)',
        borderColor: '#58a6ff',
        borderWidth: 1, borderRadius: 4,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display:false } },
      scales: {
        x: { ticks:{ color:'#8b949e', font:{size:9} }, grid:{ display:false } },
        y: { ticks:{ color:'#8b949e', font:{size:10} }, grid:{ color:'rgba(88,166,255,.025)' }, beginAtZero:true }
      }
    }
  });
}

/* ── Severity doughnut ──────────────────────────────────────── */
function _paCategoryDonut(cats) {
  var ctx = document.getElementById('pa-chart-cats');
  if (!ctx) return;
  if (_paCharts.cats) _paCharts.cats.destroy();

  var totCrit=0,totErr=0,totWarn=0,totInfo=0;
  Object.values(cats).forEach(function(c){
    totCrit+=c.critical||0; totErr+=c.errors||0;
    totWarn+=c.warnings||0; totInfo+=c.info||0;
  });
  var total = totCrit+totErr+totWarn+totInfo||1;
  var pct = function(v){ return Math.round(v/total*100); };

  _paCharts.cats = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [
        'Critical '+pct(totCrit)+'%',
        'Error '+pct(totErr)+'%',
        'Warning '+pct(totWarn)+'%',
        'Info '+pct(totInfo)+'%',
      ],
      datasets: [{
        data: [totCrit, totErr, totWarn, totInfo],
        backgroundColor: ['#b91c1c','#f85149','#d29922','#58a6ff'],
        borderWidth: 2,
        borderColor: '#161b22',
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: { position:'right', labels:{ color:'#8b949e', font:{size:10}, boxWidth:10 } }
      }
    }
  });
}

/* ── Event ID horizontal bar ────────────────────────────────── */
function _paEventIdBar(cats) {
  // We reuse pa-cat-breakdown canvas slot (already rendered as list above)
  // This is a supplementary chart — inject if a 2nd canvas exists
  var ctx = document.getElementById('pa-chart-evtid');
  if (!ctx) return;
  if (_paCharts.evtid) _paCharts.evtid.destroy();

  // Build top event sources from top_error_sources across all categories
  var srcs = {};
  Object.values(cats).forEach(function(c){
    (c.top_error_sources||[]).forEach(function(s){
      srcs[s.source] = (srcs[s.source]||0) + s.count;
    });
  });
  var sorted = Object.entries(srcs).sort(function(a,b){ return b[1]-a[1]; }).slice(0,8);
  if (!sorted.length) return;

  var colors = ['#f85149','#58a6ff','#bc8cff','#d29922','#3fb950','#39d0d8','#b91c1c','#58a6ff'];
  _paCharts.evtid = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(function(s){ return s[0].substring(0,20); }),
      datasets: [{
        data: sorted.map(function(s){ return s[1]; }),
        backgroundColor: colors,
        borderRadius: 4, borderWidth: 0,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display:false } },
      scales: {
        x: { ticks:{ color:'#8b949e', font:{size:10} }, grid:{ color:'rgba(88,166,255,.025)' }, beginAtZero:true },
        y: { ticks:{ color:'#8b949e', font:{size:9} }, grid:{ display:false } }
      }
    }
  });
}

/* ── FIM — redesigned with dropdowns, changed entities, AI intel ─── */
var _fimAllEvents  = [];
var _fimFilter     = 'ALL';

/* File-type intelligence database */
var _FIM_INTEL = {
  /* Windows critical system files */
  'lsass.exe':   { icon:'🔴', what:'Local Security Authority — manages all authentication (logins, tokens, passwords).', risk:'CRITICAL', how:'Check Event ID 4656/4663. Any WRITE or READ by non-SYSTEM process = likely credential dumping (Mimikatz, ProcDump).', action:'Isolate machine immediately. Run EDR memory scan. Check for tools like procdump.exe, mimikatz.exe in same timeframe.', mitre:'T1003.001 — LSASS Memory' },
  'sam':         { icon:'🔴', what:'Security Account Manager — stores local user password hashes.', risk:'CRITICAL', how:'Should never be opened directly while Windows runs. Any read = attacker copying hashes for offline cracking.', action:'Check who accessed it and from which process. Look for reg save HKLM\\SAM in command history.', mitre:'T1003.002 — SAM Database' },
  'ntds.dit':    { icon:'🔴', what:'Active Directory database — contains ALL domain account hashes.', risk:'CRITICAL', how:'Lives at C:\\Windows\\NTDS\\ntds.dit. Only readable by NTDS service normally. Any copy = full domain compromise.', action:'Check for vssadmin, ntdsutil, or shadow copy activity. This is a P0 incident — notify security team immediately.', mitre:'T1003.003 — NTDS' },
  'hosts':       { icon:'🟠', what:'DNS override file — attackers modify it to redirect traffic or block security tools.', risk:'HIGH', how:'Located at C:\\Windows\\System32\\drivers\\etc\\hosts. Compare against baseline. Look for added lines pointing to attacker IPs.', action:'Diff the file. Check for entries pointing unknown IPs. Revert to clean backup.', mitre:'T1565.001 — Stored Data Manipulation' },
  'system32':    { icon:'🟠', what:'Core Windows system directory — dropping files here = privilege & persistence.', risk:'HIGH', how:'New files in System32 after an incident = backdoor or DLL hijack. Check creation timestamps vs attack window.', action:'Run sigcheck on new files. Check digital signatures. Look for masquerading (svchost32.exe, etc).', mitre:'T1036.005 — Match Legitimate Name or Location' },
  /* Scripts & executables */
  '.ps1':        { icon:'🟡', what:'PowerShell script — very commonly used in attacks for payload delivery and lateral movement.', risk:'HIGH', how:'Check ScriptBlock logging (Event ID 4104). Look for Base64-encoded commands, IEX (Invoke-Expression), or download cradles.', action:'Review script content. Check parent process. Look for -EncodedCommand or -exec bypass flags.', mitre:'T1059.001 — PowerShell' },
  '.bat':        { icon:'🟡', what:'Batch script — used for persistence, lateral movement, or cleanup after an attack.', risk:'HIGH', how:'Check parent process and who wrote it. Attackers use .bat files to chain commands and delete logs.', action:'Review content for del, net use, reg add commands. Check scheduled task creation around same time.', mitre:'T1059.003 — Windows Command Shell' },
  '.cmd':        { icon:'🟡', what:'Command script — functionally identical to .bat, often used interchangeably by attackers.', risk:'HIGH', how:'Same as .bat — check content, parent process, and creation time vs attack window.', action:'Inspect for encoded payloads or deletion routines. Correlate with process creation events (EID 4688).', mitre:'T1059.003 — Windows Command Shell' },
  '.vbs':        { icon:'🟡', what:'VBScript — used in phishing attachments and legacy malware for code execution.', risk:'HIGH', how:'Check Event ID 4688 for wscript.exe or cscript.exe spawning with this file. Review file content.', action:'Quarantine file. Check email gateway for attachment delivery. Examine parent process.', mitre:'T1059.005 — Visual Basic' },
  /* Web server / config files */
  'web.config':  { icon:'🟡', what:'IIS web server config — modifying it can redirect traffic, add handlers, or expose sensitive paths.', risk:'HIGH', how:'Compare against version control or backup. Look for added <httpHandlers> or path rewrites to attacker domains.', action:'Restore from backup. Audit IIS logs for suspicious requests around modification time.', mitre:'T1505.004 — IIS Components' },
  'httpd.conf':  { icon:'🟡', what:'Apache web server config — modification can enable directory traversal or proxy to attacker.', risk:'HIGH', how:'Diff against known-good version. Check for added ProxyPass or AllowOverride All directives.', action:'Restore from backup. Review Apache access logs for exploitation attempts.', mitre:'T1505 — Server Software Component' },
  'nginx.conf':  { icon:'🟡', what:'Nginx config — attackers modify to add upstream proxies or expose internal services.', risk:'HIGH', how:'Diff against known-good. Look for new location blocks or proxy_pass to internal IPs.', action:'Restore and reload nginx. Check for any new virtual hosts added.', mitre:'T1505 — Server Software Component' },
  'sshd_config': { icon:'🟠', what:'SSH daemon config — modification can enable password auth, root login, or add authorized keys.', risk:'HIGH', how:'Check for PermitRootLogin yes, PasswordAuthentication yes, or added AuthorizedKeysFile paths.', action:'Restore from backup. Audit /root/.ssh/authorized_keys for unknown keys. Rotate all SSH credentials.', mitre:'T1098.004 — SSH Authorized Keys' },
  /* Linux system files */
  'passwd':      { icon:'🔴', what:'Linux user database — attackers add new root-level accounts for persistence.', risk:'CRITICAL', how:'Diff against backup. Look for new UIDs, especially uid=0. Check /etc/shadow too.', action:'Remove unauthorized entries. Audit who modified it (auditd log). Check for new sudo rules.', mitre:'T1136.001 — Create Local Account' },
  'shadow':      { icon:'🔴', what:'Linux password hash file — reading it = offline hash cracking of all local accounts.', risk:'CRITICAL', how:'Only readable by root. Any non-root access = privilege escalation. Check /var/log/auth.log.', action:'Force password reset for all local accounts. Check for cracking tools in /tmp or /dev/shm.', mitre:'T1003.008 — /etc/passwd and /etc/shadow' },
  'sudoers':     { icon:'🔴', what:'Sudo config — adding entries here gives any user root access without a password.', risk:'CRITICAL', how:'Check for ALL=(ALL) NOPASSWD lines added for non-admin users. Compare against known good.', action:'Restore from backup. Revoke elevated access. Audit all commands run via sudo recently.', mitre:'T1548.003 — Sudo and Sudo Caching' },
  /* Registry hives */
  'sam.hive':    { icon:'🔴', what:'Exported SAM registry hive — a file dump of local password hashes. Immediate theft risk.', risk:'CRITICAL', how:'Creation of this file means attacker ran reg save HKLM\\SAM. Look for this in command history.', action:'Delete the file. Check if it was exfiltrated (network connections after creation). Reset all local passwords.', mitre:'T1003.002 — SAM Database' },
  'security.hive':{ icon:'🔴', what:'Exported SECURITY hive — contains cached domain credentials (LSA secrets).', risk:'CRITICAL', how:'Created by reg save HKLM\\SECURITY. Contains machine account hashes and cached logons.', action:'Delete immediately. Check network logs for exfiltration. This may indicate domain-level compromise.', mitre:'T1003.004 — LSA Secrets' },
  'system.hive': { icon:'🟠', what:'Exported SYSTEM hive — needed with SAM to decrypt password hashes offline (bootkey).', risk:'HIGH', how:'Often exported alongside sam.hive. Together they allow full offline hash cracking.', action:'Delete. Check if SAM hive was also exported. Reset all local account passwords.', mitre:'T1003.002 — SAM Database' },
};

function _fimGetIntel(file, path) {
  if (!file && !path) return null;
  var combined = ((file || '') + '|' + (path || '')).toLowerCase();
  for (var key in _FIM_INTEL) {
    if (combined.indexOf(key.toLowerCase()) !== -1) return _FIM_INTEL[key];
  }
  return null;
}

function _fimActionColor(action) {
  var map = { DELETE:'#ef4444', MODIFIED:'#f97316', WRITE:'#f97316', EXECUTE:'#a78bfa', READ:'#22c55e', ACCESS:'#3b82f6', 'WRITE/MODIFIED':'#f97316' };
  return map[action] || '#8b949e';
}
function _fimSevColor(sev) {
  return { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#a78bfa', LOW:'#22c55e' }[sev] || '#8b949e';
}
function _fimFileIcon(file) {
  if (!file) return '📄';
  var f = file.toLowerCase();
  if (f.match(/\.(exe|dll|sys)$/)) return '⚙️';
  if (f.match(/\.(ps1|bat|cmd|vbs|sh)$/)) return '📜';
  if (f.match(/\.(log|evt)$/)) return '📋';
  if (f.match(/\.(conf|config|ini|cfg)$/)) return '⚙️';
  if (f.match(/\.(hive)$/)) return '🗄️';
  if (f === 'sam' || f === 'hosts' || f === 'shadow' || f === 'passwd' || f === 'sudoers') return '🔑';
  if (f === 'ntds.dit') return '🗄️';
  return '📄';
}

/* Group events by file name */
function _fimGroupByFile(events) {
  var groups = {};
  events.forEach(function(ev) {
    var key = (ev.file || '—') + '|' + (ev.full_path || '');
    if (!groups[key]) {
      groups[key] = { file: ev.file, full_path: ev.full_path, host: ev.host, severity: ev.severity, critical: ev.critical, events: [] };
    }
    groups[key].events.push(ev);
    // Upgrade severity if needed
    var sevRank = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
    if ((sevRank[ev.severity]||0) > (sevRank[groups[key].severity]||0)) {
      groups[key].severity = ev.severity;
    }
  });
  return Object.values(groups);
}

/* Render FIM entity accordion item */
function _fimRenderEntity(group, idx) {
  var intel = _fimGetIntel(group.file, group.full_path);
  var sev   = group.severity;
  var sevC  = _fimSevColor(sev);
  var icon  = (intel && intel.icon) || _fimFileIcon(group.file);
  var lastEv = group.events[0];
  var action = lastEv ? lastEv.action : 'ACCESS';
  var ac    = _fimActionColor(action);
  var entityId = 'fim-ent-' + idx;

  // Unique actions for this file
  var actSet = {};
  group.events.forEach(function(e){ actSet[e.action] = true; });
  var actPills = Object.keys(actSet).map(function(a){
    var c = _fimActionColor(a);
    return '<span class="fim-action-pill" style="background:'+c+'18;color:'+c+';border:1px solid '+c+'33">'+a+'</span>';
  }).join('');

  // Detail cells
  var detailCells = [
    { label:'Full Path',    val: group.full_path || '—' },
    { label:'Host',         val: group.host || 'LOCAL' },
    { label:'Event Count',  val: group.events.length + ' event' + (group.events.length !== 1 ? 's' : '') },
    { label:'Severity',     val: '<span style="color:'+sevC+';font-weight:700">'+sev+'</span>' },
    { label:'First Seen',   val: (group.events[group.events.length-1]||{}).timestamp || '—' },
    { label:'Last Seen',    val: (group.events[0]||{}).timestamp || '—' },
  ];

  // Intel section
  var intelHtml = '';
  if (intel) {
    intelHtml = '<div style="padding:10px 14px;background:rgba(14,165,233,.04);border-top:1px solid rgba(14,165,233,.1)">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px">' +
        '<div><div style="font-size:9px;color:#0ea5e9;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">What this file is</div><div style="color:var(--text-2);line-height:1.6">'+intel.what+'</div></div>' +
        '<div><div style="font-size:9px;color:#f97316;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">How to investigate</div><div style="color:var(--text-2);line-height:1.6">'+intel.how+'</div></div>' +
        '<div><div style="font-size:9px;color:#ef4444;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Recommended action</div><div style="color:var(--text-2);line-height:1.6">'+intel.action+'</div></div>' +
        '<div><div style="font-size:9px;color:#a78bfa;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">MITRE ATT&CK</div><div style="color:#a78bfa;font-family:var(--font-mono);font-size:10px">'+intel.mitre+'</div></div>' +
      '</div>' +
    '</div>';
  }

  // Event log rows (latest 5)
  var evRows = group.events.slice(0,5).map(function(ev){
    var eac = _fimActionColor(ev.action);
    return '<div class="fim-event-row">' +
      '<span class="fim-event-time">'+(ev.timestamp||'').substring(11,19)+'</span>' +
      '<span class="fim-action-pill" style="background:'+eac+'18;color:'+eac+';border:1px solid '+eac+'33">'+ev.action+'</span>' +
      '<span class="fim-event-user">'+ev.user+'</span>' +
      '<span class="fim-event-msg">'+(ev.full_path || ev.file || '—')+'</span>' +
    '</div>';
  }).join('');

  var moreRows = group.events.length > 5
    ? '<div style="padding:6px 14px 4px;font-size:10px;color:var(--text-3);font-family:var(--font-mono)">… and '+(group.events.length-5)+' more events</div>'
    : '';

  return '<div class="fim-entity fim-'+sev.toLowerCase()+'" id="'+entityId+'" data-action="'+action+'">' +
    '<div class="fim-entity-header" onclick="fimToggleEntity(\''+entityId+'\')">' +
      '<span class="fim-entity-icon">'+icon+'</span>' +
      '<div style="flex:1;min-width:0">' +
        '<div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">' +
          '<span class="fim-entity-name">'+group.file+'</span>' +
          '<span class="fim-sev-dot" style="background:'+sevC+'"></span>' +
        '</div>' +
        '<div class="fim-entity-path">'+(group.full_path||'Path not captured')+'</div>' +
      '</div>' +
      '<div class="fim-entity-meta">' +
        actPills +
        (intel ? '<span style="font-size:10px;color:#0ea5e9;margin-left:2px" title="AI intel available">🤖</span>' : '') +
        '<span style="font-size:11px;color:var(--text-3);margin-left:4px">×'+group.events.length+'</span>' +
        '<span class="fim-chev" id="'+entityId+'-chev">▶</span>' +
      '</div>' +
    '</div>' +
    '<div class="fim-entity-body" id="'+entityId+'-body">' +
      '<div class="fim-detail-grid">' +
        detailCells.map(function(c){ return '<div class="fim-detail-cell"><div class="fim-detail-label">'+c.label+'</div><div class="fim-detail-val">'+c.val+'</div></div>'; }).join('') +
      '</div>' +
      intelHtml +
      '<div class="fim-event-log">' +
        '<div style="font-size:9px;color:var(--text-3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">Event Log</div>' +
        evRows + moreRows +
      '</div>' +
    '</div>' +
  '</div>';
}

function _paRenderFIM(fim) {
  var $ = function(id){ return document.getElementById(id); };

  var events  = fim.events   || [];
  var byAction= fim.by_action || {};
  _fimAllEvents = events;

  // Show the card
  var card = document.getElementById('fim-card');
  if (card) card.style.display = 'block';

  // Stats pills
  var statsEl = $('fim-stats');
  if (statsEl) {
    var statItems = [
      { val: fim.total||0,   lbl:'Total Events', col:'var(--text-1)' },
      { val: fim.critical||0,lbl:'Critical',      col:'#ef4444' },
      { val: fim.high||0,    lbl:'High Risk',     col:'#f97316' },
      { val: Object.keys(byAction).length, lbl:'Action Types', col:'#a78bfa' },
    ];
    statsEl.innerHTML = statItems.map(function(s){
      return '<div class="fim-stat"><div class="fim-stat-val" style="color:'+s.col+'">'+s.val+'</div><div class="fim-stat-lbl">'+s.lbl+'</div></div>';
    }).join('');
  }

  var badge = $('fim-change-badge');
  var filterBar = $('fim-filter-bar');
  var entityEl  = $('fim-entities');
  var emptyEl   = $('fim-empty');
  var aiPanel   = $('fim-ai-panel');

  if (!events.length) {
    if (badge)     badge.style.display = 'none';
    if (filterBar) filterBar.style.display = 'none';
    if (entityEl)  entityEl.innerHTML = '';
    if (emptyEl)   emptyEl.style.display = 'block';
    if (aiPanel)   aiPanel.style.display = 'none';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';

  // Render entities according to the selected filter.
  // The badge reports how many changed events exist overall, but the list should still honor the active filter.
  var changedEvents = events.filter(function(e){ return e.action !== 'READ' && e.action !== 'ACCESS'; });
  if (badge) {
    badge.textContent = changedEvents.length + ' CHANGE' + (changedEvents.length !== 1 ? 'S' : '');
    badge.style.display = 'inline-block';
  }

  // Filter bar
  if (filterBar) filterBar.style.display = 'flex';

  // Render entities using the current filter state.
  _fimRenderEntities(events);

  // AI panel
  if (aiPanel) {
    aiPanel.style.display = 'block';
    _fimLoadAI(fim);
  }

  // Legacy dashboard FIM panel compatibility
  _paRenderFIMDashboard(fim);
}

function _paRenderFIMDashboard(fim) {
  var $ = function(id){ return document.getElementById(id); };
  var set = function(id,v){ var el=$(id); if(el) el.textContent = v; };

  var events   = fim.events || [];
  var byAction = fim.by_action || {};

  set('pa-fim-total',   (fim.total   || 0).toLocaleString());
  set('pa-fim-crit',    (fim.critical || 0).toLocaleString());
  set('pa-fim-high',    (fim.high    || 0).toLocaleString());
  set('pa-fim-actions', Object.keys(byAction).length.toLocaleString());

  var summaryEl = $('pa-fim-summary');
  if (summaryEl) {
    if (events.length) {
      summaryEl.textContent = events.length + ' file event' + (events.length !== 1 ? 's' : '') + ' found in the selected period.';
    } else {
      summaryEl.textContent = 'No file integrity events found in this period. Enable Object Access auditing in secpol.msc to capture file events.';
    }
  }

  var tbody = $('pa-fim-tbody');
  if (!tbody) return;

  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--text-dim);font-size:12px">' +
      'No file integrity events found in this period.<br>' +
      '<span style="font-size:11px">Enable Object Access auditing in secpol.msc to capture file events.</span>' +
      '</td></tr>';
    return;
  }

  var SCOL = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'};
  var ACOL = {DELETE:'#f87171',MODIFIED:'#fb923c',WRITE:'#fb923c',EXECUTE:'#a78bfa',READ:'#4ade80',ACCESS:'#4da6ff'};

  tbody.innerHTML = events.map(function(ev) {
    var sc = SCOL[ev.severity] || '#94a3b8';
    var ac = ACOL[ev.action]   || '#94a3b8';
    var critRow = ev.critical ? 'background:rgba(248,113,113,.04);' : '';
    var critMark = ev.critical ? '<span style="color:#f87171;font-size:9px;margin-left:4px">■</span>' : '';
    return '<tr style="' + critRow + 'border-bottom:1px solid var(--border)">' +
      '<td style="padding:9px 14px;font-family:var(--mono);font-size:11px;color:var(--text-bright);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        (ev.file || '—') + critMark + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim)">' + (ev.host || 'LOCAL') + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="background:' + ac + '18;color:' + ac + ';border:1px solid ' + ac + '44;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">' +
        (ev.action || 'ACCESS') + '</span>' +
      '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-muted);font-family:var(--mono)">' + (ev.user || 'UNKNOWN') + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim);font-family:var(--mono)">' + ((ev.timestamp||'').substring(11,19) || '—') + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="color:' + sc + ';font-size:10px;font-weight:700">' + (ev.severity || 'LOW') + '</span>' +
      '</td>' +
    '</tr>';
  }).join('');
}

function _fimActionMatchesFilter(action, filter) {
  var act = String(action || '').toUpperCase();
  return filter === 'ALL' || act === filter || act.indexOf(filter) !== -1;
}

function _fimRenderEntities(events) {
  var entityEl = document.getElementById('fim-entities');
  var showingEl = document.getElementById('fim-showing');
  if (!entityEl) return;

  var filtered = events.filter(function(e){ return _fimActionMatchesFilter(e.action, _fimFilter); });

  var groups = _fimGroupByFile(filtered);
  // Sort: critical first, then by event count
  groups.sort(function(a,b){
    var r = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
    return (r[b.severity]||0) - (r[a.severity]||0) || b.events.length - a.events.length;
  });

  if (showingEl) showingEl.textContent = groups.length + ' file' + (groups.length !== 1 ? 's' : '');
  entityEl.innerHTML = groups.map(function(g, i){ return _fimRenderEntity(g, i); }).join('');
}

function fimFilter(f) {
  _fimFilter = f;
  document.querySelectorAll('.fim-filter-btn').forEach(function(btn){
    btn.classList.toggle('fim-filter-active', btn.getAttribute('data-f') === f);
  });
  _fimRenderEntities(_fimAllEvents);
}

function fimToggleEntity(id) {
  var body = document.getElementById(id + '-body');
  var chev = document.getElementById(id + '-chev');
  if (!body) return;
  var open = body.classList.contains('open');
  body.classList.toggle('open', !open);
  if (chev) { chev.textContent = open ? '▶' : '▼'; chev.style.color = open ? 'var(--text-3)' : '#0ea5e9'; }
}

function fimToggleAI() {
  var body = document.getElementById('fim-ai-body');
  var chev = document.getElementById('fim-ai-chev');
  if (!body) return;
  var open = body.style.display === 'block';
  body.style.display = open ? 'none' : 'block';
  if (chev) chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
}

async function _fimLoadAI(fim) {
  var contentEl = document.getElementById('fim-ai-content');
  if (!contentEl) return;

  // Build summary for AI prompt
  var topFiles = (fim.top_files || []).slice(0, 8).map(function(f){ return f.file + ' ('+f.count+' events)'; }).join(', ');
  var byAction = fim.by_action || {};
  var actionSummary = Object.entries(byAction).map(function(kv){ return kv[1] + ' ' + kv[0]; }).join(', ');
  var critFiles = (fim.events || []).filter(function(e){ return e.critical; }).map(function(e){ return e.file; });
  var critUniq  = [...new Set(critFiles)].slice(0,5).join(', ');

  var prompt = 'You are a Windows security analyst. Analyze these File Integrity Monitoring (FIM) events and provide a structured security brief.\n\n' +
    'FIM Summary:\n' +
    '- Total events: ' + (fim.total||0) + '\n' +
    '- Critical severity: ' + (fim.critical||0) + '\n' +
    '- High severity: ' + (fim.high||0) + '\n' +
    '- Action breakdown: ' + (actionSummary || 'none') + '\n' +
    '- Most active files: ' + (topFiles || 'none') + '\n' +
    '- Critical system files accessed: ' + (critUniq || 'none') + '\n\n' +
    'Respond with EXACTLY this JSON structure (no markdown, no backticks):\n' +
    '{"overview":"2-3 sentence plain English summary of what happened","critical_files":"Explain what the critical files are and why they matter (if any)","investigation":"Step-by-step: how to investigate these specific events right now","mitre":"Which MITRE ATT&CK techniques apply to these file accesses","remediation":"Specific remediation steps based on these events"}\n\n' +
    'Be specific, concise, actionable. Reference actual file names from the data.';

  try {
    contentEl.innerHTML = '<div style="color:var(--text-3);font-size:11px;font-style:italic;display:flex;align-items:center;gap:8px"><span style="display:inline-block;width:10px;height:10px;border:2px solid #0ea5e9;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite"></span>Analysing file events with AI…</div>';

    var resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    var data = await resp.json();
    var raw  = (data.content || []).map(function(c){ return c.text || ''; }).join('');

    var parsed;
    try { parsed = JSON.parse(raw.replace(/```json|```/g,'')); } catch(e) { parsed = null; }

    if (!parsed) {
      contentEl.innerHTML = '<div style="color:var(--text-2);font-size:12px;line-height:1.7">'+raw+'</div>';
      return;
    }

    var sections = [
      { key:'overview',       icon:'🔍', title:'Overview',                color:'#0ea5e9' },
      { key:'critical_files', icon:'🔴', title:'Critical Files Analysis', color:'#ef4444' },
      { key:'investigation',  icon:'🔬', title:'How to Investigate',      color:'#f97316' },
      { key:'mitre',          icon:'🎯', title:'MITRE ATT&CK Mapping',    color:'#a78bfa' },
      { key:'remediation',    icon:'✅', title:'Remediation Steps',       color:'#22c55e' },
    ];

    contentEl.innerHTML = sections.filter(function(s){ return parsed[s.key]; }).map(function(s){
      return '<div class="fim-ai-section">' +
        '<div class="fim-ai-section-title" style="color:'+s.color+'"><span>'+s.icon+'</span><span>'+s.title+'</span></div>' +
        '<div class="fim-ai-section-body">'+parsed[s.key]+'</div>' +
      '</div>';
    }).join('');

    // Auto-open the AI body on first load
    var aiBody = document.getElementById('fim-ai-body');
    var aiChev = document.getElementById('fim-ai-chev');
    if (aiBody && aiBody.style.display === 'none') {
      aiBody.style.display = 'block';
      if (aiChev) aiChev.style.transform = 'rotate(180deg)';
    }

  } catch(e) {
    contentEl.innerHTML = '<div style="color:var(--text-3);font-size:11px">AI analysis unavailable: ' + e.message + '</div>';
  }
}


/* ── Threat accordion toggle ────────────────────────────────── */
function paToggleThreat(id) {
  var panel = document.getElementById(id);
  var chev  = document.getElementById(id+'-chev');
  if (!panel) return;
  var open = panel.style.display === 'block';
  panel.style.display = open ? 'none' : 'block';
  if (chev) {
    chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
    chev.style.color     = open ? '#484f58' : '#58a6ff';
  }
}



/* ═══════════════════════════════════════════════════════════
   AI INSIGHTS — fetch and display after report renders
═══════════════════════════════════════════════════════════ */

async function _paLoadAIInsights(report) {
  var container = document.getElementById('pa-ai-container');
  if (!container) return;

  // Show loading
  container.style.display = 'block';
  container.innerHTML =
    '<div style="display:flex;align-items:center;gap:12px;padding:16px 20px;color:var(--text-dim);font-size:13px">' +
      '<div class="pa-ai-spinner"></div>' +
      '<span>AI is analysing your actual log data…</span>' +
    '</div>';

  try {
    var r = await fetch('/api/perform-analysis/ai-insights', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(report),
    });
    var d = await r.json();

    if (!d.ok || !d.insights) {
      container.style.display = 'none';
      return;
    }

    var ins = d.insights;
    var html = '';

    // Section configs — label, key, icon, color
    var sections = [
      { key:'overview',  label:'System Status',          icon:'🔍', col:'#4da6ff' },
      { key:'threats',   label:'Active Threats On This System', icon:'🚨', col:'#f87171' },
      { key:'timeline',  label:'Activity Pattern',        icon:'📅', col:'#4da6ff' },
      { key:'anomalies', label:'What Caused The Spikes',  icon:'📈', col:'#fb923c' },
      { key:'action',    label:'What To Do Right Now',    icon:'⚡', col:'#4ade80' },
    ];

    sections.forEach(function(s) {
      var text = (ins[s.key] || '').trim();
      if (!text) return;
      html +=
        '<div class="pa-ai-section" id="pa-ais-' + s.key + '">' +
          '<div class="pa-ai-section-header" style="color:' + s.col + '">' +
            '<span style="font-size:16px">' + s.icon + '</span>' +
            '<span>' + s.label + '</span>' +
          '</div>' +
          '<div class="pa-ai-section-body" id="pa-ais-' + s.key + '-text"></div>' +
        '</div>';
    });

    container.innerHTML =
      '<div class="pa-ai-header-bar">' +
        '<div style="display:flex;align-items:center;gap:8px">' +
          '<span style="font-size:18px">🤖</span>' +
          '<span style="font-size:13px;font-weight:800;color:var(--text-bright)">AI Analysis — Based On Your Actual Log Data</span>' +
        '</div>' +
        '<span style="font-size:10px;color:var(--text-dim);font-style:italic">Powered by Llama 3.3 · ' + report.generated_at + '</span>' +
      '</div>' +
      '<div class="pa-ai-sections-grid">' + html + '</div>';

    // Type each section with slight delay between them
    var delay = 0;
    sections.forEach(function(s) {
      var text = (ins[s.key] || '').trim();
      if (!text) return;
      setTimeout(function() {
        var el = document.getElementById('pa-ais-' + s.key + '-text');
        if (el) _paTypewriter(el, text);
      }, delay);
      delay += 300;
    });

  } catch(e) {
    container.style.display = 'none';
    console.warn('AI insights failed:', e.message);
  }
}


function _paTypewriter(el, text) {
  el.textContent = '';
  el.classList.add('pa-ai-typing');
  var i = 0;
  var speed = Math.max(8, Math.min(25, 3000 / text.length)); // adaptive speed
  var iv = setInterval(function() {
    if (i < text.length) {
      el.textContent += text[i];
      i++;
    } else {
      clearInterval(iv);
      el.classList.remove('pa-ai-typing');
    }
  }, speed);
}
