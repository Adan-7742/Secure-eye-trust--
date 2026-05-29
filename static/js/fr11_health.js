/**
 * static/js/fr11_health.js
 * =========================
 * FR11-01  CPU usage + process breakdown panel
 * FR11-02  RAM + page file usage panel
 * FR11-03  Disk health + SMART status panel
 * FR11-04  Windows optimization recommendations panel
 * FR11-05  BSOD risk prediction panel
 * FR11-06  Driver health panel
 *
 * PLACE THIS FILE AT:
 *   <your_project>/static/js/fr11_health.js
 *
 * HOW TO USE — add ONE line to index.html after existing script tags:
 *   <script src="/static/js/fr11_health.js"></script>
 *
 * Add ONE div in index.html inside page-dashboard,
 * just before the closing Charts section:
 *   <div id="fr11-health-panel"></div>
 */

(function () {
  'use strict';

  // ── API ─────────────────────────────────────────────────────────────────────
  var API = {
    cpu:      '/api/health/cpu',
    memory:   '/api/health/memory',
    disk:     '/api/health/disk',
    optimize: '/api/health/optimize',
    bsod:     '/api/health/bsod',
    drivers:  '/api/health/drivers',
  };

  async function apiFetch(url) {
    var r = await fetch(url);
    return r.json();
  }

  function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function _severityColor(s) {
    var map = {
      CRITICAL:'#ef4444', HIGH:'#f97316', WARNING:'#f59e0b',
      MEDIUM:'#f59e0b', LOW:'#38bdf8', HEALTHY:'#10b981',
      NORMAL:'#10b981', OK:'#10b981', UNKNOWN:'#6a90b8'
    };
    return map[(s||'').toUpperCase()] || '#6a90b8';
  }

  function _severityBg(s) {
    var map = {
      CRITICAL:'rgba(239,68,68,.12)', HIGH:'rgba(249,115,22,.12)',
      WARNING:'rgba(245,158,11,.12)', MEDIUM:'rgba(245,158,11,.12)',
      LOW:'rgba(56,189,248,.10)', HEALTHY:'rgba(16,185,129,.10)',
      NORMAL:'rgba(16,185,129,.10)', OK:'rgba(16,185,129,.10)',
    };
    return map[(s||'').toUpperCase()] || 'rgba(100,116,139,.1)';
  }

  // ── Shell builder ────────────────────────────────────────────────────────────
  function buildShell(container) {
    container.innerHTML =
      // Tab nav
      '<div class="fr11-tab-bar">' +
        '<button class="fr11-tab active" data-tab="cpu">🖥 CPU</button>' +
        '<button class="fr11-tab" data-tab="memory">💾 Memory</button>' +
        '<button class="fr11-tab" data-tab="disk">💿 Disk Health</button>' +
        '<button class="fr11-tab" data-tab="optimize">⚡ Optimize</button>' +
        '<button class="fr11-tab" data-tab="bsod">💀 BSOD Risk</button>' +
        '<button class="fr11-tab" data-tab="drivers">🔧 Drivers</button>' +
      '</div>' +
      // Panels
      '<div class="fr11-tab-content" id="fr11-tab-cpu"></div>' +
      '<div class="fr11-tab-content" id="fr11-tab-memory" style="display:none"></div>' +
      '<div class="fr11-tab-content" id="fr11-tab-disk" style="display:none"></div>' +
      '<div class="fr11-tab-content" id="fr11-tab-optimize" style="display:none"></div>' +
      '<div class="fr11-tab-content" id="fr11-tab-bsod" style="display:none"></div>' +
      '<div class="fr11-tab-content" id="fr11-tab-drivers" style="display:none"></div>';

    // Tab switching
    container.querySelectorAll('.fr11-tab').forEach(function(btn) {
      btn.addEventListener('click', function() {
        container.querySelectorAll('.fr11-tab').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        container.querySelectorAll('.fr11-tab-content').forEach(function(p) { p.style.display = 'none'; });
        var panel = document.getElementById('fr11-tab-' + btn.dataset.tab);
        if (panel) panel.style.display = '';
        loadTab(btn.dataset.tab);
      });
    });
  }

  // ── Track loaded tabs ────────────────────────────────────────────────────────
  var _loaded = {};
  function loadTab(tab) {
    if (_loaded[tab]) return;
    _loaded[tab] = true;
    var LOADERS = {
      cpu:      loadCPU,
      memory:   loadMemory,
      disk:     loadDisk,
      optimize: loadOptimize,
      bsod:     loadBSOD,
      drivers:  loadDrivers,
    };
    if (LOADERS[tab]) LOADERS[tab]();
  }

  // ── Shared helpers ───────────────────────────────────────────────────────────
  function _loading(panelId) {
    var el = document.getElementById('fr11-tab-' + panelId);
    if (el) el.innerHTML = '<div class="fr11-loading">⏳ Loading…</div>';
  }

  function _error(panelId, msg) {
    var el = document.getElementById('fr11-tab-' + panelId);
    if (el) el.innerHTML = '<div class="fr11-err">❌ ' + _esc(msg) + '</div>';
  }

  function _sevBadge(sev) {
    return '<span class="fr11-sev-badge" style="background:' + _severityBg(sev) +
           ';color:' + _severityColor(sev) + ';border:1px solid ' + _severityColor(sev) + '44">' +
           _esc(sev) + '</span>';
  }

  function _table(headers, rows) {
    if (!rows.length) return '<div class="fr11-empty">No data</div>';
    return '<div class="fr11-table-scroll"><table class="fr11-table"><thead><tr>' +
      headers.map(function(h){ return '<th>' + _esc(h) + '</th>'; }).join('') +
      '</tr></thead><tbody>' +
      rows.map(function(r){ return '<tr>' + r.map(function(c){ return '<td>' + c + '</td>'; }).join('') + '</tr>'; }).join('') +
      '</tbody></table></div>';
  }

  function _panel(title, html, refreshFn) {
    return '<div class="fr11-card">' +
      '<div class="fr11-card-header">' +
        '<span class="fr11-card-title">' + title + '</span>' +
        (refreshFn ? '<button class="fr11-btn-sm" onclick="(' + refreshFn + ')()">↻</button>' : '') +
      '</div>' +
      '<div class="fr11-card-body">' + html + '</div>' +
    '</div>';
  }

  function _bar(pct, color) {
    color = color || '#38bdf8';
    return '<div class="fr11-bar-track"><div class="fr11-bar-fill" style="width:' +
      Math.min(100, pct) + '%;background:' + color + '"></div></div>';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-01 — CPU
  // ══════════════════════════════════════════════════════════════════════════
  function loadCPU() {
    _loading('cpu');
    apiFetch(API.cpu).then(function(d) {
      if (!d.ok) { _error('cpu', d.error); return; }
      var cpu = d.cpu;
      var col = _severityColor(cpu.status);

      // Core pills
      var corePills = (cpu.per_core_percent || []).map(function(v, i) {
        var c = v > 90 ? '#ef4444' : v > 70 ? '#f59e0b' : '#10b981';
        return '<div class="fr11-core-pill"><div class="fr11-core-val" style="color:' + c + '">' +
          v + '%</div><div class="fr11-core-lbl">C' + (i+1) + '</div></div>';
      }).join('');

      // Process table
      var procRows = (d.processes || []).slice(0, 20).map(function(p) {
        var cpuColor = p.cpu_pct > 50 ? '#ef4444' : p.cpu_pct > 20 ? '#f59e0b' : '#b8d0ee';
        return [
          _esc(p.pid),
          '<span style="color:var(--text-bright);font-weight:600">' + _esc(p.name) + '</span>',
          '<span style="color:' + cpuColor + ';font-weight:700">' + p.cpu_pct + '%</span>',
          p.ram_pct + '%',
          _esc(p.status),
          _esc(p.user || '—'),
          p.threads || '—',
        ];
      });

      var html =
        '<div class="fr11-metric-row">' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:' + col + '">' + cpu.total_percent + '%</div><div class="fr11-big-lbl">Total CPU</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + cpu.logical_cores + '</div><div class="fr11-big-lbl">Logical Cores</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + cpu.physical_cores + '</div><div class="fr11-big-lbl">Physical Cores</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + (cpu.frequency_mhz||'—') + '</div><div class="fr11-big-lbl">MHz (current)</div></div>' +
          _sevBadge(cpu.status) +
        '</div>' +
        _bar(cpu.total_percent, col) +
        '<div class="fr11-section-label">Per-Core Usage</div>' +
        '<div class="fr11-cores-grid">' + corePills + '</div>' +
        '<div class="fr11-section-label">Process Breakdown (Top 20 by CPU)</div>' +
        _table(['PID','Name','CPU%','RAM%','Status','User','Threads'], procRows);

      document.getElementById('fr11-tab-cpu').innerHTML =
        _panel('🖥 FR11-01 · CPU Usage + Process Breakdown', html);
    }).catch(function(e){ _error('cpu', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-02 — Memory
  // ══════════════════════════════════════════════════════════════════════════
  function loadMemory() {
    _loading('memory');
    apiFetch(API.memory).then(function(d) {
      if (!d.ok) { _error('memory', d.error); return; }
      var ram = d.ram;
      var pf  = d.page_file;
      var col = _severityColor(ram.status);

      // Page file display
      var pfHtml = '';
      if (pf.available && pf.pagefiles) {
        pfHtml = pf.pagefiles.map(function(p) {
          return '<div class="fr11-kv-row">' +
            '<span class="fr11-kv-key">📄 ' + _esc(p.name) + '</span>' +
            '<span>' +
              '<b style="color:var(--text-bright)">' + p.current_mb + ' MB used</b> / ' +
              p.allocated_mb + ' MB allocated (' + p.percent + '%)' +
              ' — Peak: ' + p.peak_mb + ' MB' +
            '</span></div>';
        }).join('');
      } else if (pf.swap_fallback) {
        var sw = pf.swap_fallback;
        pfHtml = '<div class="fr11-kv-row"><span class="fr11-kv-key">Page File (swap)</span>' +
          '<span><b style="color:var(--text-bright)">' + sw.used_mb + ' MB used</b> / ' +
          sw.total_mb + ' MB (' + sw.percent + '%)</span></div>';
      } else {
        pfHtml = '<div class="fr11-empty">' + _esc(pf.error || 'Page file data unavailable — install: pip install wmi') + '</div>';
      }

      // Top RAM process table
      var procRows = (d.top_ram_procs || []).slice(0,10).map(function(p) {
        var rc = p.rss_mb > 500 ? '#ef4444' : p.rss_mb > 200 ? '#f59e0b' : '#b8d0ee';
        return [
          _esc(p.pid),
          '<span style="color:var(--text-bright);font-weight:600">' + _esc(p.name) + '</span>',
          '<span style="color:' + rc + ';font-weight:700">' + p.rss_mb + ' MB</span>',
          p.vms_mb + ' MB',
          p.ram_pct + '%',
        ];
      });

      var html =
        '<div class="fr11-metric-row">' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:' + col + '">' + ram.percent + '%</div><div class="fr11-big-lbl">RAM Used</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + ram.used_gb + ' GB</div><div class="fr11-big-lbl">Used</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + ram.available_gb + ' GB</div><div class="fr11-big-lbl">Available</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + ram.total_gb + ' GB</div><div class="fr11-big-lbl">Total RAM</div></div>' +
          _sevBadge(ram.status) +
        '</div>' +
        _bar(ram.percent, col) +
        '<div class="fr11-section-label">📄 Page File (Virtual Memory / Swap)</div>' +
        '<div class="fr11-kv-block">' + pfHtml + '</div>' +
        '<div class="fr11-section-label">Top RAM Consumers</div>' +
        _table(['PID','Name','RSS (Physical)','VMS (Virtual)','RAM%'], procRows);

      document.getElementById('fr11-tab-memory').innerHTML =
        _panel('💾 FR11-02 · RAM + Page File Usage', html);
    }).catch(function(e){ _error('memory', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-03 — Disk Health + SMART
  // ══════════════════════════════════════════════════════════════════════════
  function loadDisk() {
    _loading('disk');
    apiFetch(API.disk).then(function(d) {
      if (!d.ok) { _error('disk', d.error); return; }
      var oc = _severityColor(d.overall_health);

      // SMART disks
      var smartHtml = '';
      if (d.smart.error && !d.smart.disks.length) {
        smartHtml = '<div class="fr11-warn-box">⚠ SMART: ' + _esc(d.smart.error) +
                    '<br>Install: <code>pip install wmi</code></div>';
      } else {
        smartHtml = (d.smart.disks || []).map(function(disk) {
          var hc = _severityColor(disk.health);
          return '<div class="fr11-disk-card">' +
            '<div class="fr11-disk-header">' +
              '<span style="color:var(--text-bright);font-weight:700">' + _esc(disk.model || disk.device_id) + '</span>' +
              '<span class="fr11-sev-badge" style="background:' + _severityBg(disk.health) +
                ';color:' + hc + ';border:1px solid ' + hc + '44">' + _esc(disk.health) + '</span>' +
            '</div>' +
            '<div class="fr11-kv-row"><span class="fr11-kv-key">Status</span><span>' + _esc(disk.status) + '</span></div>' +
            '<div class="fr11-kv-row"><span class="fr11-kv-key">Size</span><span>' + disk.size_gb + ' GB</span></div>' +
            '<div class="fr11-kv-row"><span class="fr11-kv-key">Interface</span><span>' + _esc(disk.interface) + '</span></div>' +
            '<div class="fr11-kv-row"><span class="fr11-kv-key">Media Type</span><span>' + _esc(disk.media_type) + '</span></div>' +
            (disk.smart_predict_failure !== undefined ?
              '<div class="fr11-kv-row"><span class="fr11-kv-key">SMART Predict Failure</span>' +
              '<span style="color:' + (disk.smart_predict_failure ? '#ef4444':'#10b981') + ';font-weight:700">' +
              (disk.smart_predict_failure ? '⚠ YES':'✅ No') + '</span></div>' : '') +
          '</div>';
        }).join('') || '<div class="fr11-empty">No disk SMART data (requires admin + pywin32)</div>';
      }

      // Partitions
      var partRows = ((d.io && d.io.partitions) || []).map(function(p) {
        var pc = _severityColor(p.status);
        return [
          _esc(p.device), _esc(p.mountpoint), _esc(p.fstype),
          p.total_gb + ' GB',
          '<span style="color:' + pc + ';font-weight:700">' + p.used_gb + ' GB (' + p.percent + '%)</span>',
          p.free_gb + ' GB',
          _sevBadge(p.status),
        ];
      });

      // Disk error events
      var errRows = (d.disk_event_errors || []).map(function(e) {
        return [_esc(e.timestamp), _esc(e.event_id), _esc(e.source),
                '<span style="color:#f87171">' + _esc(e.level) + '</span>',
                _esc((e.message||'').slice(0,80))];
      });

      var html =
        '<div class="fr11-metric-row">' +
          '<span style="font-size:13px;font-weight:700">Overall Health:</span>' +
          '<span class="fr11-sev-badge" style="background:' + _severityBg(d.overall_health) +
          ';color:' + oc + ';border:1px solid ' + oc + '44;font-size:13px">' + _esc(d.overall_health) + '</span>' +
        '</div>' +
        '<div class="fr11-section-label">🔍 SMART Status (Physical Disks)</div>' +
        smartHtml +
        '<div class="fr11-section-label">💾 Partition Usage</div>' +
        _table(['Device','Mount','FS','Total','Used','Free','Status'], partRows) +
        (d.disk_event_errors && d.disk_event_errors.length ?
          '<div class="fr11-section-label" style="color:#f87171">⚠ Disk Error Events (EIDs 7, 11, 51)</div>' +
          _table(['Time','EID','Source','Level','Message'], errRows) : '');

      document.getElementById('fr11-tab-disk').innerHTML =
        _panel('💿 FR11-03 · Disk Health + SMART Status', html);
    }).catch(function(e){ _error('disk', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-04 — Optimization Recommendations
  // ══════════════════════════════════════════════════════════════════════════
  function loadOptimize() {
    _loading('optimize');
    apiFetch(API.optimize).then(function(d) {
      if (!d.ok) { _error('optimize', d.error); return; }

      var recsHtml = (d.recommendations || []).map(function(r) {
        var col = _severityColor(r.priority);
        return '<div class="fr11-rec-card" style="border-left:3px solid ' + col + '">' +
          '<div class="fr11-rec-header">' +
            '<span class="fr11-sev-badge" style="background:' + _severityBg(r.priority) +
            ';color:' + col + ';border:1px solid ' + col + '44">' + _esc(r.priority) + '</span>' +
            '<span class="fr11-rec-cat">' + _esc(r.category) + '</span>' +
            '<span class="fr11-rec-title">' + _esc(r.title) + '</span>' +
          '</div>' +
          '<div class="fr11-rec-detail">' + _esc(r.detail) + '</div>' +
          '<div class="fr11-rec-action">💡 ' + _esc(r.action) + '</div>' +
        '</div>';
      }).join('');

      // Startup items
      var startupRows = (d.startup_items || []).map(function(s) {
        return [_esc(s.hive), _esc(s.name), _esc((s.command||'').slice(0,60))];
      });

      var html =
        recsHtml +
        '<div class="fr11-section-label" style="margin-top:16px">🚀 Startup Programs (' + (d.startup_items||[]).length + ')</div>' +
        _table(['Hive','Name','Command'], startupRows) +
        '<div class="fr11-section-label">📋 System Details</div>' +
        '<div class="fr11-kv-block">' +
          '<div class="fr11-kv-row"><span class="fr11-kv-key">Power Plan</span><span>' + _esc(d.power_plan||'—') + '</span></div>' +
          '<div class="fr11-kv-row"><span class="fr11-kv-key">Temp Folder</span><span>' +
            (d.temp_folder ? d.temp_folder.size_mb + ' MB (' + d.temp_folder.file_count + ' files)' : '—') +
          '</span></div>' +
        '</div>';

      document.getElementById('fr11-tab-optimize').innerHTML =
        _panel('⚡ FR11-04 · Windows Optimization Recommendations', html);
    }).catch(function(e){ _error('optimize', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-05 — BSOD Risk
  // ══════════════════════════════════════════════════════════════════════════
  function loadBSOD() {
    _loading('bsod');
    apiFetch(API.bsod).then(function(d) {
      if (!d.ok) { _error('bsod', d.error); return; }
      var risk = d.risk;
      var col  = _severityColor(risk.level);
      var pct  = risk.score;

      // Risk score dial
      var dialHtml =
        '<div class="fr11-risk-dial">' +
          '<div class="fr11-risk-score" style="color:' + col + '">' + pct + '</div>' +
          '<div class="fr11-risk-label">/ 100</div>' +
          '<div>' + _sevBadge(risk.level) + '</div>' +
        '</div>' +
        _bar(pct, col);

      // Factors
      var factorsHtml = risk.factors.length ?
        '<ul class="fr11-factors">' +
        risk.factors.map(function(f){ return '<li>' + _esc(f) + '</li>'; }).join('') +
        '</ul>' :
        '<div class="fr11-ok-msg">✅ No BSOD risk factors detected</div>';

      // Crash dump files
      var dumpRows = (d.crash_dumps||[]).map(function(f) {
        return [_esc(f.filename), f.size_kb + ' KB', _esc(f.created)];
      });

      // BSOD event log
      var bsodRows = (d.bsod_events||[]).map(function(e) {
        return [_esc(e.timestamp), _esc(e.event_id), _esc(e.meaning),
                '<span style="color:#f87171">' + _esc(e.level) + '</span>'];
      });

      // WHEA
      var wheaRows = (d.whea_errors||[]).map(function(e) {
        return [_esc(e.timestamp), _esc(e.event_id), _esc(e.source),
                _esc((e.message||'').slice(0,80))];
      });

      var html =
        dialHtml +
        '<div class="fr11-section-label">Risk Factors</div>' + factorsHtml +
        '<div class="fr11-section-label">💾 Crash Dump Files (' + (d.crash_dump_count||0) + ')</div>' +
        '<div class="fr11-kv-row"><span class="fr11-kv-key">Minidump Dir</span><code>' + _esc(d.minidump_dir) + '</code></div>' +
        _table(['File','Size','Created'], dumpRows) +
        '<div class="fr11-section-label">📋 BSOD Event Log (EIDs 1001, 41, 6008)</div>' +
        _table(['Time','EID','Meaning','Level'], bsodRows) +
        (d.whea_errors && d.whea_errors.length ?
          '<div class="fr11-section-label" style="color:#f87171">⚠ WHEA Hardware Errors</div>' +
          _table(['Time','EID','Source','Message'], wheaRows) : '');

      document.getElementById('fr11-tab-bsod').innerHTML =
        _panel('💀 FR11-05 · BSOD Risk Prediction', html);
    }).catch(function(e){ _error('bsod', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FR11-06 — Driver Health
  // ══════════════════════════════════════════════════════════════════════════
  function loadDrivers() {
    _loading('drivers');
    apiFetch(API.drivers).then(function(d) {
      if (!d.ok) { _error('drivers', d.error); return; }
      var oc = _severityColor(d.overall_health);

      // Summary
      var s = d.summary || {};
      var sumHtml =
        '<div class="fr11-metric-row">' +
          '<div class="fr11-big-metric"><div class="fr11-big-val">' + (s.total||0) + '</div><div class="fr11-big-lbl">Total Drivers</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:#10b981">' + (s.running||0) + '</div><div class="fr11-big-lbl">Running</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:#ef4444">' + (s.failed||0) + '</div><div class="fr11-big-lbl">Failed</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:#f59e0b">' + (s.unsigned||0) + '</div><div class="fr11-big-lbl">Unsigned</div></div>' +
          '<div class="fr11-big-metric"><div class="fr11-big-val" style="color:#f97316">' + (s.suspicious||0) + '</div><div class="fr11-big-lbl">Suspicious</div></div>' +
          _sevBadge(d.overall_health) +
        '</div>';

      // Failed drivers
      var failedRows = (d.failed_drivers||[]).map(function(dr) {
        return ['<span style="color:#f87171;font-weight:700">' + _esc(dr.name) + '</span>',
                _esc(dr.display), _esc(dr.state), _esc(dr.start_mode),
                _esc((dr.path||'').slice(0,50))];
      });

      // Unsigned drivers
      var unsignedRows = (d.unsigned_drivers||[]).map(function(dr) {
        return ['<span style="color:#f59e0b;font-weight:700">' + _esc(dr.name) + '</span>',
                _esc(dr.display), _esc(dr.state), _esc((dr.path||'').slice(0,50))];
      });

      // Driver error events
      var errRows = (d.driver_log_errors||[]).map(function(e) {
        return [_esc(e.timestamp), _esc(e.event_id), _esc(e.meaning),
                _esc((e.message||'').slice(0,80))];
      });

      var wmiWarn = d.wmi_error ?
        '<div class="fr11-warn-box">⚠ WMI: ' + _esc(d.wmi_error) + '</div>' : '';

      var html =
        wmiWarn + sumHtml +
        (d.failed_drivers && d.failed_drivers.length ?
          '<div class="fr11-section-label" style="color:#ef4444">❌ Failed Drivers</div>' +
          _table(['Name','Display','State','Start Mode','Path'], failedRows) : '') +
        (d.unsigned_drivers && d.unsigned_drivers.length ?
          '<div class="fr11-section-label" style="color:#f59e0b">⚠ Unsigned Drivers</div>' +
          _table(['Name','Display','State','Path'], unsignedRows) : '') +
        (d.driver_log_errors && d.driver_log_errors.length ?
          '<div class="fr11-section-label" style="color:#f87171">📋 Driver Error Events (EIDs 219, 7026, 10110)</div>' +
          _table(['Time','EID','Meaning','Message'], errRows) : '') +
        (!d.failed_drivers.length && !d.unsigned_drivers.length && !d.driver_log_errors.length ?
          '<div class="fr11-ok-msg">✅ All drivers appear healthy</div>' : '');

      document.getElementById('fr11-tab-drivers').innerHTML =
        _panel('🔧 FR11-06 · Driver Health + Compatibility', html);
    }).catch(function(e){ _error('drivers', e.message); });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Styles
  // ══════════════════════════════════════════════════════════════════════════
  function injectStyles() {
    if (document.getElementById('fr11-styles')) return;
    var s = document.createElement('style');
    s.id = 'fr11-styles';
    s.textContent = [
      '#fr11-health-panel{margin-bottom:24px}',
      '.fr11-tab-bar{display:flex;gap:4px;padding:0 0 0 0;margin-bottom:0;flex-wrap:wrap;background:var(--panel2,#132036);border:1px solid var(--border,#1c2d4a);border-radius:10px 10px 0 0;padding:8px 10px}',
      '.fr11-tab{padding:7px 14px;border-radius:6px;background:transparent;border:none;color:var(--text-mid,#6a90b8);font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;font-family:inherit}',
      '.fr11-tab:hover{background:rgba(26,140,255,.1);color:var(--text-bright,#e4f0ff)}',
      '.fr11-tab.active{background:rgba(26,140,255,.18);color:var(--sky-bright,#4da6ff)}',
      '.fr11-tab-content{background:var(--panel,#0f1a2e);border:1px solid var(--border,#1c2d4a);border-top:none;border-radius:0 0 10px 10px;padding:16px}',
      '.fr11-card{background:transparent}',
      '.fr11-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}',
      '.fr11-card-title{font-size:13px;font-weight:700;color:var(--text-bright,#e4f0ff)}',
      '.fr11-card-body{}',
      '.fr11-loading{color:var(--text-dim,#3d5570);font-size:12px;padding:20px 0}',
      '.fr11-err{color:#f87171;font-size:12px;padding:10px 0}',
      '.fr11-empty{color:var(--text-dim,#3d5570);font-size:11px;padding:6px 0}',
      '.fr11-ok-msg{color:#10b981;font-size:12px;padding:8px 0}',
      '.fr11-warn-box{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#fbbf24;font-size:11px;padding:8px 12px;border-radius:6px;margin-bottom:10px}',
      '.fr11-metric-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:10px}',
      '.fr11-big-metric{display:flex;flex-direction:column;align-items:center}',
      '.fr11-big-val{font-size:28px;font-weight:900;font-family:var(--mono,monospace);line-height:1;color:var(--text-bright,#e4f0ff)}',
      '.fr11-big-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim,#3d5570);margin-top:2px}',
      '.fr11-bar-track{height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden;margin-bottom:14px}',
      '.fr11-bar-fill{height:100%;border-radius:3px;transition:width 1s cubic-bezier(.4,0,.2,1)}',
      '.fr11-section-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim,#3d5570);margin:12px 0 6px;padding-bottom:4px;border-bottom:1px solid var(--border,#1c2d4a)}',
      '.fr11-sev-badge{font-size:10px;font-weight:800;padding:2px 8px;border-radius:10px;letter-spacing:.05em;text-transform:uppercase}',
      '.fr11-btn-sm{font-size:10px;padding:3px 9px;background:transparent;border:1px solid var(--border2,#253e65);color:var(--text-dim);border-radius:4px;cursor:pointer}',
      '.fr11-table-scroll{overflow-x:auto;max-height:260px;overflow-y:auto;margin-bottom:8px}',
      '.fr11-table{width:100%;border-collapse:collapse;font-size:11px}',
      '.fr11-table th{text-align:left;padding:5px 8px;background:var(--panel2,#132036);color:var(--text-dim,#3d5570);font-size:9px;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0;z-index:1}',
      '.fr11-table td{padding:5px 8px;border-bottom:1px solid var(--border,#1c2d4a);vertical-align:top;color:var(--text,#b8d0ee)}',
      '.fr11-table tr:hover td{background:var(--panel2,#132036)}',
      '.fr11-cores-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(60px,1fr));gap:6px;margin-bottom:12px}',
      '.fr11-core-pill{background:var(--bg3,#0d1528);border:1px solid var(--border,#1c2d4a);border-radius:6px;padding:6px 4px;text-align:center}',
      '.fr11-core-val{font-size:13px;font-weight:800;font-family:var(--mono,monospace);line-height:1;margin-bottom:2px}',
      '.fr11-core-lbl{font-size:9px;color:var(--text-dim,#3d5570);text-transform:uppercase;letter-spacing:.05em}',
      '.fr11-kv-block{margin-bottom:10px}',
      '.fr11-kv-row{display:flex;align-items:baseline;gap:10px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;color:var(--text,#b8d0ee);flex-wrap:wrap}',
      '.fr11-kv-key{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--text-dim,#3d5570);min-width:130px;flex-shrink:0}',
      '.fr11-disk-card{background:var(--bg3,#0d1528);border:1px solid var(--border,#1c2d4a);border-radius:8px;padding:12px;margin-bottom:8px}',
      '.fr11-disk-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}',
      '.fr11-rec-card{background:var(--bg3,#0d1528);border:1px solid var(--border,#1c2d4a);border-radius:8px;padding:12px 14px;margin-bottom:8px}',
      '.fr11-rec-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}',
      '.fr11-rec-cat{font-size:10px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em}',
      '.fr11-rec-title{font-size:12px;font-weight:700;color:var(--text-bright,#e4f0ff)}',
      '.fr11-rec-detail{font-size:11px;color:var(--text,#b8d0ee);margin-bottom:5px;line-height:1.6}',
      '.fr11-rec-action{font-size:11px;color:#38bdf8;line-height:1.6}',
      '.fr11-risk-dial{display:flex;align-items:center;gap:14px;margin-bottom:10px}',
      '.fr11-risk-score{font-size:56px;font-weight:900;font-family:var(--mono,monospace);line-height:1}',
      '.fr11-risk-label{font-size:14px;color:var(--text-dim);margin-top:10px}',
      '.fr11-factors{list-style:none;padding:0;margin:0}',
      '.fr11-factors li{padding:5px 0;font-size:12px;color:var(--text,#b8d0ee);border-bottom:1px solid rgba(255,255,255,.04);padding-left:14px;position:relative}',
      '.fr11-factors li::before{content:"→";position:absolute;left:0;color:var(--text-dim)}',
      'code{font-family:var(--mono,monospace);font-size:11px;background:rgba(26,140,255,.08);color:#38bdf8;padding:1px 5px;border-radius:3px}',
    ].join('');
    document.head.appendChild(s);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Init
  // ══════════════════════════════════════════════════════════════════════════
  function init() {
    var container = document.getElementById('fr11-health-panel');
    if (!container) return;
    injectStyles();
    buildShell(container);
    loadTab('cpu');  // load first tab immediately
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.FR11 = { reload: function(tab) { _loaded = {}; loadTab(tab || 'cpu'); } };
})();
