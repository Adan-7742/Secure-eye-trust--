/* ============================================================================
 * pa_quick_fixes.js — frontend fixes for Perform Analysis
 * ----------------------------------------------------------------------------
 * 1. Defines window.paExport(reportId, format) so the "⬇ PDF" and "⬇ JSON"
 *    download buttons in the report header actually work.
 * 2. Injects CSS to make the LOGS → SYSMON → FILES SCANNED → THREAT DETECTOR
 *    → MALWARE CORR. → RISK SCORE pipeline strip much larger and easier to
 *    read on a dashboard.  Targets the existing .ur-pipeline / .ur-pipe-node
 *    classes (defined in static/css/main.css).
 * 3. Fixes the scan-progress ticker so the "X files inspected" number stops
 *    when the API returns and is replaced with the real value from the
 *    report's files_scanned field.
 * ==========================================================================*/
(function () {
  'use strict';

  // ───────────────────────────────────────────────────────────────────────────
  // 1.  paExport — PDF + JSON download
  // ───────────────────────────────────────────────────────────────────────────
  window.paExport = function (reportId, format) {
    if (!reportId) {
      alert('No report ID available. Re-run analysis first.');
      return;
    }
    var fmt = (format || '').toLowerCase();

    // ── PDF: try the known report-pdf endpoints ─────────────────────────────
    if (fmt === 'pdf') {
      var pdfCandidates = [
        '/api/perform-analysis/export/' + encodeURIComponent(reportId) + '/pdf',
        '/api/reports/'                 + encodeURIComponent(reportId) + '/pdf',
        '/api/reports/pdf/'             + encodeURIComponent(reportId),
        '/api/analysis/'                + encodeURIComponent(reportId) + '/pdf',
      ];
      _tryDownloadPdf(pdfCandidates);
      return;
    }

    // ── JSON: fetch the report object and save it client-side ───────────────
    if (fmt === 'json') {
      var jsonCandidates = [
        '/api/reports/'          + encodeURIComponent(reportId),
        '/api/reports/get/'      + encodeURIComponent(reportId),
        '/api/perform-analysis/' + encodeURIComponent(reportId),
        '/api/analysis/report/'  + encodeURIComponent(reportId),
      ];
      _tryDownloadJson(jsonCandidates, reportId);
      return;
    }
    console.warn('paExport: unknown format', format);
  };

  function _tryDownloadPdf(urls) {
    (function next(i) {
      if (i >= urls.length) {
        if (confirm(
          'PDF endpoint not found on this server.\n\n' +
          'Click OK to open the print dialog instead — you can then choose ' +
          '"Save as PDF" in the printer list.'
        )) { window.print(); }
        return;
      }
      fetch(urls[i], { method: 'HEAD' })
        .then(function (r) {
          if (r.ok || r.status === 405) {
            // 405 = method not allowed but the GET still works
            window.open(urls[i], '_blank');
          } else { next(i + 1); }
        })
        .catch(function () { next(i + 1); });
    })(0);
  }

  function _tryDownloadJson(urls, reportId) {
    (function next(i) {
      if (i >= urls.length) {
        // Last resort: save whatever the page currently has loaded
        var fallback = window._paLastReport || window._paCurrentReport ||
                       window.paReport || null;
        if (fallback) {
          _saveBlob(JSON.stringify(fallback, null, 2),
                    'security-report-' + reportId + '.json', 'application/json');
          return;
        }
        alert('JSON endpoint not found on this server.');
        return;
      }
      fetch(urls[i])
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (data) {
          _saveBlob(JSON.stringify(data, null, 2),
                    'security-report-' + reportId + '.json', 'application/json');
        })
        .catch(function () { next(i + 1); });
    })(0);
  }

  function _saveBlob(text, filename, mime) {
    var blob = new Blob([text], { type: mime || 'application/octet-stream' });
    var url  = URL.createObjectURL(blob);
    var a    = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }


  // ───────────────────────────────────────────────────────────────────────────
  // 2.  Bigger, more readable pipeline strip
  //
  //     The strip's HTML structure is:
  //       <div class="ur-pipeline">
  //         <div class="ur-pipe-node">
  //           <span class="ur-pipe-icon">🗂</span>
  //           <span class="ur-pipe-label">Logs</span>
  //           <span class="ur-pipe-count">147,433</span>
  //         </div>
  //         <div class="ur-pipe-arrow">→</div>
  //         …
  //       </div>
  // ───────────────────────────────────────────────────────────────────────────
  function injectPipelineCss() {
    if (document.getElementById('pa-pipeline-fix-style')) return;
    var css = [
      // Container — more padding, breathing room between nodes
      '.ur-pipeline {',
      '  padding: 22px 22px !important;',
      '  gap: 6px !important;',
      '  border-radius: 16px !important;',
      '  background: linear-gradient(180deg, rgba(0,8,18,.85) 0%, rgba(0,8,18,.55) 100%) !important;',
      '  border: 1px solid rgba(0,229,255,.15) !important;',
      '  box-shadow: 0 6px 24px rgba(0,0,0,.35), inset 0 0 0 1px rgba(255,255,255,.03) !important;',
      '}',

      // Each node — much bigger card with proper spacing
      '.ur-pipe-node {',
      '  min-width: 170px !important;',
      '  min-height: 130px !important;',
      '  padding: 20px 18px !important;',
      '  gap: 10px !important;',
      '  border-radius: 14px !important;',
      '  border: 1px solid rgba(255,255,255,.10) !important;',
      '  background: linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.015)) !important;',
      '  box-shadow: 0 2px 10px rgba(0,0,0,.25), inset 0 1px 0 rgba(255,255,255,.04) !important;',
      '  transition: transform .15s ease, box-shadow .15s ease !important;',
      '}',
      '.ur-pipe-node:hover {',
      '  transform: translateY(-2px) !important;',
      '  box-shadow: 0 8px 20px rgba(0,229,255,.18), inset 0 1px 0 rgba(255,255,255,.06) !important;',
      '}',

      // Risk node — strongest highlight
      '.ur-pipe-node--risk {',
      '  border-color: rgba(0,255,136,.4) !important;',
      '  background: linear-gradient(180deg, rgba(0,255,136,.10), rgba(0,255,136,.025)) !important;',
      '  box-shadow: 0 4px 18px rgba(0,255,136,.18), inset 0 0 0 1px rgba(0,255,136,.15) !important;',
      '}',

      // Icon — much larger
      '.ur-pipe-icon {',
      '  font-size: 30px !important;',
      '  line-height: 1 !important;',
      '  margin-bottom: 2px !important;',
      '}',

      // Label — clearer & more spaced
      '.ur-pipe-label {',
      '  font-size: 10px !important;',
      '  letter-spacing: 0.16em !important;',
      '  color: rgba(255,255,255,.55) !important;',
      '  font-weight: 700 !important;',
      '  white-space: nowrap !important;',
      '}',

      // Value — large and prominent
      '.ur-pipe-count {',
      '  font-size: 22px !important;',
      '  font-weight: 800 !important;',
      '  line-height: 1.1 !important;',
      '  letter-spacing: -0.01em !important;',
      '}',

      // Arrows between nodes — bigger and more visible
      '.ur-pipe-arrow {',
      '  font-size: 26px !important;',
      '  color: rgba(0,229,255,.45) !important;',
      '  padding: 0 8px !important;',
      '  font-weight: 600 !important;',
      '}',

      // Download buttons (PDF / JSON) — slightly larger
      '#pa-download-btns button {',
      '  font-size: 13px !important;',
      '  padding: 10px 18px !important;',
      '  border-radius: 9px !important;',
      '}',

      // Responsive: wrap on narrow screens
      '@media (max-width: 1100px) {',
      '  .ur-pipeline { flex-wrap: wrap !important; }',
      '  .ur-pipe-arrow { display: none !important; }',
      '  .ur-pipe-node { min-width: 140px !important; flex: 1 1 140px !important; }',
      '}',
    ].join('\n');

    var style = document.createElement('style');
    style.id = 'pa-pipeline-fix-style';
    style.textContent = css;
    document.head.appendChild(style);
  }


  // ───────────────────────────────────────────────────────────────────────────
  // 3.  Sync the "X files inspected" ticker with the real value
  //
  //     The page has a fake counter that increments every 170ms during the
  //     scan animation. That's why it shows e.g. 192 while the actual
  //     scanner only inspected 93 files. After the report comes back we
  //     overwrite the ticker text with the real count from r.files_scanned.
  // ───────────────────────────────────────────────────────────────────────────
  function syncRealFilesScanned() {
    var realEl   = document.getElementById('urp-files-count');
    var tickerEl = document.getElementById('pa-file-ticker-count');
    if (!realEl) return;

    var sync = function () {
      var v = (realEl.textContent || '').trim();
      // Don't sync the placeholder dash or any non-numeric label
      if (!v || v === '—' || /[a-zA-Z]/.test(v.replace(/[, ]/g, ''))) return;
      if (tickerEl) tickerEl.textContent = v + ' files inspected';
    };

    sync(); // Initial sync if already set

    try {
      new MutationObserver(sync).observe(realEl, {
        characterData: true, childList: true, subtree: true,
      });
    } catch (e) { /* old browser; ignore */ }
  }


  // ── Boot ─────────────────────────────────────────────────────────────────
  function boot() {
    injectPipelineCss();
    syncRealFilesScanned();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
