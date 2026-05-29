/**
 * rag_analysis.js — Secure Eye Trust+
 * =====================================
 * Frontend integration for the RAG analysis endpoint.
 * Adds "RAG Deep Analysis" capability to the Perform Analysis section.
 *
 * Usage in perform_analysis.js / index.html:
 *   <script src="/static/js/rag_analysis.js"></script>
 *   ragAnalyzeLog(logText);          // analyze a single log
 *   ragAnalyzeReport(reportObject);  // analyze all threats in a report
 */

/* ── Config ──────────────────────────────────────────────────────────────── */

var RAG_API = {
  analyze:    "/api/rag-analysis",
  bulk:       "/api/rag-analysis/bulk",
  indexLogs:  "/api/rag-analysis/index-logs",
  status:     "/api/rag-analysis/status",
  retrieve:   "/api/rag-analysis/retrieve",
};

/* ── Severity helpers ─────────────────────────────────────────────────────── */

var RAG_SEV_COLOR = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#f59e0b",
  LOW:      "#4ade80",
  INFO:     "#38bdf8",
};

var RAG_SEV_BG = {
  CRITICAL: "rgba(239,68,68,.10)",
  HIGH:     "rgba(249,115,22,.10)",
  MEDIUM:   "rgba(245,158,11,.10)",
  LOW:      "rgba(74,222,128,.08)",
  INFO:     "rgba(56,189,248,.08)",
};

function ragSevColor(sev) { return RAG_SEV_COLOR[sev] || "#94a3b8"; }
function ragSevBg(sev)    { return RAG_SEV_BG[sev]    || "rgba(148,163,184,.06)"; }

/* ── Single log analysis ──────────────────────────────────────────────────── */

/**
 * Analyze a single log entry via RAG.
 * @param {string|Object} log  — log text or log object
 * @param {Array}         ctx  — optional surrounding log lines
 * @returns {Promise<Object>}
 */
async function ragAnalyzeLog(log, ctx) {
  var body = { log: log, k: 5 };
  if (ctx && ctx.length) body.context_logs = ctx;

  var resp = await fetch(RAG_API.analyze, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body),
  });
  if (!resp.ok) throw new Error("RAG API error: " + resp.status);
  return resp.json();
}

/* ── Bulk analysis from perform-analysis report ─────────────────────────── */

/**
 * Run RAG analysis on all threat hits in a Perform Analysis report.
 * @param {Object} report   — report object from /api/perform-analysis
 * @param {Function} onResult — called for each result as they come back
 * @returns {Promise<Array>}
 */
async function ragAnalyzeReport(report, onResult) {
  var threats = report.threat_hits || [];
  if (!threats.length) return [];

  // Build log strings from threat evidence + name
  var logs = threats.map(function (h) {
    return (
      "[" + h.severity + "] " + h.name +
      " — Count: " + h.count +
      " — Last: " + (h.latest || "") +
      " — EventIDs: " + (h.event_ids || []).join(",") +
      " — " + (h.evidence || []).join("; ")
    );
  });

  var resp = await fetch(RAG_API.bulk, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ logs: logs, k: 3 }),
  });
  if (!resp.ok) throw new Error("RAG Bulk API error: " + resp.status);
  var data = await resp.json();
  if (data.ok && onResult) data.results.forEach(onResult);
  return data.results || [];
}

/* ── Render a single RAG result card ─────────────────────────────────────── */

/**
 * Render a RAG analysis result as an HTML card.
 * @param {Object} result  — result from ragAnalyzeLog
 * @param {string} title   — optional card title (defaults to log snippet)
 * @returns {string} HTML string
 */
function ragRenderCard(result, title) {
  if (!result || !result.ok) {
    return '<div class="rag-card rag-error">RAG analysis unavailable</div>';
  }

  var sev      = result.severity || "MEDIUM";
  var color    = ragSevColor(sev);
  var bg       = ragSevBg(sev);
  var mitre    = (result.mitre || []).map(function (m) {
    return '<span class="rag-mitre-badge" title="' + m.tactic + '">' + m.id + ' · ' + m.technique + '</span>';
  }).join("");

  var actions  = (result.recommended_actions || []).map(function (a) {
    return '<li class="rag-action-item">→ ' + _ragEsc(a) + '</li>';
  }).join("");

  var cardTitle = title || _ragEsc((result.log || "").substring(0, 80)) + "…";

  return (
    '<div class="rag-card" style="border-left: 3px solid ' + color + '; background: ' + bg + ';">' +
      '<div class="rag-card-header">' +
        '<span class="rag-sev-badge" style="color:' + color + '; border-color:' + color + '44;">' + sev + '</span>' +
        '<span class="rag-card-title">' + cardTitle + '</span>' +
        '<span class="rag-elapsed">' + (result.elapsed_s || 0) + 's</span>' +
      '</div>' +

      (mitre ? '<div class="rag-mitre-row">' + mitre + '</div>' : '') +

      '<p class="rag-description">' + _ragEsc(result.attack_description || "") + '</p>' +

      (actions
        ? '<div class="rag-actions-section"><div class="rag-actions-title">Recommended Actions</div><ul class="rag-actions-list">' + actions + '</ul></div>'
        : '') +

      '<div class="rag-footer">' +
        'Vector store: ' + (result.retrieval_stats ? result.retrieval_stats.store_size : '?') + ' docs · ' +
        'Keyword matches: ' + (result.retrieval_stats ? result.retrieval_stats.keyword_matches : '?') +
      '</div>' +
    '</div>'
  );
}

/* ── Inject RAG panel into Perform Analysis page ─────────────────────────── */

/**
 * Add "RAG Deep Analysis" button + panel to the perform analysis section.
 * Call this after _paRender() has already rendered the report.
 * @param {Object} report — the perform-analysis report object
 */
function ragInjectPanel(report) {
  // Don't inject twice
  if (document.getElementById("rag-panel")) return;

  var anchor = document.getElementById("pa-recommendations") ||
               document.getElementById("pa-threat-list")     ||
               document.querySelector(".pa-section-threats")  ||
               document.querySelector(".pa-report-body");

  if (!anchor) return;

  // Create panel wrapper
  var panel = document.createElement("div");
  panel.id  = "rag-panel";
  panel.innerHTML = [
    '<div class="rag-panel-header">',
      '<span class="rag-panel-icon">🧠</span>',
      '<span class="rag-panel-title">RAG Deep Analysis</span>',
      '<span class="rag-panel-sub">Retrieval-Augmented Generation · Groq LLaMA 3.3 70B · MITRE ATT&CK</span>',
      '<button class="rag-run-btn" id="rag-run-btn" onclick="ragRunFromReport()">',
        '<span>▶</span> Analyze with RAG',
      '</button>',
    '</div>',
    '<div id="rag-results-area" class="rag-results-area" style="display:none;"></div>',
  ].join("");

  // Insert after the anchor element
  anchor.parentNode.insertBefore(panel, anchor.nextSibling);

  // Store report reference for later
  window._ragCurrentReport = report;

  // Inject styles once
  _ragInjectStyles();
}

/**
 * Called when user clicks "Analyze with RAG".
 */
async function ragRunFromReport() {
  var report = window._ragCurrentReport;
  if (!report) return;

  var btn  = document.getElementById("rag-run-btn");
  var area = document.getElementById("rag-results-area");
  if (!btn || !area) return;

  btn.disabled   = true;
  btn.innerHTML  = '<span class="rag-spinner">⟳</span> Analyzing…';
  area.style.display = "block";
  area.innerHTML = '<div class="rag-loading">Retrieving context · Building prompt · Calling Groq LLaMA…</div>';

  try {
    var threats = report.threat_hits || [];
    if (!threats.length) {
      area.innerHTML = '<div class="rag-empty">No threat hits to analyze.</div>';
      btn.disabled  = false;
      btn.innerHTML = '▶ Analyze with RAG';
      return;
    }

    area.innerHTML = "";
    var done = 0;

    await ragAnalyzeReport(report, function (result) {
      done++;
      var threat = threats[done - 1] || {};
      var title  = _ragEsc(threat.name || ("Threat #" + done));
      var card   = document.createElement("div");
      card.innerHTML = ragRenderCard(result, title);
      area.appendChild(card.firstChild || card);
    });

    btn.disabled  = false;
    btn.innerHTML = '🔄 Re-analyze';

  } catch (err) {
    area.innerHTML = '<div class="rag-error">RAG error: ' + _ragEsc(err.message) + '</div>';
    btn.disabled   = false;
    btn.innerHTML  = '▶ Retry';
  }
}

/* ── Status check ─────────────────────────────────────────────────────────── */

async function ragCheckStatus() {
  var resp = await fetch(RAG_API.status);
  return resp.json();
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function _ragEsc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function _ragInjectStyles() {
  if (document.getElementById("rag-styles")) return;
  var s = document.createElement("style");
  s.id  = "rag-styles";
  s.textContent = `
    /* ── RAG Panel ─────────────────────────────────── */
    #rag-panel {
      margin: 18px 0;
      border-radius: 12px;
      background: #0d1525;
      border: 1px solid rgba(26,140,255,.25);
      overflow: hidden;
    }
    .rag-panel-header {
      display: flex; align-items: center; gap: 10px;
      padding: 14px 18px;
      background: rgba(26,140,255,.06);
      border-bottom: 1px solid rgba(26,140,255,.15);
      flex-wrap: wrap;
    }
    .rag-panel-icon  { font-size: 20px; }
    .rag-panel-title { font-size: 15px; font-weight: 700; color: #e2e8f0; }
    .rag-panel-sub   { font-size: 11px; color: #64748b; flex: 1; }
    .rag-run-btn {
      padding: 7px 16px; border-radius: 8px; border: 1px solid #1a8cff55;
      background: rgba(26,140,255,.12); color: #4da6ff;
      font-size: 12px; font-weight: 700; cursor: pointer;
      transition: background .15s;
    }
    .rag-run-btn:hover:not(:disabled) { background: rgba(26,140,255,.22); }
    .rag-run-btn:disabled { opacity: .5; cursor: not-allowed; }
    .rag-spinner { display: inline-block; animation: rag-spin .8s linear infinite; }
    @keyframes rag-spin { to { transform: rotate(360deg); } }

    /* ── Results area ────────────────────────────────── */
    .rag-results-area { padding: 14px 16px; display: flex; flex-direction: column; gap: 12px; }
    .rag-loading { color: #64748b; font-size: 13px; text-align: center; padding: 18px; }
    .rag-empty   { color: #64748b; font-size: 13px; text-align: center; padding: 12px; }
    .rag-error   { color: #ef4444; font-size: 12px; padding: 10px; }

    /* ── Card ────────────────────────────────────────── */
    .rag-card {
      border-radius: 9px; padding: 13px 15px;
      border: 1px solid rgba(255,255,255,.06);
    }
    .rag-card-header {
      display: flex; align-items: center; gap: 10px; margin-bottom: 8px;
    }
    .rag-sev-badge {
      font-size: 10px; font-weight: 800; padding: 2px 8px;
      border-radius: 20px; border: 1px solid;
      text-transform: uppercase; letter-spacing: .04em;
      white-space: nowrap;
    }
    .rag-card-title { font-size: 13px; color: #cbd5e1; flex: 1; }
    .rag-elapsed    { font-size: 10px; color: #475569; white-space: nowrap; }

    .rag-mitre-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
    .rag-mitre-badge {
      font-size: 10px; padding: 2px 8px; border-radius: 20px;
      background: rgba(167,139,250,.12); color: #c4b5fd;
      border: 1px solid rgba(167,139,250,.25);
    }

    .rag-description {
      font-size: 13px; color: #94a3b8; line-height: 1.55; margin-bottom: 10px;
    }
    .rag-actions-section { margin-top: 8px; }
    .rag-actions-title   { font-size: 10px; color: #475569; text-transform: uppercase;
                           letter-spacing: .06em; margin-bottom: 5px; font-weight: 700; }
    .rag-actions-list    { list-style: none; padding: 0; margin: 0; display: flex;
                           flex-direction: column; gap: 4px; }
    .rag-action-item     { font-size: 12px; color: #cbd5e1; padding: 4px 8px;
                           background: rgba(255,255,255,.03); border-radius: 5px; }
    .rag-footer          { font-size: 10px; color: #334155; margin-top: 10px;
                           padding-top: 8px; border-top: 1px solid rgba(255,255,255,.05); }
  `;
  document.head.appendChild(s);
}
