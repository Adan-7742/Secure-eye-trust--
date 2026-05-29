/* ============================================================================
 * pa_fix_all.js  —  ONE-CLICK "Fix All Threats" patch for Perform Analysis
 * ----------------------------------------------------------------------------
 * What this file adds (purely additive — does NOT touch existing functions):
 *
 *   1. DEDUPE — file_drops + yara_hits that point at the same path were
 *      rendered as two cards (SET_TEST_payload.exe shows up twice). We
 *      patch _paRenderActiveResponse to collapse those duplicates by path.
 *
 *   2. BIG "FIX ALL THREATS" BUTTON — appended to the bottom of the
 *      Active Response panel whenever there is ≥1 actionable threat.
 *      Click → confirm modal → POST /api/action/fix-all → live progress
 *      → auto re-run analysis → "System Secure" hero when clean.
 *
 *   3. KILL-PROCESS RETRY HARDENING — when a process card's kill failed
 *      with "process not found", flip the card to "✅ Already gone"
 *      instead of leaving a useless Retry button there.
 *
 *   4. SYSTEM SECURE STATE — when the post-fix analysis returns 0
 *      actionable threats, the Active Response panel renders a clean
 *      hero card instead of the empty-state line.
 *
 * Loaded once at the end of templates/index.html, after perform_analysis.js
 * and pa_quick_fixes.js — no other code paths are aware of it.
 * ==========================================================================*/
(function () {
  'use strict';

  // ────────────────────────────────────────────────────────────────────────
  // STYLES
  // ────────────────────────────────────────────────────────────────────────
  function injectCSS() {
    if (document.getElementById('pa-fix-all-css')) return;
    var s = document.createElement('style');
    s.id = 'pa-fix-all-css';
    s.textContent = [
      // ── Fix-All CTA bar ──────────────────────────────────────────────
      '.fxall-bar{margin-top:18px;padding:18px 20px;border-radius:14px;',
      '  border:1px solid rgba(239,68,68,.28);',
      '  background:linear-gradient(135deg,rgba(239,68,68,.08) 0%,rgba(251,146,60,.06) 100%);',
      '  display:flex;align-items:center;gap:16px;flex-wrap:wrap;',
      '  box-shadow:0 4px 18px rgba(239,68,68,.12), inset 0 1px 0 rgba(255,255,255,.04)}',
      '.fxall-bar-left{flex:1;min-width:240px}',
      '.fxall-bar-title{font-size:14px;font-weight:800;color:#fca5a5;letter-spacing:.02em}',
      '.fxall-bar-sub{font-size:12px;color:#94a3b8;margin-top:3px;line-height:1.5}',
      '.fxall-bar-counts{font-family:JetBrains Mono,Consolas,monospace;font-size:11px;',
      '  color:#fbbf24;margin-top:6px;letter-spacing:.04em}',
      '.fxall-btn{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);',
      '  color:#fff;border:none;padding:14px 28px;border-radius:11px;cursor:pointer;',
      '  font-size:14px;font-weight:800;letter-spacing:.04em;',
      '  box-shadow:0 6px 22px rgba(239,68,68,.45), inset 0 1px 0 rgba(255,255,255,.15);',
      '  transition:transform .12s ease, box-shadow .12s ease;display:inline-flex;align-items:center;gap:8px}',
      '.fxall-btn:hover{transform:translateY(-1px);box-shadow:0 10px 28px rgba(239,68,68,.6)}',
      '.fxall-btn:active{transform:translateY(0)}',
      '.fxall-btn:disabled{cursor:not-allowed;opacity:.55;transform:none;box-shadow:none}',
      '.fxall-btn-quar{background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);',
      '  box-shadow:0 6px 22px rgba(245,158,11,.45), inset 0 1px 0 rgba(255,255,255,.15)}',
      '.fxall-btn-quar:hover{box-shadow:0 10px 28px rgba(245,158,11,.6)}',
      // ── Confirm modal ────────────────────────────────────────────────
      '.fxall-overlay{position:fixed;inset:0;z-index:10001;',
      '  background:rgba(0,0,0,.68);backdrop-filter:blur(6px);',
      '  display:flex;align-items:center;justify-content:center;',
      '  animation:fxall-fadein .15s ease both}',
      '@keyframes fxall-fadein{from{opacity:0}to{opacity:1}}',
      '.fxall-modal{background:#0d1626;border:1px solid rgba(255,255,255,.1);',
      '  border-radius:14px;max-width:560px;width:92%;padding:22px 24px;',
      '  box-shadow:0 24px 64px rgba(0,0,0,.6)}',
      '.fxall-modal-title{font-size:18px;font-weight:800;color:#fff;margin-bottom:4px}',
      '.fxall-modal-sub{font-size:12.5px;color:#94a3b8;line-height:1.6;margin-bottom:16px}',
      '.fxall-modal-summary{background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);',
      '  border-radius:10px;padding:12px 14px;margin-bottom:14px;font-size:12.5px;color:#cbd5e1;line-height:1.7}',
      '.fxall-modal-summary code{color:#fbbf24;background:rgba(251,191,36,.08);',
      '  padding:1px 6px;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:11.5px}',
      '.fxall-modal-input{width:100%;background:rgba(255,255,255,.04);',
      '  border:1px solid rgba(255,255,255,.1);border-radius:8px;',
      '  padding:10px 12px;color:#fff;font-size:13px;font-family:inherit;',
      '  margin-bottom:6px;box-sizing:border-box}',
      '.fxall-modal-input:focus{outline:none;border-color:rgba(239,68,68,.45);',
      '  box-shadow:0 0 0 3px rgba(239,68,68,.12)}',
      '.fxall-modal-hint{font-size:11px;color:#64748b;margin-bottom:14px;line-height:1.55}',
      '.fxall-modal-row{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:14px}',
      '.fxall-modal-btn{padding:10px 18px;border-radius:9px;font-size:12.5px;',
      '  font-weight:700;cursor:pointer;border:1px solid transparent;letter-spacing:.02em}',
      '.fxall-modal-btn--cancel{background:rgba(255,255,255,.04);color:#cbd5e1;',
      '  border-color:rgba(255,255,255,.08)}',
      '.fxall-modal-btn--cancel:hover{background:rgba(255,255,255,.08)}',
      '.fxall-modal-btn--ok{background:#ef4444;color:#fff;border-color:#ef4444}',
      '.fxall-modal-btn--ok:hover{background:#dc2626}',
      '.fxall-modal-btn--ok-quar{background:#f59e0b;border-color:#f59e0b}',
      '.fxall-modal-btn--ok-quar:hover{background:#d97706}',
      // ── Progress bar ─────────────────────────────────────────────────
      '.fxall-prog-wrap{margin-top:14px;background:rgba(255,255,255,.04);',
      '  border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px 16px}',
      '.fxall-prog-row{display:flex;justify-content:space-between;align-items:center;',
      '  margin-bottom:10px;font-size:12px;color:#cbd5e1;font-family:JetBrains Mono,monospace}',
      '.fxall-prog-bar{height:8px;background:rgba(255,255,255,.04);',
      '  border-radius:5px;overflow:hidden}',
      '.fxall-prog-fill{height:100%;background:linear-gradient(90deg,#10b981,#34d399);',
      '  border-radius:5px;width:0%;transition:width .35s ease}',
      // ── System Secure hero ───────────────────────────────────────────
      '.fxall-secure{padding:32px 28px;border-radius:14px;text-align:center;',
      '  border:1px solid rgba(34,197,94,.32);',
      '  background:linear-gradient(135deg,rgba(34,197,94,.10) 0%,rgba(16,185,129,.05) 100%);',
      '  box-shadow:0 4px 22px rgba(34,197,94,.18), inset 0 1px 0 rgba(255,255,255,.04)}',
      '.fxall-secure-icon{font-size:56px;line-height:1;margin-bottom:14px;',
      '  filter:drop-shadow(0 0 18px rgba(34,197,94,.5));animation:fxall-pulse 2.4s ease-in-out infinite}',
      '@keyframes fxall-pulse{0%,100%{filter:drop-shadow(0 0 12px rgba(34,197,94,.4))}',
      '  50%{filter:drop-shadow(0 0 24px rgba(34,197,94,.8))}}',
      '.fxall-secure-title{font-size:22px;font-weight:900;color:#34d399;',
      '  letter-spacing:.02em;margin-bottom:6px}',
      '.fxall-secure-sub{font-size:13px;color:#a7f3d0;line-height:1.6;max-width:480px;',
      '  margin:0 auto 18px;letter-spacing:.01em}',
      '.fxall-secure-stats{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;',
      '  margin:10px 0 18px}',
      '.fxall-secure-stat{background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.2);',
      '  padding:8px 14px;border-radius:8px;font-size:11.5px;color:#86efac;',
      '  font-family:JetBrains Mono,monospace;letter-spacing:.03em}',
      '.fxall-secure-rebtn{background:rgba(34,197,94,.1);color:#86efac;',
      '  border:1px solid rgba(34,197,94,.35);padding:10px 22px;border-radius:10px;',
      '  cursor:pointer;font-size:12.5px;font-weight:700;letter-spacing:.03em;',
      '  transition:all .15s ease}',
      '.fxall-secure-rebtn:hover{background:rgba(34,197,94,.18);transform:translateY(-1px)}',
      // ── Review Required panel (cards visible but no actionable target) ─
      //   Amber instead of green/red — this is "stop and look", not
      //   "everything is fine" and not "press the button to fix".
      '.fxall-review{padding:24px 26px;border-radius:14px;text-align:left;',
      '  border:1px solid rgba(245,158,11,.32);',
      '  background:linear-gradient(135deg,rgba(245,158,11,.10) 0%,rgba(217,119,6,.05) 100%);',
      '  box-shadow:0 4px 22px rgba(245,158,11,.15), inset 0 1px 0 rgba(255,255,255,.04)}',
      '.fxall-review-icon{font-size:34px;line-height:1;float:left;margin-right:14px;color:#fbbf24}',
      '.fxall-review-title{font-size:17px;font-weight:800;color:#fbbf24;margin-bottom:4px;letter-spacing:.02em}',
      '.fxall-review-sub{font-size:13px;color:#fde68a;line-height:1.65;margin-bottom:14px}',
      '.fxall-review-sub strong{color:#fff;font-weight:800}',
      '.fxall-review-points{margin:0 0 16px;padding-left:22px;list-style-type:"▸  ";',
      '  font-size:12.5px;color:#fcd34d;line-height:1.85}',
      '.fxall-review-points li{padding-left:4px}',
      '.fxall-review-rebtn{background:rgba(245,158,11,.12);color:#fbbf24;',
      '  border:1px solid rgba(245,158,11,.4);padding:10px 22px;border-radius:10px;',
      '  cursor:pointer;font-size:12.5px;font-weight:700;letter-spacing:.03em;',
      '  transition:all .15s ease;clear:both;display:inline-block}',
      '.fxall-review-rebtn:hover{background:rgba(245,158,11,.22);transform:translateY(-1px)}',
      // ── Results modal ────────────────────────────────────────────────
      '.fxall-res-list{max-height:46vh;overflow-y:auto;margin:14px 0 6px;',
      '  border:1px solid rgba(255,255,255,.06);border-radius:10px}',
      '.fxall-res-item{display:grid;grid-template-columns:24px 1fr 90px;gap:10px;',
      '  padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);',
      '  align-items:center;font-size:12px}',
      '.fxall-res-item:last-child{border-bottom:0}',
      '.fxall-res-icon{font-size:16px;text-align:center}',
      '.fxall-res-main{color:#cbd5e1;word-break:break-all;line-height:1.4}',
      '.fxall-res-main code{color:#94a3b8;font-family:JetBrains Mono,monospace;font-size:11.5px}',
      '.fxall-res-tag{text-align:right;font-size:10.5px;font-weight:700;',
      '  font-family:JetBrains Mono,monospace;letter-spacing:.06em;padding:3px 9px;',
      '  border-radius:5px;justify-self:end}',
      '.fxall-res-tag--ok{background:rgba(34,197,94,.12);color:#86efac}',
      '.fxall-res-tag--gone{background:rgba(56,189,248,.12);color:#7dd3fc}',
      '.fxall-res-tag--fail{background:rgba(239,68,68,.12);color:#fca5a5}',
      '.fxall-res-tag--skip{background:rgba(148,163,184,.12);color:#94a3b8}',
    ].join('\n');
    document.head.appendChild(s);
  }


  // ────────────────────────────────────────────────────────────────────────
  // 1.  DEDUPE — collapse duplicate cards in Active Response.
  //
  // We wrap _paRenderActiveResponse so that BEFORE it builds HTML, the
  // report's malware_analysis.file_drops + yara_hits lists are deduped
  // by file path (case-insensitive). Same for suspicious_processes by PID.
  // ────────────────────────────────────────────────────────────────────────
  function dedupeReport(r) {
    if (!r || !r.malware_analysis) return r;
    var ma = r.malware_analysis;
    var seenPath = Object.create(null);
    var seenPid  = Object.create(null);

    if (Array.isArray(ma.file_drops)) {
      ma.file_drops = ma.file_drops.filter(function (f) {
        if (!f || !f.path) return true;
        var k = String(f.path).toLowerCase();
        if (seenPath[k]) return false;
        seenPath[k] = 1;
        return true;
      });
    }
    if (Array.isArray(ma.yara_hits)) {
      ma.yara_hits = ma.yara_hits.filter(function (y) {
        var p = y && (y.path || y.file || y.target);
        if (!p) return true;
        var k = String(p).toLowerCase();
        if (seenPath[k]) return false;
        seenPath[k] = 1;
        return true;
      });
    }
    if (Array.isArray(ma.suspicious_processes)) {
      ma.suspicious_processes = ma.suspicious_processes.filter(function (p) {
        if (!p || !p.pid) return true;
        var k = String(p.pid);
        if (seenPid[k]) return false;
        seenPid[k] = 1;
        return true;
      });
    }
    return r;
  }


  // Cache of the last report so we can re-render the Fix-All bar
  // after the user closes the results modal.
  var _lastReport = null;

  function wrapRenderActiveResponse() {
    if (typeof window._paRenderActiveResponse !== 'function' &&
        typeof window.paRenderActiveResponse !== 'function') {
      // The function is private in perform_analysis.js (declared with
      // `function _paRenderActiveResponse`). It's not on window. We can't
      // intercept directly, so we observe the DOM container instead.
      _observeActiveResponseContainer();
      return;
    }
    var orig = window._paRenderActiveResponse || window.paRenderActiveResponse;
    var wrapped = function (r) {
      _lastReport = r;
      try { dedupeReport(r); } catch (e) {}
      orig.call(this, r);
      try { injectFixAllBar(r); } catch (e) { console.warn('fix-all bar:', e); }
    };
    if (window._paRenderActiveResponse) window._paRenderActiveResponse = wrapped;
    if (window.paRenderActiveResponse)  window.paRenderActiveResponse  = wrapped;
  }


  // ────────────────────────────────────────────────────────────────────────
  // FALLBACK: observe the active-response container and inject the bar
  // every time its contents change. Works even when the render function
  // is module-private.
  // ────────────────────────────────────────────────────────────────────────
  function _observeActiveResponseContainer() {
    var host = document.getElementById('pa-active-response');
    if (!host) {
      // Container not in DOM yet — try again shortly
      setTimeout(_observeActiveResponseContainer, 400);
      return;
    }
    var _injecting = false;
    var mo = new MutationObserver(function () {
      if (_injecting) return;
      // If our bar is already there, don't re-inject
      if (host.querySelector('.fxall-bar')) return;
      _injecting = true;
      try {
        // Pull the latest report from anywhere we can find it
        var r = _lastReport ||
                window._paLastReport ||
                window._paCurrentReport ||
                window.paReport ||
                null;
        // Dedupe DOM cards directly when we don't have the report object
        dedupeDomCards(host);
        injectFixAllBar(r, host);
      } catch (e) { /* swallow */ }
      _injecting = false;
    });
    mo.observe(host, { childList: true, subtree: false });
  }


  // ────────────────────────────────────────────────────────────────────────
  // DOM-level dedupe — used when we can't intercept the renderer. Walks
  // the active-response cards and removes any whose visible "title" /
  // path occurs twice.
  // ────────────────────────────────────────────────────────────────────────
  function dedupeDomCards(host) {
    if (!host) return;
    // Active Response cards have class .pa-resp-card (per perform_analysis.js).
    var cards = host.querySelectorAll('.pa-resp-card');
    var seen = Object.create(null);
    cards.forEach(function (c) {
      // Build a fingerprint from the title + the "Path" meta value.
      var title = (c.querySelector('.pa-resp-title, [class*="title"]') || {}).textContent || '';
      // Look for a meta row whose label is "Path"
      var pathVal = '';
      c.querySelectorAll('[class*="meta"]').forEach(function (m) {
        var t = (m.textContent || '').trim();
        if (/^path[:\s]/i.test(t)) pathVal = t.replace(/^path[:\s]+/i, '').trim();
      });
      var key = (title + '|' + pathVal).toLowerCase();
      if (!title && !pathVal) return;
      if (seen[key]) { c.style.display = 'none'; return; }
      seen[key] = 1;
    });
  }


  // ────────────────────────────────────────────────────────────────────────
  // 2.  COLLECT THREATS — walk the report and build the list we'd send
  //     to /api/action/fix-all. Falls back to scraping the DOM if we
  //     don't have the report object.
  //
  //  This function MUST stay in sync with everything `_paRenderActiveResponse`
  //  in perform_analysis.js renders as a card. Whenever a new data source is
  //  added there, mirror it here — otherwise users see cards on screen but
  //  the bar shows "System Secure" with zero counts. (That mismatch was a
  //  real bug: registry_persistence-without-target rendered as an info
  //  card, and sigma_hits rendered fix tasks, but neither was collected.)
  // ────────────────────────────────────────────────────────────────────────
  function collectThreatsFromReport(r) {
    var out = [];
    var seen = Object.create(null);
    function add(kind, target, name) {
      if (target === undefined || target === null || target === '') return;
      var ts = String(target).trim();
      if (!ts || ts === 'undefined' || ts === 'null') return;
      var key = kind + '|' + ts.toLowerCase();
      if (seen[key]) return;
      seen[key] = 1;
      var item = { kind: kind, target: ts };
      if (name) item.name = name;
      out.push(item);
    }

    if (!r) return out;
    var ma = r.malware_analysis || {};

    // ── (A) Suspicious processes ─────────────────────────────────────────
    //   Accept ANY entry with a PID — the renderer also falls back to
    //   `p.pid && !p.suspicious` when the strict-suspicious list is empty,
    //   so we mirror the same behaviour here.
    (ma.suspicious_processes || []).forEach(function (p) {
      if (p && p.pid) add('process', p.pid, p.image || '');
    });

    // ── (B) File drops ───────────────────────────────────────────────────
    (ma.file_drops || []).forEach(function (f) {
      if (f && f.path) add('file', f.path);
    });

    // ── (C) YARA hits — already covered by file_drops dedupe ─────────────
    (ma.yara_hits || []).forEach(function (y) {
      var p = y && (y.path || y.file || y.target);
      if (p) add('file', p);
    });

    // ── (D) Registry persistence ─────────────────────────────────────────
    //   The backend stores this in 3 different shapes across code paths:
    //     • ma.registry_persistence.key            (sysmon EID 13 query)
    //     • ma.registry_persistence_target         (legacy top-level)
    //     • ma.registry_persistence_path           (legacy top-level)
    //   Check all three, in priority order.
    var regT =
        (ma.registry_persistence && (ma.registry_persistence.key ||
                                     ma.registry_persistence.target ||
                                     ma.registry_persistence.path))
        || ma.registry_persistence_target
        || ma.registry_persistence_path;
    if (regT) add('registry', regT);

    // ── (E) Sigma hits — same parsing perform_analysis.js does at L1616 ──
    //   Rules whose ID contains FILE / DROP / UNSIGNED / TEMP_EXE point
    //   to a file path; RUN_PERSIST / REGISTRY → a registry key;
    //   SCHTASK / SCHEDULED → a scheduled task name.
    (ma.sigma_hits || []).forEach(function (h) {
      if (!h) return;
      var rule = String(h.rule || h.rule_id || '').toUpperCase();
      var fp   = h.path || h.file || h.target || '';
      if (fp && (rule.indexOf('FILE') >= 0 || rule.indexOf('DROP') >= 0 ||
                 rule.indexOf('UNSIGNED') >= 0 || rule.indexOf('TEMP_EXE') >= 0)) {
        add('file', fp);
      }
      if (rule.indexOf('REGISTRY') >= 0 || rule.indexOf('RUN_PERSIST') >= 0) {
        add('registry', h.reg_key || h.target || '');
      }
      if (rule.indexOf('SCHTASK') >= 0 || rule.indexOf('SCHEDULED') >= 0) {
        add('task', h.task_name || h.target || '');
      }
    });

    // ── (F) Threat-detector hits with concrete targets ───────────────────
    (r.threat_hits || []).forEach(function (t) {
      ((t.targets || t.evidence_targets) || []).forEach(function (tg) {
        if (tg.pid)     add('process',  tg.pid, tg.name || '');
        if (tg.path)    add('file',     tg.path);
        if (tg.task)    add('task',     tg.task);
        if (tg.service) add('service',  tg.service);
      });
    });

    return out;
  }


  // ────────────────────────────────────────────────────────────────────────
  // reportHasAnyCardWorthyData — does this report contain ANYTHING that
  // _paRenderActiveResponse would draw as a card? Used to decide between
  // "System Secure" (truly nothing) and "Review Required" (cards on screen
  // but no concrete action target collectThreatsFromReport could extract).
  // ────────────────────────────────────────────────────────────────────────
  function reportHasAnyCardWorthyData(r) {
    if (!r) return false;
    var ma = r.malware_analysis || {};
    if ((ma.suspicious_processes || []).some(function (p) { return p && p.pid; })) return true;
    if ((ma.file_drops           || []).some(function (f) { return f && f.path; })) return true;
    if ((ma.yara_hits            || []).length > 0) return true;
    if (ma.registry_persistence) return true;          // even if .key is empty
    if (ma.registry_persistence_target) return true;
    if (ma.registry_persistence_path)   return true;
    if ((ma.sigma_hits           || []).length > 0) return true;
    if ((r.threat_hits           || []).some(function (t) {
      return (t.targets || t.evidence_targets || []).length > 0;
    })) return true;
    return false;
  }


  // ────────────────────────────────────────────────────────────────────────
  // 3.  INJECT FIX-ALL BAR at the bottom of pa-active-response
  //
  // Three possible end states, in priority order:
  //
  //   (a) THREATS WITH ACTIONABLE TARGETS  → big red/orange "Fix All" bar.
  //   (b) THREATS BUT NO CONCRETE TARGETS  → amber "Review Required" panel
  //       (e.g. Registry Persistence Indicator with empty key, or sigma
  //       hit referencing only event IDs the user must inspect manually).
  //       Hard requirement: NEVER claim System Secure while a card with
  //       threat severity is visible on screen.
  //   (c) NOTHING AT ALL  → green "System Secure" hero.
  // ────────────────────────────────────────────────────────────────────────
  function injectFixAllBar(r, hostOverride) {
    var host = hostOverride || document.getElementById('pa-active-response');
    if (!host) return;

    // Hide everything we previously appended so we can re-decide cleanly.
    var oldBar  = host.querySelector('.fxall-bar');     if (oldBar)  oldBar.remove();
    var oldSec  = host.querySelector('.fxall-secure');  if (oldSec)  oldSec.remove();
    var oldRev  = host.querySelector('.fxall-review');  if (oldRev)  oldRev.remove();

    // Is there a visible (non-hidden) card on screen right now?
    var visibleCards = Array.from(host.querySelectorAll('.pa-resp-card'))
                            .filter(function (c) { return c.style.display !== 'none'; });
    var hasVisibleCard = visibleCards.length > 0;

    // Did the renderer print its "no actionable malicious entities" line?
    var rendererSaidClean = !!host.querySelector('.ur-clean');

    // Does the report payload itself contain any card-worthy data?
    // (Could be true even before cards have finished animating in.)
    var reportHasThreats = reportHasAnyCardWorthyData(r);

    // Build the list of *actionable* (concrete-target) threats — what the
    // Fix All button will actually send to /api/action/fix-all.
    var threats = collectThreatsFromReport(r);
    if (!threats.length && hasVisibleCard) {
      // Last-ditch effort: scrape any cards that DID expose action buttons.
      threats = scrapeThreatsFromDom(host);
    }

    // ── State (c): genuinely clean ──────────────────────────────────────
    //   Renderer said clean AND report has nothing AND no visible cards.
    //   All three must be true — any disagreement falls through to (b).
    if (rendererSaidClean && !reportHasThreats && !hasVisibleCard) {
      host.appendChild(buildSystemSecure());
      return;
    }

    // ── Wait-for-render dance: report has data but cards haven't drawn
    //    yet. Retry shortly. (Originally added because of race conditions
    //    when the renderer is async; preserved.)
    if (!hasVisibleCard && reportHasThreats && !rendererSaidClean) {
      setTimeout(function () { injectFixAllBar(r, hostOverride); }, 600);
      return;
    }

    // ── State (a): we have something to action ──────────────────────────
    if (threats.length > 0) {
      host.appendChild(buildFixAllBar(threats));
      return;
    }

    // ── State (b): threats visible but nothing concrete to auto-fix ─────
    //   Show the amber "Review Required" panel pointing the operator at
    //   the panels above. This is the case the user hit in their
    //   screenshot: Registry Persistence Indicator card on screen but
    //   the backend left .key empty, so we can't auto-remediate.
    if (hasVisibleCard || reportHasThreats) {
      host.appendChild(buildReviewRequired(visibleCards.length, r));
      return;
    }

    // Defensive fallback — shouldn't reach here, but be safe.
    host.appendChild(buildSystemSecure());
  }


  // ────────────────────────────────────────────────────────────────────────
  // buildFixAllBar — extracted from injectFixAllBar so the same UI can be
  // produced from either the report-driven path or the DOM-scrape path.
  // ────────────────────────────────────────────────────────────────────────
  function buildFixAllBar(threats) {
    var counts = { file: 0, process: 0, registry: 0, task: 0, service: 0 };
    threats.forEach(function (t) { counts[t.kind] = (counts[t.kind] || 0) + 1; });
    var partsTxt = [
      counts.file     ? counts.file     + ' file' + (counts.file     !== 1 ? 's' : '')         : '',
      counts.process  ? counts.process  + ' process' + (counts.process !== 1 ? 'es' : '')      : '',
      counts.registry ? counts.registry + ' registry key' + (counts.registry !== 1 ? 's' : '') : '',
      counts.task     ? counts.task     + ' task' + (counts.task     !== 1 ? 's' : '')         : '',
      counts.service  ? counts.service  + ' service' + (counts.service !== 1 ? 's' : '')       : '',
    ].filter(Boolean).join('  ·  ');

    var bar = document.createElement('div');
    bar.className = 'fxall-bar';
    bar.innerHTML = [
      '<div class="fxall-bar-left">',
      '  <div class="fxall-bar-title">⚡ One-Click Remediation</div>',
      '  <div class="fxall-bar-sub">',
      '    Kill processes, quarantine or delete malicious files, remove registry / task persistence — all in one action.',
      '  </div>',
      '  <div class="fxall-bar-counts">▸ ' + threats.length + ' actionable threat' +
        (threats.length !== 1 ? 's' : '') + (partsTxt ? '  ·  ' + partsTxt : '') + '</div>',
      '</div>',
      '<button class="fxall-btn fxall-btn-quar" data-mode="quarantine" type="button">',
      '  📦 Quarantine All',
      '</button>',
      '<button class="fxall-btn" data-mode="delete" type="button">',
      '  🛡 Fix All &amp; Delete',
      '</button>',
    ].join('');
    bar.querySelector('[data-mode="delete"]').addEventListener('click', function () {
      openConfirmModal('delete', threats);
    });
    bar.querySelector('[data-mode="quarantine"]').addEventListener('click', function () {
      openConfirmModal('quarantine', threats);
    });
    return bar;
  }


  // ────────────────────────────────────────────────────────────────────────
  // buildReviewRequired — amber panel for the "cards visible but nothing
  // concrete to action" middle ground. Tells the user exactly which panels
  // upstairs hold the evidence they need to check by hand.
  // ────────────────────────────────────────────────────────────────────────
  function buildReviewRequired(visibleCount, r) {
    var d = document.createElement('div');
    d.className = 'fxall-review';

    // Build a list of "where to look next" pointers based on what the
    // report contains — concrete, not generic boilerplate.
    var pointers = [];
    var ma = (r && r.malware_analysis) || {};
    if (ma.registry_persistence || ma.registry_persistence_target || ma.registry_persistence_path) {
      pointers.push('Sysmon Hits panel — find the Run / Userinit / IFEO key that was touched');
    }
    if ((ma.sigma_hits || []).length > 0) {
      pointers.push('Threat Detector Hits panel — review the Sigma rule that fired and its evidence');
    }
    if ((r && r.threat_hits || []).length > 0) {
      pointers.push('Threat Detector Hits panel — examine the firing rule(s) and their associated event IDs');
    }
    if (!pointers.length) {
      pointers.push('Sysmon Hits panel and Threat Detector Hits panel — both above this card');
    }

    d.innerHTML = [
      '<div class="fxall-review-icon">⚠</div>',
      '<div class="fxall-review-title">Review Required</div>',
      '<div class="fxall-review-sub">',
      '  Found <strong>' + visibleCount + '</strong> threat indicator' +
        (visibleCount !== 1 ? 's' : '') + ' that need a manual look — ',
      '  there isn\u2019t a concrete file / process / key the auto-fixer can act on yet.',
      '</div>',
      '<ul class="fxall-review-points">',
      pointers.map(function (p) { return '<li>' + p + '</li>'; }).join(''),
      '</ul>',
      '<button class="fxall-review-rebtn" type="button">🔄 Re-run analysis</button>',
    ].join('');
    var _rescanBtn = d.querySelector('button');
    if (_rescanBtn) _rescanBtn.addEventListener('click', triggerRescan);
    return d;
  }


  // ────────────────────────────────────────────────────────────────────────
  // DOM scraper fallback — extract {kind,target} pairs from visible cards
  // ────────────────────────────────────────────────────────────────────────
  function scrapeThreatsFromDom(host) {
    var out = [];
    var seen = Object.create(null);
    function add(kind, target, name) {
      // Reject missing, "undefined", "null" or whitespace-only targets that
      // can appear when a Sysmon path field is absent from the report.
      if (!target) return;
      var ts = String(target).trim();
      if (!ts || ts === 'undefined' || ts === 'null') return;
      var k = kind + '|' + ts.toLowerCase();
      if (seen[k]) return; seen[k] = 1;
      out.push(name ? { kind: kind, target: ts, name: name } : { kind: kind, target: ts });
    }
    host.querySelectorAll('.pa-resp-card').forEach(function (c) {
      if (c.style.display === 'none') return;
      // Look at inline onclick handlers on action buttons — that's where
      // the path / pid is encoded by perform_analysis.js.
      c.querySelectorAll('button[onclick], .pa-act-btn[onclick]').forEach(function (b) {
        var oc = b.getAttribute('onclick') || '';
        var m;
        m = /paKillProcess\(\s*this\s*,\s*(\d+)\s*,\s*['"]([^'"]*)['"]/.exec(oc);
        if (m) { add('process', parseInt(m[1], 10), m[2] || ''); return; }
        m = /paDeleteFile\(\s*this\s*,\s*['"]((?:\\.|[^'"\\])+)['"]/.exec(oc);
        if (m) { add('file', _unescJs(m[1])); return; }
        m = /paQuarantineFile\(\s*this\s*,\s*['"]((?:\\.|[^'"\\])+)['"]/.exec(oc);
        if (m) { add('file', _unescJs(m[1])); return; }
        m = /paRemovePersistence\(\s*this\s*,\s*['"](task|registry|service)['"]\s*,\s*['"]((?:\\.|[^'"\\])+)['"]/.exec(oc);
        if (m) { add(m[1], _unescJs(m[2])); return; }
      });
    });
    return out;
  }
  function _unescJs(s) {
    return String(s || '').replace(/\\\\/g, '\u0000').replace(/\\'/g, "'")
      .replace(/\\"/g, '"').replace(/\u0000/g, '\\');
  }


  // ────────────────────────────────────────────────────────────────────────
  // 4.  CONFIRM MODAL  →  POST  /api/action/fix-all
  // ────────────────────────────────────────────────────────────────────────
  function openConfirmModal(mode, threats) {
    var isDelete = (mode === 'delete');
    var summary = summariseThreats(threats);

    var overlay = document.createElement('div');
    overlay.className = 'fxall-overlay';
    overlay.innerHTML = [
      '<div class="fxall-modal" role="dialog" aria-modal="true">',
      '  <div class="fxall-modal-title">',
      '    ', isDelete ? '🛡 Fix All & Delete Threats' : '📦 Quarantine All Threats',
      '  </div>',
      '  <div class="fxall-modal-sub">',
      isDelete
        ? 'Permanently remove every detected threat in one operation. The action is logged in the audit history but cannot be undone.'
        : 'Move every detected file to the sealed quarantine folder and revert processes / persistence. Files can be restored later from the quarantine.',
      '  </div>',
      '  <div class="fxall-modal-summary">',
      summary,
      '  </div>',
      // No password field: perform Delete mode without asking for admin password
      '',
      '  <div class="fxall-modal-row">',
      '    <button class="fxall-modal-btn fxall-modal-btn--cancel" data-act="cancel" type="button">Cancel</button>',
      '    <button class="fxall-modal-btn ',
            isDelete ? 'fxall-modal-btn--ok' : 'fxall-modal-btn--ok-quar',
            '" data-act="go" type="button">',
            isDelete ? 'Yes, Fix All & Delete' : 'Yes, Quarantine All',
      '    </button>',
      '  </div>',
      '  <div id="fxall-progress" style="display:none"></div>',
      '</div>',
    ].join('');
    document.body.appendChild(overlay);

    // No password input to focus

    function close() { overlay.remove(); }
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) close();
    });
    overlay.querySelector('[data-act="cancel"]').addEventListener('click', close);
    overlay.querySelector('[data-act="go"]').addEventListener('click', function () {
      // Always use the requested mode (delete/quarantine) without prompting for a password
      runFixAll(overlay, mode, '', threats);
    });
    // no password input — nothing to bind to
  }

  function summariseThreats(threats) {
    if (!threats.length) return '<em>No threats detected.</em>';
    var lines = [];
    var groups = { file: [], process: [], registry: [], task: [], service: [] };
    threats.forEach(function (t) { (groups[t.kind] || []).push(t); });
    if (groups.process.length) {
      lines.push('🛑 <strong>' + groups.process.length + ' process'
        + (groups.process.length !== 1 ? 'es' : '') + '</strong> will be terminated: '
        + groups.process.slice(0, 3).map(function (p) {
            return '<code>PID ' + p.target + (p.name ? ' (' + _esc(p.name) + ')' : '') + '</code>';
          }).join(', ')
        + (groups.process.length > 3 ? ' …+' + (groups.process.length - 3) + ' more' : ''));
    }
    if (groups.file.length) {
      lines.push('🦠 <strong>' + groups.file.length + ' file'
        + (groups.file.length !== 1 ? 's' : '') + '</strong> will be handled: '
        + groups.file.slice(0, 2).map(function (f) {
            return '<code>' + _esc(_baseName(f.target)) + '</code>';
          }).join(', ')
        + (groups.file.length > 2 ? ' …+' + (groups.file.length - 2) + ' more' : ''));
    }
    if (groups.registry.length) {
      lines.push('🔑 <strong>' + groups.registry.length + ' registry key'
        + (groups.registry.length !== 1 ? 's' : '') + '</strong> will be removed.');
    }
    if (groups.task.length) {
      lines.push('📅 <strong>' + groups.task.length + ' scheduled task'
        + (groups.task.length !== 1 ? 's' : '') + '</strong> will be removed.');
    }
    if (groups.service.length) {
      lines.push('⚙ <strong>' + groups.service.length + ' service'
        + (groups.service.length !== 1 ? 's' : '') + '</strong> will be removed.');
    }
    return lines.join('<br>');
  }
  function _baseName(p) {
    var s = String(p || '');
    var i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'));
    return i >= 0 ? s.slice(i + 1) : s;
  }
  function _esc(s) {
    return String(s || '').replace(/[&<>"']/g, function (c) {
      return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);
    });
  }


  // ────────────────────────────────────────────────────────────────────────
  // 5.  EXECUTE — POST /api/action/fix-all, show progress, show results,
  //              re-run analysis automatically.
  // ────────────────────────────────────────────────────────────────────────
  function runFixAll(overlay, mode, password, threats) {
    // Switch the modal body to a progress view
    overlay.querySelector('.fxall-modal-row').style.display = 'none';
    overlay.querySelector('.fxall-modal-summary').style.display = 'none';
    var pwIn = overlay.querySelector('#fxall-pw');
    if (pwIn) pwIn.disabled = true;

    var prog = overlay.querySelector('#fxall-progress');
    prog.style.display = '';
    prog.innerHTML = [
      '<div class="fxall-prog-wrap">',
      '  <div class="fxall-prog-row">',
      '    <span id="fxall-prog-msg">Running ' + threats.length + ' action'
           + (threats.length !== 1 ? 's' : '') + '…</span>',
      '    <span id="fxall-prog-pct">0%</span>',
      '  </div>',
      '  <div class="fxall-prog-bar"><div class="fxall-prog-fill" id="fxall-prog-fill"></div></div>',
      '</div>',
    ].join('');

    // Optimistic progress animation (the backend call is one shot, so we
    // fake a smooth 0 → 90% climb while waiting, then jump to 100%).
    var fill = overlay.querySelector('#fxall-prog-fill');
    var pct  = overlay.querySelector('#fxall-prog-pct');
    var t0   = Date.now();
    var animTimer = setInterval(function () {
      var elapsed = (Date.now() - t0) / 1000;
      var target  = 90 * (1 - Math.exp(-elapsed / 3));   // asymptotic to 90%
      fill.style.width = target.toFixed(1) + '%';
      pct.textContent  = Math.round(target) + '%';
    }, 90);

    fetch('/api/action/fix-all', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        threats:  threats,
        mode:     mode,
        password: password || '',
      }),
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      clearInterval(animTimer);
      fill.style.width = '100%';
      pct.textContent  = '100%';
      setTimeout(function () { showResults(overlay, d); }, 280);
    })
    .catch(function (e) {
      clearInterval(animTimer);
      showResults(overlay, {
        ok: false, error: 'Network error: ' + e.message,
        results: [], fixed: 0, failed: threats.length, already_gone: 0,
        total: threats.length, mode: mode,
      });
    });
  }


  function showResults(overlay, d) {
    var modal = overlay.querySelector('.fxall-modal');
    if (!modal) return;

    if (!d.ok && d.error) {
      modal.querySelector('.fxall-modal-title').innerHTML = '⚠ Fix All Failed';
      modal.querySelector('.fxall-modal-sub').innerHTML = _esc(d.error || 'Unknown error');
      modal.querySelector('#fxall-progress').style.display = 'none';
      var pwIn = modal.querySelector('#fxall-pw'); if (pwIn) pwIn.disabled = false;
      var row  = modal.querySelector('.fxall-modal-row'); row.style.display = '';
      row.innerHTML = '<button class="fxall-modal-btn fxall-modal-btn--cancel" data-act="cancel" type="button">Close</button>';
      row.querySelector('[data-act="cancel"]').addEventListener('click', function () { overlay.remove(); });
      return;
    }

    modal.querySelector('.fxall-modal-title').innerHTML =
      (d.failed === 0
        ? '✅ All Threats Handled'
        : '⚠ Completed With Issues');

    // Immediately hide the Quarantine/Fix All bar in the background
    if (d.failed === 0) {
      var arHost = document.getElementById('pa-active-response');
      if (arHost) { var fbar = arHost.querySelector('.fxall-bar'); if (fbar) fbar.style.display = 'none'; }
    }

    modal.querySelector('.fxall-modal-sub').innerHTML =
      '<strong>' + (d.fixed + d.already_gone) + '</strong> of <strong>' + d.total
      + '</strong> threats resolved · <span style="color:#86efac">'
      + d.fixed + ' actioned</span> · <span style="color:#7dd3fc">'
      + d.already_gone + ' already gone</span>'
      + (d.failed ? ' · <span style="color:#fca5a5">' + d.failed + ' failed</span>' : '')
      + '<br><span style="font-size:11px;color:#64748b">Mode: <code style="color:#fbbf24;background:rgba(251,191,36,.08);padding:1px 6px;border-radius:4px;font-family:JetBrains Mono,monospace">'
      + d.mode + '</code> · ' + ((d.elapsed_ms || 0) / 1000).toFixed(2) + ' s</span>';

    modal.querySelector('#fxall-progress').style.display = 'none';
    var pwIn = modal.querySelector('#fxall-pw'); if (pwIn) pwIn.remove();

    var listHtml = '<div class="fxall-res-list">' +
      (d.results || []).map(function (it) {
        var statusTxt = ({
          fixed:         { tag: 'fxall-res-tag--ok',   icon: '✅', text: 'FIXED' },
          already_gone:  { tag: 'fxall-res-tag--gone', icon: '✓',  text: 'ALREADY GONE' },
          failed:        { tag: 'fxall-res-tag--fail', icon: '✗',  text: 'FAILED' },
          skipped:       { tag: 'fxall-res-tag--skip', icon: '–',  text: 'SKIPPED' },
        })[it.status] || { tag: 'fxall-res-tag--skip', icon: '?', text: it.status };
        var label = '';
        if (it.kind === 'file')     label = '📁 ' + _esc(_baseName(it.target)) + ' <br><code>' + _esc(it.target) + '</code>';
        else if (it.kind === 'process')  label = '⚙ Process <code>PID ' + _esc(it.target) + '</code>';
        else if (it.kind === 'registry') label = '🔑 Registry <code>' + _esc(it.target) + '</code>';
        else if (it.kind === 'task')     label = '📅 Task <code>' + _esc(it.target) + '</code>';
        else if (it.kind === 'service')  label = '⚙ Service <code>' + _esc(it.target) + '</code>';
        else                              label = _esc(it.kind) + ' <code>' + _esc(it.target) + '</code>';
        return [
          '<div class="fxall-res-item" title="', _esc(it.detail || ''), '">',
          '  <span class="fxall-res-icon">', statusTxt.icon, '</span>',
          '  <span class="fxall-res-main">', label, '</span>',
          '  <span class="fxall-res-tag ', statusTxt.tag, '">', statusTxt.text, '</span>',
          '</div>',
        ].join('');
      }).join('') +
      '</div>';
    var sub = modal.querySelector('.fxall-modal-sub');
    sub.insertAdjacentHTML('afterend', listHtml);

    var row = modal.querySelector('.fxall-modal-row');
    row.style.display = '';
    row.innerHTML = [
      '<button class="fxall-modal-btn fxall-modal-btn--cancel" data-act="close" type="button">Close</button>',
      '<button class="fxall-modal-btn fxall-modal-btn--ok-quar" data-act="rescan" type="button">🔄 Re-scan Now</button>',
    ].join('');
    row.querySelector('[data-act="close"]').addEventListener('click', function () {
      overlay.remove();
      // Hide the Fix All bar — threats have been handled
      var bar = document.getElementById('pa-active-response');
      if (bar) { var b = bar.querySelector('.fxall-bar'); if (b) b.style.display = 'none'; }
      _maybeRescanSoon();
    });
    row.querySelector('[data-act="rescan"]').addEventListener('click', function () {
      overlay.remove();
      var bar = document.getElementById('pa-active-response');
      if (bar) { var b = bar.querySelector('.fxall-bar'); if (b) b.style.display = 'none'; }
      triggerRescan();
    });

    // Always re-scan in the background to refresh the dashboard
    _maybeRescanSoon();
  }


  // ────────────────────────────────────────────────────────────────────────
  // 6.  AUTO RE-SCAN — calls the existing runPerformAnalysis(30) or the
  //                    Rescan Files endpoint, whichever is wired up.
  // ────────────────────────────────────────────────────────────────────────
  var _rescanScheduled = false;
  function _maybeRescanSoon() {
    if (_rescanScheduled) return;
    _rescanScheduled = true;
    setTimeout(function () {
      _rescanScheduled = false;
      triggerRescan();
    }, 900);
  }

  function triggerRescan() {
    // Ensure the Perform Analysis page is visible before starting the scan.
    if (typeof window.showPage === 'function') {
      window.showPage('perform');
    }

    // First: ask the backend to wipe cached YARA hits so disappeared
    // files don't reappear on the next analysis.
    fetch('/api/action/rescan-files', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }).catch(function () {})
      .finally(function () {
        if (typeof window.runPerformAnalysis === 'function') {
          window.runPerformAnalysis(30);
        } else if (typeof window.paStartHunting === 'function') {
          window.paStartHunting();
        }
      });
  }


  // ────────────────────────────────────────────────────────────────────────
  // 7.  SYSTEM SECURE STATE — replaces the active-response empty line
  // ────────────────────────────────────────────────────────────────────────
  function buildSystemSecure() {
    var d = document.createElement('div');
    d.className = 'fxall-secure';
    d.innerHTML = [
      '<div class="fxall-secure-icon">🛡️</div>',
      '<div class="fxall-secure-title">System Secure</div>',
      '<div class="fxall-secure-sub">',
      '  No actionable threats found in the latest analysis. Processes, files, ',
      '  registry, and scheduled tasks all appear clean.',
      '</div>',
      '<div class="fxall-secure-stats">',
      '  <div class="fxall-secure-stat">✓ 0 malicious files</div>',
      '  <div class="fxall-secure-stat">✓ 0 suspicious processes</div>',
      '  <div class="fxall-secure-stat">✓ 0 persistence indicators</div>',
      '</div>',
    ].join('');
    d.querySelector('button').addEventListener('click', triggerRescan);
    return d;
  }


  // ────────────────────────────────────────────────────────────────────────
  // HIDE OLD BANNER — the legacy #pa-fix-all-wrap (rendered by
  // perform_analysis.js) is superseded by the new .fxall-bar system.
  // Hide it permanently so it never shows alongside the new UI.
  // ────────────────────────────────────────────────────────────────────────
  function hideOldFixAllBanner() {
    if (document.getElementById('pa-fix-all-legacy-hide')) return;
    var s = document.createElement('style');
    s.id = 'pa-fix-all-legacy-hide';
    s.textContent = '#pa-fix-all-wrap { display: none !important; }';
    document.head.appendChild(s);
  }


  // ────────────────────────────────────────────────────────────────────────
  // BOOT
  // ────────────────────────────────────────────────────────────────────────
  function boot() {
    injectCSS();
    hideOldFixAllBanner();
    wrapRenderActiveResponse();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
