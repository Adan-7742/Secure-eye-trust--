/**
 * perform_analysis.js — Secure Eye Trust+
 * Deep time-based analysis report with animated loader
 */

var _paCharts    = {};
var _paLastReport = null;   // keeps report alive across tab switches

/* ── Init — called every time tab is opened ──────────────────── */
function initPerformAnalysis() {
  // If already rendered this session, just show it — don't re-fetch
  if (_paLastReport) {
    document.getElementById('pa-idle').style.display    = 'none';
    document.getElementById('pa-loading').style.display = 'none';
    document.getElementById('pa-report').style.display  = 'block';
    _paUpdateRunButton();
    return;
  }

  // Show the top action button right away while the latest report loads
  _paShowIdle();

  // First visit: try loading last saved report from DB
  fetch('/api/perform-analysis/latest')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.ok && d.report) {
        _paLastReport = d.report;
        _paRender(d.report);
        var hdr = document.getElementById('pa-generated');
        if (hdr) hdr.textContent = d.report.generated_at + '  (saved — click Re-run to refresh)';
        _paUpdateRunButton();
      } else {
        _paShowIdle();
      }
    })
    .catch(function() { _paShowIdle(); });
}

function _paShowIdle() {
  document.getElementById('pa-idle').style.display    = 'flex';
  document.getElementById('pa-loading').style.display = 'none';
  document.getElementById('pa-report').style.display  = 'none';
  _paUpdateRunButton();
}

function _paUpdateRunButton() {
  var btn = document.getElementById('pa-run-btn');
  if (!btn) return;
  btn.style.display = 'inline-flex';
  btn.disabled = false;
  btn.style.opacity = '';
  btn.style.cursor = 'pointer';
  btn.innerHTML = '<span>🔄</span> ' + (_paLastReport ? 'Re-run Analysis' : 'Run Analysis');
}

function _paSetRunButtonLoading(loading) {
  var btn = document.getElementById('pa-run-btn');
  if (!btn) return;
  btn.disabled = loading;
  btn.style.opacity = loading ? '0.65' : '';
  btn.style.cursor = loading ? 'not-allowed' : 'pointer';
}

function paShowPeriodModal() {
  var modal = document.getElementById('pa-period-modal');
  if (modal) modal.style.display = 'flex';
}

function paHidePeriodModal() {
  var modal = document.getElementById('pa-period-modal');
  if (modal) modal.style.display = 'none';
}

function paToggleCustomDays() {
  var wrap = document.getElementById('pa-custom-days-wrap');
  if (!wrap) return;
  wrap.style.display = (wrap.style.display === 'flex') ? 'none' : 'flex';
}

function paSelectPeriod(days) {
  if (days === 'custom') {
    paToggleCustomDays();
    return;
  }
  paHidePeriodModal();
  if (typeof days !== 'number' || isNaN(days) || days < 1) days = 30;
  document.querySelectorAll('.pa-period-btn').forEach(function(btn) {
    var d = parseInt(btn.getAttribute('data-days'), 10);
    btn.classList.toggle('pa-period-selected', d === days);
  });
  runPerformAnalysis(days);
}

/* ── Run analysis ────────────────────────────────────────────── */
async function runPerformAnalysis(days) {
  _paSetRunButtonLoading(true);

  document.getElementById('pa-idle').style.display    = 'none';
  document.getElementById('pa-loading').style.display = 'flex';
  document.getElementById('pa-report').style.display  = 'none';

  // Destroy old charts
  Object.values(_paCharts).forEach(function(ch){ try{ ch.destroy(); }catch(e){} });
  _paCharts = {};

  // Animate steps
  var stepInterval = (function() {
    var steps = ['pa-step1','pa-step2','pa-step3','pa-step4'];
    var cur = 0;
    return setInterval(function() {
      steps.forEach(function(s){
        var el = document.getElementById(s);
        if (el) { el.className = 'pa-step'; el.textContent = el.textContent.replace('✅','◎').replace('⟳','◎'); }
      });
      if (cur > 0) {
        var prev = document.getElementById(steps[cur-1]);
        if (prev) { prev.className = 'pa-step pa-step-done'; prev.textContent = prev.textContent.replace('◎','✅').replace('⟳','✅'); }
      }
      var el = document.getElementById(steps[cur]);
      if (el) { el.className = 'pa-step pa-step-active'; el.textContent = el.textContent.replace('◎','⟳'); }
      cur = (cur + 1) % steps.length;
    }, 600);
  })();

  try {
    var url = '/api/perform-analysis';
    if (typeof days === 'number' && !isNaN(days) && days > 0) {
      url += '?days=' + encodeURIComponent(days);
    }
    var r   = await fetch(url);
    var d   = await r.json();
    clearInterval(stepInterval);
    if (!d.ok || !d.report) { _paError('Server returned no report'); return; }
    await new Promise(function(res){ setTimeout(res, 600); });
    _paLastReport = d.report;
    _paRender(d.report);
    _paUpdateRunButton();
    // Push to reports page
    if (typeof loadReportsFromServer === 'function') loadReportsFromServer();
  } catch(e) {
    clearInterval(stepInterval);
    _paError('Analysis failed: ' + e.message);
  } finally {
    _paSetRunButtonLoading(false);
  }
}

function _paError(msg) {
  document.getElementById('pa-loading').style.display = 'none';
  _paShowIdle();
  _paSetRunButtonLoading(false);
  toast('❌ ' + msg);
}

/* ── Render report ───────────────────────────────────────────── */
function _paRender(r) {
  _paLastReport = r;

  document.getElementById('pa-loading').style.display = 'none';
  document.getElementById('pa-idle').style.display    = 'none';
  var rep = document.getElementById('pa-report');
  rep.style.display = 'block';

  var $ = function(id){ return document.getElementById(id); };
  var set = function(id, v){ var e=$(id); if(e) e.textContent = v; };

  set('pa-generated', r.generated_at);
  set('pa-period',    'Last ' + r.period_days + ' days');
  set('pa-total-ev',  (r.total_events||0).toLocaleString());
  set('pa-total-err', (r.total_errors||0).toLocaleString());
  set('pa-peak-hour', r.peak_hour || '—');

  // Risk badge
  var RCOL = {Low:'#4ade80', Medium:'#fbbf24', High:'#fb923c', Critical:'#f87171'};
  var rs   = r.risk_summary || {};
  var rc   = RCOL[rs.label] || '#94a3b8';
  var rb   = $('pa-risk-badge');
  if (rb) {
    rb.textContent = rs.label + ' Risk · ' + rs.score + '/100';
    rb.style.cssText = 'background:' + rc + '18;color:' + rc + ';border:1px solid ' + rc + '44;padding:7px 20px;border-radius:24px;font-size:14px;font-weight:800;letter-spacing:.02em';
  }

  // Stat cards
  var cats = r.categories || {};
  var totCrit=0, totErr=0, totWarn=0, totInfo=0;
  Object.values(cats).forEach(function(c){
    totCrit += c.critical||0; totErr  += c.errors||0;
    totWarn += c.warnings||0; totInfo += c.info||0;
  });
  set('pa-s-critical',  totCrit.toLocaleString());
  set('pa-s-errors',    totErr.toLocaleString());
  set('pa-s-warnings',  totWarn.toLocaleString());
  set('pa-s-info',      totInfo.toLocaleString());
  set('pa-s-threats',  (r.threat_hits||[]).length.toLocaleString());
  set('pa-s-anomalies',(r.anomaly_days||[]).length.toLocaleString());

  // Category breakdown
  var catEl = $('pa-cat-breakdown');
  if (catEl) {
    var catIcons = {application:'⚙️', system:'🖥️', security:'🔒', windows_update:'🔄'};
    catEl.innerHTML = Object.entries(cats).map(function(entry){
      var name = entry[0], cv = entry[1];
      var errPct = cv.total > 0 ? Math.round((cv.errors+cv.critical)/cv.total*100) : 0;
      var barCol = errPct>30?'#ef4444':errPct>10?'#fb923c':'#1a8cff';
      return '<div class="pa-cat-row">' +
        '<div class="pa-cat-name">'+(catIcons[name]||'📋')+' '+name.replace('_',' ')+'</div>'+
        '<div class="pa-cat-stats">'+
          '<span class="pa-cat-total">'+(cv.total||0).toLocaleString()+' events</span>'+
          '<span class="pa-cat-err" style="color:#ef4444">'+((cv.errors||0)+(cv.critical||0))+' errors</span>'+
          '<span class="pa-cat-warn" style="color:#fbbf24">'+(cv.warnings||0)+' warnings</span>'+
        '</div>'+
        '<div class="pa-cat-bar-wrap"><div class="pa-cat-bar" style="width:'+errPct+'%;background:'+barCol+'"></div></div>'+
        '<span class="pa-cat-pct">'+errPct+'%</span>'+
      '</div>';
    }).join('');
  }

  // Threat hits — card grid
  // ── Threat Pattern Matches — new design ─────────────────────────────
  var threatEl = $('pa-threats-table');
  var badgeEl  = $('pa-threat-count-badge');
  if (threatEl) {
    var threats = (r.threat_hits || []).slice().sort(function(a,b){
      var O = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
      var d = (O[a.severity]||3)-(O[b.severity]||3);
      return d !== 0 ? d : b.count - a.count;
    });

    if (badgeEl) {
      badgeEl.style.display = threats.length ? '' : 'none';
      badgeEl.textContent   = threats.length + ' pattern' + (threats.length!==1?'s':'') + ' matched';
    }

    if (!threats.length) {
      threatEl.innerHTML =
        '<div style="background:rgba(74,222,128,.06);border:1px solid rgba(74,222,128,.2);border-radius:12px;padding:28px;text-align:center">' +
          '<div style="font-size:36px;margin-bottom:8px">✅</div>' +
          '<div style="color:#4ade80;font-weight:800;font-size:14px">No Threat Patterns Detected</div>' +
          '<div style="color:var(--text-dim);font-size:12px;margin-top:4px">System shows no known attack signatures in this period</div>' +
        '</div>';
      return;
    }

    var SCOL  = {CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#4ade80'};
    var SBCOL = {CRITICAL:'rgba(239,68,68,.08)',HIGH:'rgba(251,146,60,.08)',MEDIUM:'rgba(251,191,36,.06)',LOW:'rgba(74,222,128,.06)'};
    var ICONS = {
      'Brute Force Login':'🔐','Account Lockout':'🔒','Privilege Escalation':'⬆',
      'Windows Defender Alert':'🛡','Unexpected Shutdown':'💥','Disk Hardware Error':'💽',
      'Memory Corruption':'🧠','Application Crash':'💀','New Admin Account':'👤',
      'Scheduled Task Created':'📅','Audit Policy Change':'📋','Service Failure':'⚙',
      'Registry Tampering':'🔑','TLS/SSL Error':'🔗','Network Error':'🌐',
    };
    var SEV_DESC = {
      CRITICAL:'Requires immediate action — active or imminent threat',
      HIGH:    'Elevated risk — investigate within 2 hours',
      MEDIUM:  'Moderate concern — review at next maintenance window',
      LOW:     'Informational — monitor for changes',
    };

    // ── Summary bar ───────────────────────────────────────────────────
    var totByS = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
    var totEvents = 0;
    threats.forEach(function(h){
      totByS[h.severity] = (totByS[h.severity]||0) + 1;
      totEvents += h.count||0;
    });

    var html = '';

    // Top summary strip
    html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0;border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:14px">';
    ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(function(sev) {
      var sc = SCOL[sev]; var sbc = SBCOL[sev];
      html +=
        '<div style="padding:14px 16px;background:'+sbc+';border-right:1px solid var(--border);last-child:border:none">' +
          '<div style="font-size:22px;font-weight:900;color:'+sc+'">'+totByS[sev]+'</div>' +
          '<div style="font-size:9px;color:'+sc+';font-weight:700;text-transform:uppercase;letter-spacing:.07em">'+sev+'</div>' +
          '<div style="font-size:9px;color:var(--text-dim);margin-top:2px">pattern'+(totByS[sev]!==1?'s':'')+'</div>' +
        '</div>';
    });
    html += '</div>';

    // ── Threat list — accordion-style ─────────────────────────────────
    html += '<div style="display:flex;flex-direction:column;gap:8px">';

    threats.forEach(function(h, idx) {
      var sc   = SCOL[h.severity]  || '#94a3b8';
      var sbc  = SBCOL[h.severity] || 'rgba(255,255,255,.03)';
      var icon = ICONS[h.name] || '⚠';
      var desc = SEV_DESC[h.severity] || '';
      var ex   = h.examples && h.examples[0] ? h.examples[0].message : '';
      var ts   = (h.latest||'').substring(0,16);
      var id   = 'threat-detail-'+idx;

      // Progress bar width — relative to highest count
      var maxCount = threats[0].count || 1;
      var barW = Math.max(4, Math.round(h.count / maxCount * 100));

      html +=
        '<div style="border:1px solid '+sc+'28;border-radius:12px;overflow:hidden;background:'+sbc+'">' +

          // ── Main row (always visible) ──────────────────────────────
          '<div onclick="paToggleThreat(\''+id+'\')" style="display:grid;grid-template-columns:44px 1fr auto auto auto;align-items:center;gap:12px;padding:14px 16px;cursor:pointer;transition:background .15s" class="pa-threat-main-row">' +

            // Icon bubble
            '<div style="width:40px;height:40px;border-radius:10px;background:'+sc+'18;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0">'+icon+'</div>' +

            // Name + severity desc
            '<div>' +
              '<div style="font-size:13px;font-weight:800;color:var(--text-bright)">'+h.name+'</div>' +
              '<div style="font-size:10px;color:var(--text-dim);margin-top:1px">'+desc+'</div>' +
            '</div>' +

            // Event count
            '<div style="text-align:center;min-width:52px">' +
              '<div style="font-size:20px;font-weight:900;color:'+sc+';line-height:1">'+h.count.toLocaleString()+'</div>' +
              '<div style="font-size:9px;color:var(--text-dim)">events</div>' +
            '</div>' +

            // Severity badge
            '<div style="min-width:72px;text-align:center">' +
              '<span style="display:inline-block;padding:4px 10px;border-radius:20px;font-size:10px;font-weight:800;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'44;text-transform:uppercase;letter-spacing:.06em">'+h.severity+'</span>' +
            '</div>' +

            // Expand chevron
            '<div id="'+id+'-chev" style="color:var(--text-dim);font-size:11px;transition:transform .2s">▼</div>' +
          '</div>' +

          // ── Progress bar (event volume relative to max) ────────────
          '<div style="padding:0 16px;padding-bottom:2px">' +
            '<div style="height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden">' +
              '<div style="width:'+barW+'%;height:100%;background:linear-gradient(90deg,'+sc+','+sc+'88);border-radius:2px;transition:width .6s ease"></div>' +
            '</div>' +
          '</div>' +

          // ── Expandable detail panel ────────────────────────────────
          '<div id="'+id+'" style="display:none;border-top:1px solid '+sc+'22;padding:14px 16px;background:rgba(0,0,0,.15)">' +
            '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:'+( ex ? '12px' : '0')+'px">' +
              '<div>' +
                '<div style="font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">First/Last Seen</div>' +
                '<div style="font-size:12px;color:var(--text-bright);font-family:var(--mono)">'+ts+'</div>' +
              '</div>' +
              '<div>' +
                '<div style="font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Total Matches</div>' +
                '<div style="font-size:12px;color:'+sc+';font-weight:700">'+h.count.toLocaleString()+' log entries</div>' +
              '</div>' +
              '<div>' +
                '<div style="font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Risk Level</div>' +
                '<div style="font-size:12px;color:'+sc+';font-weight:700">'+h.severity+'</div>' +
              '</div>' +
            '</div>' +
            ( ex ?
              '<div style="font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px">Sample Log Entry</div>' +
              '<div style="font-family:var(--mono);font-size:11px;color:#94a3b8;background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);border-radius:7px;padding:10px 12px;line-height:1.5;word-break:break-all">'+
                ex.replace(/</g,'&lt;').replace(/>/g,'&gt;') +
              '</div>'
            : '') +
          '</div>' +

        '</div>';
    });

    html += '</div>'; // end flex col

    threatEl.innerHTML = html;

    // Add hover effect via CSS class
    threatEl.querySelectorAll('.pa-threat-main-row').forEach(function(row){
      row.addEventListener('mouseenter',function(){ this.style.background='rgba(255,255,255,.04)'; });
      row.addEventListener('mouseleave',function(){ this.style.background=''; });
    });
  }



  // Anomaly days
  var anomEl = $('pa-anomalies');
  if (anomEl) {
    if (r.anomaly_days && r.anomaly_days.length) {
      anomEl.innerHTML = r.anomaly_days.map(function(a) {
        return '<div class="pa-anom-row">'+
          '<span class="pa-anom-date">📅 '+a.date+'</span>'+
          '<span class="pa-anom-count">'+a.count.toLocaleString()+' events</span>'+
          '<span class="pa-anom-z" style="color:#fb923c">Z='+a.zscore+'</span>'+
        '</div>';
      }).join('');
    } else {
      anomEl.innerHTML = '<div style="color:#4ade80;padding:10px;font-size:13px">✅ No anomalous days detected</div>';
    }
  }

  // Recommendations
  var recEl = $('pa-recommendations');
  if (recEl) {
    var PCOL={'CRITICAL':'#f87171','HIGH':'#fb923c','MEDIUM':'#fbbf24','LOW':'#4ade80'};
    var PBCOL={'CRITICAL':'rgba(248,113,113,.08)','HIGH':'rgba(251,146,60,.08)','MEDIUM':'rgba(251,191,36,.08)','LOW':'rgba(74,222,128,.08)'};
    recEl.innerHTML = (r.recommendations||[]).map(function(rec,i){
      var pc=PCOL[rec.priority]||'#94a3b8', pb=PBCOL[rec.priority]||'rgba(255,255,255,.04)';
      return '<div class="pa-rec-row" style="border-left:3px solid '+pc+';background:'+pb+';animation-delay:'+(i*0.08)+'s">'+
        '<span class="pa-rec-p" style="color:'+pc+'">'+rec.priority+'</span>'+
        '<span class="pa-rec-text">'+rec.text+'</span>'+
      '</div>';
    }).join('');
  }

  // Next check
  set('pa-next-check', r.next_check || '—');

  // Download buttons
  var dlEl = $('pa-download-btns');
  if (dlEl && r.id) {
    dlEl.innerHTML =
      '<button onclick="paExport(\''+r.id+'\',\'pdf\')" style="background:linear-gradient(135deg,#ef4444,#b91c1c);color:#fff;border:none;padding:11px 22px;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700;margin:4px">⬇ PDF</button>'+
      '<button onclick="paExport(\''+r.id+'\',\'html\')" style="background:rgba(26,140,255,.15);color:#4da6ff;border:1px solid rgba(26,140,255,.3);padding:11px 22px;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700;margin:4px">⬇ HTML</button>'+
      '<button onclick="paExport(\''+r.id+'\',\'csv\')" style="background:rgba(74,222,128,.12);color:#4ade80;border:1px solid rgba(74,222,128,.3);padding:11px 22px;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700;margin:4px">⬇ CSV</button>'+
      '<button onclick="paExport(\''+r.id+'\',\'json\')" style="background:rgba(255,255,255,.06);color:var(--text-dim);border:1px solid var(--border2);padding:11px 22px;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700;margin:4px">⬇ JSON</button>';
  }

  // FIM section
  _paRenderFIM(r.fim || {});

  // Charts
  _paTimelineChart(r.timeline||[]);
  _paHourlyChart(r.hourly_pattern||[]);
  _paWeekdayChart(r.weekday_pattern||[]);
  _paCategoryChart(r.categories||{});

  // Animate rows in
  rep.querySelectorAll('.pa-threat-row,.pa-rec-row,.pa-cat-row').forEach(function(el,i){
    el.style.opacity='0'; el.style.transform='translateY(10px)';
    setTimeout(function(){
      el.style.transition='all .3s ease';
      el.style.opacity='1'; el.style.transform='translateY(0)';
    }, 80+i*35);
  });

  // Load AI insights after charts render — ONE consolidated section
  setTimeout(function() { _paLoadAIInsights(r); }, 600);

  // RAG Intelligence Panel — inject after report renders
  setTimeout(function() {
    if (typeof rigInjectPanel === 'function') rigInjectPanel(r);
    window._ragCurrentReport = r;
  }, 800);
}

/* ── Export ──────────────────────────────────────────────────── */
async function paExport(reportId, fmt) {
  var url = '/api/perform-analysis/export/' + reportId + '/' + fmt;
  try {
    var r = await fetch(url);
    if (!r.ok) {
      var err = {}; try { err = await r.json(); } catch(e2){}
      toast('❌ Export failed: ' + (err.error||r.status)); return;
    }
    var blob = await r.blob();
    var ext  = {pdf:'.pdf',html:'.html',csv:'.csv',json:'.json'}[fmt]||'.'+fmt;
    var a    = document.createElement('a');
    a.href   = URL.createObjectURL(blob);
    a.download = 'analysis_report_'+reportId+ext;
    document.body.appendChild(a); a.click();
    setTimeout(function(){ a.remove(); URL.revokeObjectURL(a.href); }, 2000);
    toast('✅ '+fmt.toUpperCase()+' downloaded');
  } catch(e) { toast('❌ '+e.message); }
}

/* ── Charts ──────────────────────────────────────────────────── */

function _paRenderThreats(threats) {
  var el = document.getElementById('pa-threats-table');
  var lbl= document.getElementById('pa-threat-count-label');
  if (!el) return;

  if (lbl) lbl.textContent = threats.length + ' pattern' + (threats.length !== 1 ? 's' : '') + ' detected';

  if (!threats.length) {
    el.innerHTML =
      '<div style="background:rgba(74,222,128,.06);border:1px solid rgba(74,222,128,.2);border-radius:12px;padding:24px;text-align:center;color:#4ade80;font-size:14px;font-weight:700">' +
      '✅ No threat patterns matched in this period' +
      '</div>';
    return;
  }

  var META = {
    'Brute Force Login':      { icon: '🔑', desc: 'Repeated failed login attempts from one or more sources.' },
    'Account Lockout':        { icon: '🔒', desc: 'Accounts locked out — possible automated credential attack.' },
    'Privilege Escalation':   { icon: '⬆',  desc: 'Elevated privileges assigned — check for unauthorized access.' },
    'Windows Defender Alert': { icon: '🛡',  desc: 'Defender flagged malware, ransomware, or suspicious tools.' },
    'Unexpected Shutdown':    { icon: '💥',  desc: 'System crashed or powered off without clean shutdown.' },
    'Disk Hardware Error':    { icon: '💾',  desc: 'Disk I/O errors — risk of data loss or hardware failure.' },
    'Memory Corruption':      { icon: '🧠',  desc: 'Memory or hardware errors — system instability risk.' },
    'Application Crash':      { icon: '💻',  desc: 'Application terminated unexpectedly — check faulting module.' },
    'New Admin Account':      { icon: '👤',  desc: 'New user or admin group membership created.' },
    'Scheduled Task Created': { icon: '⏰',  desc: 'Scheduled task added — common attacker persistence method.' },
    'Audit Policy Change':    { icon: '📋',  desc: 'Security audit policy modified — could hide attacker activity.' },
    'Service Failure':        { icon: '⚙',   desc: 'Windows service crashed — check for tampering or instability.' },
    'Registry Tampering':     { icon: '📝',  desc: 'Registry value modified — potential persistence or config change.' },
    'TLS/SSL Error':          { icon: '🔐',  desc: 'Certificate or TLS handshake failure.' },
    'Network Error':          { icon: '🌐',  desc: 'Network connectivity issues detected.' },
  };

  var SEV_STYLES = {
    CRITICAL: { bg: 'rgba(239,68,68,.08)',   border: 'rgba(239,68,68,.35)',   col: '#f87171', glow: '0 0 20px rgba(239,68,68,.15)' },
    HIGH:     { bg: 'rgba(251,146,60,.07)',   border: 'rgba(251,146,60,.3)',   col: '#fb923c', glow: '0 0 20px rgba(251,146,60,.12)' },
    MEDIUM:   { bg: 'rgba(251,191,36,.06)',   border: 'rgba(251,191,36,.25)',  col: '#fbbf24', glow: 'none' },
    LOW:      { bg: 'rgba(74,222,128,.05)',   border: 'rgba(74,222,128,.2)',   col: '#4ade80', glow: 'none' },
  };

  // Sort: CRITICAL first, then HIGH, MEDIUM, LOW; within same severity by count desc
  var sevOrder = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  threats = threats.slice().sort(function(a,b) {
    var sd = (sevOrder[a.severity]||9) - (sevOrder[b.severity]||9);
    return sd !== 0 ? sd : b.count - a.count;
  });

  // Group critical/high separately for visual emphasis
  var html = '';
  var critHigh = threats.filter(function(h){ return h.severity === 'CRITICAL' || h.severity === 'HIGH'; });
  var medLow   = threats.filter(function(h){ return h.severity === 'MEDIUM'   || h.severity === 'LOW';  });

  function makeCard(h) {
    var ss  = SEV_STYLES[h.severity] || SEV_STYLES.LOW;
    var meta= META[h.name] || { icon: '⚠', desc: 'Suspicious activity detected matching this pattern.' };
    var ex  = h.examples && h.examples[0] ? h.examples[0].message : '';
    var ts  = (h.latest || '').substring(0, 16);
    var pct = h.score ? Math.min(100, Math.round(h.score / 10)) : 0;

    return '<div style="background:' + ss.bg + ';border:1px solid ' + ss.border + ';border-radius:14px;' +
      'padding:18px;display:flex;flex-direction:column;gap:10px;box-shadow:' + ss.glow + ';' +
      'transition:transform .15s;cursor:default" ' +
      'class="pa-fim-card">' +

      // Header row
      '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">' +
        '<div style="display:flex;align-items:center;gap:10px">' +
          '<div style="font-size:22px;line-height:1;flex-shrink:0">' + meta.icon + '</div>' +
          '<div>' +
            '<div style="font-size:13px;font-weight:800;color:#e2e8f0;line-height:1.2">' + h.name + '</div>' +
            '<div style="margin-top:3px">' +
              '<span style="background:' + ss.col + '22;color:' + ss.col + ';border:1px solid ' + ss.col + '55;' +
              'padding:1px 8px;border-radius:4px;font-size:10px;font-weight:800;letter-spacing:.06em">' +
              h.severity + '</span>' +
            '</div>' +
          '</div>' +
        '</div>' +
        // Hit counter
        '<div style="text-align:right;flex-shrink:0">' +
          '<div style="font-size:26px;font-weight:900;color:' + ss.col + ';line-height:1;font-variant-numeric:tabular-nums">' +
            h.count.toLocaleString() + '</div>' +
          '<div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.05em">events</div>' +
        '</div>' +
      '</div>' +

      // Description
      '<div style="font-size:12px;color:#94a3b8;line-height:1.5">' + meta.desc + '</div>' +

      // Severity bar
      '<div>' +
        '<div style="display:flex;justify-content:space-between;margin-bottom:4px">' +
          '<span style="font-size:10px;color:#64748b">Threat Score</span>' +
          '<span style="font-size:10px;color:' + ss.col + ';font-weight:700">' + pct + '/100</span>' +
        '</div>' +
        '<div style="height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden">' +
          '<div style="height:100%;width:' + pct + '%;background:' + ss.col + ';border-radius:2px;' +
          'transition:width .6s ease"></div>' +
        '</div>' +
      '</div>' +

      // Example message (if available and meaningful)
      (ex ? '<div style="background:rgba(0,0,0,.2);border-radius:8px;padding:8px 10px;border-left:2px solid ' + ss.col + '66">' +
        '<div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Latest Example</div>' +
        '<div style="font-size:11px;color:#94a3b8;font-family:var(--mono,monospace);line-height:1.4;word-break:break-word">' +
          ex.substring(0, 130) + (ex.length > 130 ? '…' : '') +
        '</div>' +
      '</div>' : '') +

      // Footer: last seen
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-top:2px">' +
        '<span style="font-size:10px;color:#475569">Last seen</span>' +
        '<span style="font-size:11px;color:#64748b;font-family:var(--mono,monospace)">' + (ts || '—') + '</span>' +
      '</div>' +

    '</div>';
  }

  // Critical/High: 2-column grid
  if (critHigh.length > 0) {
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-bottom:12px">';
    critHigh.forEach(function(h) { html += makeCard(h); });
    html += '</div>';
  }

  // Medium/Low: 3-column compact grid
  if (medLow.length > 0) {
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px">';
    medLow.forEach(function(h) { html += makeCard(h); });
    html += '</div>';
  }

  el.innerHTML = html;
}

function _paTimelineChart(timeline) {
  var ctx = document.getElementById('pa-chart-timeline');
  if (!ctx||!timeline.length) return;
  if (_paCharts.timeline) { _paCharts.timeline.destroy(); }
  var labels = timeline.map(function(t){return t.date;});
  var data   = timeline.map(function(t){return t.count;});
  var avg    = data.reduce(function(a,b){return a+b;},0)/(data.length||1);
  _paCharts.timeline = new Chart(ctx,{
    type:'line',
    data:{labels:labels,datasets:[
      {label:'Events',data:data,borderColor:'#1a8cff',backgroundColor:'rgba(26,140,255,.12)',
       borderWidth:2,pointRadius:3,pointHoverRadius:6,
       pointBackgroundColor:data.map(function(v){return v>avg*1.8?'#ef4444':'#1a8cff';}),
       tension:0.35,fill:true},
      {label:'Avg',data:data.map(function(){return Math.round(avg);}),
       borderColor:'rgba(255,255,255,.15)',borderDash:[4,4],borderWidth:1,pointRadius:0,fill:false}
    ]},
    options:{plugins:{legend:{labels:{color:'#8faac8',font:{size:11}}}},
      scales:{x:{ticks:{color:'#4a6080',maxTicksLimit:10},grid:{color:'#1a2540'}},
              y:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'},beginAtZero:true}}}
  });
}

function _paHourlyChart(hourly) {
  var ctx = document.getElementById('pa-chart-hourly');
  if (!ctx) return;
  if (_paCharts.hourly) { _paCharts.hourly.destroy(); }
  var maxV = Math.max.apply(null,hourly.map(function(h){return h.count;}))||1;
  _paCharts.hourly = new Chart(ctx,{
    type:'bar',
    data:{labels:hourly.map(function(h){return h.hour;}),
      datasets:[{label:'Activity',data:hourly.map(function(h){return h.count;}),
        backgroundColor:hourly.map(function(h){var p=h.count/maxV;return p>0.75?'#ef444488':p>0.45?'#fb923c88':'#1a8cff44';}),
        borderColor:hourly.map(function(h){var p=h.count/maxV;return p>0.75?'#ef4444':p>0.45?'#fb923c':'#1a8cff';}),
        borderWidth:1,borderRadius:3}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#4a6080',maxRotation:0,font:{size:9}},grid:{color:'#1a2540'}},
              y:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'},beginAtZero:true}}}
  });
}

function _paWeekdayChart(weekday) {
  var ctx = document.getElementById('pa-chart-weekday');
  if (!ctx) return;
  if (_paCharts.weekday) { _paCharts.weekday.destroy(); }
  _paCharts.weekday = new Chart(ctx,{
    type:'bar',
    data:{labels:weekday.map(function(w){return w.day;}),
      datasets:[{label:'Events',data:weekday.map(function(w){return w.count;}),
        backgroundColor:'rgba(26,140,255,.45)',borderColor:'#1a8cff',borderWidth:1,borderRadius:4}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'}},
              y:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'},beginAtZero:true}}}
  });
}

function _paCategoryChart(cats) {
  var ctx = document.getElementById('pa-chart-cats');
  if (!ctx) return;
  if (_paCharts.cats) { _paCharts.cats.destroy(); }
  var names  = Object.keys(cats);
  var totals = names.map(function(n){return cats[n].total||0;});
  var errors = names.map(function(n){return (cats[n].errors||0)+(cats[n].critical||0);});
  _paCharts.cats = new Chart(ctx,{
    type:'bar',
    data:{labels:names.map(function(n){return n.replace('_',' ');}),
      datasets:[
        {label:'Total', data:totals,backgroundColor:'rgba(26,140,255,.3)',borderColor:'#1a8cff',borderWidth:1,borderRadius:4},
        {label:'Errors',data:errors,backgroundColor:'rgba(239,68,68,.5)', borderColor:'#ef4444',borderWidth:1,borderRadius:4}
      ]},
    options:{plugins:{legend:{labels:{color:'#8faac8',font:{size:11}}}},
      scales:{x:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'}},
              y:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'},beginAtZero:true}}}
  });
}

function _paRenderFIM(fim) {
  var $ = function(id){ return document.getElementById(id); };
  var set = function(id,v){ var e=$(id); if(e) e.textContent=v; };

  var events  = fim.events  || [];
  var byAction= fim.by_action || {};
  set('pa-fim-total',   (fim.total   || 0).toLocaleString());
  set('pa-fim-crit',    (fim.critical || 0).toLocaleString());
  set('pa-fim-high',    (fim.high    || 0).toLocaleString());
  set('pa-fim-actions', Object.keys(byAction).length.toLocaleString());

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
    var critMark= ev.critical ? '<span style="color:#f87171;font-size:9px;margin-left:4px">&#9632;</span>' : '';
    return '<tr style="' + critRow + 'border-bottom:1px solid var(--border)">' +
      '<td style="padding:9px 14px;font-family:var(--mono);font-size:11px;color:var(--text-bright);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' +
        ev.file + critMark + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim)">' + ev.host + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="background:' + ac + '18;color:' + ac + ';border:1px solid ' + ac + '44;' +
        'padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">' + ev.action + '</span>' +
      '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-muted);font-family:var(--mono)">' + ev.user + '</td>' +
      '<td style="padding:9px 14px;font-size:11px;color:var(--text-dim);font-family:var(--mono)">' + (ev.timestamp||'').substring(11,19) + '</td>' +
      '<td style="padding:9px 14px">' +
        '<span style="color:' + sc + ';font-size:10px;font-weight:700">' + ev.severity + '</span>' +
      '</td>' +
    '</tr>';
  }).join('');
}

/* ── Threat accordion toggle ─────────────────────────────────── */
function paToggleThreat(id) {
  var panel = document.getElementById(id);
  var chev  = document.getElementById(id + '-chev');
  if (!panel) return;
  var open = panel.style.display === 'block';
  panel.style.display = open ? 'none' : 'block';
  if (chev) {
    chev.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
    chev.style.color     = open ? 'var(--text-dim)' : 'var(--sky-bright)';
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
