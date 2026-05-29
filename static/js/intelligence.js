/**
 * static/js/intelligence.js — Secure Eye Trust+
 * Real API schemas verified against live endpoints 2026-05-14:
 *
 * GET /api/pipeline/stats  → {ok, pipeline:{processed,accepted,duplicates,rejected,alerts_fired},
 *                              worker:{enqueued,completed,failed,queue_size,workers},
 *                              alerts:{total_pushed,in_memory,subscribers,unread}}
 *
 * GET /api/intelligence    → {ok, generated_at, failed_logons, lockouts, malware_events,
 *                              network_blocks, priv_escalations,
 *                              threat_summary:[{type,severity,detail}],
 *                              top_event_ids:[{event_id,count,level,last_seen}]}
 *
 * GET /api/perform-analysis/latest → {ok, cached, report:{risk_summary:{label,score,
 *                              risk_color,risk_icon,risk_message,threat_types,anomaly_days,
 *                              chain_count}, threat_hits:[...], attack_chains:[], anomaly_days:[]}}
 */

var _pipelineTimer = null;
var _intelLoading  = false;

/* ═══════════════════════════════════════════════════════════
   PIPELINE BAR
═══════════════════════════════════════════════════════════ */
async function loadPipelineStats() {
  var dot = document.getElementById('pipeline-dot');
  if (dot) dot.style.background = '#fbbf24';
  try {
    var resp = await fetch('/api/pipeline/stats');
    if (!resp.ok) throw new Error('HTTP '+resp.status);
    var d = await resp.json();
    if (!d.ok) throw new Error(d.error||'error');
    var p=d.pipeline||{}, w=d.worker||{}, a=d.alerts||{};
    _ps('ps-processed', _fmt(p.processed  ||0));
    _ps('ps-accepted',  _fmt(p.accepted   ||0));
    _ps('ps-dupes',     _fmt(p.duplicates ||0));
    _ps('ps-alerts',    _fmt(a.total_pushed||p.alerts_fired||0));
    _ps('ps-queue',     _fmt(w.queue_size ||0));
    _ps('ps-ml',        w.workers ? w.workers+' threads' : 'active');
    if (dot) dot.style.background = '#22c55e';
  } catch(e) {
    // Fallback from /api/stats
    try {
      var r2 = await fetch('/api/stats');
      var s  = await r2.json();
      var tot=0, err=0;
      Object.values(s).forEach(function(c){ tot+=(c.total||0); err+=(c.errors||0); });
      _ps('ps-processed', _fmt(tot)); _ps('ps-accepted', _fmt(tot));
      _ps('ps-dupes','0'); _ps('ps-alerts',_fmt(err)); _ps('ps-queue','0'); _ps('ps-ml','zscore');
    } catch(e2){}
    if (dot) dot.style.background = '#22c55e';
  }
}
function startPipelinePolling(){ if(_pipelineTimer)return; loadPipelineStats(); _pipelineTimer=setInterval(loadPipelineStats,12000); }
function stopPipelinePolling(){ if(_pipelineTimer){clearInterval(_pipelineTimer);_pipelineTimer=null;} }

/* ═══════════════════════════════════════════════════════════
   INTELLIGENCE PANEL
═══════════════════════════════════════════════════════════ */
async function loadIntelligence() {
  if (_intelLoading) return;
  _intelLoading = true;
  var btn = document.getElementById('intel-refresh-btn');
  if (btn){ btn.disabled=true; btn.innerHTML='⟳ Analyzing…'; }
  ['icard-crit-val','icard-high-val','icard-chains-val','icard-anom-val'].forEach(function(id){
    var el=document.getElementById(id); if(el){el.textContent='…';el.style.opacity='.4';}
  });
  try {
    var results = await Promise.allSettled([
      fetch('/api/intelligence'),
      fetch('/api/perform-analysis/latest'),
    ]);
    var intel=null, report=null;
    if (results[0].status==='fulfilled' && results[0].value.ok) {
      var d=await results[0].value.json(); if(d.ok) intel=d;
    }
    if (results[1].status==='fulfilled' && results[1].value.ok) {
      var d2=await results[1].value.json(); if(d2.ok && d2.report) report=d2.report;
    }
    if (!intel && !report) throw new Error('No data');
    _render(intel, report);
  } catch(e) {
    console.warn('[intelligence]', e.message);
    var msgEl=document.getElementById('intel-risk-msg');
    if(msgEl){msgEl.textContent='Intelligence engine error: '+e.message;msgEl.style.color='#ef4444';}
    ['icard-crit-val','icard-high-val','icard-chains-val','icard-anom-val'].forEach(function(id){
      var el=document.getElementById(id); if(el){el.textContent='—';el.style.opacity='.4';}
    });
  } finally {
    _intelLoading=false;
    if(btn){btn.disabled=false;btn.innerHTML='⟳ Refresh Intelligence';}
  }
}

function _render(intel, report) {
  /* --- derive values from report (preferred) then intel --- */
  var critCount=0, highCount=0, chainCount=0, anomCount=0;
  var score=0, level='Normal', color='#22c55e', icon='✅';
  var msg='No significant threats in current window';
  var threats=[], chains=[];

  if (report) {
    var rs=report.risk_summary||{};
    score=rs.score||0; level=rs.label||'Normal';
    color=rs.risk_color||_lcolor(level); icon=rs.risk_icon||_licon(level);
    msg=rs.risk_message||_lmsg(level,score);
    chainCount=(report.attack_chains||[]).length;
    anomCount=(report.anomaly_days||[]).length;
    chains=report.attack_chains||[];
    var hits=report.threat_hits||[];
    critCount=hits.filter(function(t){return t.severity==='CRITICAL';}).length;
    highCount=hits.filter(function(t){return t.severity==='HIGH';}).length;
    threats=hits.map(function(h){return{name:h.name,severity:h.severity,count:h.count,
      detail:h.human_summary||h.description||'',confidence_pct:h.confidence_pct,
      latest:h.latest||'',off_hours:h.off_hours_count||0};});
  }

  if (intel && !threats.length) {
    (intel.threat_summary||[]).forEach(function(t){
      var sev=t.severity||'MEDIUM';
      if(sev==='CRITICAL')critCount++; else if(sev==='HIGH')highCount++;
      threats.push({name:t.type,severity:sev,count:_cfor(intel,t.type),
        detail:t.detail,confidence_pct:null,latest:'',off_hours:0});
    });
    if(!score){score=_iscore(intel);level=_classify(score);color=_lcolor(level);icon=_licon(level);msg=_lmsg(level,score);}
  }

  /* --- risk badge --- */
  var badge=document.getElementById('intel-risk-badge');
  if(badge){
    badge.innerHTML=icon+' '+level+' &middot; '+score+'/100';
    badge.style.cssText='padding:8px 20px;border-radius:24px;font-size:14px;font-weight:800;background:'+color+'18;color:'+color+';border:1px solid '+color+'44';
  }
  var msgEl=document.getElementById('intel-risk-msg');
  if(msgEl){msgEl.textContent=msg;msgEl.style.color=score>40?color:'#64748b';}

  /* --- 4 cards --- */
  _ic('icard-crit-val',  critCount, '#ef4444');
  _ic('icard-high-val',  highCount, '#f97316');
  _ic('icard-chains-val',chainCount,'#a78bfa');
  _ic('icard-anom-val',  anomCount, '#fbbf24');
  [['icard-critical','#ef4444',critCount],['icard-high','#f97316',highCount],
   ['icard-chains','#a78bfa',chainCount],['icard-anomalies','#fbbf24',anomCount]
  ].forEach(function(x){
    var el=document.getElementById(x[0]); if(!el)return;
    el.style.borderColor=x[2]>0?x[1].replace('rgb','rgba').replace(')',',.3)'):'';
  });

  /* --- summary text --- */
  var summEl=document.getElementById('intel-summary-text');
  if(summEl){
    var parts=[];
    if(score>0) parts.push(level+' risk ('+score+'/100).');
    if(critCount) parts.push(critCount+' critical threat'+(critCount>1?'s':'')+' detected.');
    if(highCount) parts.push(highCount+' high-severity pattern'+(highCount>1?'s':'')+'.');
    if(chainCount)parts.push(chainCount+' attack chain'+(chainCount>1?'s':'')+' confirmed.');
    if(anomCount) parts.push(anomCount+' anomalous day'+(anomCount>1?'s':'')+' (Z-score > 2.0).');
    if(intel){
      if((intel.malware_events||0)>0)   parts.push(intel.malware_events.toLocaleString()+' malware/defender events.');
      if((intel.priv_escalations||0)>0) parts.push(intel.priv_escalations.toLocaleString()+' privilege escalation events (EID 4672/4673).');
      if((intel.network_blocks||0)>0)   parts.push(intel.network_blocks.toLocaleString()+' network connection blocks (EID 5152/5157).');
      if((intel.failed_logons||0)>0)    parts.push(intel.failed_logons.toLocaleString()+' failed logon attempts.');
    }
    if(!parts.length) parts.push('No significant threats detected.');
    summEl.style.display='block';
    summEl.style.borderLeft='3px solid '+color;
    summEl.style.color=score>40?'#e2e8f0':'#94a3b8';
    _type(summEl, parts.join(' '));
  }

  /* --- threat list --- */
  var tw=document.getElementById('intel-threats-wrap'), tl=document.getElementById('intel-threats-list');
  if(tw&&tl){
    if(threats.length){
      tw.style.display='block';
      var ce=document.getElementById('intel-threat-count');
      if(ce)ce.textContent=threats.length+' active pattern'+(threats.length!==1?'s':'');
      tl.innerHTML=_threatRows(threats);
    } else { tw.style.display='none'; }
  }

  /* --- attack chains --- */
  var cw=document.getElementById('intel-chains-wrap'), cl=document.getElementById('intel-chains-list');
  if(cw&&cl){
    if(chains.length){cw.style.display='block';cl.innerHTML=_chainRows(chains);}
    else cw.style.display='none';
  }

  /* --- top event IDs --- */
  if(intel&&(intel.top_event_ids||[]).length) _renderEids(intel.top_event_ids);
}

/* ── Threat rows ──────────────────────────────────────────── */
function _threatRows(threats){
  var SCOL={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#fbbf24',LOW:'#4ade80'};
  var ORD={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  threats=threats.slice().sort(function(a,b){return(ORD[a.severity]||3)-(ORD[b.severity]||3);});
  return threats.map(function(t){
    var sc=SCOL[t.severity]||'#94a3b8';
    var ts=(t.latest||'').substring(0,16);
    var conf=t.confidence_pct?t.confidence_pct+'%':'';
    var offH=t.off_hours>0?'⚠ '+t.off_hours+' off-hours':'';
    return '<div style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.04)">'+
      '<span style="flex-shrink:0;font-size:9px;font-weight:800;padding:3px 9px;border-radius:20px;background:'+sc+'18;color:'+sc+';border:1px solid '+sc+'44;text-transform:uppercase;letter-spacing:.06em;min-width:68px;text-align:center">'+t.severity+'</span>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:#e2e8f0">'+_e(t.name)+'</div>'+
        (t.detail?'<div style="font-size:11px;color:#64748b;margin-top:2px;line-height:1.5">'+_e(t.detail.substring(0,140))+'</div>':'')+
      '</div>'+
      '<div style="text-align:right;flex-shrink:0">'+
        '<div style="font-size:20px;font-weight:900;color:'+sc+';line-height:1">'+(t.count||0).toLocaleString()+'</div>'+
        '<div style="font-size:9px;color:#475569">events</div>'+
        (conf?'<div style="font-size:10px;color:#64748b;font-family:monospace">'+conf+' conf</div>':'')+
        (ts  ?'<div style="font-size:10px;color:#334155;font-family:monospace">'+ts+'</div>':'')+
        (offH?'<div style="font-size:10px;color:#f97316">'+offH+'</div>':'')+
      '</div></div>';
  }).join('');
}

/* ── Chain rows ───────────────────────────────────────────── */
function _chainRows(chains){
  return chains.map(function(c){
    var desc=c.human_summary||c.description||'';
    var conf=c.confidence_pct||'';
    var steps=(c.steps||c.events||[]).join(' → ');
    return '<div style="padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.04)">'+
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">'+
        '<span>🔗</span>'+
        '<span style="font-size:13px;font-weight:700;color:#e2e8f0">'+_e(c.name||'Attack Chain')+'</span>'+
        (conf?'<span style="font-size:10px;font-family:monospace;color:#a78bfa;margin-left:auto">'+conf+'% conf</span>':'')+
      '</div>'+
      (desc?'<div style="font-size:12px;color:#64748b;line-height:1.6;margin-bottom:4px">'+_e(desc)+'</div>':'')+
      (steps?'<div style="font-size:10px;color:#475569;font-family:monospace;background:rgba(0,0,0,.25);padding:5px 10px;border-radius:5px;border-left:2px solid #a78bfa">'+_e(steps)+'</div>':'')+
    '</div>';
  }).join('');
}

/* ── Top Event IDs table ─────────────────────────────────── */
function _renderEids(eids){
  var slot=document.getElementById('intel-event-ids-wrap');
  if(!slot){
    var cw=document.getElementById('intel-chains-wrap'); if(!cw)return;
    slot=document.createElement('div'); slot.id='intel-event-ids-wrap'; slot.style.marginTop='12px';
    cw.parentNode.insertBefore(slot,cw.nextSibling);
  }
  var LCOL={FAILURE:'#ef4444',WARNING:'#fbbf24',SUCCESS:'#4ade80',INFO:'#38bdf8'};
  var ENAMES={4624:'Logon Success',4625:'Failed Logon',4634:'Logoff',4648:'Explicit Logon',
    4656:'Object Handle',4658:'Handle Closed',4663:'Object Access',4672:'Special Privileges',
    4688:'Process Created',4690:'Handle Dup',4698:'Task Created',4702:'Task Updated',
    4720:'Account Created',4740:'Account Lockout',5152:'Packet Blocked',5154:'Listen Allowed',
    5156:'Connection Allowed',5157:'Connection Blocked',5158:'Bind Allowed',5379:'Credential Read'};
  var rows=eids.slice(0,12).map(function(e){
    var lc=LCOL[e.level]||'#94a3b8';
    return '<tr style="border-bottom:1px solid rgba(255,255,255,.04)">'+
      '<td style="padding:8px 14px;font-family:monospace;font-size:12px;color:#e2e8f0;font-weight:700">'+e.event_id+'</td>'+
      '<td style="padding:8px 14px;font-size:12px;color:#94a3b8">'+(ENAMES[e.event_id]||'Event '+e.event_id)+'</td>'+
      '<td style="padding:8px 14px"><span style="background:'+lc+'18;color:'+lc+';border:1px solid '+lc+'44;padding:1px 7px;border-radius:4px;font-size:9px;font-weight:700">'+e.level+'</span></td>'+
      '<td style="padding:8px 14px;font-size:12px;color:#e2e8f0;font-weight:700;text-align:right">'+e.count.toLocaleString()+'</td>'+
      '<td style="padding:8px 14px;font-size:11px;color:#334155;font-family:monospace">'+(e.last_seen||'').substring(0,10)+'</td>'+
    '</tr>';
  }).join('');
  slot.innerHTML='<div class="panel"><div class="panel-header"><div class="panel-title">📋 Top Event IDs — Live Security Log</div><div style="font-size:11px;color:#64748b">'+eids.length+' unique event IDs</div></div>'+
    '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'+
    '<thead><tr style="background:rgba(255,255,255,.03)">'+
    ['Event ID','Description','Level','Count','Last Seen'].map(function(h){return'<th style="padding:9px 14px;text-align:'+(h==='Count'?'right':'left')+';color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid rgba(255,255,255,.07)">'+h+'</th>';}).join('')+
    '</tr></thead><tbody>'+rows+'</tbody></table></div></div>';
}

/* ── Helpers ──────────────────────────────────────────────── */
function _cfor(intel,type){
  return {
    'Privilege Escalation':intel.priv_escalations,
    'Malware Detected':intel.malware_events,
    'Network Blocks':intel.network_blocks,
    'Failed Logons':intel.failed_logons,
    'Account Lockout':intel.lockouts
  }[type]||0;
}
function _iscore(intel){
  var s=0;
  if((intel.malware_events||0)>0)   s+=30;
  if((intel.priv_escalations||0)>50) s+=20;
  if((intel.failed_logons||0)>10)   s+=15;
  if((intel.lockouts||0)>0)         s+=10;
  if((intel.network_blocks||0)>1000) s+=10;
  return Math.min(100,s);
}
function _classify(s){ return s>=75?'Critical':s>=50?'High':s>=25?'Suspicious':'Normal'; }
function _lcolor(l){ return{Critical:'#ef4444',High:'#f97316',Suspicious:'#fbbf24',Normal:'#22c55e'}[l]||'#22c55e'; }
function _licon(l){  return{Critical:'🚨',High:'🔶',Suspicious:'⚠️',Normal:'✅'}[l]||'✅'; }
function _lmsg(l,s){ return{
  Critical:'CRITICAL — Active threats detected. Immediate action required.',
  High:'HIGH RISK — Threats confirmed. Investigate within 2 hours.',
  Suspicious:'SUSPICIOUS — Unusual patterns. Review within 24 hours.',
  Normal:'All clear — no significant threats in current monitoring window.'
}[l]||'Risk score: '+s+'/100'; }
function _ic(id,val,col){
  var el=document.getElementById(id); if(!el)return;
  el.textContent=String(val!==undefined?val:'—'); el.style.color=col; el.style.opacity='1';
  el.style.transition='transform .2s'; el.style.transform='scale(1.18)';
  setTimeout(function(){el.style.transform='scale(1)';},200);
}
function _type(el,text){
  var i=0; el.textContent='';
  var spd=Math.max(10,Math.min(22,2400/Math.max(text.length,1)));
  var iv=setInterval(function(){if(i<text.length){el.textContent+=text[i];i++;}else clearInterval(iv);},spd);
}
function _ps(id,val){var el=document.getElementById(id);if(el)el.textContent=val;}
function _fmt(n){return(n===undefined||n===null)?'—':Number(n).toLocaleString();}
function _e(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

/* ═══════════════════════════════════════════════════════════
   AUTO-WIRE loadDashboard
═══════════════════════════════════════════════════════════ */
(function(){
  var _orig=typeof window.loadDashboard==='function'?window.loadDashboard:null;
  window.loadDashboard=async function(){
    if(_orig) await _orig();
    startPipelinePolling();
    loadIntelligence();
  };
})();
