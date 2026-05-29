/**
 * perform_analysis_redesign.js  v3
 * ─ Centered hero layout with conic-gradient revolver ring
 * ─ Clickable stat cards → drawer with real log events
 * ─ Errors tab → full event table + inline AI "why + fix" per row
 */

/* ═══════════════════ PALETTE ══════════════════════ */
var PA_COLORS = {
  CRITICAL: { hex:'#ff3d5a', glow:'rgba(255,61,90,0.35)',  bg:'rgba(255,61,90,0.08)'  },
  HIGH:     { hex:'#ff7a2f', glow:'rgba(255,122,47,0.3)',  bg:'rgba(255,122,47,0.08)' },
  MEDIUM:   { hex:'#f5c518', glow:'rgba(245,197,24,0.25)', bg:'rgba(245,197,24,0.07)' },
  LOW:      { hex:'#00e5a0', glow:'rgba(0,229,160,0.25)',  bg:'rgba(0,229,160,0.07)'  },
  INFO:     { hex:'#38bdf8', glow:'rgba(56,189,248,0.25)', bg:'rgba(56,189,248,0.07)' },
};

/* ═══════════════════ STYLES ═══════════════════════ */
function _paInjectStyles() {
  if (document.getElementById('pa-r3-css')) return;
  var s = document.createElement('style');
  s.id = 'pa-r3-css';
  s.textContent = `
/* ── page bg ── */
#page-perform { background:#05080f; min-height:100vh; padding:0 0 60px; }

/* The .page class is display:block — page-perform is handled by JS state machine */
/* report container full width */
#r3-report { width:100%; box-sizing:border-box; display:none; }

/* ══ HERO IDLE ══════════════════════════════════════ */
.r3-hero {
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  min-height:68vh; width:100%; gap:0; position:relative; overflow:hidden;
  padding:40px 20px; box-sizing:border-box;
}
.r3-hero-bg {
  position:absolute; inset:0; pointer-events:none;
  background:radial-gradient(ellipse 70% 55% at 50% 55%, rgba(26,111,255,0.09) 0%, transparent 70%);
}
.r3-scanline {
  position:absolute; inset:0; pointer-events:none; opacity:0.025;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,#fff 2px,#fff 4px);
}
/* revolver ring */
.r3-ring-wrap {
  width:200px; height:200px; position:relative; margin-bottom:28px;
  display:flex; align-items:center; justify-content:center;
}
.r3-ring-svg { position:absolute; inset:0; width:100%; height:100%; }
.r3-ring-svg circle.track { fill:none; stroke:rgba(255,255,255,0.06); stroke-width:8; }
.r3-ring-arc {
  fill:none; stroke-width:8; stroke-linecap:round;
  stroke-dasharray:565; stroke-dashoffset:0;
  transform-origin:center; transform:rotate(-90deg);
  animation:r3-spin 3.5s linear infinite;
  filter:drop-shadow(0 0 8px var(--arc-color,#38bdf8));
}
.r3-ring-arc2 {
  fill:none; stroke-width:4; stroke-linecap:round;
  stroke-dasharray:282; stroke-dashoffset:90;
  transform-origin:center; transform:rotate(60deg);
  animation:r3-spin 5s linear infinite reverse;
  opacity:0.5;
}
@keyframes r3-spin { to { transform:rotate(270deg); } }
.r3-ring-inner {
  position:relative; z-index:2; font-size:64px; line-height:1;
  animation:r3-pulse 3s ease-in-out infinite;
  filter:drop-shadow(0 0 20px rgba(56,189,248,0.7));
}
@keyframes r3-pulse {
  0%,100%{filter:drop-shadow(0 0 20px rgba(56,189,248,0.7));transform:scale(1)}
  50%    {filter:drop-shadow(0 0 36px rgba(56,189,248,1));transform:scale(1.05)}
}
/* floating particles */
.r3-particle {
  position:absolute; border-radius:50%; pointer-events:none; z-index:0;
  animation:r3-float linear infinite;
}
@keyframes r3-float {
  0%  {transform:translateY(0) scale(1);opacity:0}
  10% {opacity:1}
  90% {opacity:1}
  100%{transform:translateY(-100px) scale(0.5);opacity:0}
}
.r3-hero-title {
  font-size:30px; font-weight:900; letter-spacing:-0.02em; z-index:1;
  background:linear-gradient(135deg,#fff 0%,#94d4ff 60%,#38bdf8 100%);
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text; text-align:center; margin-bottom:8px;
}
.r3-hero-sub {
  color:#4a6080; font-size:13px; max-width:460px; text-align:center;
  line-height:1.7; z-index:1; margin-bottom:32px;
}
.r3-launch-btn {
  z-index:1; background:linear-gradient(135deg,#1a6fff,#0044cc);
  color:#fff; border:none; padding:16px 48px; border-radius:14px;
  cursor:pointer; font-size:16px; font-weight:800; letter-spacing:0.03em;
  box-shadow:0 8px 32px rgba(26,111,255,0.5), inset 0 0 0 1px rgba(255,255,255,0.1);
  transition:all .2s; display:flex; align-items:center; gap:10px;
}
.r3-launch-btn:hover{transform:translateY(-2px);box-shadow:0 14px 40px rgba(26,111,255,0.65)}
.r3-launch-btn:active{transform:translateY(0)}

/* ══ LOADING ARC ════════════════════════════════════ */
.r3-loader {
  display:none; flex-direction:column; align-items:center;
  justify-content:center; min-height:60vh; gap:28px;
  width:100%; box-sizing:border-box; padding:40px 20px;
}
.r3-arc-wrap { width:180px; height:180px; position:relative; }
.r3-arc-wrap svg { width:100%; height:100%; animation:r3-loader-spin 2s linear infinite; }
@keyframes r3-loader-spin{to{transform:rotate(360deg)}}
.r3-arc-center {
  position:absolute; inset:0; display:flex; flex-direction:column;
  align-items:center; justify-content:center; gap:2px;
}
.r3-arc-pct  {font-size:30px;font-weight:900;color:#fff;font-variant-numeric:tabular-nums}
.r3-arc-lbl  {font-size:10px;color:#38bdf8;text-transform:uppercase;letter-spacing:.1em}
.r3-lsteps   {display:flex;flex-direction:column;gap:8px;width:320px}
.r3-lstep    {display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;border:1px solid rgba(255,255,255,0.05);font-size:12px;color:#4a6080;transition:all .4s}
.r3-lstep.active{border-color:rgba(56,189,248,.3);background:rgba(56,189,248,.06);color:#e0f2fe;box-shadow:0 0 16px rgba(56,189,248,.1)}
.r3-lstep.done  {border-color:rgba(0,229,160,.25);background:rgba(0,229,160,.05);color:#6ee7b7}
.r3-ldot     {width:8px;height:8px;border-radius:50%;flex-shrink:0;background:rgba(255,255,255,.12)}
.r3-lstep.active .r3-ldot{background:#38bdf8;box-shadow:0 0 8px #38bdf8;animation:r3-dot-p 1s ease-in-out infinite}
.r3-lstep.done   .r3-ldot{background:#00e5a0;box-shadow:0 0 6px #00e5a0}
@keyframes r3-dot-p{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.5)}}

/* ══ REPORT BODY ════════════════════════════════════ */
#r3-report { display:none; }

/* centered hero card */
.r3-hero-card {
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  padding:40px 32px 32px;
  background:linear-gradient(160deg,#070b14 0%,#0a1220 100%);
  border:1px solid rgba(255,255,255,0.07); border-radius:20px;
  margin-bottom:20px; position:relative; overflow:hidden;
  text-align:center;
}
.r3-hero-bg-glow {
  position:absolute; inset:0; pointer-events:none;
}

/* revolver ring inside report */
.r3-report-ring {
  width:200px; height:200px; position:relative; margin:0 auto 12px;
  display:flex; align-items:center; justify-content:center;
  flex-shrink:0;
}
.r3-report-ring svg { position:absolute; inset:0; width:100%; height:100%; }
.r3-ring-score-wrap {
  position:relative; z-index:2; display:flex; flex-direction:column;
  align-items:center; justify-content:center;
}
.r3-ring-score { font-size:54px; font-weight:900; line-height:1; font-variant-numeric:tabular-nums; }
.r3-ring-score-lbl { font-size:11px; color:#4a6080; margin-top:2px; }
.r3-risk-badge {
  display:inline-flex; align-items:center; padding:6px 20px; border-radius:20px;
  font-size:12px; font-weight:800; letter-spacing:.06em; text-transform:uppercase;
  border:1px solid; margin-top:10px;
}
.r3-hero-title-sm {
  font-size:13px; color:#94a3b8; margin-top:8px; text-align:center;
}

/* 4 stat cards row */
.r3-stat-row {
  display:grid; grid-template-columns:repeat(4,1fr); gap:12px;
  margin-top:24px; width:100%;
}
.r3-stat-card {
  background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.07);
  border-radius:14px; padding:18px 14px; text-align:center;
  cursor:pointer; transition:all .2s; position:relative; overflow:hidden;
}
.r3-stat-card:hover { transform:translateY(-3px); }
.r3-stat-card-glow {
  position:absolute; bottom:-10px; left:50%; transform:translateX(-50%);
  width:60px; height:20px; border-radius:50%; filter:blur(10px); opacity:.6;
}
.r3-stat-val { font-size:26px; font-weight:900; line-height:1; font-variant-numeric:tabular-nums; position:relative; z-index:1; }
.r3-stat-lbl { font-size:10px; color:#4a6080; text-transform:uppercase; letter-spacing:.07em; margin-top:4px; position:relative; z-index:1; }
.r3-stat-icon { font-size:18px; margin-bottom:4px; position:relative; z-index:1; }
.r3-stat-hint { font-size:9px; margin-top:3px; opacity:.7; position:relative; z-index:1; }

/* ══ DRAWER ═════════════════════════════════════════ */
.r3-drawer {
  display:none; position:fixed; inset:0; z-index:9999;
  background:rgba(0,0,0,.75); backdrop-filter:blur(4px);
  align-items:flex-end; justify-content:center;
}
.r3-drawer.open { display:flex; }
.r3-drawer-box {
  width:min(1100px,100%); height:82vh; background:#070c18;
  border-top:1px solid rgba(255,255,255,.09); border-radius:20px 20px 0 0;
  display:flex; flex-direction:column; overflow:hidden;
  transform:translateY(100%); transition:transform .35s cubic-bezier(.22,1,.36,1);
}
.r3-drawer.open .r3-drawer-box { transform:translateY(0); }
.r3-drawer-hdr {
  display:flex; align-items:center; justify-content:space-between;
  padding:16px 22px; border-bottom:1px solid rgba(255,255,255,.07);
  flex-shrink:0;
}
.r3-drawer-title { font-size:15px; font-weight:800; color:#e2e8f0; display:flex; align-items:center; gap:10px; }
.r3-drawer-close {
  width:32px; height:32px; border-radius:8px; background:rgba(255,255,255,.07);
  border:none; color:#94a3b8; font-size:18px; cursor:pointer; line-height:32px;
  display:flex; align-items:center; justify-content:center;
  transition:background .15s;
}
.r3-drawer-close:hover { background:rgba(255,255,255,.13); }
.r3-drawer-tabs {
  display:flex; gap:4px; padding:10px 22px 0; border-bottom:1px solid rgba(255,255,255,.07);
  flex-shrink:0;
}
.r3-dtab {
  padding:8px 18px; border-radius:8px 8px 0 0; font-size:12px; font-weight:700;
  cursor:pointer; background:transparent; border:1px solid rgba(255,255,255,.07);
  border-bottom:none; color:#4a6080; transition:all .15s; position:relative;
  bottom:-1px;
}
.r3-dtab.active {
  background:#0d1525; color:#e2e8f0; border-color:rgba(255,255,255,.1);
  border-bottom-color:#0d1525;
}
.r3-drawer-body {
  flex:1; overflow-y:auto; padding:16px 22px;
}
.r3-drawer-body::-webkit-scrollbar { width:6px; }
.r3-drawer-body::-webkit-scrollbar-track { background:transparent; }
.r3-drawer-body::-webkit-scrollbar-thumb { background:rgba(255,255,255,.1); border-radius:3px; }

/* ── Events table ── */
.r3-evt-table { width:100%; border-collapse:collapse; font-size:12px; }
.r3-evt-table th {
  text-align:left; padding:9px 12px; font-size:10px; text-transform:uppercase;
  letter-spacing:.06em; color:#4a6080; border-bottom:1px solid rgba(255,255,255,.06);
  position:sticky; top:0; background:#070c18; font-weight:700; z-index:2;
}
.r3-evt-table td {
  padding:9px 12px; border-bottom:1px solid rgba(255,255,255,.04);
  color:#94a3b8; vertical-align:top; line-height:1.45;
}
.r3-evt-table tr:hover td { background:rgba(255,255,255,.03); }
.r3-evt-table td.r3-msg { color:#cbd5e1; max-width:380px; word-break:break-word; }
.r3-lbadge {
  display:inline-flex; padding:2px 8px; border-radius:4px;
  font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.04em;
  white-space:nowrap;
}

/* ── AI explain row ── */
.r3-ai-row { display:none; }
.r3-ai-row.open { display:table-row; }
.r3-ai-cell {
  padding:14px 16px !important; background:rgba(26,111,255,.05) !important;
  border-bottom:2px solid rgba(26,111,255,.15) !important;
  border-left:3px solid #1a6fff;
}
.r3-ai-typing-wrap {
  background:rgba(0,0,0,.25); border-radius:10px; padding:14px 16px;
  font-size:12px; line-height:1.7;
}
.r3-ai-section-lbl {
  font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.08em;
  margin-bottom:4px;
}
.r3-ai-section-body { color:#cbd5e1; }
.r3-ai-section-body.typing::after {
  content:'▌'; animation:r3-blink .7s step-end infinite; color:#38bdf8;
}
@keyframes r3-blink{0%,100%{opacity:1}50%{opacity:0}}
.r3-ai-btn {
  display:inline-flex; align-items:center; gap:5px;
  padding:5px 12px; border-radius:6px; font-size:11px; font-weight:700;
  cursor:pointer; border:1px solid rgba(26,111,255,.4);
  background:rgba(26,111,255,.1); color:#60a5fa; transition:all .15s;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; min-width:80px;
}
.r3-ai-btn:hover { background:rgba(26,111,255,.2); }
.r3-ai-btn.loading { opacity:.6; pointer-events:none; }

/* stat-row badges for filter buttons in drawer */
.r3-filter-row {
  display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap;
}
.r3-filter-btn {
  padding:5px 14px; border-radius:20px; font-size:11px; font-weight:700;
  cursor:pointer; border:1px solid; transition:all .15s; background:transparent;
}
.r3-filter-btn.active { color:#fff !important; }

/* ══ SECTION DIVIDER ════════════════════════════════ */
.r3-divider {
  display:flex; align-items:center; gap:12px; margin:24px 0 14px;
}
.r3-divider-label {
  font-size:10px; font-weight:800; text-transform:uppercase;
  letter-spacing:.12em; padding:5px 14px; border-radius:6px;
  white-space:nowrap; font-family:monospace;
}
.r3-divider-line { flex:1; height:1px; background:rgba(255,255,255,.05); }

/* ══ TICKER STRIP ════════════════════════════════════ */
.r3-ticker { display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin-bottom:18px; }
.r3-tick {
  background:#070b14; border:1px solid rgba(255,255,255,.07);
  border-radius:12px; padding:16px 12px; text-align:center; position:relative;
  overflow:hidden; cursor:pointer; transition:all .2s;
}
.r3-tick:hover{transform:translateY(-3px)}
.r3-tick-glow{position:absolute;bottom:-10px;left:50%;transform:translateX(-50%);width:50px;height:18px;border-radius:50%;filter:blur(8px);opacity:.5}
.r3-tick-val{font-size:26px;font-weight:900;line-height:1;position:relative;font-variant-numeric:tabular-nums}
.r3-tick-lbl{font-size:9px;color:#4a6080;margin-top:3px;text-transform:uppercase;letter-spacing:.06em}
.r3-tick-icon{font-size:18px;margin-bottom:3px}

/* ══ THREAT CARDS ════════════════════════════════════ */
.r3-threats { display:flex; flex-direction:column; gap:8px; margin-bottom:18px; }
.r3-threat-card {
  border-radius:12px; overflow:hidden; border:1px solid rgba(255,255,255,.06);
  transition:box-shadow .2s;
}
.r3-threat-card:hover{box-shadow:0 4px 20px rgba(0,0,0,.4)}
.r3-threat-hdr {
  display:grid; grid-template-columns:46px 1fr auto 70px 26px;
  align-items:center; gap:12px; padding:14px 16px; cursor:pointer;
}
.r3-threat-ico {
  width:44px;height:44px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;font-size:20px;flex-shrink:0;
}
.r3-threat-name{font-size:13px;font-weight:800;color:#e2e8f0}
.r3-threat-hint{font-size:10px;color:#4a6080;margin-top:1px}
.r3-threat-cnt{font-size:22px;font-weight:900;line-height:1;text-align:center}
.r3-threat-cnt-lbl{font-size:9px;color:#4a6080;text-align:center}
.r3-sev-pill{display:inline-flex;align-items:center;justify-content:center;padding:4px 10px;border-radius:14px;font-size:9px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;border:1px solid;width:68px}
.r3-chev{font-size:10px;color:#4a6080;transition:transform .25s}
.r3-chev.open{transform:rotate(180deg)}
.r3-threat-bar-bg{height:3px;background:rgba(255,255,255,.04)}
.r3-threat-bar{height:100%;transition:width 1s cubic-bezier(.22,1,.36,1)}
.r3-threat-detail{display:none;border-top:1px solid rgba(255,255,255,.05);padding:14px 16px;background:rgba(0,0,0,.2)}
.r3-detail-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:10px}
.r3-dc-lbl{font-size:10px;color:#4a6080;text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px}
.r3-dc-val{font-size:12px;color:#cbd5e1;font-weight:600}
.r3-sample-log{font-family:'Courier New',monospace;font-size:10px;color:#7dd3fc;background:rgba(0,0,0,.35);border:1px solid rgba(56,189,248,.15);border-radius:8px;padding:8px 12px;line-height:1.6;word-break:break-all;margin-top:8px}

/* ══ MISC ════════════════════════════════════════════ */
.r3-panel{background:#070b14;border:1px solid rgba(255,255,255,.07);border-radius:14px;overflow:hidden;margin-bottom:14px}
.r3-panel-hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.05)}
.r3-panel-title{font-size:12px;font-weight:800;color:#e2e8f0}
.r3-panel-body{padding:14px 16px}
.r3-two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.r3-cat-row{display:flex;flex-direction:column;gap:3px;margin-bottom:10px}
.r3-cat-top{display:flex;justify-content:space-between;align-items:baseline}
.r3-cat-name{font-size:12px;font-weight:700;color:#e2e8f0}
.r3-cat-nums{font-size:10px;color:#4a6080}
.r3-cat-bg{height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.r3-cat-fill{height:100%;border-radius:3px;transition:width 1s cubic-bezier(.22,1,.36,1)}
.r3-anom-row{display:grid;grid-template-columns:88px 1fr 52px 48px;align-items:center;gap:10px;margin-bottom:5px}
.r3-anom-date{font-size:11px;color:#94a3b8;font-family:monospace}
.r3-anom-bg{background:rgba(255,255,255,.05);border-radius:3px;height:5px}
.r3-anom-fill{height:100%;border-radius:3px;transition:width .8s ease}
.r3-anom-cnt{font-size:11px;color:#94a3b8;text-align:right}
.r3-anom-z{font-size:10px;font-weight:700;text-align:right;color:#fb923c;font-family:monospace}
.r3-rec-item{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-radius:8px;border-left:3px solid;margin-bottom:6px;opacity:0;transform:translateX(-6px);animation:r3-rec-in .4s forwards}
@keyframes r3-rec-in{to{opacity:1;transform:translateX(0)}}
.r3-rec-pri{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;padding:2px 7px;border-radius:3px;white-space:nowrap;flex-shrink:0;margin-top:1px}
.r3-rec-txt{font-size:12px;color:#94a3b8;line-height:1.55}
.r3-dl-bar{display:flex;gap:8px;flex-wrap:wrap;padding:14px 16px}
.r3-dl-btn{padding:9px 18px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;border:1px solid;transition:all .15s;display:flex;align-items:center;gap:5px}
.r3-dl-btn:hover{transform:translateY(-1px)}
.r3-fim-stats{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid rgba(255,255,255,.05)}
.r3-fim-stat{padding:16px 12px;text-align:center;border-right:1px solid rgba(255,255,255,.05)}
.r3-fim-stat:last-child{border-right:none}
.r3-fim-val{font-size:26px;font-weight:900;line-height:1}
.r3-fim-lbl{font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}

/* empty state */
.r3-empty{text-align:center;padding:48px 24px;color:#4a6080;font-size:13px}
.r3-empty-ico{font-size:40px;margin-bottom:8px}

/* loading spinner */
.r3-spin-sm{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.2);border-top-color:#38bdf8;border-radius:50%;animation:r3-loader-spin .6s linear infinite;vertical-align:middle}

@keyframes r3-count-in{0%{opacity:0;transform:translateY(10px) scale(.85)}100%{opacity:1;transform:translateY(0) scale(1)}}

@media(max-width:860px){
  .r3-stat-row{grid-template-columns:repeat(2,1fr)}
  .r3-ticker{grid-template-columns:repeat(3,1fr)}
  .r3-two-col{grid-template-columns:1fr}
  .r3-threat-hdr{grid-template-columns:42px 1fr auto 24px}
  .r3-sev-pill{display:none}
  .r3-detail-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:540px){.r3-ticker{grid-template-columns:repeat(2,1fr)}}
  `;
  document.head.appendChild(s);
}

/* ═══════════════════ IDLE HERO ════════════════════ */
function _r3BuildIdle() {
  var idle = document.getElementById('pa-idle');
  if (!idle || idle.dataset.r3) return;
  idle.dataset.r3 = '1';

  var parts = '';
  var pCols = ['#38bdf8','#a855f7','#00e5a0','#ff3d5a','#f5c518','#fb923c'];
  for (var i=0;i<20;i++){
    var col=pCols[i%pCols.length], sz=2+Math.random()*3;
    parts += '<div class="r3-particle" style="left:'+Math.random()*100+'%;bottom:'+Math.random()*80+'%;width:'+sz+'px;height:'+sz+'px;background:'+col+';animation-duration:'+(3+Math.random()*5)+'s;animation-delay:'+Math.random()*6+'s;box-shadow:0 0 '+(sz*2)+'px '+col+'"></div>';
  }

  idle.innerHTML =
    '<div class="r3-hero">'+
    '<div class="r3-hero-bg"></div><div class="r3-scanline"></div>'+parts+
    '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;width:100%;max-width:520px;z-index:1;position:relative">'+
    '<div class="r3-ring-wrap" style="margin:0 auto 28px">'+
      '<svg class="r3-ring-svg" viewBox="0 0 200 200">'+
        '<circle class="track" cx="100" cy="100" r="88"/>'+
        '<circle class="r3-ring-arc" cx="100" cy="100" r="88" style="--arc-color:#38bdf8;stroke:url(#r3g1)"/>'+
        '<circle class="r3-ring-arc2" cx="100" cy="100" r="88" stroke="#a855f7"/>'+
        '<defs><linearGradient id="r3g1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ff3d5a"/><stop offset="33%" stop-color="#f5c518"/><stop offset="66%" stop-color="#00e5a0"/><stop offset="100%" stop-color="#38bdf8"/></linearGradient></defs>'+
      '</svg>'+
      '<div class="r3-ring-inner">🔐</div>'+
    '</div>'+
    '<div class="r3-hero-title">Secure Eye Trust+</div>'+
    '<div class="r3-hero-sub">Deep-scan threat intelligence engine combining ML anomaly detection, MITRE ATT&CK matching, temporal correlation and kill-chain analysis.</div>'+
    '<button class="r3-launch-btn" style="margin:0 auto" onclick="paShowPeriodModal()">'+
      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polygon points="5,3 19,12 5,21"/></svg>'+
      'Launch Analysis'+
    '</button>'+
    '</div>'+
    '</div>';

  // Show idle, hide everything else
  _r3ShowOnly('idle');
}

/* ═══════════════════ LOADER ══════════════════════ */
function _r3BuildLoader() {
  var ld = document.getElementById('pa-loading');
  if (!ld || ld.dataset.r3) return;
  ld.dataset.r3='1';
  ld.innerHTML=
    '<div class="r3-loader" id="r3-loader-inner">'+
    '<div style="display:flex;flex-direction:column;align-items:center;gap:28px;width:100%;max-width:400px">'+
    '<div class="r3-arc-wrap" style="margin:0 auto">'+
      '<svg viewBox="0 0 180 180"><defs><linearGradient id="r3ag" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="#38bdf8" stop-opacity="0"/><stop offset="100%" stop-color="#38bdf8"/></linearGradient></defs>'+
      '<circle cx="90" cy="90" r="80" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="6"/>'+
      '<circle cx="90" cy="90" r="80" fill="none" stroke="url(#r3ag)" stroke-width="6" stroke-linecap="round" stroke-dasharray="502" stroke-dashoffset="502" id="r3-arc-path"/></svg>'+
      '<div class="r3-arc-center"><div class="r3-arc-pct" id="r3-pct">0%</div><div class="r3-arc-lbl">scanning</div></div>'+
    '</div>'+
    '<div class="r3-lsteps" style="width:100%;max-width:380px;margin:0 auto">'+
      '<div class="r3-lstep active" id="r3s1"><div class="r3-ldot"></div>Scanning threat pattern signatures</div>'+
      '<div class="r3-lstep" id="r3s2"><div class="r3-ldot"></div>ML anomaly detection (Isolation Forest)</div>'+
      '<div class="r3-lstep" id="r3s3"><div class="r3-ldot"></div>Temporal correlation & kill-chain analysis</div>'+
      '<div class="r3-lstep" id="r3s4"><div class="r3-ldot"></div>Generating intelligence report</div>'+
    '</div>'+
    '</div>'+
    '</div>';
  // Always hidden until explicitly shown
  ld.style.display='none';
}

/* ═══════════════════ STATE MACHINE ════════════════
   Only ONE state is visible at a time: idle | loading | report
   Call _r3ShowOnly('idle'|'loading'|'report') to switch.
══════════════════════════════════════════════════ */
function _r3ShowOnly(state) {
  var idle  = document.getElementById('pa-idle');
  var ld    = document.getElementById('pa-loading');
  var r3rep = document.getElementById('r3-report');
  var oldrep= document.getElementById('pa-report');
  var runBtn= document.getElementById('pa-run-btn');

  var HIDE      = 'display:none';
  var SHOW_FLEX = 'display:flex;flex-direction:column;align-items:center;justify-content:center;width:100%;min-height:65vh;padding:0;box-sizing:border-box';

  // Hide ALL first
  if (idle)   idle.style.cssText   = HIDE;
  if (ld)     ld.style.cssText     = HIDE;
  if (r3rep)  r3rep.style.display  = 'none';
  if (oldrep) oldrep.style.display = 'none';

  // Run button: only visible when report is shown
  if (runBtn) runBtn.style.display = (state === 'report') ? 'flex' : 'none';

  if (state === 'idle' && idle) {
    idle.style.cssText = SHOW_FLEX;
  } else if (state === 'loading' && ld) {
    ld.style.cssText = SHOW_FLEX;
    ['r3s1','r3s2','r3s3','r3s4'].forEach(function(id,i){
      var el=document.getElementById(id);
      if(el) el.className='r3-lstep'+(i===0?' active':'');
    });
    var arc=document.getElementById('r3-arc-path'); if(arc) arc.setAttribute('stroke-dashoffset','502');
    var pe=document.getElementById('r3-pct'); if(pe) pe.textContent='0%';
  } else if (state === 'report' && r3rep) {
    r3rep.style.display = 'block';
    setTimeout(function(){ r3rep.scrollIntoView({behavior:'smooth',block:'start'}); },100);
  }
}

/* ═══════════════════ ARC ANIMATION ════════════════ */
var _r3ArcTmr = null;
function _r3StartArc(){
  var pct=0, arc=document.getElementById('r3-arc-path'), pe=document.getElementById('r3-pct');
  var sPct=[0,28,55,80], sIds=['r3s1','r3s2','r3s3','r3s4'];
  if(_r3ArcTmr) clearInterval(_r3ArcTmr);
  _r3ArcTmr=setInterval(function(){
    pct=Math.min(pct+0.5+Math.random()*.8,96);
    if(arc) arc.setAttribute('stroke-dashoffset',502-(502*pct/100));
    if(pe) pe.textContent=Math.round(pct)+'%';
    sIds.forEach(function(id,i){
      var el=document.getElementById(id); if(!el) return;
      el.className='r3-lstep'+(pct>=(sPct[i+1]||100)?' done':pct>=sPct[i]?' active':'');
    });
    if(pct>=96) clearInterval(_r3ArcTmr);
  },80);
}
function _r3StopArc(){
  if(_r3ArcTmr){clearInterval(_r3ArcTmr);_r3ArcTmr=null;}
  var arc=document.getElementById('r3-arc-path'); if(arc) arc.setAttribute('stroke-dashoffset','0');
  var pe=document.getElementById('r3-pct'); if(pe) pe.textContent='100%';
}

/* ═══════════════════ COUNTER ══════════════════════ */
function _r3Count(el,target,dur){
  if(!el) return; dur=dur||900; target=parseInt(target)||0;
  var start=0,st=null;
  function f(ts){
    if(!st) st=ts;
    var p=Math.min((ts-st)/dur,1), e=1-Math.pow(1-p,3);
    el.textContent=Math.round(e*target).toLocaleString();
    if(p<1) requestAnimationFrame(f);
  }
  requestAnimationFrame(f);
}

/* ═══════════════════ REVOLVER SVG ═════════════════ */
function _r3GaugeSVG(score,color,size){
  size=size||200; var r=(size/2)-14, cx=size/2, cy=size/2;
  var circ=2*Math.PI*r, offset=circ*(1-Math.min(Math.max(score/100,0),1));
  // conic multi-color stops
  var arcs=[
    {col:'#ff3d5a',pct:.33},{col:'#f5c518',pct:.33},{col:'#00e5a0',pct:.34}
  ];
  // build three partial arcs for the conic effect
  var defs='<defs>'+
    '<linearGradient id="r3rg'+size+'" x1="0%" y1="0%" x2="100%" y2="100%">'+
      '<stop offset="0%" stop-color="#ff3d5a"/>'+
      '<stop offset="33%" stop-color="#f5c518"/>'+
      '<stop offset="66%" stop-color="#00e5a0"/>'+
      '<stop offset="100%" stop-color="'+color+'"/>'+
    '</linearGradient>'+
    '<filter id="r3glow'+size+'"><feGaussianBlur in="SourceGraphic" stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'+
  '</defs>';
  return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'">'+defs+
    '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="10"/>'+
    '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="url(#r3rg'+size+')" stroke-width="10" stroke-linecap="round"'+
      ' stroke-dasharray="'+circ+'" stroke-dashoffset="'+offset+'" transform="rotate(-90 '+cx+' '+cy+')"'+
      ' filter="url(#r3glow'+size+')" style="transition:stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)"/>'+
    // inner glow pulse ring
    '<circle cx="'+cx+'" cy="'+cy+'" r="'+(r-14)+'" fill="none" stroke="'+color+'" stroke-width="1" opacity="0.15"/>'+
  '</svg>';
}

/* ═══════════════════ DRAWER ════════════════════ */
var _r3DrawerData = {};  // { category, level, events, aiCache }

function _r3OpenDrawer(type, data, report){
  _r3DrawerData = { type:type, data:data, report:report, aiCache:{} };
  var dr = document.getElementById('r3-drawer');
  if(!dr){ _r3BuildDrawer(); dr=document.getElementById('r3-drawer'); }
  dr.classList.add('open');
  _r3RenderDrawer(type, data, report);
  document.body.style.overflow='hidden';
}
function _r3CloseDrawer(){
  var dr=document.getElementById('r3-drawer');
  if(dr) dr.classList.remove('open');
  document.body.style.overflow='';
}

function _r3BuildDrawer(){
  var dr=document.createElement('div');
  dr.id='r3-drawer'; dr.className='r3-drawer';
  dr.innerHTML=
    '<div class="r3-drawer-box">'+
      '<div class="r3-drawer-hdr">'+
        '<div class="r3-drawer-title" id="r3-dr-title">Events</div>'+
        '<button class="r3-drawer-close" onclick="_r3CloseDrawer()">✕</button>'+
      '</div>'+
      '<div class="r3-drawer-tabs" id="r3-dr-tabs"></div>'+
      '<div class="r3-drawer-body" id="r3-dr-body">'+
        '<div class="r3-empty"><div class="r3-empty-ico">📋</div>Loading…</div>'+
      '</div>'+
    '</div>';
  dr.addEventListener('click',function(e){if(e.target===dr) _r3CloseDrawer();});
  document.body.appendChild(dr);
}

var _r3ActiveTab = '';
function _r3RenderDrawer(type, data, report){
  var titleEl=document.getElementById('r3-dr-title');
  var tabsEl=document.getElementById('r3-dr-tabs');
  var bodyEl=document.getElementById('r3-dr-body');
  if(!bodyEl) return;

  var ICONS={total:'📊',errors:'🔴',warnings:'🟡',threats:'⚠️',anomalies:'📈'};
  var icon=ICONS[type]||'📋';

  if(titleEl) titleEl.innerHTML = icon+' '+_r3DrTitle(type,data);
  if(tabsEl){
    if(type==='errors'||type==='total'||type==='warnings'){
      var cats=['application','system','security','windows_update'];
      var tabHtml='';
      cats.forEach(function(c,i){
        var cnt=(report.categories&&report.categories[c])?_r3CatCount(c,type,report):'';
        var active=i===0?'active':'';
        tabHtml+='<div class="r3-dtab '+active+'" onclick="_r3SwitchTab(\''+c+'\',\''+type+'\')" id="r3tab-'+c+'">'+c.replace('_',' ')+' '+(cnt?'<span style="color:#64748b">('+cnt+')</span>':'')+'</div>';
      });
      tabsEl.innerHTML=tabHtml;
      _r3ActiveTab=cats[0];
      _r3LoadCategory(cats[0],type,report,bodyEl);
    } else {
      tabsEl.innerHTML='';
      _r3LoadSpecial(type,data,report,bodyEl);
    }
  }
}

function _r3DrTitle(type,data){
  if(type==='total') return 'All Events &nbsp;<span style="color:#38bdf8;font-size:12px">'+(data||0).toLocaleString()+' total</span>';
  if(type==='errors') return 'Errors & Critical &nbsp;<span style="color:#ff3d5a;font-size:12px">'+(data||0).toLocaleString()+' events</span>';
  if(type==='warnings') return 'Warnings &nbsp;<span style="color:#f5c518;font-size:12px">'+(data||0).toLocaleString()+' events</span>';
  if(type==='threats') return 'Threat Patterns';
  if(type==='anomalies') return 'Anomalous Days';
  return 'Events';
}
function _r3CatCount(cat,type,report){
  var c=report.categories&&report.categories[cat]; if(!c) return 0;
  if(type==='errors') return (c.errors||0)+(c.critical||0);
  if(type==='warnings') return c.warnings||0;
  return c.total||0;
}

window._r3SwitchTab=function(cat,type){
  var oldTab=document.getElementById('r3tab-'+_r3ActiveTab);
  if(oldTab) oldTab.classList.remove('active');
  _r3ActiveTab=cat;
  var newTab=document.getElementById('r3tab-'+cat);
  if(newTab) newTab.classList.add('active');
  var body=document.getElementById('r3-dr-body');
  if(body) _r3LoadCategory(cat,type,_r3DrawerData.report,body);
};

function _r3LoadCategory(cat,type,report,bodyEl){
  bodyEl.innerHTML='<div class="r3-empty"><div class="r3-spin-sm"></div> Loading events…</div>';
  var lvl='';
  if(type==='errors') lvl='ERROR';
  else if(type==='warnings') lvl='WARNING';
  var url='/api/logs/'+cat+'?per_page=200'+(lvl?'&level='+lvl:'');
  fetch(url).then(function(r){return r.json();}).then(function(d){
    _r3RenderEvtTable(d.logs||[], cat, type, bodyEl, report);
  }).catch(function(){
    bodyEl.innerHTML='<div class="r3-empty">Could not load events. Is the server running?</div>';
  });
}

var _LEVEL_COLORS={CRITICAL:'#ff3d5a',ERROR:'#ff3d5a',WARNING:'#f5c518',INFO:'#38bdf8',VERBOSE:'#64748b'};

function _r3RenderEvtTable(rows, cat, type, bodyEl, report){
  if(!rows.length){
    bodyEl.innerHTML='<div class="r3-empty"><div class="r3-empty-ico">✅</div>No '+type+' events in '+cat+'</div>';
    return;
  }
  // filter row
  var levels=['ALL','CRITICAL','ERROR','WARNING','INFO'];
  var filterHtml='<div class="r3-filter-row">';
  levels.forEach(function(l){
    var c=_LEVEL_COLORS[l]||'#64748b';
    var isActive=(l==='ALL'&&(type==='total'))||(l===type.toUpperCase()&&type!=='total');
    filterHtml+='<button class="r3-filter-btn'+(isActive?' active':'')+'" style="border-color:'+c+'44;color:'+c+'" onclick="_r3FilterTable(\''+l+'\',this)">'+l+'</button>';
  });
  filterHtml+='</div>';

  var tableHtml='<table class="r3-evt-table" id="r3-evt-tbl">'+
    '<thead><tr>'+
    '<th>#</th><th>Time</th><th>Level</th><th>EventID</th><th>Source</th><th>Message</th><th>AI</th>'+
    '</tr></thead><tbody>';

  rows.forEach(function(row,i){
    var lc=_LEVEL_COLORS[row.level]||'#64748b';
    var msg=(row.message||'').substring(0,200);
    var eid='r3-ai-'+cat+'-'+i;
    tableHtml+=
      '<tr id="r3-tr-'+i+'" data-level="'+(row.level||'')+'" data-idx="'+i+'">'+
        '<td style="color:#4a6080;font-size:10px">'+(i+1)+'</td>'+
        '<td style="white-space:nowrap;color:#64748b;font-size:10px">'+(row.timestamp||'').substring(0,16)+'</td>'+
        '<td><span class="r3-lbadge" style="background:'+lc+'18;color:'+lc+';border:1px solid '+lc+'33">'+(row.level||'?')+'</span></td>'+
        '<td style="font-family:monospace;font-size:11px;color:#94a3b8">'+(row.event_id||'—')+'</td>'+
        '<td style="font-size:10px;color:#64748b;max-width:140px;word-break:break-all">'+(row.source||'').substring(0,40)+'</td>'+
        '<td class="r3-msg">'+msg+'</td>'+
        '<td><button class="r3-ai-btn" onclick="_r3AskAI(this,'+i+',\''+cat+'\',\''+eid+'\')" data-row=\''+JSON.stringify({ts:row.timestamp,level:row.level,eid:row.event_id,src:row.source,msg:msg}).replace(/'/g,'&apos;')+'\''+
          '>🤖 Explain</button></td>'+
      '</tr>'+
      '<tr class="r3-ai-row" id="'+eid+'">'+
        '<td colspan="7" class="r3-ai-cell" id="'+eid+'-cell"><div style="color:#4a6080;font-size:12px">Click Explain to analyse this event with AI…</div></td>'+
      '</tr>';
  });
  tableHtml+='</tbody></table>';
  bodyEl.innerHTML=filterHtml+tableHtml;
}

window._r3FilterTable=function(level,btn){
  document.querySelectorAll('.r3-filter-btn').forEach(function(b){b.classList.remove('active');b.style.color='';});
  btn.classList.add('active');
  btn.style.color='#fff';
  document.querySelectorAll('#r3-evt-tbl tbody tr[data-level]').forEach(function(tr){
    var l=tr.dataset.level||'';
    tr.style.display=(level==='ALL'||l===level)?'':'none';
    // also hide/show AI row
    var idx=tr.dataset.idx;
    var aiRow=document.getElementById('r3-ai-'+tr.closest('[id^="r3-dr"]')+'');
    // find by sibling
    var nextSib=tr.nextElementSibling;
    if(nextSib&&nextSib.classList.contains('r3-ai-row')){
      nextSib.style.display=(level==='ALL'||l===level)?'':'none';
    }
  });
};

/* ── AI explain per row ── */
window._r3AskAI=function(btn, idx, cat, eid){
  var aiRow=document.getElementById(eid);
  var aiCell=document.getElementById(eid+'-cell');
  if(!aiRow||!aiCell) return;

  // toggle if already open
  if(aiRow.classList.contains('open')&&!btn.classList.contains('loading')){
    aiRow.classList.remove('open'); return;
  }
  aiRow.classList.add('open');

  // check cache
  var cacheKey=cat+'-'+idx;
  if(_r3DrawerData.aiCache[cacheKey]){
    _r3ShowAIResult(aiCell, _r3DrawerData.aiCache[cacheKey]);
    return;
  }

  btn.classList.add('loading');
  btn.innerHTML='<span class="r3-spin-sm"></span> Analysing…';

  var rowData={};
  try{ rowData=JSON.parse(btn.dataset.row.replace(/&apos;/g,"'")); }catch(e){}

  var payload={
    event:{
      timestamp:rowData.ts,level:rowData.level,event_id:rowData.eid,
      source:rowData.src,message:rowData.msg,category:cat
    },
    report_context:{
      risk_label:((_r3DrawerData.report||{}).risk_summary||{}).label||'Unknown',
      hostname:((_r3DrawerData.report||{}).hostname)||'this system'
    }
  };

  aiCell.innerHTML='<div class="r3-ai-typing-wrap" style="color:#4a6080">'+
    '<span class="r3-spin-sm"></span> AI is analysing this event…</div>';

  fetch('/api/perform-analysis/explain-event',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  }).then(function(r){return r.json();})
  .then(function(d){
    btn.classList.remove('loading');
    btn.innerHTML='🤖 Explain';
    var result=d.explanation||{why:'Could not retrieve AI explanation.',fix:'Please try again.'};
    _r3DrawerData.aiCache[cacheKey]=result;
    _r3ShowAIResult(aiCell,result);
  }).catch(function(err){
    btn.classList.remove('loading');
    btn.innerHTML='🤖 Explain';
    aiCell.innerHTML='<div class="r3-ai-typing-wrap" style="color:#ff3d5a">AI service unavailable. Check GROQ_API_KEY.</div>';
  });
};

function _r3ShowAIResult(cell, result){
  cell.innerHTML=
    '<div class="r3-ai-typing-wrap">'+
      '<div class="r3-ai-section-lbl" style="color:#f87171">🔍 Why This Is Happening</div>'+
      '<div class="r3-ai-section-body typing" id="r3-ai-why"></div>'+
      '<div style="height:10px"></div>'+
      '<div class="r3-ai-section-lbl" style="color:#4ade80">🛠 How To Resolve</div>'+
      '<div class="r3-ai-section-body typing" id="r3-ai-fix"></div>'+
    '</div>';
  setTimeout(function(){
    var whyEl=document.getElementById('r3-ai-why');
    var fixEl=document.getElementById('r3-ai-fix');
    if(whyEl) _r3Typewrite(whyEl, result.why||'');
    if(fixEl) setTimeout(function(){_r3Typewrite(fixEl, result.fix||'');}, Math.min((result.why||'').length*10+200, 2500));
  },50);
}

function _r3Typewrite(el, text){
  el.textContent='';
  var i=0, speed=Math.max(6,Math.min(20,2500/text.length));
  var iv=setInterval(function(){
    if(i<text.length){ el.textContent+=text[i]; i++; }
    else{ clearInterval(iv); el.classList.remove('typing'); }
  },speed);
}

function _r3LoadSpecial(type, data, report, bodyEl){
  if(type==='threats'){
    var threats=(report.threat_hits||[]);
    if(!threats.length){ bodyEl.innerHTML='<div class="r3-empty"><div class="r3-empty-ico">✅</div>No threat patterns detected</div>'; return; }
    var h='<table class="r3-evt-table"><thead><tr><th>Name</th><th>Severity</th><th>Count</th><th>Last Seen</th><th>Category</th></tr></thead><tbody>';
    threats.forEach(function(t){
      var c=PA_COLORS[t.severity]||PA_COLORS.INFO;
      h+='<tr><td style="color:#e2e8f0;font-weight:700">'+t.name+'</td>'+
        '<td><span class="r3-lbadge" style="background:'+c.bg+';color:'+c.hex+';border:1px solid '+c.hex+'44">'+t.severity+'</span></td>'+
        '<td style="color:'+c.hex+';font-weight:800">'+t.count.toLocaleString()+'</td>'+
        '<td style="color:#64748b;font-size:10px">'+(t.latest||'').substring(0,16)+'</td>'+
        '<td style="color:#64748b;font-size:10px">'+(t.category||'')+'</td>'+
      '</tr>';
    });
    h+='</tbody></table>';
    bodyEl.innerHTML=h;
  } else if(type==='anomalies'){
    var days=report.anomaly_days||[];
    if(!days.length){ bodyEl.innerHTML='<div class="r3-empty"><div class="r3-empty-ico">✅</div>No anomalous days detected</div>'; return; }
    var h='<table class="r3-evt-table"><thead><tr><th>Date</th><th>Event Count</th><th>Z-Score</th><th>Risk</th></tr></thead><tbody>';
    days.forEach(function(a){
      var z=parseFloat(a.zscore), col=z>3.5?'#ff3d5a':z>2.5?'#fb923c':'#f5c518';
      h+='<tr><td style="font-family:monospace;color:#94a3b8">'+a.date+'</td>'+
        '<td style="color:#e2e8f0;font-weight:700">'+a.count.toLocaleString()+'</td>'+
        '<td style="font-family:monospace;font-weight:800;color:'+col+'">'+a.zscore+'</td>'+
        '<td><span class="r3-lbadge" style="background:'+col+'18;color:'+col+';border:1px solid '+col+'33">'+(z>3.5?'HIGH':z>2.5?'MEDIUM':'LOW')+'</span></td>'+
      '</tr>';
    });
    h+='</tbody></table>';
    bodyEl.innerHTML=h;
  }
}

/* ═══════════════════ MAIN RENDER ═════════════════════ */
var _r3Report=null;
var _r3TickIdx=0;

window._paRender = function(r){
  _paInjectStyles();
  _r3Report=r;

  // ── Switch to loading-hidden state first, then mount report ──
  _r3StopArc();

  // mount container
  var rep=document.getElementById('r3-report');
  if(!rep){
    rep=document.createElement('div'); rep.id='r3-report';
    rep.style.display='none';
    var ref=document.getElementById('pa-report')||document.getElementById('pa-loading');
    if(ref) ref.parentNode.insertBefore(rep,ref.nextSibling);
    else document.getElementById('page-perform').appendChild(rep);
  }

  var rs=r.risk_summary||{}, score=rs.score||0, label=rs.label||'Low', PC=PA_COLORS[label]||PA_COLORS.INFO;
  var cats=r.categories||{};
  var totCrit=0,totErr=0,totWarn=0,totInfo=0;
  Object.values(cats).forEach(function(c){totCrit+=c.critical||0;totErr+=c.errors||0;totWarn+=c.warnings||0;totInfo+=c.info||0;});
  var threats=(r.threat_hits||[]).slice().sort(function(a,b){var O={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};return (O[a.severity]||3)-(O[b.severity]||3)||b.count-a.count;});
  var anomDays=r.anomaly_days||[];
  var totErrCrit=totCrit+totErr;

  var html='';

  /* ── CENTERED HERO CARD ─────────────────────────── */
  html+='<div class="r3-hero-card">'+
    '<div class="r3-hero-bg-glow" style="background:radial-gradient(ellipse 70% 60% at 50% 60%,'+PC.glow+' 0%,transparent 70%)"></div>'+
    '<div class="r3-report-ring" id="r3-ring-wrap">'+
      '<div id="r3-ring-svg-inner"></div>'+
      '<div class="r3-ring-score-wrap">'+
        '<div class="r3-ring-score" id="r3-score" style="color:'+PC.hex+'">0</div>'+
        '<div class="r3-ring-score-lbl">/100 Risk Score</div>'+
      '</div>'+
    '</div>'+
    '<div class="r3-risk-badge" style="background:'+PC.bg+';color:'+PC.hex+';border-color:'+PC.hex+'44">'+label+' Risk</div>'+
    '<div class="r3-hero-title-sm">Analysed '+(r.total_events||0).toLocaleString()+' events · Generated '+(r.generated_at||'')+'</div>'+

    /* 4 clickable stat cards */
    '<div class="r3-stat-row">'+
      _r3StatCard('📊','Total Events',(r.total_events||0),'#38bdf8','Click to browse all events','total',r.total_events)+
      _r3StatCard('🔴','Errors & Critical',totErrCrit,'#ff3d5a','Click to investigate errors','errors',totErrCrit)+
      _r3StatCard('⚠️','Threat Patterns',threats.length,'#a855f7','Click to see all threats','threats',threats)+
      _r3StatCard('📈','Anomalous Days',anomDays.length,'#fb923c','Click to see anomaly days','anomalies',anomDays)+
    '</div>'+
  '</div>';

  /* ── TICKER STRIP ────────────────────────────────── */
  _r3TickIdx=0;
  html+='<div class="r3-ticker">'+
    _r3Tick('🔴','Critical',totCrit,'#ff3d5a')+
    _r3Tick('🟠','Errors',totErr,'#ff7a2f')+
    _r3Tick('🟡','Warnings',totWarn,'#f5c518')+
    _r3Tick('🟢','Info',totInfo,'#00e5a0')+
    _r3Tick('🛡','Threats',threats.length,'#a855f7')+
    _r3Tick('📈','Anomalies',anomDays.length,'#fb923c')+
  '</div>';

  /* ── CATEGORY BREAKDOWN ─────────────────────────── */
  html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(56,189,248,.1);color:#38bdf8;border:1px solid rgba(56,189,248,.2)">📂 Log Category Breakdown</div><div class="r3-divider-line"></div></div>';
  var catMax=1; Object.values(cats).forEach(function(c){if((c.total||0)>catMax) catMax=c.total;});
  var catIcons={application:'⚙️',system:'🖥️',security:'🔒',windows_update:'🔄'};
  html+='<div class="r3-panel"><div class="r3-panel-body">';
  Object.entries(cats).forEach(function(e){
    var name=e[0],cv=e[1],errs=(cv.errors||0)+(cv.critical||0);
    var bc=errs/cv.total>.3?'#ff3d5a':errs/cv.total>.1?'#fb923c':'#38bdf8';
    var fw=cv.total>0?Math.max(3,Math.round(cv.total/catMax*100)):0;
    html+='<div class="r3-cat-row">'+
      '<div class="r3-cat-top"><span class="r3-cat-name">'+(catIcons[name]||'📋')+' '+name.replace('_',' ')+'</span>'+
      '<span class="r3-cat-nums" style="color:'+bc+'">'+errs+' errors · '+(cv.warnings||0)+' warnings · '+(cv.total||0)+' total</span></div>'+
      '<div class="r3-cat-bg"><div class="r3-cat-fill" style="width:0%;background:'+bc+'" data-target="'+fw+'"></div></div>'+
    '</div>';
  });
  html+='</div></div>';

  /* ── CHARTS ─────────────────────────────────────── */
  html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(168,85,247,.1);color:#a855f7;border:1px solid rgba(168,85,247,.2)">📅 30-Day Timeline</div><div class="r3-divider-line"></div><div style="font-size:10px;color:#4a6080">Peak: <span style="color:#38bdf8;font-weight:700" id="r3-peak">'+(r.peak_hour||'—')+'</span></div></div>';
  html+='<div class="r3-panel" style="margin-bottom:14px"><div class="r3-panel-body" style="height:200px;position:relative"><canvas id="pa-chart-timeline"></canvas></div></div>';
  html+='<div class="r3-two-col">'+
    '<div class="r3-panel"><div class="r3-panel-hdr"><div class="r3-panel-title">🕐 24-Hour Activity</div></div><div class="r3-panel-body" style="height:160px;position:relative"><canvas id="pa-chart-hourly"></canvas></div></div>'+
    '<div class="r3-panel"><div class="r3-panel-hdr"><div class="r3-panel-title">📆 Weekday Pattern</div></div><div class="r3-panel-body" style="height:160px;position:relative"><canvas id="pa-chart-weekday"></canvas></div></div>'+
  '</div>';

  /* ── THREATS ─────────────────────────────────────── */
  html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(255,61,90,.1);color:#ff3d5a;border:1px solid rgba(255,61,90,.25)">🎯 Threat Pattern Matches</div><div class="r3-divider-line"></div></div>';
  html+='<div class="r3-threats">';
  if(!threats.length){
    html+='<div style="background:rgba(0,229,160,.05);border:1px solid rgba(0,229,160,.2);border-radius:12px;padding:28px;text-align:center"><div style="font-size:36px;margin-bottom:6px">✅</div><div style="color:#00e5a0;font-weight:800">No Threat Patterns Detected</div></div>';
  } else {
    var maxT=threats[0].count||1;
    var TICO={'Brute Force Login':'🔐','Account Lockout':'🔒','Privilege Escalation':'⬆️','Windows Defender Alert':'🛡️','Unexpected Shutdown':'💥','Disk Hardware Error':'💽','Application Crash':'💀','New Admin Account':'👤','Scheduled Task Created':'📅','Service Failure':'⚙️','Registry Tampering':'🔑','Network Error':'🌐'};
    threats.forEach(function(t,i){
      var c=PA_COLORS[t.severity]||PA_COLORS.INFO, ico=TICO[t.name]||'⚠️';
      var bw=Math.max(3,Math.round(t.count/maxT*100)), ex=(t.examples&&t.examples[0])?t.examples[0].message:'', did='r3td'+i;
      html+='<div class="r3-threat-card" style="background:'+c.bg+';border-color:'+c.hex+'22">'+
        '<div class="r3-threat-hdr" onclick="_r3ToggleTC(\''+did+'\')">'+
          '<div class="r3-threat-ico" style="background:'+c.hex+'18">'+ico+'</div>'+
          '<div><div class="r3-threat-name">'+t.name+'</div><div class="r3-threat-hint">Last seen: '+(t.latest||'').substring(0,16)+'</div></div>'+
          '<div><div class="r3-threat-cnt" style="color:'+c.hex+'">'+t.count.toLocaleString()+'</div><div class="r3-threat-cnt-lbl">events</div></div>'+
          '<div class="r3-sev-pill" style="color:'+c.hex+';background:'+c.bg+';border-color:'+c.hex+'44">'+t.severity+'</div>'+
          '<div class="r3-chev" id="'+did+'-chev">▼</div>'+
        '</div>'+
        '<div class="r3-threat-bar-bg"><div class="r3-threat-bar" style="width:0%;background:linear-gradient(90deg,'+c.hex+','+c.hex+'88)" data-target="'+bw+'"></div></div>'+
        '<div class="r3-threat-detail" id="'+did+'">'+
          '<div class="r3-detail-grid">'+
            '<div><div class="r3-dc-lbl">Total Matches</div><div class="r3-dc-val" style="color:'+c.hex+'">'+t.count.toLocaleString()+'</div></div>'+
            '<div><div class="r3-dc-lbl">Severity</div><div class="r3-dc-val" style="color:'+c.hex+'">'+t.severity+'</div></div>'+
            '<div><div class="r3-dc-lbl">Category</div><div class="r3-dc-val">'+(t.category||'—')+'</div></div>'+
          '</div>'+
          (ex?'<div class="r3-dc-lbl" style="margin-bottom:4px">Sample Log</div><div class="r3-sample-log">'+ex.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</div>':'')+
        '</div>'+
      '</div>';
    });
  }
  html+='</div>';

  /* ── ANOMALIES + RECOMMENDATIONS ─────────────────── */
  html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(251,146,60,.1);color:#fb923c;border:1px solid rgba(251,146,60,.2)">📊 Anomaly Analysis</div><div class="r3-divider-line"></div></div>';
  html+='<div class="r3-two-col">';
  html+='<div class="r3-panel"><div class="r3-panel-hdr"><div class="r3-panel-title">📈 Anomalous Days (Z > 2.0)</div></div><div class="r3-panel-body">';
  if(anomDays.length){
    var maxA=anomDays.reduce(function(m,a){return Math.max(m,a.count||0);},1);
    anomDays.slice(0,12).forEach(function(a){
      var z=parseFloat(a.zscore),zc=z>3.5?'#ff3d5a':z>2.5?'#fb923c':'#f5c518';
      var w=Math.round(a.count/maxA*100);
      html+='<div class="r3-anom-row"><div class="r3-anom-date">'+a.date+'</div><div class="r3-anom-bg"><div class="r3-anom-fill" style="width:0%;background:'+zc+'" data-target="'+w+'"></div></div><div class="r3-anom-cnt">'+a.count.toLocaleString()+'</div><div class="r3-anom-z" style="color:'+zc+'">Z='+a.zscore+'</div></div>';
    });
  } else { html+='<div style="color:#00e5a0;font-size:12px">✅ No anomalous days</div>'; }
  html+='</div></div>';

  html+='<div class="r3-panel"><div class="r3-panel-hdr"><div class="r3-panel-title">💡 Recommendations</div></div><div class="r3-panel-body">';
  (r.recommendations||[]).forEach(function(rec,i){
    var c=PA_COLORS[rec.priority]||PA_COLORS.INFO;
    html+='<div class="r3-rec-item" style="border-left-color:'+c.hex+';background:'+c.bg+';animation-delay:'+(i*.07)+'s">'+
      '<span class="r3-rec-pri" style="color:'+c.hex+';background:'+c.bg+';border:1px solid '+c.hex+'44">'+rec.priority+'</span>'+
      '<span class="r3-rec-txt">'+rec.text+'</span>'+
    '</div>';
  });
  html+='</div></div></div>';

  /* ── FIM ─────────────────────────────────────────── */
  var fim=r.fim||{};
  if(fim.total){
    html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(168,85,247,.1);color:#a855f7;border:1px solid rgba(168,85,247,.2)">🗂 File Integrity Monitor</div><div class="r3-divider-line"></div></div>';
    html+='<div class="r3-panel"><div class="r3-fim-stats">'+
      '<div class="r3-fim-stat"><div class="r3-fim-val" style="color:#38bdf8">'+(fim.total||0)+'</div><div class="r3-fim-lbl">Total</div></div>'+
      '<div class="r3-fim-stat"><div class="r3-fim-val" style="color:#ff3d5a">'+(fim.critical_count||0)+'</div><div class="r3-fim-lbl">Critical</div></div>'+
      '<div class="r3-fim-stat"><div class="r3-fim-val" style="color:#ff7a2f">'+(fim.high_count||0)+'</div><div class="r3-fim-lbl">High</div></div>'+
      '<div class="r3-fim-stat"><div class="r3-fim-val" style="color:#f5c518">'+(fim.unique_actions||0)+'</div><div class="r3-fim-lbl">Actions</div></div>'+
    '</div><div id="r3-fim-body"></div></div>';
  }

  /* ── AI ZONE ─────────────────────────────────────── */
  html+='<div id="r3-ai-zone"></div>';

  /* ── DOWNLOADS ───────────────────────────────────── */
  if(r.id){
    html+='<div class="r3-divider"><div class="r3-divider-label" style="background:rgba(56,189,248,.07);color:#38bdf8;border:1px solid rgba(56,189,248,.15)">⬇ Export</div><div class="r3-divider-line"></div></div>';
    html+='<div class="r3-panel" style="margin-bottom:24px"><div class="r3-dl-bar">'+
      '<button class="r3-dl-btn" onclick="paExport(\''+r.id+'\',\'pdf\')" style="background:rgba(239,68,68,.1);color:#f87171;border-color:rgba(239,68,68,.3)">⬇ PDF</button>'+
      '<button class="r3-dl-btn" onclick="paExport(\''+r.id+'\',\'html\')" style="background:rgba(56,189,248,.07);color:#38bdf8;border-color:rgba(56,189,248,.25)">⬇ HTML</button>'+
      '<button class="r3-dl-btn" onclick="paExport(\''+r.id+'\',\'csv\')" style="background:rgba(0,229,160,.07);color:#00e5a0;border-color:rgba(0,229,160,.25)">⬇ CSV</button>'+
      '<button class="r3-dl-btn" onclick="paExport(\''+r.id+'\',\'json\')" style="background:rgba(255,255,255,.04);color:#64748b;border-color:rgba(255,255,255,.1)">⬇ JSON</button>'+
      (r.next_check?'<div style="margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;justify-content:center"><div style="font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:.06em">Next check</div><div style="font-size:13px;font-weight:800;color:#38bdf8">'+r.next_check+'</div></div>':'')+
    '</div></div>';
  }

  /* ── MOUNT ───────────────────────────────────────── */
  rep.innerHTML=html;

  // Switch page state to report — hide idle + loader, show only report
  _r3ShowOnly('report');

  /* ── ANIMATE GAUGE ───────────────────────────────── */
  var gInner=document.getElementById('r3-ring-svg-inner');
  if(gInner){ gInner.innerHTML=_r3GaugeSVG(0,PC.hex,200); }
  setTimeout(function(){
    if(gInner) gInner.innerHTML=_r3GaugeSVG(score,PC.hex,200);
    _r3Count(document.getElementById('r3-score'),score,1200);
  },300);

  /* ── ANIMATE STAT CARDS ──────────────────────────── */
  [['r3-sc-0',r.total_events||0],['r3-sc-1',totErrCrit],['r3-sc-2',threats.length],['r3-sc-3',anomDays.length]].forEach(function(p,i){
    setTimeout(function(){_r3Count(document.getElementById(p[0]),p[1],900);},150+i*80);
  });

  /* ── ANIMATE TICKERS ─────────────────────────────── */
  [totCrit,totErr,totWarn,totInfo,threats.length,anomDays.length].forEach(function(v,i){
    setTimeout(function(){_r3Count(document.getElementById('r3-tv-'+i),v,700);},100+i*80);
  });

  /* ── ANIMATE BARS ────────────────────────────────── */
  setTimeout(function(){
    rep.querySelectorAll('[data-target]').forEach(function(el){el.style.width=el.dataset.target+'%';});
  },400);

  /* ── CHARTS ──────────────────────────────────────── */
  if(typeof _paTimelineChart==='function'){
    // Use double rAF to ensure canvases are fully painted in DOM before Chart.js reads them
    requestAnimationFrame(function(){
      requestAnimationFrame(function(){
        try{ _paTimelineChart(r.timeline||[]); }catch(e){console.warn('timeline chart:',e);}
        try{ _paHourlyChart(r.hourly_pattern||[]); }catch(e){console.warn('hourly chart:',e);}
        try{ _paWeekdayChart(r.weekday_pattern||[]); }catch(e){console.warn('weekday chart:',e);}
      });
    });
  }

  /* ── AI PANEL ────────────────────────────────────── */
  setTimeout(function(){
    var aiPanel=document.getElementById('pa-ai-panel');
    var aiZone=document.getElementById('r3-ai-zone');
    if(aiPanel&&aiZone){aiZone.innerHTML='';aiZone.appendChild(aiPanel);aiPanel.style.display='block';}
    if(typeof _paLoadAIInsights==='function') _paLoadAIInsights(r);
  },800);
};

/* helpers */
function _r3StatCard(icon,label,val,col,hint,type,data){
  var id='r3-sc-'+(_r3StatCard._i=(_r3StatCard._i||0));_r3StatCard._i++;
  return '<div class="r3-stat-card" style="border-color:'+col+'22" '+
    'onclick="_r3OpenDrawer(\''+type+'\','+JSON.stringify(typeof data==='number'?data:0)+',_r3Report)" '+
    'onmouseenter="this.style.boxShadow=\'0 8px 24px '+col+'22\';this.style.borderColor=\''+col+'44\'" '+
    'onmouseleave="this.style.boxShadow=\'\';this.style.borderColor=\''+col+'22\'">'+
    '<div class="r3-stat-card-glow" style="background:'+col+'"></div>'+
    '<div class="r3-stat-icon">'+icon+'</div>'+
    '<div class="r3-stat-val" id="'+id+'" style="color:'+col+'">0</div>'+
    '<div class="r3-stat-lbl">'+label+'</div>'+
    '<div class="r3-stat-hint" style="color:'+col+'">'+hint+'</div>'+
  '</div>';
}
function _r3Tick(icon,label,val,col){
  var id='r3-tv-'+_r3TickIdx++;
  return '<div class="r3-tick" style="border-color:'+col+'22">'+
    '<div class="r3-tick-glow" style="background:'+col+'"></div>'+
    '<div class="r3-tick-icon">'+icon+'</div>'+
    '<div class="r3-tick-val" id="'+id+'" style="color:'+col+'">0</div>'+
    '<div class="r3-tick-lbl">'+label+'</div>'+
  '</div>';
}
window._r3ToggleTC=function(id){
  var el=document.getElementById(id),ch=document.getElementById(id+'-chev');
  if(!el) return;
  var o=el.style.display==='block';
  el.style.display=o?'none':'block';
  if(ch) ch.classList.toggle('open',!o);
};

/* ═══ OVERRIDE run + init ══════════════════════════ */
var _r3OrigRun=window.runPerformAnalysis;
window.runPerformAnalysis=async function(days){
  // Build UI components if not yet built
  _r3BuildLoader();

  // Switch to loading state — hides idle + any previous report
  _r3ShowOnly('loading');
  _r3StartArc();

  // Run the original analysis
  if(_r3OrigRun) await _r3OrigRun(days);
  // _paRender() will be called by _r3OrigRun and will switch to 'report' state
};
var _r3OrigInit=window.initPerformAnalysis;
window.initPerformAnalysis=function(){
  _paInjectStyles();
  _r3BuildIdle();   // builds + calls _r3ShowOnly('idle')
  _r3BuildLoader(); // builds hidden
  if(_r3OrigInit) _r3OrigInit();
};
window.paToggleThreat=window._r3ToggleTC;

// Auto-apply on script load
(function(){
  _paInjectStyles();
  _r3BuildIdle();
  _r3BuildLoader();
})();
