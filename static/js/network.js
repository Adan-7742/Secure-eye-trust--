/**
 * network.js — Full Network Analyzer
 * ====================================
 * ROOT CAUSE OF TAB FREEZE (now fixed):
 *   /api/network/bandwidth was calling time.sleep(1) on Flask's request thread.
 *   With Flask's default threaded=True, this held one worker thread busy for 1s
 *   on every call, and repeated calls stacked up, eventually exhausting all workers.
 *   Fix: backend now uses threading.Event — the sleep happens in a daemon thread,
 *   Flask thread just waits on done.wait(timeout=3) which yields properly.
 *   Frontend: teardownNetwork() always fires on ANY tab change, killing the SSE
 *   connection and all polling timers so no background requests leak.
 */

// ── Module state ──────────────────────────────────────────────────────────────
let _pktSSE    = null;
let _pktChart  = null;
let _pktLabels = [], _pktRecv = [], _pktSent = [];
let _d3Sim     = null;
let _bwTimer   = null;
let _procTimer = null;
let _capPoll   = null;
let _corrChart = null;
const MAX_PTS  = 60;

// ── Init ──────────────────────────────────────────────────────────────────────
async function initNetwork() {
  // Non-blocking dep check
  api('/api/network/status').then(s => {
    const tip = document.getElementById('net-psutil-tip');
    if (!s.psutil_available && tip)
      tip.textContent = '⚠ psutil missing — run: pip install psutil';
    else if (tip) tip.textContent = '';
  }).catch(()=>{});

  switchNetTab('packets');
  startPacketStream();
  loadInterfaces();
  loadConnections();
  loadBandwidth();
  loadTopProcesses();
  loadSecurityCorrelations();
}

// ── Teardown — called by navigation.js on EVERY tab change ───────────────────
function teardownNetwork() {
  if (_pktSSE)    { try{_pktSSE.close();}catch(e){} _pktSSE = null; }
  if (_bwTimer)   { clearTimeout(_bwTimer);   _bwTimer   = null; }
  if (_procTimer) { clearTimeout(_procTimer); _procTimer = null; }
  if (_capPoll)   { clearInterval(_capPoll);  _capPoll   = null; }
  if (_d3Sim)     { try{_d3Sim.stop();}catch(e){} _d3Sim = null; }
}

// ── Sub-tab switching ─────────────────────────────────────────────────────────
function switchNetTab(name) {
  document.querySelectorAll('.net-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.net-tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === `net-panel-${name}`));
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. PACKET FLOW
// ─────────────────────────────────────────────────────────────────────────────
function startPacketStream() {
  if (_pktSSE) { try{_pktSSE.close();}catch(e){} _pktSSE=null; }
  initPktChart();
  spawnParticles();
  try {
    _pktSSE = new EventSource('/api/network/packets/stream');
    _pktSSE.onmessage = e => {
      let d; try{d=JSON.parse(e.data);}catch{return;}
      if (d.type !== 'packet_tick') return;
      if (_pktLabels.length >= MAX_PTS){_pktLabels.shift();_pktRecv.shift();_pktSent.shift();}
      _pktLabels.push(d.ts);
      _pktRecv.push(+(d.recv_bps/1024).toFixed(1));
      _pktSent.push(+(d.sent_bps/1024).toFixed(1));
      if (_pktChart){
        _pktChart.data.labels           = [..._pktLabels];
        _pktChart.data.datasets[0].data = [..._pktRecv];
        _pktChart.data.datasets[1].data = [..._pktSent];
        _pktChart.update('none');
      }
      setTxt('net-recv-val', d.recv_fmt||'0 B/s');
      setTxt('net-sent-val', d.sent_fmt||'0 B/s');
      setTxt('net-pkts-val', fmtN((d.pkts_recv||0)+(d.pkts_sent||0)));
      setTxt('net-err-val',  (d.errin||0)+(d.errout||0));
      setTxt('net-drops-val', d.dropin||0);
      adjustParticles(d.recv_bps+d.sent_bps);
    };
    _pktSSE.onerror = () => { try{_pktSSE?.close();}catch(e){} _pktSSE=null; };
  } catch(e){ console.warn('SSE failed:',e); }
}

function initPktChart(){
  const ctx=document.getElementById('packet-flow-chart'); if(!ctx) return;
  if(_pktChart){_pktChart.destroy();_pktChart=null;}
  _pktLabels=[];_pktRecv=[];_pktSent=[];
  _pktChart=new Chart(ctx,{type:'line',
    data:{labels:_pktLabels,datasets:[
      {label:'↓ Recv KB/s',data:_pktRecv,borderColor:'#38bdf8',backgroundColor:'rgba(56,189,248,.08)',borderWidth:2,pointRadius:0,fill:true,tension:.4},
      {label:'↑ Send KB/s',data:_pktSent,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.08)',borderWidth:2,pointRadius:0,fill:true,tension:.4},
    ]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,
      interaction:{mode:'index',intersect:false},
      plugins:{legend:{labels:{color:'#5a7090',font:{size:11}}}},
      scales:{
        x:{ticks:{color:'#4a6080',maxTicksLimit:10,font:{size:9}},grid:{color:'#1a2540'}},
        y:{ticks:{color:'#4a6080',font:{size:9}},grid:{color:'#1a2540'},min:0,
           title:{display:true,text:'KB/s',color:'#4a6080',font:{size:10}}},
      },
    },
  });
}

function spawnParticles(){
  const box=document.getElementById('packet-particles'); if(!box) return;
  box.innerHTML='';
  for(let i=0;i<16;i++){
    const p=document.createElement('div');
    p.className=`pkt-particle ${i%2===0?'recv':'sent'}`;
    p.style.top=`${5+Math.random()*88}%`;
    p.style.animationDuration=`${2.5+Math.random()*3.5}s`;
    p.style.animationDelay=`${-Math.random()*5}s`;
    const sz=`${3+Math.random()*5}px`; p.style.width=sz; p.style.height=sz;
    box.appendChild(p);
  }
}

function adjustParticles(bps){
  const sp=Math.max(.4,Math.min(5,bps/40000));
  document.querySelectorAll('.pkt-particle').forEach(p=>{p.style.animationDuration=`${(3.5/sp).toFixed(2)}s`;});
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. TOPOLOGY
// ─────────────────────────────────────────────────────────────────────────────
async function loadConnections(){
  const mapEl=document.getElementById('conn-map-svg');
  const tblEl=document.getElementById('conn-list-body');
  try{
    const data=await api('/api/network/connections');
    setTxt('net-conn-val',fmtN(data.total||0));
    if(tblEl){
      const conns=data.connections||[];
      const badge=document.getElementById('conn-count-badge');
      if(badge) badge.textContent=conns.length+' active connections';
      // Update sidebar
      const scc=document.getElementById('sidebar-conn-count');
      if(scc) scc.textContent=conns.length;
      tblEl.innerHTML=!conns.length
        ?'<div style="color:var(--text-dim);padding:20px;text-align:center;font-size:12px">No connections — run as Administrator for full list</div>'
        :conns.map(cn=>{
          const isTCP=cn.proto==='TCP';
          const st=(cn.status||'').toUpperCase();
          let statusClass='status-other', statusLabel=st||'—';
          if(st==='ESTABLISHED'){statusClass='status-established';}
          else if(st==='LISTEN'){statusClass='status-listen';}
          else if(st.includes('CLOSE')){statusClass='status-close';}
          return '<div class="conn-row">'
            +'<span><span class="proto-badge '+(isTCP?'proto-tcp':'proto-udp')+'">'+(cn.proto||'?')+'</span></span>'
            +'<span class="conn-ip">'+(cn.local||'—')+'</span>'
            +'<span class="conn-ip remote">'+(cn.remote||'—')+'</span>'
            +'<span><span class="status-badge '+statusClass+'">'+statusLabel+'</span></span>'
            +'<span class="enc-tls">🔒 TLS</span>'
            +'<span class="conn-process">'+(cn.process||'—')+'</span>'
            +'</div>';
        }).join('');
      // Fire alert if many connections
      // alert handled by /api/live-alerts polling
    }
    if(mapEl&&(data.nodes||[]).length){await ensureD3();renderD3(data.nodes,data.links||[]);}
  }catch(e){if(tblEl)tblEl.innerHTML='<div style="color:var(--red);padding:12px">⚠ '+e.message+'</div>';}
}

async function ensureD3(){
  if(window.d3) return;
  await new Promise((res,rej)=>{
    const s=document.createElement('script');
    s.src='https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js';
    s.onload=res; s.onerror=rej; document.head.appendChild(s);
  });
}

function renderD3(nodes,links){
  const svgEl=document.getElementById('conn-map-svg'); if(!svgEl) return;
  const W=svgEl.clientWidth||700,H=svgEl.clientHeight||400;
  const svg=d3.select('#conn-map-svg'); svg.selectAll('*').remove();
  const defs=svg.append('defs');
  const f=defs.append('filter').attr('id','net-glow');
  f.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
  const fm=f.append('feMerge'); fm.append('feMergeNode').attr('in','blur'); fm.append('feMergeNode').attr('in','SourceGraphic');
  const g=svg.append('g');
  svg.call(d3.zoom().scaleExtent([.2,5]).on('zoom',e=>g.attr('transform',e.transform)));
  if(_d3Sim) _d3Sim.stop();
  const nc=nodes.map(n=>({...n}));
  const idSet=new Set(nc.map(n=>n.id));
  const lc=links.filter(l=>idSet.has(l.source)&&idSet.has(l.target)).map(l=>({...l}));
  _d3Sim=d3.forceSimulation(nc)
    .force('link',d3.forceLink(lc).id(d=>d.id).distance(90))
    .force('charge',d3.forceManyBody().strength(-200))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collide',d3.forceCollide(22));
  const link=g.append('g').selectAll('line').data(lc).join('line')
    .attr('stroke',d=>d.proto==='UDP'?'#ffd700':'#58a6ff').attr('stroke-opacity',.4).attr('stroke-width',1.5);
  const node=g.append('g').selectAll('g').data(nc).join('g')
    .call(d3.drag()
      .on('start',(e,d)=>{if(!e.active)_d3Sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag', (e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on('end',  (e,d)=>{if(!e.active)_d3Sim.alphaTarget(0);d.fx=null;d.fy=null;}));
  node.append('circle')
    .attr('r',d=>d.type==='local'?11:d.type==='private'?8:7)
    .attr('fill',d=>d.type==='local'?'#0d2010':d.type==='private'?'#0d1a2a':'#1a0d0d')
    .attr('stroke',d=>d.type==='local'?'#38bdf8':d.type==='private'?'#58a6ff':'#ff7675')
    .attr('stroke-width',2).attr('filter','url(#net-glow)');
  node.append('title').text(d=>`${d.id}\nType: ${d.type}\nConns: ${d.connections||0}`);
  node.append('text').attr('x',14).attr('dy','0.35em').attr('fill','#5a7090').attr('font-size',9).attr('font-family','monospace')
    .text(d=>d.label.length>16?d.label.slice(0,15)+'…':d.label);
  _d3Sim.on('tick',()=>{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>`translate(${d.x},${d.y})`);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. BANDWIDTH
// ─────────────────────────────────────────────────────────────────────────────
async function loadBandwidth(){
  const el=document.getElementById('bw-bar-list'); if(!el) return;
  el.innerHTML='<div style="color:var(--text-dim);font-size:12px;padding:10px">Sampling 1 second…</div>';
  try{
    const data=await api('/api/network/bandwidth');
    const nics=data.nics||[];
    if(!nics.length){el.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">All interfaces idle (0 bytes/s)</div>';}
    else{
      const max=Math.max(...nics.map(n=>n.total_bps),1);
      el.innerHTML=nics.map(n=>{
        const rp=Math.round(n.recv_bps/max*100),sp=Math.round(n.sent_bps/max*100);
        return `<div style="margin-bottom:16px">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <span style="font-size:12px;font-weight:600;color:var(--text-bright)">${n.nic}</span>
            <span style="font-size:11px;font-family:var(--mono);color:var(--text-dim)">${n.total_fmt}</span>
          </div>
          <div style="margin-bottom:4px">
            <div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="font-size:10px;color:#58e6a0">↓ Download</span><span style="font-size:10px;font-family:var(--mono);color:#58e6a0">${n.recv_fmt}</span></div>
            <div class="bw-bar-track"><div class="bw-bar-fill" style="width:${rp}%;background:linear-gradient(90deg,#58e6a0,#2ed573)"></div></div>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="font-size:10px;color:#58a6ff">↑ Upload</span><span style="font-size:10px;font-family:var(--mono);color:#58a6ff">${n.sent_fmt}</span></div>
            <div class="bw-bar-track"><div class="bw-bar-fill" style="width:${sp}%;background:linear-gradient(90deg,#58a6ff,#1e90ff)"></div></div>
          </div>
          <div style="margin-top:4px;font-size:10px;color:var(--text-dim)">Pkts ↓${fmtN(n.pkts_recv)} ↑${fmtN(n.pkts_sent)}</div>
        </div>`;
      }).join('');
    }
  }catch(e){if(el)el.innerHTML=`<div style="color:var(--red);padding:10px;font-size:12px">⚠ ${e.message}</div>`;}
  clearTimeout(_bwTimer); _bwTimer=setTimeout(loadBandwidth,5000);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. TOP PROCESSES
// ─────────────────────────────────────────────────────────────────────────────
async function loadTopProcesses(){
  const el=document.getElementById('proc-list'); if(!el) return;
  try{
    const data=await api('/api/network/top-processes');
    const procs=data.processes||[];
    if(!procs.length){el.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">No processes with connections found</div>';return;}
    const max=Math.max(...procs.map(p=>p.connections),1);
    el.innerHTML=`<table style="width:100%;border-collapse:collapse;font-size:11px">
      <thead><tr style="color:var(--text-dim);font-size:10px;text-transform:uppercase">
        <th style="text-align:left;padding:4px 8px">Process</th><th style="text-align:right;padding:4px 8px">PID</th>
        <th style="text-align:right;padding:4px 8px">Conns</th><th style="text-align:right;padding:4px 8px">CPU%</th><th style="text-align:right;padding:4px 8px">RAM</th>
      </tr></thead>
      <tbody>${procs.map(p=>{
        const pct=Math.round(p.connections/max*100);
        return `<tr style="border-bottom:1px solid rgba(255,255,255,.04)">
          <td style="padding:6px 8px"><div style="font-weight:600;color:var(--text-bright)">${p.name}</div>
            <div style="height:3px;background:rgba(88,166,255,.15);border-radius:2px;margin-top:3px"><div style="width:${pct}%;height:100%;background:#58a6ff;border-radius:2px"></div></div></td>
          <td style="text-align:right;padding:6px 8px;font-family:var(--mono);color:var(--text-dim)">${p.pid}</td>
          <td style="text-align:right;padding:6px 8px;font-family:var(--mono);color:#58a6ff;font-weight:700">${p.connections}</td>
          <td style="text-align:right;padding:6px 8px;font-family:var(--mono);color:${p.cpu_pct>50?'#ff4d6a':p.cpu_pct>20?'#ffd700':'var(--text-dim)'}">${(p.cpu_pct||0).toFixed(1)}%</td>
          <td style="text-align:right;padding:6px 8px;font-family:var(--mono);color:var(--text-dim)">${p.mem_fmt}</td>
        </tr>`;
      }).join('')}</tbody></table>`;
  }catch(e){if(el)el.innerHTML=`<div style="color:var(--red);padding:10px;font-size:12px">⚠ ${e.message}</div>`;}
  clearTimeout(_procTimer); _procTimer=setTimeout(loadTopProcesses,6000);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PORT SCANNER
// ─────────────────────────────────────────────────────────────────────────────
async function runPortScan(){
  const target=document.getElementById('scan-target')?.value?.trim();
  const ports =document.getElementById('scan-ports')?.value?.trim()||'1-1024';
  const resEl =document.getElementById('portscan-results');
  const btn   =document.getElementById('scan-btn');
  if(!target){toast('Enter a target IP or hostname');return;}
  if(!resEl) return;
  btn&&(btn.disabled=true,btn.textContent='⟳ Scanning…');
  resEl.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">⟳ Scanning — may take 10–30 seconds…</div>';
  try{
    const data=await apiPost('/api/network/port-scan',{target,ports});
    if(data.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">${data.error}<br><small style="color:var(--text-dim)">${data.tip||''}</small></div>`;return;}
    const op=data.open_ports||[];
    const RISK={22:'medium',21:'high',23:'critical',445:'high',3389:'high',6379:'high',27017:'medium',5900:'high'};
    const RCOL={low:'#38bdf8',medium:'#ffd700',high:'#ff9500',critical:'#ff4d6a'};
    resEl.innerHTML=`
      <div style="margin-bottom:12px;padding:8px 12px;background:rgba(88,230,160,.07);border-left:3px solid #58e6a0;border-radius:4px">
        <strong style="color:#58e6a0">${data.total_open} open ports</strong> on <code>${data.target_ip}</code>
        · range ${data.ports} · ${data.elapsed_s}s · via ${data.scanner}
      </div>
      ${!op.length?'<div style="color:var(--text-dim);padding:8px">No open ports in this range</div>':`
      <table style="width:100%;border-collapse:collapse;font-size:11px">
        <thead><tr style="color:var(--text-dim);font-size:10px;text-transform:uppercase">
          <th style="text-align:left;padding:4px 8px">Port</th><th style="text-align:left;padding:4px 8px">Proto</th>
          <th style="text-align:left;padding:4px 8px">Service</th><th style="text-align:left;padding:4px 8px">Risk</th><th style="text-align:left;padding:4px 8px">Info</th>
        </tr></thead>
        <tbody>${op.map(p=>{
          const r=RISK[p.port]||'low',c=RCOL[r];
          return `<tr style="border-bottom:1px solid rgba(255,255,255,.04)">
            <td style="padding:6px 8px;font-family:var(--mono);font-weight:700;color:#58a6ff">${p.port}</td>
            <td style="padding:6px 8px;font-family:var(--mono);color:var(--text-dim)">${p.proto}</td>
            <td style="padding:6px 8px;color:var(--text-bright)">${p.service||'unknown'}</td>
            <td style="padding:6px 8px"><span style="font-size:10px;padding:1px 7px;border-radius:3px;background:${c}22;color:${c}">${r.toUpperCase()}</span></td>
            <td style="padding:6px 8px;font-size:10px;color:var(--text-dim)">${p.product||p.version||''}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>`}`;
  }catch(e){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${e.message}</div>`;}
  finally{btn&&(btn.disabled=false,btn.textContent='▶ Scan');}
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DNS LOOKUP
// ─────────────────────────────────────────────────────────────────────────────
async function runDNS(){
  const domain=document.getElementById('dns-domain')?.value?.trim();
  const resEl =document.getElementById('dns-results');
  const btn   =document.getElementById('dns-btn');
  if(!domain){toast('Enter a domain');return;}
  btn&&(btn.disabled=true,btn.textContent='⟳ Resolving…');
  resEl.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">⟳ Looking up DNS…</div>';
  try{
    const data=await apiPost('/api/network/dns-lookup',{domain});
    if(data.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">${data.error}</div>`;return;}
    const recs=data.records||{};
    const TC={A:'#58a6ff',AAAA:'#38bdf8',MX:'#ffd700',NS:'#ff9500',TXT:'#c9d1d9',CNAME:'#bc8cff',SOA:'#5a7090'};
    let html=`<div style="margin-bottom:10px;font-size:12px;color:var(--text-dim)">DNS for <strong style="color:var(--text-bright)">${domain}</strong></div>`;
    if(data.note) html+=`<div style="margin-bottom:10px;font-size:11px;color:#ffd700;padding:6px 10px;background:rgba(255,215,0,.07);border-radius:4px">ℹ ${data.note}</div>`;
    for(const [type,records] of Object.entries(recs)){
      if(!records.length) continue;
      html+=`<div style="margin-bottom:12px">
        <div style="font-size:10px;font-weight:700;color:${TC[type]||'#5a7090'};text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">${type}</div>
        ${records.map(r=>`<div style="font-family:var(--mono);font-size:11px;padding:4px 10px;background:rgba(255,255,255,.03);border-radius:4px;margin-bottom:3px;color:var(--text-bright)">${typeof r==='object'?JSON.stringify(r):r}</div>`).join('')}
      </div>`;
    }
    if(Object.keys(data.reverse_dns||{}).length){
      html+=`<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">Reverse DNS (PTR)</div>`;
      for(const [ip,ptr] of Object.entries(data.reverse_dns)){
        html+=`<div style="font-family:var(--mono);font-size:11px;padding:4px 10px;background:rgba(255,255,255,.03);border-radius:4px;margin-bottom:3px"><span style="color:#58a6ff">${ip}</span> → <span style="color:var(--text-bright)">${ptr||'No PTR'}</span></div>`;
      }
      html+='</div>';
    }
    resEl.innerHTML=html;
  }catch(e){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${e.message}</div>`;}
  finally{btn&&(btn.disabled=false,btn.textContent='🔍 Lookup');}
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. HTTP PROBE
// ─────────────────────────────────────────────────────────────────────────────
async function runHTTPProbe(){
  const url  =document.getElementById('http-url')?.value?.trim();
  const resEl=document.getElementById('http-results');
  const btn  =document.getElementById('http-btn');
  if(!url){toast('Enter a URL');return;}
  btn&&(btn.disabled=true,btn.textContent='⟳ Probing…');
  resEl.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">⟳ Probing…</div>';
  try{
    const data=await apiPost('/api/network/http-probe',{url});
    if(data.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">${data.error}</div>`;return;}
    const cc=data.status_code<300?'#38bdf8':data.status_code<400?'#ffd700':data.status_code<500?'#ff9500':'#ff4d6a';
    let html=`<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
      <div class="net-stat-pill"><div class="pill-val" style="color:${cc}">${data.status_code}</div><div class="pill-lbl">${data.reason}</div></div>
      <div class="net-stat-pill"><div class="pill-val" style="color:#58a6ff">${data.elapsed_ms}ms</div><div class="pill-lbl">Latency</div></div>
      <div class="net-stat-pill"><div class="pill-val" style="font-size:13px">${data.server||'—'}</div><div class="pill-lbl">Server</div></div>
      ${(data.redirects?.length||0)>1?`<div class="net-stat-pill"><div class="pill-val" style="color:#ffd700">${data.redirects.length-1}</div><div class="pill-lbl">Redirects</div></div>`:''}
    </div>`;

    // Security headers
    html+=`<div style="margin-bottom:14px">
      <div style="font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">Security Headers</div>
      ${Object.entries(data.security_headers||{}).map(([k,v])=>{
        const ok=!v.includes('❌');
        return `<div style="display:flex;justify-content:space-between;padding:5px 10px;background:rgba(255,255,255,.02);border-radius:3px;margin-bottom:2px;border-left:2px solid ${ok?'#38bdf8':'#ff4d6a'}">
          <span style="font-size:10px;font-family:var(--mono);color:var(--text)">${k}</span>
          <span style="font-size:10px;color:${ok?'#38bdf8':'#ff4d6a'}">${ok?'✅ Present':'❌ Missing'}</span>
        </div>`;
      }).join('')}
    </div>`;

    // TLS
    if(data.tls&&!data.tls.error&&Object.keys(data.tls).length){
      html+=`<div style="margin-bottom:14px">
        <div style="font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">TLS Certificate</div>
        <div style="font-family:var(--mono);font-size:10px;background:rgba(0,0,0,.3);padding:10px;border-radius:6px;color:var(--text);line-height:1.6">
          <div>Subject: <span style="color:#58a6ff">${JSON.stringify(data.tls.subject||{})}</span></div>
          <div>Issuer: <span style="color:#58e6a0">${JSON.stringify(data.tls.issuer||{})}</span></div>
          <div>Expires: <span style="color:#ffd700">${data.tls.not_after||'—'}</span></div>
          ${(data.tls.san||[]).length?`<div>SANs: ${data.tls.san.slice(0,5).join(', ')}</div>`:''}
        </div>
      </div>`;
    }

    // Redirects
    if((data.redirects||[]).length>1){
      html+=`<div><div style="font-size:10px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">Redirect Chain</div>
        ${data.redirects.map((r,i)=>`<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          ${i>0?'<span style="color:var(--text-dim)">→</span>':''}
          <span style="font-size:10px;font-family:var(--mono);color:var(--text)">${r.url}</span>
          <span style="font-size:10px;color:${r.status<300?'#38bdf8':'#ffd700'}">[${r.status}]</span>
        </div>`).join('')}
      </div>`;
    }
    resEl.innerHTML=html;
  }catch(e){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${e.message}</div>`;}
  finally{btn&&(btn.disabled=false,btn.textContent='🔍 Probe');}
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. ARP / LAN SCAN
// ─────────────────────────────────────────────────────────────────────────────
async function runARPScan(){
  const subnet=document.getElementById('arp-subnet')?.value?.trim()||'';
  const resEl =document.getElementById('arp-results');
  const btn   =document.getElementById('arp-btn');
  if(!resEl) return;
  btn&&(btn.disabled=true,btn.textContent='⟳ Scanning LAN…');
  resEl.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">⟳ Discovering devices…</div>';
  try{
    const data=await apiPost('/api/network/arp-scan',{subnet});
    if(data.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">${data.error}<br><small style="color:var(--text-dim)">${data.tip||''}</small></div>`;return;}
    const devs=data.devices||[];
    resEl.innerHTML=`
      <div style="margin-bottom:12px;padding:8px 12px;background:rgba(88,230,160,.07);border-left:3px solid #58e6a0;border-radius:4px">
        Found <strong style="color:#58e6a0">${data.total} devices</strong> on <code>${data.subnet}</code> · via ${data.scanner}
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px">
        ${devs.map(d=>`
          <div class="iface-card up">
            <div style="font-size:13px;font-weight:600;color:var(--text-bright);margin-bottom:4px">📡 ${d.ip}</div>
            <div style="font-size:10px;font-family:var(--mono);color:#58a6ff">${d.mac||'—'}</div>
            ${d.hostname?`<div style="font-size:10px;color:var(--text-dim);margin-top:2px">${d.hostname}</div>`:''}
            <div style="font-size:9px;color:var(--text-dim);margin-top:4px">${d.method}</div>
          </div>`).join('')}
      </div>`;
  }catch(e){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${e.message}</div>`;}
  finally{btn&&(btn.disabled=false,btn.textContent='🔍 Scan LAN');}
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. PACKET CAPTURE
// ─────────────────────────────────────────────────────────────────────────────
async function startCapture(){
  const count =parseInt(document.getElementById('cap-count')?.value||50);
  const filter=document.getElementById('cap-filter')?.value?.trim()||'';
  const resEl =document.getElementById('cap-results');
  const btnS  =document.getElementById('cap-start-btn');
  const btnX  =document.getElementById('cap-stop-btn');
  if(!resEl) return;
  btnS&&(btnS.disabled=true); btnX&&(btnX.disabled=false);
  resEl.innerHTML='<div style="color:var(--text-dim);padding:12px;font-size:12px">⟳ Capturing… click Stop when done</div>';
  try{
    const r=await apiPost('/api/network/packet-capture/start',{count,filter});
    if(r.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">${r.error}<br><small>${r.tip||''}</small></div>`;btnS&&(btnS.disabled=false);return;}
    clearInterval(_capPoll); _capPoll=setInterval(pollCapture,1000);
  }catch(e){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${e.message}</div>`;btnS&&(btnS.disabled=false);}
}

async function stopCapture(){
  clearInterval(_capPoll); _capPoll=null;
  await apiPost('/api/network/packet-capture/stop',{}).catch(()=>{});
  document.getElementById('cap-start-btn')&&(document.getElementById('cap-start-btn').disabled=false);
  document.getElementById('cap-stop-btn') &&(document.getElementById('cap-stop-btn').disabled=true);
  pollCapture();
}

async function pollCapture(){
  const resEl=document.getElementById('cap-results'); if(!resEl) return;
  try{
    const data=await api('/api/network/packet-capture/results');
    const pkts=data.packets||[];
    if(!pkts.length) return;
    if(!data.running){clearInterval(_capPoll);_capPoll=null;document.getElementById('cap-start-btn')&&(document.getElementById('cap-start-btn').disabled=false);}
    if(pkts[0]?.error){resEl.innerHTML=`<div style="color:var(--red);padding:12px">⚠ ${pkts[0].error}<br><small style="color:var(--text-dim)">Requires Npcap from npcap.com + Administrator</small></div>`;return;}
    const PC={TCP:'#58a6ff',UDP:'#ffd700',ICMP:'#ff9500',IP:'#5a7090'};
    resEl.innerHTML=`
      <div style="margin-bottom:8px;font-size:11px;color:var(--text-dim)">${data.running?'⟳ Capturing…':'✅ Done'} · ${data.total} packets</div>
      <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:10px;font-family:var(--mono)">
        <thead><tr style="color:var(--text-dim);font-size:9px;text-transform:uppercase">
          <th style="text-align:left;padding:3px 8px">#</th><th style="text-align:left;padding:3px 8px">Time</th>
          <th style="text-align:left;padding:3px 8px">Proto</th><th style="text-align:left;padding:3px 8px">Src</th>
          <th style="text-align:left;padding:3px 8px">Dst</th><th style="text-align:left;padding:3px 8px">Len</th>
          <th style="text-align:left;padding:3px 8px">Info</th>
        </tr></thead>
        <tbody>${pkts.map((p,i)=>`<tr style="border-bottom:1px solid rgba(255,255,255,.03)">
          <td style="padding:3px 8px;color:var(--text-dim)">${i+1}</td>
          <td style="padding:3px 8px;color:var(--text-dim)">${p.time||''}</td>
          <td style="padding:3px 8px;color:${PC[p.proto]||'#5a7090'};font-weight:700">${p.proto||'?'}</td>
          <td style="padding:3px 8px;color:var(--text)">${p.src||'—'}</td>
          <td style="padding:3px 8px;color:var(--text)">${p.dst||'—'}</td>
          <td style="padding:3px 8px;color:var(--text-dim)">${p.len}</td>
          <td style="padding:3px 8px;color:var(--text-dim)">${p.info||''}</td>
        </tr>`).join('')}</tbody>
      </table></div>`;
  }catch(e){}
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. SECURITY CORRELATIONS
// ─────────────────────────────────────────────────────────────────────────────
async function loadSecurityCorrelations(){
  const tlEl=document.getElementById('corr-timeline');
  const smEl=document.getElementById('evt-summary');
  try{
    const data=await api('/api/network/security-correlations');
    setTxt('net-live-ips',`${data.live_ip_count||0} remote IPs currently active`);
    const EID={4624:'Logon Success',4625:'Failed Logon',4634:'Logoff',4648:'Explicit Creds',4672:'Admin Logon',4720:'Account Created',4726:'Account Deleted',4740:'Account Locked',4698:'Scheduled Task',4688:'Process Created',7045:'Service Installed',4776:'NTLM Auth'};
    if(smEl){
      const evts=data.event_summary||[];
      smEl.innerHTML=!evts.length?'<div style="color:var(--text-dim);padding:12px;font-size:12px">No Security log data — fetch logs first (run as Administrator)</div>':`
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr style="color:var(--text-dim);font-size:10px;text-transform:uppercase">
            <th style="text-align:left;padding:4px 8px">Event ID</th><th style="text-align:left;padding:4px 8px">Description</th>
            <th style="text-align:left;padding:4px 8px">Level</th><th style="text-align:right;padding:4px 8px">Count</th>
          </tr></thead>
          <tbody>${evts.map(e=>{
            const lc=e.level==='FAILURE'||e.level==='ERROR'?'#ff4d6a':e.level==='WARNING'?'#ffd700':'#5a7090';
            return `<tr style="border-bottom:1px solid rgba(255,255,255,.04)">
              <td style="padding:5px 8px;font-family:var(--mono);color:#58a6ff;font-weight:700">${e.event_id}</td>
              <td style="padding:5px 8px;color:var(--text)">${EID[e.event_id]||'—'}</td>
              <td style="padding:5px 8px"><span style="font-size:10px;padding:1px 7px;border-radius:3px;background:${lc}22;color:${lc}">${e.level}</span></td>
              <td style="padding:5px 8px;text-align:right;font-family:var(--mono);font-weight:700;color:var(--text-bright)">${fmtN(e.cnt)}</td>
            </tr>`;
          }).join('')}</tbody>
        </table>`;
    }
    if((data.failed_logons||[]).length) renderCorrChart(data.failed_logons);
    if(tlEl){
      const corrSet=new Set((data.correlations||[]).map(c=>c.timestamp));
      const evts=data.security_events||[];
      tlEl.innerHTML=!evts.length?'<div style="color:var(--text-dim);padding:12px;font-size:12px">No Security log data</div>'
        :evts.map(ev=>{
          const corr=(data.correlations||[]).find(c=>c.timestamp===ev.timestamp);
          const lc=ev.level==='FAILURE'||ev.level==='ERROR'?'#ff4d6a':ev.level==='WARNING'?'#ffd700':'#5a7090';
          return `<div class="corr-event">
            <div class="corr-dot" style="background:${lc}"></div>
            <div class="corr-body">
              <div class="corr-title">${ev.source||'—'} · EID ${ev.event_id||'—'}</div>
              <div class="corr-meta">${ev.timestamp||''} · <span style="color:${lc}">${ev.level}</span></div>
              <div class="corr-meta">${(ev.message||'').slice(0,100)}</div>
              ${corr?`<div class="corr-alert">🔗 ${corr.note}</div>`:''}
            </div>
          </div>`;
        }).join('');
    }
  }catch(e){if(tlEl)tlEl.innerHTML=`<div style="color:var(--red);font-size:12px;padding:10px">⚠ ${e.message}</div>`;}
}

function renderCorrChart(logons){
  const ctx=document.getElementById('corr-chart'); if(!ctx) return;
  if(_corrChart){_corrChart.destroy();_corrChart=null;}
  const labels=[...logons].reverse().map(d=>(d.hour||'').slice(8));
  const values=[...logons].reverse().map(d=>d.cnt||0);
  _corrChart=new Chart(ctx,{type:'bar',data:{labels,datasets:[{label:'Failed Logons (EID 4625)',data:values,backgroundColor:'rgba(255,77,106,.4)',borderColor:'#ff4d6a',borderWidth:1,borderRadius:3}]},options:{plugins:{legend:{labels:{color:'#5a7090',font:{size:11}}}},scales:{x:{ticks:{color:'#4a6080',font:{size:9},maxTicksLimit:12},grid:{color:'#1a2540'}},y:{ticks:{color:'#4a6080'},grid:{color:'#1a2540'},min:0}}}});
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. INTERFACES
// ─────────────────────────────────────────────────────────────────────────────
async function loadInterfaces(){
  const el=document.getElementById('iface-grid'); if(!el) return;
  try{
    const data=await api('/api/network/interfaces');
    el.innerHTML=(data.interfaces||[]).map(i=>`
      <div class="iface-card ${i.is_up?'up':'down'}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <div class="iface-name">${i.name}</div>
          <span style="font-size:10px;color:${i.is_up?'#38bdf8':'#ff4d6a'}">${i.is_up?'● UP':'● DOWN'}</span>
        </div>
        ${i.ipv4.length?`<div class="iface-ip">IPv4: ${i.ipv4[0]}</div>`:'<div class="iface-ip" style="color:var(--text-dim)">No IPv4</div>'}
        ${i.mac?`<div class="iface-stat">MAC: ${i.mac}</div>`:''}
        ${i.speed_mbps?`<div class="iface-stat">Speed: ${i.speed_mbps} Mbps · MTU: ${i.mtu}</div>`:''}
        <div class="iface-stat" style="margin-top:6px"><span style="color:#58e6a0">↓ ${i.bytes_recv_fmt}</span> &nbsp; <span style="color:#58a6ff">↑ ${i.bytes_sent_fmt}</span></div>
        <div class="iface-stat">Pkts ↓${fmtN(i.pkts_recv)} ↑${fmtN(i.pkts_sent)}</div>
        ${i.errin+i.errout>0?`<div class="iface-stat" style="color:#ff4d6a;margin-top:4px">⚠ Errors in:${i.errin} out:${i.errout}</div>`:''}
      </div>`).join('')||'<div style="color:var(--text-dim)">No interfaces found</div>';
  }catch(e){if(el)el.innerHTML=`<div style="color:var(--red);font-size:12px;padding:10px">⚠ ${e.message}</div>`;}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function setTxt(id,v){const e=document.getElementById(id);if(e)e.textContent=v;}
function fmtN(n){if(!n)return'0';return n>=1e6?`${(n/1e6).toFixed(1)}M`:n>=1e3?`${(n/1e3).toFixed(1)}K`:String(n);}

// ─────────────────────────────────────────────────────────────────────────────
// SCANNER STUBS — UI removed, kept as stubs to avoid JS errors
// ─────────────────────────────────────────────────────────────────────────────
function runPortScan(){}
function runDNS(){}
function runHTTPProbe(){}
function runARPScan(){}
function startCapture(){}
function stopCapture(){}


// ══════════════════════════════════════════════════════════════
//  NETWORK ANOMALY DETECTION
//  Calls /api/network/anomaly/scan — real psutil-based engine
// ══════════════════════════════════════════════════════════════

let _anomAutoTimer = null;
let _anomAutoOn    = false;
let _anomHistory   = [];

const ANOM_SEV_COLOR = {
  CRITICAL: '#f87171',
  HIGH:     '#fdba74',
  MEDIUM:   '#fcd34d',
  LOW:      '#93c5fd',
};

// ── Scan ──────────────────────────────────────────────────────
async function runAnomalyScan() {
  const btn  = document.getElementById('anom-scan-btn');
  const dot  = document.getElementById('anom-engine-dot');
  const last = document.getElementById('anom-last-scan');

  _showAnomalyState('scanning');
  if (btn)  { btn.disabled = true; btn.textContent = '⟳ Scanning…'; }
  if (dot)  dot.className = 'anom-engine-dot scanning';

  // Animate scan steps
  const steps = [
    'Connecting to network layer…',
    'Enumerating active connections…',
    'Checking destination ports against threat database…',
    'Analysing connection patterns for port scans…',
    'Measuring traffic baselines…',
    'Checking for beaconing and C2 patterns…',
    'Inspecting process-to-connection mapping…',
    'Measuring packet error and drop rates…',
    'Running SYN flood heuristics…',
    'Finalising anomaly report…',
  ];
  let si = 0;
  const stepEl = document.getElementById('anom-scan-steps');
  const stepTimer = setInterval(function() {
    if (stepEl && si < steps.length) stepEl.textContent = steps[si++];
  }, 400);

  try {
    const data = await api('/api/network/anomaly/scan');
    clearInterval(stepTimer);

    // Update stats
    _updateAnomalyStats(data.stats || {});

    // Stash in history
    const ts = new Date().toLocaleTimeString();
    (data.anomalies || []).forEach(function(a) {
      _anomHistory.unshift({ ...a, scanned_at: ts });
    });
    if (_anomHistory.length > 200) _anomHistory = _anomHistory.slice(0, 200);
    _renderAnomalyHistory();

    if (data.healthy || !data.anomalies || data.anomalies.length === 0) {
      _showAnomalyState('healthy');
    } else {
      _showAnomalyState('results');
      _renderAnomalyCards(data.anomalies);
    }

    if (last) last.textContent = 'Last scan: ' + ts;
    if (dot)  dot.className = data.healthy ? 'anom-engine-dot' : 'anom-engine-dot threat';

  } catch(e) {
    clearInterval(stepTimer);
    _showAnomalyState('idle');
    toast('❌ Anomaly scan failed: ' + e.message);
    if (dot) dot.className = 'anom-engine-dot idle';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🔍 Scan Now'; }
  }
}

// ── State display ─────────────────────────────────────────────
function _showAnomalyState(state) {
  const states = { idle: 'anom-idle', scanning: 'anom-scanning', healthy: 'anom-healthy', results: 'anom-card-list' };
  Object.values(states).forEach(function(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  const target = states[state];
  if (target) {
    const el = document.getElementById(target);
    if (el) el.style.display = state === 'results' ? 'block' : 'block';
  }
}

// ── Render anomaly cards ──────────────────────────────────────
function _renderAnomalyCards(anomalies) {
  const container = document.getElementById('anom-card-list');
  if (!container) return;

  const critCount = anomalies.filter(a => a.severity === 'CRITICAL').length;
  const highCount = anomalies.filter(a => a.severity === 'HIGH').length;
  const medCount  = anomalies.filter(a => a.severity === 'MEDIUM').length;

  // Summary banner
  const topSev    = critCount > 0 ? 'critical' : highCount > 0 ? 'high' : 'medium';
  const topCount  = critCount || highCount || medCount;
  const bannerMsg = critCount > 0
    ? `${critCount} critical threat${critCount>1?'s':''} detected — immediate action required`
    : highCount > 0
    ? `${highCount} high-severity anomal${highCount>1?'ies':'y'} — review recommended`
    : `${medCount} medium-severity pattern${medCount>1?'s':''} detected`;

  let html = `<div class="anom-card-list-wrap">
    <div class="anom-summary-banner ${topSev}">
      <div class="anom-summary-count">${anomalies.length}</div>
      <div class="anom-summary-text">
        <strong>Anomalies detected</strong><br>${bannerMsg}
      </div>
    </div>`;

  anomalies.forEach(function(a, i) {
    const col = ANOM_SEV_COLOR[a.severity] || '#94a3b8';
    html += `
    <div class="anom-card ${a.severity}" style="animation-delay:${i*0.05}s">
      <div class="anom-card-top-bar"></div>
      <div class="anom-card-body">
        <div class="anom-card-row">
          <div class="anom-card-icon">${a.icon || '⚠'}</div>
          <div class="anom-card-content">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
              <div class="anom-card-title">${a.title}</div>
              <span class="anom-sev-badge">${a.severity}</span>
            </div>
            <div class="anom-card-detail">${a.detail}</div>
            <div class="anom-card-type">TYPE: ${a.type}</div>
          </div>
        </div>
      </div>
    </div>`;
  });

  html += '</div>';

  // ── Fix Network Threats button ──────────────────────────────────────────
  // Extract actionable threats: suspicious processes (unknown_process_external)
  // and suspicious port connections — we can kill the process or block the IP.
  const actionable = anomalies.filter(function(a) {
    return a.type === 'unknown_process_external' ||
           a.type === 'suspicious_port' ||
           a.type === 'beaconing' ||
           a.type === 'port_scan';
  });

  if (actionable.length > 0) {
    html += `
    <div id="net-fix-bar" style="
      margin-top:16px;padding:16px 20px;border-radius:12px;
      border:1px solid rgba(239,68,68,.3);
      background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(251,146,60,.06));
      display:flex;align-items:center;gap:14px;flex-wrap:wrap;
      box-shadow:0 4px 16px rgba(239,68,68,.12)">
      <div style="flex:1;min-width:200px">
        <div style="font-size:13px;font-weight:800;color:#fca5a5;letter-spacing:.02em">⚡ Fix Network Threats</div>
        <div style="font-size:11.5px;color:#94a3b8;margin-top:3px">
          Kill suspicious processes &amp; block malicious IPs — ${actionable.length} actionable threat${actionable.length!==1?'s':''}
        </div>
      </div>
      <button id="net-fix-btn" onclick="fixNetworkThreats()" style="
        background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;
        border:none;padding:12px 24px;border-radius:10px;cursor:pointer;
        font-size:13px;font-weight:800;letter-spacing:.03em;
        box-shadow:0 4px 18px rgba(239,68,68,.4);transition:all .15s">
        🛡 Fix All Network Threats
      </button>
    </div>`;
  }

  container.innerHTML = html;
  // Store actionable list on window so the fix handler can use it
  window._netActionableThreats = actionable;
}

// ── Fix Network Threats ───────────────────────────────────────
async function fixNetworkThreats() {
  const btn = document.getElementById('net-fix-btn');
  const bar = document.getElementById('net-fix-bar');
  const threats = window._netActionableThreats || [];
  if (!threats.length) return;

  if (btn) { btn.disabled = true; btn.textContent = '⟳ Fixing…'; }

  // Build fix-all payload: kill processes + block IPs
  const fixList = [];
  const seen = new Set();

  threats.forEach(function(a) {
    if (a.type === 'unknown_process_external') {
      // Extract PID from detail string e.g. "PID 1234 → 1.2.3.4:80"
      const pidM = (a.detail || '').match(/PID\s+(\d+)/i);
      const ipM  = (a.detail || '').match(/→\s*([\d.]+):/);
      if (pidM && !seen.has('proc:'+pidM[1])) {
        seen.add('proc:'+pidM[1]);
        fixList.push({ kind: 'process', target: parseInt(pidM[1], 10), name: a.title });
      }
      if (ipM && !seen.has('net:'+ipM[1])) {
        seen.add('net:'+ipM[1]);
        // Block IP via separate endpoint
        fetch('/api/action/block-network', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ipM[1] })
        }).catch(function(){});
      }
    } else if (a.type === 'suspicious_port' || a.type === 'beaconing' || a.type === 'port_scan') {
      // Extract IP from title/detail
      const ipM = (a.title + ' ' + (a.detail||'')).match(/([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})/);
      if (ipM && !seen.has('net:'+ipM[1])) {
        seen.add('net:'+ipM[1]);
        fetch('/api/action/block-network', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ipM[1] })
        }).catch(function(){});
      }
    }
  });

  let fixResult = { ok: true, fixed: 0, already_gone: 0, failed: 0, total: 0, results: [] };
  if (fixList.length > 0) {
    try {
      const r = await fetch('/api/action/fix-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threats: fixList, mode: 'quarantine' })
      });
      fixResult = await r.json();
    } catch(e) {
      console.warn('fix-all failed:', e);
    }
  }

  const ipBlocked = Array.from(seen).filter(k => k.startsWith('net:')).length;
  const totalFixed = fixResult.fixed + fixResult.already_gone + ipBlocked;
  const totalAll   = fixList.length + ipBlocked;

  if (bar) {
    bar.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;width:100%">
        <span style="font-size:26px">✅</span>
        <div>
          <div style="font-size:13px;font-weight:800;color:#34d399">Network Threats Fixed</div>
          <div style="font-size:11.5px;color:#86efac;margin-top:2px">
            ${totalFixed} of ${totalAll} actioned
            ${ipBlocked ? ' · ' + ipBlocked + ' IP' + (ipBlocked!==1?'s':'') + ' blocked via firewall' : ''}
            ${fixList.length ? ' · ' + fixList.length + ' process' + (fixList.length!==1?'es':'') + ' terminated' : ''}
          </div>
        </div>
        <button onclick="runAnomalyScan()" style="
          margin-left:auto;background:rgba(34,197,94,.1);color:#86efac;
          border:1px solid rgba(34,197,94,.35);padding:8px 16px;border-radius:8px;
          cursor:pointer;font-size:12px;font-weight:700">
          🔄 Re-scan Network
        </button>
      </div>`;
  }
}

// ── Update stats bar ──────────────────────────────────────────
function _updateAnomalyStats(stats) {
  function setStatCard(id, val, warnThresh, dangerThresh) {
    const el = document.getElementById(id);
    if (!el) return;
    const valEl = el.querySelector('.anom-stat-val');
    if (valEl) valEl.textContent = val;
    el.classList.remove('warn','danger');
    if (dangerThresh && val >= dangerThresh) el.classList.add('danger');
    else if (warnThresh && val >= warnThresh) el.classList.add('warn');
  }
  setStatCard('astat-conns',       stats.total_connections || 0, 150, 300);
  setStatCard('astat-established', stats.established       || 0, 100, 200);
  setStatCard('astat-listen',      stats.listen            || 0,  30,  50);
  setStatCard('astat-syn',         stats.syn               || 0,   5,  20);
  setStatCard('astat-timewait',    stats.time_wait         || 0,  50, 150);
  setStatCard('astat-closewait',   stats.close_wait        || 0,  15,  30);
}

// ── Render history ────────────────────────────────────────────
function _renderAnomalyHistory() {
  const el    = document.getElementById('anom-history-list');
  const count = document.getElementById('anom-history-count');
  if (!el) return;
  if (count) count.textContent = _anomHistory.length + ' events';

  if (!_anomHistory.length) {
    el.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-dim);font-size:12px">Run a scan to populate history</div>';
    return;
  }

  el.innerHTML = _anomHistory.slice(0, 60).map(function(a) {
    const col = ANOM_SEV_COLOR[a.severity] || '#94a3b8';
    return `<div class="anom-hist-row">
      <div class="anom-hist-dot" style="background:${col}"></div>
      <span style="font-family:var(--mono);color:var(--text-dim);flex-shrink:0">${a.scanned_at}</span>
      <span style="padding:2px 6px;border-radius:4px;font-size:9px;font-weight:700;background:${col}18;color:${col}">${a.severity}</span>
      <span style="color:var(--text-bright);font-size:12px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.title}</span>
    </div>`;
  }).join('');
}

// ── Auto-scan toggle ──────────────────────────────────────────
function toggleAnomalyAuto() {
  const btn = document.getElementById('anom-auto-btn');
  _anomAutoOn = !_anomAutoOn;

  if (_anomAutoOn) {
    runAnomalyScan();
    _anomAutoTimer = setInterval(runAnomalyScan, 30000);
    if (btn) { btn.textContent = '⏹ Stop Auto'; btn.style.borderColor = 'var(--red)'; btn.style.color = 'var(--red-bright)'; }
    toast('🔄 Auto-scan every 30s enabled');
  } else {
    clearInterval(_anomAutoTimer);
    _anomAutoTimer = null;
    if (btn) { btn.textContent = '▶ Auto'; btn.style.borderColor = ''; btn.style.color = ''; }
    toast('⏹ Auto-scan stopped');
  }
}
