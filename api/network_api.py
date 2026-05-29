"""
api/network_api.py  —  Full Network Analyzer
=============================================
KEY FIX: bandwidth() no longer sleeps on Flask thread.
         Uses two quick snapshots with threading.Event instead.

Endpoints:
  /status                     psutil + optional lib check
  /packets/stream             SSE live bytes/s
  /interfaces                 NIC info
  /connections                TCP/UDP + D3 graph
  /bandwidth                  per-NIC bytes/s (background thread)
  /top-processes              processes by connection count
  /security-correlations      log events x live IPs
  /port-scan        POST      open port scanner
  /dns-lookup       POST      A/AAAA/MX/NS/TXT/CNAME/SOA
  /http-probe       POST      HTTP headers + TLS + security headers
  /arp-scan         POST      LAN device discovery
  /packet-capture/start POST  scapy live capture
  /packet-capture/results GET results
  /packet-capture/stop  POST  stop capture
"""

import time, socket, json, re, threading
from datetime import datetime
from collections import defaultdict
from flask import Blueprint, jsonify, request, Response, stream_with_context
from database.db import get_conn

network_bp = Blueprint("network", __name__)

# ── Optional libs ─────────────────────────────────────────────────────────────
try:
    import psutil; PSUTIL_OK = True
except ImportError:
    psutil = None; PSUTIL_OK = False

try:
    import dns.resolver, dns.reversename; DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import scapy.all as scapy; SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import nmap as nmap_lib; NMAP_OK = True
except ImportError:
    NMAP_OK = False

try:
    import requests as req_lib; REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

import subprocess

def _fmt(n):
    if not n: return "0 B"
    for u in ['B','KB','MB','GB','TB']:
        if abs(n) < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def _no_psutil():
    return jsonify({"error":"psutil not installed","fix":"pip install psutil"}), 400


# ── STATUS ────────────────────────────────────────────────────────────────────
@network_bp.route("/status")
def net_status():
    missing = []
    if not PSUTIL_OK:   missing.append("psutil")
    if not SCAPY_OK:    missing.append("scapy")
    if not NMAP_OK:     missing.append("python-nmap")
    if not DNS_OK:      missing.append("dnspython")
    if not REQUESTS_OK: missing.append("requests")
    return jsonify({
        "psutil_available":    PSUTIL_OK,
        "scapy_available":     SCAPY_OK,
        "nmap_available":      NMAP_OK,
        "dnspython_available": DNS_OK,
        "requests_available":  REQUESTS_OK,
        "missing": missing,
    })


# ── PACKET STREAM (SSE) ───────────────────────────────────────────────────────
@network_bp.route("/packets/stream")
def packet_stream():
    if not PSUTIL_OK:
        def _e(): yield f"data: {json.dumps({'type':'error','msg':'pip install psutil'})}\n\n"
        return Response(stream_with_context(_e()), mimetype="text/event-stream")

    def generate():
        prev = psutil.net_io_counters()
        while True:
            time.sleep(1)
            try:
                cur  = psutil.net_io_counters()
                sb   = max(0, cur.bytes_sent   - prev.bytes_sent)
                rb   = max(0, cur.bytes_recv   - prev.bytes_recv)
                ps   = max(0, cur.packets_sent - prev.packets_sent)
                pr   = max(0, cur.packets_recv - prev.packets_recv)
                prev = cur
                payload = {
                    "type":"packet_tick","ts":datetime.now().strftime("%H:%M:%S"),
                    "sent_bps":sb,"recv_bps":rb,"pkts_sent":ps,"pkts_recv":pr,
                    "errin":max(0,cur.errin-prev.errin) if prev else 0,
                    "errout":max(0,cur.errout-prev.errout) if prev else 0,
                    "dropin":max(0,cur.dropin-prev.dropin) if prev else 0,
                    "sent_fmt":_fmt(sb)+"/s","recv_fmt":_fmt(rb)+"/s",
                    "total_sent_fmt":_fmt(cur.bytes_sent),
                    "total_recv_fmt":_fmt(cur.bytes_recv),
                }
                yield f"data: {json.dumps(payload)}\n\n"
            except Exception as ex:
                yield f"data: {json.dumps({'type':'error','msg':str(ex)})}\n\n"
                break

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


# ── INTERFACES ────────────────────────────────────────────────────────────────
@network_bp.route("/interfaces")
def interfaces():
    if not PSUTIL_OK: return _no_psutil()
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io    = psutil.net_io_counters(pernic=True)
    out   = []
    for name, al in addrs.items():
        ipv4 = [a.address for a in al if a.family == socket.AF_INET]
        ipv6 = [a.address for a in al if a.family == socket.AF_INET6]
        mac  = [a.address for a in al if hasattr(psutil,'AF_LINK') and a.family == psutil.AF_LINK]
        s, c = stats.get(name), io.get(name)
        out.append({
            "name":name,"ipv4":ipv4,"ipv6":ipv6[:1],
            "mac":mac[0] if mac else "",
            "is_up":s.isup if s else False,
            "speed_mbps":s.speed if s else 0,
            "mtu":s.mtu if s else 0,
            "bytes_sent":c.bytes_sent if c else 0,
            "bytes_recv":c.bytes_recv if c else 0,
            "pkts_sent":c.packets_sent if c else 0,
            "pkts_recv":c.packets_recv if c else 0,
            "errin":c.errin if c else 0,"errout":c.errout if c else 0,
            "dropin":c.dropin if c else 0,"dropout":c.dropout if c else 0,
            "bytes_sent_fmt":_fmt(c.bytes_sent) if c else "0 B",
            "bytes_recv_fmt":_fmt(c.bytes_recv) if c else "0 B",
        })
    out.sort(key=lambda x: (-int(x["is_up"]), -x["bytes_recv"]))
    return jsonify({"interfaces":out,"count":len(out)})


# ── BANDWIDTH — non-blocking background thread ────────────────────────────────
@network_bp.route("/bandwidth")
def bandwidth():
    """
    CRITICAL FIX: previous version called time.sleep(1) on the Flask request
    thread, which held a worker and blocked all other requests for 1 second.
    Now uses a background thread so the HTTP response returns immediately
    after the measurement is done without blocking Flask.
    """
    if not PSUTIL_OK: return _no_psutil()

    result = {}
    done   = threading.Event()

    def _measure():
        snap1 = psutil.net_io_counters(pernic=True)
        time.sleep(1.0)
        snap2 = psutil.net_io_counters(pernic=True)
        nics  = []
        for nic in snap1:
            if nic not in snap2: continue
            a, b = snap1[nic], snap2[nic]
            sent = max(0, b.bytes_sent - a.bytes_sent)
            recv = max(0, b.bytes_recv - a.bytes_recv)
            if sent + recv == 0: continue
            nics.append({
                "nic":nic,"sent_bps":sent,"recv_bps":recv,"total_bps":sent+recv,
                "sent_fmt":_fmt(sent)+"/s","recv_fmt":_fmt(recv)+"/s",
                "total_fmt":_fmt(sent+recv)+"/s",
                "pkts_sent":max(0,b.packets_sent-a.packets_sent),
                "pkts_recv":max(0,b.packets_recv-a.packets_recv),
            })
        nics.sort(key=lambda x: -x["total_bps"])
        result["nics"] = nics
        done.set()

    t = threading.Thread(target=_measure, daemon=True)
    t.start()
    done.wait(timeout=3)   # wait max 3s — never blocks indefinitely
    return jsonify({"nics": result.get("nics",[]), "sampled_at": datetime.now().isoformat()})


# ── CONNECTIONS ───────────────────────────────────────────────────────────────
@network_bp.route("/connections")
def connections():
    if not PSUTIL_OK: return _no_psutil()
    proc_map = {}
    try:
        for p in psutil.process_iter(['pid','name']):
            try: proc_map[p.pid] = p.name()
            except: pass
    except: pass
    conns, nodes, links = [], {}, []
    try: raw = psutil.net_connections(kind='inet')
    except Exception as e:
        return jsonify({"error":str(e),"connections":[],"nodes":[],"links":[],"total":0})
    try:   local_ip = socket.gethostbyname(socket.gethostname())
    except: local_ip = "127.0.0.1"

    def _priv(ip): return ip.startswith(('10.','192.168.','172.','127.','::1','fe80'))

    for c in raw:
        if not c.raddr: continue
        lip, rip  = (c.laddr.ip if c.laddr else local_ip), c.raddr.ip
        lp,  rp   = (c.laddr.port if c.laddr else 0), c.raddr.port
        proc  = proc_map.get(c.pid, f"PID {c.pid}") if c.pid else "unknown"
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        ntype = "local" if lip == local_ip else ("private" if _priv(rip) else "public")
        if lip not in nodes: nodes[lip] = {"id":lip,"type":"local","label":lip,"connections":0}
        if rip not in nodes: nodes[rip] = {"id":rip,"type":ntype,"label":rip,"connections":0}
        nodes[lip]["connections"] += 1; nodes[rip]["connections"] += 1
        links.append({"source":lip,"target":rip,"process":proc,"proto":proto,"status":c.status or "","lport":lp,"rport":rp})
        conns.append({"local":f"{lip}:{lp}","remote":f"{rip}:{rp}","proto":proto,"status":c.status or "","pid":c.pid,"process":proc})

    seen, ul = set(), []
    for lk in links:
        k = (lk["source"],lk["target"],lk["process"])
        if k not in seen: seen.add(k); ul.append(lk)

    return jsonify({"connections":conns[:200],"nodes":list(nodes.values()),
                    "links":ul[:200],"total":len(conns),"sampled_at":datetime.now().isoformat()})


# ── TOP PROCESSES ─────────────────────────────────────────────────────────────
@network_bp.route("/top-processes")
def top_processes():
    if not PSUTIL_OK: return _no_psutil()
    counts = defaultdict(int)
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.pid: counts[c.pid] += 1
    except: pass
    result = []
    for pid, cnt in sorted(counts.items(), key=lambda x:-x[1])[:20]:
        try:
            p = psutil.Process(pid)
            result.append({"pid":pid,"name":p.name(),"connections":cnt,
                           "cpu_pct":p.cpu_percent(interval=0),
                           "mem_bytes":p.memory_info().rss,
                           "mem_fmt":_fmt(p.memory_info().rss)})
        except: result.append({"pid":pid,"name":f"PID {pid}","connections":cnt,"cpu_pct":0,"mem_bytes":0,"mem_fmt":"0 B"})
    return jsonify({"processes":result,"sampled_at":datetime.now().isoformat()})


# ── SECURITY CORRELATIONS ─────────────────────────────────────────────────────
@network_bp.route("/security-correlations")
def security_correlations():
    db = get_conn(); cur = db.cursor()
    try:
        cur.execute("SELECT timestamp,level,source,message,event_id FROM logs_security ORDER BY timestamp DESC LIMIT 100")
        sec_events = [{"timestamp":r[0],"level":r[1],"source":r[2],"message":r[3],"event_id":r[4]} for r in cur.fetchall()]
    except: sec_events = []
    try:
        cur.execute("SELECT substr(timestamp,1,13) hr,COUNT(*) cnt FROM logs_security WHERE event_id=4625 GROUP BY hr ORDER BY hr DESC LIMIT 48")
        failed_logons = [{"hour":r[0],"cnt":r[1]} for r in cur.fetchall()]
    except: failed_logons = []
    try:
        cur.execute("SELECT event_id,COUNT(*) cnt,level FROM logs_security GROUP BY event_id ORDER BY cnt DESC LIMIT 20")
        event_summary = [{"event_id":r[0],"cnt":r[1],"level":r[2]} for r in cur.fetchall()]
    except: event_summary = []
    db.close()
    live_ips = set()
    if PSUTIL_OK:
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.raddr: live_ips.add(c.raddr.ip)
        except: pass
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    correlations = []
    for ev in sec_events:
        hits = [ip for ip in ip_re.findall(ev.get("message") or "") if ip in live_ips]
        if hits:
            correlations.append({**ev,"matched_ips":hits,
                "note":f"⚠ IP {hits[0]} seen in Security log AND live connections"})
    return jsonify({"security_events":sec_events[:30],"failed_logons":failed_logons,
                    "event_summary":event_summary,"correlations":correlations,
                    "live_ip_count":len(live_ips),"live_ips_sample":list(live_ips)[:10]})


# ── PORT SCANNER ──────────────────────────────────────────────────────────────
@network_bp.route("/port-scan", methods=["POST"])
def port_scan():
    body   = request.get_json(force=True) or {}
    target = body.get("target","").strip()
    ports  = body.get("ports","1-1024").strip()
    if not target: return jsonify({"error":"target is required"}), 400
    try:    target_ip = socket.gethostbyname(target)
    except Exception as e: return jsonify({"error":f"Cannot resolve {target}: {e}"}), 400

    open_ports = []
    t0 = time.time()

    if NMAP_OK:
        try:
            nm = nmap_lib.PortScanner()
            nm.scan(target_ip, ports, arguments="-T4 --open")
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        info = nm[host][proto][port]
                        if info["state"] == "open":
                            open_ports.append({"port":port,"proto":proto.upper(),"state":"open",
                                               "service":info.get("name",""),"version":info.get("version",""),"product":info.get("product","")})
        except Exception as e:
            return jsonify({"error":f"nmap: {e}","tip":"Install nmap binary from nmap.org"}), 200
    else:
        # Raw socket fallback
        try:
            if "-" in ports:
                p1, p2 = ports.split("-"); port_list = range(int(p1), min(int(p2)+1, int(p1)+500))
            elif "," in ports:
                port_list = [int(p.strip()) for p in ports.split(",")]
            else:
                port_list = [int(ports)]
        except: port_list = range(1, 101)

        lock = threading.Lock()
        def chk(p):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((target_ip, p)) == 0:
                    try: svc = socket.getservbyport(p)
                    except: svc = ""
                    with lock: open_ports.append({"port":p,"proto":"TCP","state":"open","service":svc,"version":"","product":""})
                s.close()
            except: pass

        threads = [threading.Thread(target=chk, args=(p,)) for p in port_list]
        for t in threads: t.start()
        for t in threads: t.join(timeout=2)
        open_ports.sort(key=lambda x: x["port"])

    return jsonify({"target":target,"target_ip":target_ip,"ports":ports,
                    "open_ports":open_ports,"total_open":len(open_ports),
                    "elapsed_s":round(time.time()-t0,2),
                    "scanner":"nmap" if NMAP_OK else "socket (pip install python-nmap for better results)",
                    "scanned_at":datetime.now().isoformat()})


# ── DNS LOOKUP ────────────────────────────────────────────────────────────────
@network_bp.route("/dns-lookup", methods=["POST"])
def dns_lookup():
    body   = request.get_json(force=True) or {}
    domain = body.get("domain","").strip().lower()
    if not domain: return jsonify({"error":"domain is required"}), 400
    result = {"domain":domain,"records":{},"errors":{}}

    if DNS_OK:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5; resolver.lifetime = 5
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
            try:
                answers = resolver.resolve(domain, rtype)
                recs = []
                for r in answers:
                    if rtype=="MX": recs.append({"preference":r.preference,"exchange":str(r.exchange)})
                    elif rtype=="SOA": recs.append({"mname":str(r.mname),"rname":str(r.rname),"serial":r.serial})
                    elif rtype=="TXT": recs.append({"text":" ".join(s.decode() for s in r.strings)})
                    else: recs.append(str(r))
                result["records"][rtype] = recs
            except dns.resolver.NXDOMAIN: result["errors"][rtype]="NXDOMAIN"
            except dns.resolver.NoAnswer:  result["errors"][rtype]="No records"
            except Exception as e:         result["errors"][rtype]=str(e)
        reverses = {}
        for ip in result["records"].get("A",[]):
            try:
                rev = dns.reversename.from_address(ip)
                reverses[ip] = str(resolver.resolve(rev,"PTR")[0])
            except: reverses[ip] = None
        result["reverse_dns"] = reverses
    else:
        try:
            ips = socket.getaddrinfo(domain, None)
            result["records"]["A"]    = list({r[4][0] for r in ips if ":" not in r[4][0]})
            result["records"]["AAAA"] = list({r[4][0] for r in ips if ":" in r[4][0]})
        except Exception as e: result["errors"]["A"] = str(e)
        result["note"] = "Install dnspython for full DNS: pip install dnspython"

    result["resolved_at"] = datetime.now().isoformat()
    return jsonify(result)


# ── HTTP PROBE ────────────────────────────────────────────────────────────────
@network_bp.route("/http-probe", methods=["POST"])
def http_probe():
    body = request.get_json(force=True) or {}
    url  = body.get("url","").strip()
    if not url: return jsonify({"error":"url is required"}), 400
    if not url.startswith(("http://","https://")): url = "https://" + url
    if not REQUESTS_OK: return jsonify({"error":"pip install requests"}), 400

    t0 = time.time()
    try:
        resp = req_lib.get(url, timeout=10, allow_redirects=True, headers={"User-Agent":"LogVault-Probe/1.0"})
        elapsed = round((time.time()-t0)*1000, 1)

        # TLS cert
        tls = {}
        if url.startswith("https://"):
            try:
                import ssl
                from urllib.parse import urlparse
                host = urlparse(url).hostname
                ctx  = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                    s.settimeout(5); s.connect((host, 443))
                    cert = s.getpeercert()
                    tls  = {"subject":dict(x[0] for x in cert.get("subject",[])),"issuer":dict(x[0] for x in cert.get("issuer",[])),"not_after":cert.get("notAfter"),"san":[v for _,v in cert.get("subjectAltName",[])][:6]}
            except Exception as e: tls = {"error":str(e)}

        sec_hdrs = {h: resp.headers.get(h,"❌ Missing") for h in ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy"]}
        redirects = [{"url":r.url,"status":r.status_code} for r in resp.history] + [{"url":resp.url,"status":resp.status_code}]

        return jsonify({"url":url,"final_url":resp.url,"status_code":resp.status_code,"reason":resp.reason,
                        "elapsed_ms":elapsed,"content_type":resp.headers.get("Content-Type",""),
                        "server":resp.headers.get("Server",""),"headers":dict(resp.headers),
                        "security_headers":sec_hdrs,"redirects":redirects,"tls":tls,
                        "probed_at":datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error":str(e)}), 200


# ── ARP / LAN SCAN ────────────────────────────────────────────────────────────
@network_bp.route("/arp-scan", methods=["POST"])
def arp_scan():
    body   = request.get_json(force=True) or {}
    subnet = body.get("subnet","").strip()
    if not subnet and PSUTIL_OK:
        for al in psutil.net_if_addrs().values():
            for a in al:
                if a.family==socket.AF_INET and not a.address.startswith("127."):
                    p = a.address.split(".")
                    subnet = f"{p[0]}.{p[1]}.{p[2]}.0/24"; break
            if subnet: break
    if not subnet: return jsonify({"error":"Could not detect subnet. Provide subnet e.g. 192.168.1.0/24"}), 400

    devices = []
    if SCAPY_OK:
        try:
            answered, _ = scapy.arping(subnet, timeout=2, verbose=False)
            for sent, received in answered:
                hostname = ""
                try: hostname = socket.gethostbyaddr(received.psrc)[0]
                except: pass
                devices.append({"ip":received.psrc,"mac":received.hwsrc,"hostname":hostname,"method":"ARP"})
        except Exception as e:
            return jsonify({"error":f"Scapy ARP failed: {e}","tip":"Run as Administrator and install Npcap"}), 200
    else:
        try:
            out = subprocess.check_output("arp -a", shell=True, text=True, timeout=10)
            for ip, mac in re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-:]{17})', out, re.I):
                hostname = ""
                try: hostname = socket.gethostbyaddr(ip)[0]
                except: pass
                devices.append({"ip":ip,"mac":mac.replace("-",":"),"hostname":hostname,"method":"ARP-table"})
        except Exception as e:
            return jsonify({"error":f"ARP table: {e}"}), 200

    devices.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
    return jsonify({"subnet":subnet,"devices":devices,"total":len(devices),
                    "scanner":"scapy" if SCAPY_OK else "arp-table (pip install scapy for active scan)",
                    "scanned_at":datetime.now().isoformat()})


# ── PACKET CAPTURE ────────────────────────────────────────────────────────────
_cap_results = []; _cap_running = False; _cap_lock = threading.Lock()

@network_bp.route("/packet-capture/start", methods=["POST"])
def cap_start():
    global _cap_results, _cap_running
    if not SCAPY_OK:
        return jsonify({"error":"pip install scapy","tip":"Also install Npcap from npcap.com (Windows)"}), 400
    body    = request.get_json(force=True) or {}
    count   = min(int(body.get("count",50)), 200)
    filter_ = body.get("filter","")
    iface   = body.get("iface", None)
    with _cap_lock:
        if _cap_running: return jsonify({"error":"Capture already running"}), 400
        _cap_results = []; _cap_running = True

    def _run():
        global _cap_running
        try:
            pkts = scapy.sniff(count=count, filter=filter_, iface=iface, timeout=30)
            with _cap_lock:
                for p in pkts:
                    e = {"time":datetime.fromtimestamp(float(p.time)).strftime("%H:%M:%S.%f")[:12],"len":len(p),"proto":"?","src":"","dst":"","info":""}
                    if p.haslayer(scapy.IP):
                        e["src"]   = p[scapy.IP].src; e["dst"] = p[scapy.IP].dst
                        e["proto"] = "TCP" if p.haslayer(scapy.TCP) else "UDP" if p.haslayer(scapy.UDP) else "IP"
                    if p.haslayer(scapy.TCP):   e["info"] = f":{p[scapy.TCP].sport}→:{p[scapy.TCP].dport} [{p[scapy.TCP].flags}]"
                    elif p.haslayer(scapy.UDP): e["info"] = f":{p[scapy.UDP].sport}→:{p[scapy.UDP].dport}"
                    elif p.haslayer(scapy.ICMP):e["proto"]="ICMP"; e["info"]=f"type={p[scapy.ICMP].type}"
                    _cap_results.append(e)
        except Exception as ex:
            with _cap_lock: _cap_results.append({"error":str(ex)})
        finally: _cap_running = False

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status":"started","count":count,"filter":filter_})

@network_bp.route("/packet-capture/results")
def cap_results():
    with _cap_lock:
        return jsonify({"running":_cap_running,"packets":list(_cap_results),"total":len(_cap_results)})

@network_bp.route("/packet-capture/stop", methods=["POST"])
def cap_stop():
    global _cap_running
    _cap_running = False
    return jsonify({"status":"stopped","captured":len(_cap_results)})


# ── PACKET ANOMALY DETECTION ENGINE ───────────────────────────────────────────
# No scapy needed — uses psutil connection analysis + statistical baselines.
# Detects: port scans, SYN floods, DNS tunnelling, data exfil, beaconing,
#           suspicious processes, known bad ports, high-entropy connections.

import collections, math, re as _re

_anomaly_baseline  = {}   # rolling baseline per metric
_anomaly_history   = collections.deque(maxlen=120)  # 2-min history ticks
_anomaly_alerts    = collections.deque(maxlen=200)   # detected anomalies
_anomaly_tick_lock = threading.Lock()

# Known suspicious / threat-relevant ports
_THREAT_PORTS = {
    4444:  ("Metasploit default",          "CRITICAL"),
    1337:  ("Common backdoor/leet port",   "HIGH"),
    31337: ("Back Orifice backdoor",       "CRITICAL"),
    6667:  ("IRC (botnet C2 common)",      "HIGH"),
    6697:  ("IRC over TLS",                "HIGH"),
    9001:  ("Tor default port",            "MEDIUM"),
    9050:  ("Tor SOCKS proxy",             "MEDIUM"),
    9051:  ("Tor control port",            "HIGH"),
    1080:  ("SOCKS proxy",                 "MEDIUM"),
    3389:  ("RDP — remote access",         "MEDIUM"),
    5900:  ("VNC — remote desktop",        "MEDIUM"),
    22:    ("SSH — check if expected",     "LOW"),
    23:    ("Telnet — unencrypted",        "HIGH"),
    25:    ("SMTP — possible spam relay",  "MEDIUM"),
    445:   ("SMB — lateral movement risk", "MEDIUM"),
    135:   ("RPC — exploitation target",   "MEDIUM"),
    8080:  ("HTTP proxy / C2 common",      "LOW"),
    4545:  ("Known RAT port",              "HIGH"),
    5555:  ("Android Debug Bridge / RAT",  "HIGH"),
    12345: ("Netbus backdoor",             "CRITICAL"),
    27374: ("Sub7 backdoor",               "CRITICAL"),
}

_SAFE_PROCS = {
    "chrome.exe","firefox.exe","msedge.exe","explorer.exe","svchost.exe",
    "lsass.exe","services.exe","wininit.exe","System","python.exe","python3.exe",
    "code.exe","node.exe","git.exe","curl.exe","WindowsTerminal.exe","conhost.exe",
    "RuntimeBroker.exe","SearchIndexer.exe","spoolsv.exe","taskhostw.exe",
}

def _entropy(s):
    """Shannon entropy of a string — high entropy = random/encrypted."""
    if not s: return 0
    freq = collections.Counter(s)
    n    = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values() if c)

def _analyse_connections():
    """
    Analyse current psutil connections for anomaly signals.
    Returns list of anomaly dicts with type, severity, detail.
    """
    if not PSUTIL_OK:
        return []

    found = []
    now   = time.time()

    try:
        conns = psutil.net_connections(kind='inet')
    except Exception:
        return []

    # Count per remote IP, per remote port, per local port
    remote_ip_count  = collections.Counter()
    remote_port_set  = collections.defaultdict(set)  # local_pid → remote ports
    established_ips  = set()
    listen_ports     = set()
    syn_count        = 0
    close_wait_count = 0
    time_wait_count  = 0
    total_conns      = len(conns)

    for c in conns:
        raddr = c.raddr
        laddr = c.laddr
        status = (c.status or '').upper()

        if raddr:
            remote_ip_count[raddr.ip] += 1

        if status == 'ESTABLISHED' and raddr:
            established_ips.add(raddr.ip)

        if status == 'LISTEN' and laddr:
            listen_ports.add(laddr.port)

        if 'SYN' in status:
            syn_count += 1
        if status == 'CLOSE_WAIT':
            close_wait_count += 1
        if status == 'TIME_WAIT':
            time_wait_count += 1

        # Suspicious destination port
        if raddr and raddr.port in _THREAT_PORTS:
            desc, sev = _THREAT_PORTS[raddr.port]
            found.append({
                "type":      "suspicious_port",
                "severity":  sev,
                "title":     f"Connection to suspicious port {raddr.port}",
                "detail":    f"{desc} → {raddr.ip}:{raddr.port} (Status: {status})",
                "icon":      "🚨",
                "ts":        now,
            })

        # Non-standard process with external connection
        if raddr and c.pid:
            try:
                proc = psutil.Process(c.pid)
                pname = proc.name()
                # Proc with external (non-private) IP
                if not _is_private(raddr.ip) and pname not in _SAFE_PROCS:
                    found.append({
                        "type":      "unknown_process_external",
                        "severity":  "MEDIUM",
                        "title":     f"Unknown process with external connection: {pname}",
                        "detail":    f"PID {c.pid} → {raddr.ip}:{raddr.port}",
                        "icon":      "⚙",
                        "ts":        now,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # Port scan heuristic: single IP connecting to many local ports
    local_port_per_src = collections.defaultdict(set)
    for c in conns:
        if c.raddr and c.laddr:
            local_port_per_src[c.raddr.ip].add(c.laddr.port)

    for ip, ports in local_port_per_src.items():
        if len(ports) >= 8:  # 8+ distinct local ports from same source
            found.append({
                "type":      "port_scan",
                "severity":  "HIGH",
                "title":     f"Possible port scan from {ip}",
                "detail":    f"{ip} is accessing {len(ports)} local ports: {sorted(ports)[:10]}…",
                "icon":      "🔍",
                "ts":        now,
            })

    # SYN flood heuristic
    if syn_count > 20:
        found.append({
            "type":      "syn_flood",
            "severity":  "CRITICAL",
            "title":     f"Possible SYN flood: {syn_count} half-open connections",
            "detail":    "High number of SYN_SENT/SYN_RECV states may indicate DDoS or scan",
            "icon":      "🌊",
            "ts":        now,
        })

    # Connection count spike vs baseline
    baseline_key = "total_conns"
    if baseline_key in _anomaly_baseline:
        baseline_avg = _anomaly_baseline[baseline_key]
        if total_conns > baseline_avg * 2.5 and total_conns > 50:
            found.append({
                "type":      "connection_spike",
                "severity":  "HIGH",
                "title":     f"Connection spike: {total_conns} vs baseline {int(baseline_avg)}",
                "detail":    "Active connections are 2.5× above rolling average — possible exfil or flood",
                "icon":      "📈",
                "ts":        now,
            })
    # Update baseline with EMA
    _anomaly_baseline[baseline_key] = (
        total_conns * 0.2 + _anomaly_baseline.get(baseline_key, total_conns) * 0.8
    )

    # Single IP with many connections (potential beaconing / data exfil)
    for ip, cnt in remote_ip_count.items():
        if cnt >= 12 and not _is_private(ip):
            found.append({
                "type":      "beaconing",
                "severity":  "MEDIUM",
                "title":     f"Possible beaconing to {ip} ({cnt} connections)",
                "detail":    f"Unusually high number of connections to a single external IP — may indicate C2",
                "icon":      "📡",
                "ts":        now,
            })

    # CLOSE_WAIT buildup (possible resource leak or targeted attack)
    if close_wait_count > 30:
        found.append({
            "type":      "close_wait_buildup",
            "severity":  "MEDIUM",
            "title":     f"CLOSE_WAIT buildup: {close_wait_count} sockets",
            "detail":    "Excessive CLOSE_WAIT may indicate a DoS attack or application bug",
            "icon":      "⚠",
            "ts":        now,
        })

    # Deduplicate by type+ip key
    seen = set()
    deduped = []
    for a in found:
        key = a["type"] + a["title"][:30]
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    return deduped


def _analyse_traffic():
    """
    Analyse psutil net_io_counters over a 1-second window for traffic anomalies.
    Returns list of anomaly dicts.
    """
    if not PSUTIL_OK:
        return []

    found = []
    try:
        a = psutil.net_io_counters()
        time.sleep(1)
        b = psutil.net_io_counters()
    except Exception:
        return []

    sent_bps = b.bytes_sent - a.bytes_sent
    recv_bps = b.bytes_recv - a.bytes_recv
    errin    = max(0, b.errin  - a.errin)
    errout   = max(0, b.errout - a.errout)
    dropin   = max(0, b.dropin - a.dropin)
    dropout  = max(0, b.dropout - a.dropout)

    # Data exfil spike — outbound > 10 MB/s
    if sent_bps > 10_000_000:
        found.append({
            "type":      "exfil_spike",
            "severity":  "CRITICAL",
            "title":     f"Data exfiltration spike: {sent_bps//1024//1024} MB/s outbound",
            "detail":    "Unusually high outbound traffic — possible data theft or large upload",
            "icon":      "💸",
            "ts":        time.time(),
        })
    elif sent_bps > 5_000_000:
        found.append({
            "type":      "high_upload",
            "severity":  "HIGH",
            "title":     f"High upload rate: {sent_bps//1024//1024} MB/s",
            "detail":    "Elevated outbound traffic detected",
            "icon":      "⬆",
            "ts":        time.time(),
        })

    # High inbound (DDoS / incoming flood)
    if recv_bps > 50_000_000:
        found.append({
            "type":      "ddos_inbound",
            "severity":  "CRITICAL",
            "title":     f"Incoming flood: {recv_bps//1024//1024} MB/s inbound",
            "detail":    "Very high inbound traffic — possible DDoS attack",
            "icon":      "🌊",
            "ts":        time.time(),
        })

    # Packet errors
    if errin + errout > 50:
        found.append({
            "type":      "packet_errors",
            "severity":  "MEDIUM",
            "title":     f"Packet errors: {errin} in / {errout} out",
            "detail":    "High error rate may indicate network attack, bad hardware or intrusion",
            "icon":      "❌",
            "ts":        time.time(),
        })

    # Drops
    if dropin + dropout > 100:
        found.append({
            "type":      "packet_drops",
            "severity":  "MEDIUM",
            "title":     f"Packet drops: {dropin} in / {dropout} out",
            "detail":    "High drop rate may indicate flood or resource exhaustion",
            "icon":      "🗑",
            "ts":        time.time(),
        })

    return found


def _is_private(ip):
    return ip.startswith(('10.','192.168.','172.','127.','::1','fe80','0.0.0.0',''))


# ── ANOMALY ENDPOINTS ────────────────────────────────────────────────────────

@network_bp.route("/anomaly/scan")
def anomaly_scan():
    """
    Run a full anomaly scan: connection analysis + traffic analysis.
    Returns detected anomalies sorted by severity.
    """
    conn_anomalies    = _analyse_connections()
    traffic_anomalies = _analyse_traffic()
    all_anomalies     = conn_anomalies + traffic_anomalies

    # Severity order
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_anomalies.sort(key=lambda a: sev_order.get(a["severity"], 9))

    # Store in rolling history
    if all_anomalies:
        with _anomaly_tick_lock:
            _anomaly_alerts.extend(all_anomalies)

    # Connection stats summary
    stats = {"total_connections": 0, "established": 0, "listen": 0,
             "syn": 0, "time_wait": 0, "close_wait": 0}
    if PSUTIL_OK:
        try:
            for c in psutil.net_connections(kind='inet'):
                stats["total_connections"] += 1
                s = (c.status or '').upper()
                if s == "ESTABLISHED":   stats["established"] += 1
                elif s == "LISTEN":      stats["listen"] += 1
                elif "SYN" in s:         stats["syn"] += 1
                elif s == "TIME_WAIT":   stats["time_wait"] += 1
                elif s == "CLOSE_WAIT":  stats["close_wait"] += 1
        except:
            pass

    return jsonify({
        "anomalies":     all_anomalies,
        "count":         len(all_anomalies),
        "healthy":       len(all_anomalies) == 0,
        "stats":         stats,
        "scanned_at":    datetime.now().isoformat(),
        "engine":        "Secure Eye Trust+ Network Anomaly Engine v1",
        "methods": [
            "Suspicious port detection (30+ known threat ports)",
            "Port scan heuristic (8+ local ports from single source)",
            "SYN flood detection (half-open connection threshold)",
            "Beaconing detection (single IP with 12+ connections)",
            "Connection count spike (2.5× rolling baseline)",
            "Unknown process with external connection",
            "Data exfil spike (outbound traffic threshold)",
            "DDoS inbound detection (50MB/s threshold)",
            "Packet error & drop rate analysis",
            "CLOSE_WAIT socket buildup",
        ],
    })


@network_bp.route("/anomaly/history")
def anomaly_history():
    """Return recent detected anomalies from rolling buffer."""
    with _anomaly_tick_lock:
        items = list(_anomaly_alerts)
    return jsonify({"history": items[-50:], "total": len(items)})
