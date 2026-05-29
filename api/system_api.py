"""
api/system_api.py
=================
Blueprint: /api/status  /api/stats

This module exposes system status and aggregated dashboard statistics.
"""

from flask import Blueprint, jsonify
from database.db import get_conn, CATEGORIES
from core.event_collector.windows_reader import is_admin, WIN32_AVAILABLE

system_bp = Blueprint("system", __name__)


@system_bp.route("/status")
def status():
    """Check environment: pywin32 installed? Running as admin?"""
    admin = is_admin()
    return jsonify({
        "win32_available": WIN32_AVAILABLE,
        "is_admin":        admin,
        "security_access": admin and WIN32_AVAILABLE,
        "security_tip":    "" if admin else "Run as Administrator to read Security logs",
    })


@system_bp.route("/stats")
def stats():
    """Return total / error / warning counts per category for dashboard cards."""
    result = {cat: {"total": 0, "errors": 0, "warnings": 0} for cat in CATEGORIES}
    try:
        conn = get_conn()
        c    = conn.cursor()
        for cat in CATEGORIES:
            try:
                c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
                total = c.fetchone()[0]
                c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level IN ('ERROR','CRITICAL','FAILURE')")
                errors = c.fetchone()[0]
                c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level='WARNING'")
                warnings = c.fetchone()[0]
                result[cat] = {"total": total, "errors": errors, "warnings": warnings}
            except Exception as e:
                result[cat] = {"total": 0, "errors": 0, "warnings": 0}
        conn.close()
    except Exception as e:
        print(f"[stats] DB error: {e}")
    return jsonify(result)


@system_bp.route("/system-stats")
def system_stats():
    """Real system stats: CPU, RAM, disk via psutil."""
    try:
        import psutil, platform
        # interval=None uses cached value — non-blocking, fast
        psutil.cpu_percent(interval=None)          # warm up cache
        cpu_percent  = psutil.cpu_percent(interval=0.2)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
        vm            = psutil.virtual_memory()
        # Windows-safe disk path
        import os
        disk_path = 'C:\\' if os.name == 'nt' else '/'
        disk      = psutil.disk_usage(disk_path)
        boot_time     = psutil.boot_time()
        net           = psutil.net_io_counters()
        import time as _time
        uptime_secs   = int(_time.time() - boot_time)
        h, rem        = divmod(uptime_secs, 3600)
        m, s          = divmod(rem, 60)

        # CPU freq
        try:
            freq = psutil.cpu_freq()
            freq_mhz = round(freq.current) if freq else 0
        except Exception:
            freq_mhz = 0

        # Battery
        try:
            batt = psutil.sensors_battery()
            battery = {'percent': batt.percent, 'plugged': batt.power_plugged} if batt else None
        except Exception:
            battery = None

        return jsonify({
            "cpu": {
                "percent":   round(cpu_percent, 1),
                "per_core":  [round(c, 1) for c in (cpu_per_core or [])],
                "count":     psutil.cpu_count(logical=True),
                "freq_mhz":  freq_mhz,
                "status":    "Critical" if cpu_percent > 90 else "High" if cpu_percent > 70 else "Normal",
            },
            "memory": {
                "percent":    round(vm.percent, 1),
                "used_gb":    round(vm.used  / 1e9, 1),
                "total_gb":   round(vm.total / 1e9, 1),
                "avail_gb":   round(vm.available / 1e9, 1),
                "status":     "Critical" if vm.percent > 90 else "High" if vm.percent > 75 else "Normal",
            },
            "disk": {
                "percent":    round(disk.percent, 1),
                "used_gb":    round(disk.used  / 1e9, 1),
                "total_gb":   round(disk.total / 1e9, 1),
                "free_gb":    round(disk.free  / 1e9, 1),
                "status":     "Critical" if disk.percent > 90 else "High" if disk.percent > 75 else "Normal",
            },
            "network": {
                "bytes_sent_mb": round(net.bytes_sent / 1e6, 1),
                "bytes_recv_mb": round(net.bytes_recv / 1e6, 1),
            },
            "uptime": f"{h}h {m}m {s}s",
            "platform": platform.node(),
            "battery": battery,
        })
    except ImportError:
        return jsonify({"error": "psutil not installed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route("/live-alerts")
def live_alerts():
    """
    Generate REAL alerts from actual system data.
    Polls: Windows event logs (errors/threats), psutil (CPU/RAM/disk),
           network connections, security log anomalies.
    Returns list of alert objects with severity, category, source, value.
    """
    import time as _time
    alerts = []

    # ── 1. LOG-BASED ALERTS (from SQLite) ─────────────────────────
    try:
        conn = get_conn()
        c = conn.cursor()

        # Recent critical/error events (last 10 mins)
        c.execute("""
            SELECT category, COUNT(*) cnt FROM (
                SELECT 'application' as category, level, timestamp FROM logs_application
                WHERE level IN ('CRITICAL','ERROR') AND timestamp >= datetime('now','-10 minutes')
                UNION ALL
                SELECT 'system', level, timestamp FROM logs_system
                WHERE level IN ('CRITICAL','ERROR') AND timestamp >= datetime('now','-10 minutes')
            ) GROUP BY category
        """)
        for row in c.fetchall():
            cat, cnt = row
            if cnt > 0:
                alerts.append({
                    "id":       f"err_{cat}",
                    "type":     "critical" if cnt > 10 else "warning",
                    "category": "logs",
                    "icon":     "🔴",
                    "title":    f"{cnt} {cat.title()} error{'s' if cnt>1 else ''} in last 10 min",
                    "detail":   f"Event source: Windows {cat.title()} Log",
                    "value":    cnt,
                    "source":   cat.title() + " Log",
                    "ts":       int(_time.time()),
                })

        # Failed logons (Event ID 4625)
        c.execute("""
            SELECT COUNT(*) FROM logs_security
            WHERE event_id=4625 AND timestamp >= datetime('now','-1 hour')
        """)
        row = c.fetchone()
        if row and row[0] > 0:
            n = row[0]
            alerts.append({
                "id":       "logon_fail",
                "type":     "critical" if n >= 5 else "warning",
                "category": "security",
                "icon":     "🔑",
                "title":    f"{n} failed logon attempt{'s' if n>1 else ''} (EID 4625)",
                "detail":   "Possible brute-force or credential attack",
                "value":    n,
                "source":   "Security Log",
                "ts":       int(_time.time()),
            })

        # Account lockouts (Event ID 4740)
        c.execute("""
            SELECT COUNT(*) FROM logs_security WHERE event_id=4740
            AND timestamp >= datetime('now','-1 hour')
        """)
        row = c.fetchone()
        if row and row[0] > 0:
            alerts.append({
                "id":       "lockout",
                "type":     "critical",
                "category": "security",
                "icon":     "🔒",
                "title":    f"{row[0]} account lockout event{'s' if row[0]>1 else ''}",
                "detail":   "EID 4740 — Account was locked out",
                "value":    row[0],
                "source":   "Security Log",
                "ts":       int(_time.time()),
            })

        # Privilege escalation (EID 4672, 4673)
        c.execute("""
            SELECT COUNT(*) FROM logs_security WHERE event_id IN (4672,4673)
            AND timestamp >= datetime('now','-30 minutes')
        """)
        row = c.fetchone()
        if row and row[0] > 3:
            alerts.append({
                "id":       "privesc",
                "type":     "warning",
                "category": "security",
                "icon":     "⚡",
                "title":    f"Privilege escalation: {row[0]} special logon events",
                "detail":   "EID 4672/4673 — Special privileges assigned",
                "value":    row[0],
                "source":   "Security Log",
                "ts":       int(_time.time()),
            })

        # Windows Update failures
        c.execute("""
            SELECT COUNT(*) FROM logs_windows_update
            WHERE level IN ('ERROR','CRITICAL')
            AND timestamp >= datetime('now','-24 hours')
        """)
        row = c.fetchone()
        if row and row[0] > 0:
            alerts.append({
                "id":       "wupdate_err",
                "type":     "warning",
                "category": "system",
                "icon":     "🔄",
                "title":    f"{row[0]} Windows Update failure{'s' if row[0]>1 else ''}",
                "detail":   "Check Windows Update log for details",
                "value":    row[0],
                "source":   "Windows Update",
                "ts":       int(_time.time()),
            })

        conn.close()
    except Exception as e:
        print(f"[live-alerts] DB error: {e}")

    # ── 2. SYSTEM RESOURCE ALERTS (psutil) ────────────────────────
    try:
        import psutil, os
        cpu = psutil.cpu_percent(interval=0.3)
        vm  = psutil.virtual_memory()
        disk_path = 'C:\\' if os.name == 'nt' else '/'
        dsk = psutil.disk_usage(disk_path)

        # Calculate CPU used by THIS app (python.exe) so we can subtract it
        # and only alert if OTHER processes are causing high CPU
        own_cpu = 0.0
        try:
            import psutil as _ps
            own_pid = os.getpid()
            own_proc = _ps.Process(own_pid)
            own_cpu = own_proc.cpu_percent(interval=0.1)
            # Also count child processes of this app
            for child in own_proc.children(recursive=True):
                try: own_cpu += child.cpu_percent(interval=None)
                except: pass
        except: pass

        # CPU usage excluding this monitoring app
        cpu_excl = max(0.0, cpu - own_cpu)

        if cpu_excl > 90:
            alerts.append({
                "id": "cpu_critical",
                "type": "critical", "category": "system", "icon": "🖥",
                "title": f"CPU critically high: {cpu_excl:.1f}% (excl. monitor)",
                "detail": "System may become unresponsive — external process causing load",
                "value": cpu_excl, "source": "System Monitor", "ts": int(_time.time()),
            })
        elif cpu_excl > 75:
            alerts.append({
                "id": "cpu_high",
                "type": "warning", "category": "system", "icon": "🖥",
                "title": f"CPU usage elevated: {cpu_excl:.1f}% (excl. monitor)",
                "detail": "High processing load from external processes",
                "value": cpu_excl, "source": "System Monitor", "ts": int(_time.time()),
            })

        # RAM alert: calculate memory used by this app and subtract it
        # so RAM alerts only fire if OTHER processes are consuming memory
        own_ram_mb = 0.0
        try:
            own_proc2 = _ps.Process(os.getpid())
            own_ram_mb = own_proc2.memory_info().rss / (1024 * 1024)
            for child in own_proc2.children(recursive=True):
                try: own_ram_mb += child.memory_info().rss / (1024 * 1024)
                except: pass
        except: pass

        total_mb   = vm.total / (1024 * 1024)
        used_excl  = max(0.0, (vm.used / (1024 * 1024)) - own_ram_mb)
        ram_pct_excl = round((used_excl / total_mb) * 100, 1) if total_mb > 0 else vm.percent

        if ram_pct_excl > 90:
            alerts.append({
                "id": "ram_critical",
                "type": "critical", "category": "system", "icon": "💾",
                "title": f"Memory critically low: {ram_pct_excl:.1f}% used (excl. monitor)",
                "detail": f"Only {round(vm.available/1e9,1)} GB remaining — external processes",
                "value": ram_pct_excl, "source": "System Monitor", "ts": int(_time.time()),
            })
        elif ram_pct_excl > 80:
            alerts.append({
                "id": "ram_high",
                "type": "warning", "category": "system", "icon": "💾",
                "title": f"Memory usage high: {ram_pct_excl:.1f}% (excl. monitor)",
                "detail": f"Available: {round(vm.available/1e9,1)} GB — check other processes",
                "value": ram_pct_excl, "source": "System Monitor", "ts": int(_time.time()),
            })

        if dsk.percent > 90:
            alerts.append({
                "id": "disk_critical",
                "type": "critical", "category": "system", "icon": "💿",
                "title": f"Disk nearly full: {dsk.percent:.1f}%",
                "detail": f"Free: {round(dsk.free/1e9,1)} GB",
                "value": dsk.percent, "source": "Disk Monitor", "ts": int(_time.time()),
            })
        elif dsk.percent > 80:
            alerts.append({
                "id": "disk_high",
                "type": "warning", "category": "system", "icon": "💿",
                "title": f"Disk usage elevated: {dsk.percent:.1f}%",
                "detail": f"Free: {round(dsk.free/1e9,1)} GB",
                "value": dsk.percent, "source": "Disk Monitor", "ts": int(_time.time()),
            })

        # Suspicious processes using high CPU
        # NOTE: OWN_PROCESS_NAMES excludes the monitoring app itself from alerts
        OWN_PROCESS_NAMES = {
            'python.exe', 'python3.exe', 'python',   # this app
            'pythonw.exe', 'py.exe',                  # python variants
            'System Idle Process', 'System', '',       # Windows internals
            'Registry', 'Memory Compression',          # Windows internals
            'svchost.exe',                             # Windows services (too generic)
        }
        try:
            sus = []
            own_pid = os.getpid()
            for p in psutil.process_iter(['name', 'cpu_percent', 'pid', 'status']):
                try:
                    pname = p.info['name'] or ''
                    ppid  = p.info['pid']
                    pc    = p.info['cpu_percent'] or 0
                    # Skip: our own process, known own names, system idle, low CPU
                    if ppid == own_pid:          continue
                    if pname in OWN_PROCESS_NAMES: continue
                    if pname.lower().startswith('python'): continue
                    if pc > 80:
                        sus.append(f"{pname} ({pc:.0f}%)")
                except: pass
            if sus:
                alerts.append({
                    "id": "proc_high",
                    "type": "warning", "category": "system", "icon": "⚙",
                    "title": f"High-CPU process: {sus[0]}",
                    "detail": "Process consuming excessive CPU resources",
                    "value": sus[0], "source": "Process Monitor", "ts": int(_time.time()),
                })
        except: pass

    except ImportError:
        pass
    except Exception as e:
        print(f"[live-alerts] psutil error: {e}")

    # ── 3. NETWORK ALERTS ─────────────────────────────────────────
    try:
        import psutil as ps2
        conns = ps2.net_connections(kind='inet')
        conn_count = len(conns)
        if conn_count > 300:
            alerts.append({
                "id": "net_conns_critical",
                "type": "critical", "category": "network", "icon": "🌐",
                "title": f"Excessive connections: {conn_count} active",
                "detail": "Potential port scan or malware activity",
                "value": conn_count, "source": "Network Monitor", "ts": int(_time.time()),
            })
        elif conn_count > 150:
            alerts.append({
                "id": "net_conns_warning",
                "type": "warning", "category": "network", "icon": "🌐",
                "title": f"High connection count: {conn_count}",
                "detail": "Above average network activity",
                "value": conn_count, "source": "Network Monitor", "ts": int(_time.time()),
            })
    except: pass

    # Remove any duplicate alert IDs so the same problem does not reappear
    seen = set()
    unique_alerts = []
    for a in alerts:
        aid = str(a.get("id", ""))
        if not aid or aid in seen:
            continue
        seen.add(aid)
        unique_alerts.append(a)
    alerts = unique_alerts

    # v3: Filter out resolved alerts from panel
    try:
        _conn2 = get_conn()
        _c2    = _conn2.cursor()
        _c2.execute("SELECT alert_id FROM resolved_alerts")
        _resolved_ids = {row[0] for row in _c2.fetchall()}
        _conn2.close()
        alerts = [a for a in alerts if str(a.get("id","")) not in _resolved_ids]
    except Exception:
        pass  # Table not yet created — skip filtering

    # Sort by severity
    order = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda a: order.get(a["type"], 9))

    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "ts": int(_time.time()),
        "healthy": len(alerts) == 0,
    })


# ── /api/intelligence — threat intelligence summary ───────────────────────────
@system_bp.route("/intelligence")
def threat_intelligence():
    """
    Returns a threat intelligence summary built from real log data.
    Covers: top threat event IDs, failed logons, privilege escalation,
    malware detections, and network anomalies.
    """
    from database.db import get_conn, CATEGORIES
    import time as _t

    result = {
        "ok":              True,
        "generated_at":    __import__('datetime').datetime.now().isoformat(),
        "threat_summary":  [],
        "ioc_counts":      {},
        "top_event_ids":   [],
        "failed_logons":   0,
        "lockouts":        0,
        "priv_escalations":0,
        "malware_events":  0,
        "network_blocks":  0,
    }

    try:
        conn = get_conn()
        c    = conn.cursor()

        # Failed logons
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4625")
        row = c.fetchone()
        result["failed_logons"] = row[0] if row else 0

        # Account lockouts
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4740")
        row = c.fetchone()
        result["lockouts"] = row[0] if row else 0

        # Privilege escalation
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id IN (4672,4673)")
        row = c.fetchone()
        result["priv_escalations"] = row[0] if row else 0

        # Malware / Defender events
        c.execute("""
            SELECT COUNT(*) FROM logs_application
            WHERE message LIKE '%malware%' OR message LIKE '%defender%'
               OR message LIKE '%threat%' OR message LIKE '%virus%'
               OR message LIKE '%mimikatz%'
        """)
        row = c.fetchone()
        result["malware_events"] = row[0] if row else 0

        # Network blocks
        c.execute("""
            SELECT COUNT(*) FROM logs_security
            WHERE event_id IN (5152, 5157) OR message LIKE '%blocked%'
        """)
        row = c.fetchone()
        result["network_blocks"] = row[0] if row else 0

        # Top event IDs across security log
        c.execute("""
            SELECT event_id, COUNT(*) cnt, level, MAX(timestamp) last_seen
            FROM logs_security
            WHERE event_id IS NOT NULL
            GROUP BY event_id
            ORDER BY cnt DESC
            LIMIT 15
        """)
        result["top_event_ids"] = [
            {"event_id": r[0], "count": r[1], "level": r[2], "last_seen": r[3]}
            for r in c.fetchall()
        ]

        # Build threat summary
        if result["failed_logons"] > 10:
            result["threat_summary"].append({
                "severity": "CRITICAL", "type": "Brute Force",
                "detail": f"{result['failed_logons']} failed logon attempts detected (EID 4625)"
            })
        if result["lockouts"] > 0:
            result["threat_summary"].append({
                "severity": "HIGH", "type": "Account Lockout",
                "detail": f"{result['lockouts']} account lockout events (EID 4740)"
            })
        if result["priv_escalations"] > 50:
            result["threat_summary"].append({
                "severity": "HIGH", "type": "Privilege Escalation",
                "detail": f"{result['priv_escalations']} privilege escalation events (EID 4672/4673)"
            })
        if result["malware_events"] > 0:
            result["threat_summary"].append({
                "severity": "CRITICAL", "type": "Malware Detected",
                "detail": f"{result['malware_events']} potential malware/defender events"
            })
        if result["network_blocks"] > 100:
            result["threat_summary"].append({
                "severity": "MEDIUM", "type": "Network Blocks",
                "detail": f"{result['network_blocks']} network connection blocks (EID 5152/5157)"
            })

        conn.close()
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)
