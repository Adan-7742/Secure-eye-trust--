"""
api/rt_status_api.py
======================
REST endpoints exposing real-time pipeline status and performance data.

ENDPOINTS:
  GET /api/rt-status              — pipeline health (all collectors alive?)
  GET /api/perf/current           — latest CPU/RAM/Disk/Network snapshot
  GET /api/perf/history           — last N perf samples (for charts)
  GET /api/defender/recent        — recent Defender events
  GET /api/firewall/recent        — recent firewall events

  FR09-03:
  GET /api/dns/recent             — recent Windows DNS client queries
  GET /api/dns/stats              — query volume, NXDOMAIN rate, top domains

  FR09-04:
  GET /api/smb/recent             — recent SMB/file-share access events
  GET /api/smb/stats              — share access counts, auth failures, admin shares

  FR09-06:
  GET /api/psremoting/recent      — recent PS remoting / WinRM sessions
  GET /api/psremoting/stats       — session counts, auth failures, obfuscated scripts
"""

from flask import Blueprint, jsonify, request, session
from utils.logger import get_logger

log       = get_logger("rt_status_api")
rt_api_bp = Blueprint("rt_status", __name__)


def _auth():
    if not session.get("authenticated"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None


# ── PIPELINE STATUS ────────────────────────────────────────────────────────────

@rt_api_bp.route("/rt-status")
def rt_status():
    """Real-time pipeline health — all collectors + latency info."""
    err = _auth()
    if err:
        return err
    try:
        from core.event_collector.rt_pipeline import get_rt_pipeline
        status = get_rt_pipeline().status()
        return jsonify({"ok": True, **status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "running": False})


# ── PERFORMANCE ────────────────────────────────────────────────────────────────

@rt_api_bp.route("/perf/current")
def perf_current():
    """Latest system performance snapshot (CPU/RAM/Disk/Network)."""
    err = _auth()
    if err:
        return err
    try:
        from core.event_collector.perf_monitor import get_perf_monitor
        sample = get_perf_monitor().get_current()
        if sample:
            return jsonify({"ok": True, "sample": sample})
        return jsonify({"ok": False, "error": "No sample yet — monitor may be starting"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@rt_api_bp.route("/perf/history")
def perf_history():
    """Last N performance samples from DB (for trend charts)."""
    err = _auth()
    if err:
        return err
    limit = min(int(request.args.get("limit", 60)), 2880)
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            SELECT ts, cpu_pct, ram_pct, disk_iops, net_mbps
            FROM perf_samples
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = [
            {"ts": r[0], "cpu": r[1], "ram": r[2], "disk_iops": r[3], "net_mbps": r[4]}
            for r in c.fetchall()
        ]
        conn.close()
        rows.reverse()
        return jsonify({"ok": True, "samples": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "samples": [], "error": str(e)})


# ── DEFENDER ───────────────────────────────────────────────────────────────────

@rt_api_bp.route("/defender/recent")
def defender_recent():
    """Recent Windows Defender events from security log."""
    err = _auth()
    if err:
        return err
    limit = min(int(request.args.get("limit", 50)), 200)
    try:
        from database.db import get_conn
        DEFENDER_EIDS = (1116, 1117, 1118, 1119, 1120, 2001, 2002, 5001, 5004, 5007, 5010, 5012)
        placeholders  = ",".join("?" * len(DEFENDER_EIDS))
        conn = get_conn()
        c    = conn.cursor()
        c.execute(f"""
            SELECT timestamp, level, source, event_id, message
            FROM logs_security
            WHERE event_id IN ({placeholders})
            ORDER BY timestamp DESC LIMIT ?
        """, DEFENDER_EIDS + (limit,))
        rows = [
            {"timestamp": r[0], "level": r[1], "source": r[2],
             "event_id": r[3], "message": (r[4] or "")[:300]}
            for r in c.fetchall()
        ]
        conn.close()
        return jsonify({"ok": True, "events": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "events": [], "error": str(e)})


# ── FIREWALL ───────────────────────────────────────────────────────────────────

@rt_api_bp.route("/firewall/recent")
def firewall_recent():
    """Recent firewall events (blocked/suspicious) from security log."""
    err = _auth()
    if err:
        return err
    limit = min(int(request.args.get("limit", 100)), 500)
    try:
        from database.db import get_conn
        FW_EIDS      = (5152, 5153, 5155, 5157, 4946, 4947, 4950)
        placeholders = ",".join("?" * len(FW_EIDS))
        conn = get_conn()
        c    = conn.cursor()
        c.execute(f"""
            SELECT timestamp, level, source, event_id, message
            FROM logs_security
            WHERE event_id IN ({placeholders})
            ORDER BY timestamp DESC LIMIT ?
        """, FW_EIDS + (limit,))
        rows = [
            {"timestamp": r[0], "level": r[1], "source": r[2],
             "event_id": r[3], "message": (r[4] or "")[:300]}
            for r in c.fetchall()
        ]
        conn.close()
        return jsonify({"ok": True, "events": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "events": [], "error": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# FR09-03 — DNS Client Monitoring Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@rt_api_bp.route("/dns/recent")
def dns_recent():
    """
    FR09-03 — Recent Windows DNS client queries and failures.

    Query params:
      limit        int   (default 100, max 500)
      suspicious   bool  (default false — set to 1 to filter suspicious only)
      result       str   (filter by result: NXDOMAIN | TIMEOUT | SUCCESS)
    """
    err = _auth()
    if err:
        return err

    limit      = min(int(request.args.get("limit", 100)), 500)
    susp_only  = request.args.get("suspicious", "0") in ("1", "true", "True")
    result_flt = request.args.get("result", "").strip().upper()

    try:
        from database.db import get_conn
        # DNS events stored in logs_security with source containing "DNS-Client"
        conn = get_conn()
        c    = conn.cursor()

        # Build WHERE clause
        where_parts = ["source LIKE '%DNS-Client%' OR source LIKE '%DNS Client%'"]
        params: list = []

        if susp_only:
            where_parts.append(
                "(message LIKE '%⚠%' OR level IN ('WARNING','ERROR','CRITICAL'))"
            )

        if result_flt:
            where_parts.append("message LIKE ?")
            params.append(f"%[{result_flt}]%")

        where = " AND ".join(where_parts)

        c.execute(
            f"""
            SELECT timestamp, date, level, source, event_id, message
            FROM logs_security
            WHERE {where}
            ORDER BY timestamp DESC LIMIT ?
            """,
            params + [limit]
        )
        rows = [
            {
                "timestamp": r[0], "date": r[1], "level": r[2],
                "source":    r[3], "event_id": r[4],
                "message":   (r[5] or "")[:300],
            }
            for r in c.fetchall()
        ]

        # Summary stats
        c.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN message LIKE '%NXDOMAIN%' THEN 1 ELSE 0 END) as nxdomain,
                SUM(CASE WHEN message LIKE '%TIMEOUT%'  THEN 1 ELSE 0 END) as timeouts,
                SUM(CASE WHEN message LIKE '%⚠%'
                          OR level IN ('WARNING','ERROR','CRITICAL') THEN 1 ELSE 0 END) as suspicious
            FROM logs_security
            WHERE source LIKE '%DNS-Client%' OR source LIKE '%DNS Client%'
            """
        )
        s = c.fetchone()
        conn.close()

        stats = {
            "total":     s[0] or 0,
            "nxdomain":  s[1] or 0,
            "timeouts":  s[2] or 0,
            "suspicious": s[3] or 0,
        }

        return jsonify({
            "ok":     True,
            "events": rows,
            "count":  len(rows),
            "stats":  stats,
            "note":   (
                "DNS-Client/Operational log must be enabled for full coverage. "
                "Collector attempts wevtutil enable at startup (requires Admin)."
            ),
        })
    except Exception as e:
        return jsonify({"ok": False, "events": [], "error": str(e)})


@rt_api_bp.route("/dns/stats")
def dns_stats():
    """
    FR09-03 — DNS client statistics: top queried domains, NXDOMAIN rate,
    suspicious query breakdown.
    """
    err = _auth()
    if err:
        return err
    try:
        from database.db import get_conn
        import re
        conn = get_conn()
        c    = conn.cursor()

        c.execute(
            """
            SELECT message, level, timestamp
            FROM logs_security
            WHERE (source LIKE '%DNS-Client%' OR source LIKE '%DNS Client%')
            ORDER BY timestamp DESC LIMIT 2000
            """
        )
        rows = c.fetchall()

        _re_qname = re.compile(r"DNS [^:]+: ([^\s]+)", re.IGNORECASE)
        _re_result = re.compile(r"\[(\w+)\]")
        domain_counts: dict = {}
        nxdomain_domains: dict = {}
        result_counts: dict = {}
        threat_counts: dict = {}

        for row in rows:
            msg   = row[0] or ""
            level = row[1] or ""
            qm    = _re_qname.search(msg)
            rm    = _re_result.findall(msg)
            domain = qm.group(1) if qm else ""
            result = rm[0] if rm else "UNKNOWN"

            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            result_counts[result] = result_counts.get(result, 0) + 1
            if "NXDOMAIN" in msg and domain:
                nxdomain_domains[domain] = nxdomain_domains.get(domain, 0) + 1

            # Threat type from message tag
            for tag in ("dga", "suspicious_tld", "beaconing", "nxdomain_burst"):
                if tag in msg.lower():
                    threat_counts[tag] = threat_counts.get(tag, 0) + 1

        conn.close()

        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:20]
        top_nxdomain = sorted(nxdomain_domains.items(), key=lambda x: -x[1])[:10]
        total = len(rows)
        nxdomain_rate = round(
            (result_counts.get("NXDOMAIN", 0) / max(total, 1)) * 100, 1
        )

        return jsonify({
            "ok":            True,
            "total_queries": total,
            "nxdomain_rate": nxdomain_rate,
            "result_counts": result_counts,
            "threat_counts": threat_counts,
            "top_domains":   [{"domain": d, "count": c} for d, c in top_domains],
            "top_nxdomain":  [{"domain": d, "count": c} for d, c in top_nxdomain],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# FR09-04 — SMB / File Sharing Monitoring Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@rt_api_bp.route("/smb/recent")
def smb_recent():
    """
    FR09-04 — Recent SMB file sharing and network share access events.

    Query params:
      limit        int   (default 100, max 500)
      suspicious   bool  (filter suspicious only)
      admin_only   bool  (filter admin share accesses only)
    """
    err = _auth()
    if err:
        return err

    limit      = min(int(request.args.get("limit", 100)), 500)
    susp_only  = request.args.get("suspicious", "0") in ("1", "true", "True")
    admin_only = request.args.get("admin_only",  "0") in ("1", "true", "True")

    try:
        from database.db import get_conn

        SMB_EIDS     = (5140, 5142, 5143, 5144, 5145, 4776, 1000, 1001, 1003, 1006, 3000)
        placeholders = ",".join("?" * len(SMB_EIDS))

        conn = get_conn()
        c    = conn.cursor()

        extra_where = ""
        extra_params: list = []

        if susp_only:
            extra_where += " AND (message LIKE '%⚠%' OR level IN ('WARNING','ERROR','CRITICAL'))"

        if admin_only:
            extra_where += (
                " AND (message LIKE '%C$%' OR message LIKE '%ADMIN$%'"
                " OR message LIKE '%IPC$%' OR message LIKE '%admin_share%')"
            )

        c.execute(
            f"""
            SELECT timestamp, date, level, source, event_id, message
            FROM logs_security
            WHERE (
                event_id IN ({placeholders})
                OR source LIKE '%SMB%'
                OR source LIKE '%SmbMonitor%'
            )
            {extra_where}
            ORDER BY timestamp DESC LIMIT ?
            """,
            list(SMB_EIDS) + extra_params + [limit]
        )
        rows = [
            {
                "timestamp": r[0], "date": r[1], "level": r[2],
                "source":    r[3], "event_id": r[4],
                "message":   (r[5] or "")[:300],
            }
            for r in c.fetchall()
        ]

        # Summary stats
        c.execute(
            f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN event_id=5140 THEN 1 ELSE 0 END) as share_access,
                SUM(CASE WHEN event_id=5145 THEN 1 ELSE 0 END) as object_checks,
                SUM(CASE WHEN (message LIKE '%C$%' OR message LIKE '%ADMIN$%'
                               OR message LIKE '%IPC$%') THEN 1 ELSE 0 END) as admin_share,
                SUM(CASE WHEN (message LIKE '%⚠%' OR level IN ('WARNING','CRITICAL')) THEN 1 ELSE 0 END) as suspicious
            FROM logs_security
            WHERE (
                event_id IN ({placeholders})
                OR source LIKE '%SMB%'
                OR source LIKE '%SmbMonitor%'
            )
            """,
            list(SMB_EIDS)
        )
        s = c.fetchone()
        conn.close()

        return jsonify({
            "ok":     True,
            "events": rows,
            "count":  len(rows),
            "stats": {
                "total":        s[0] or 0,
                "share_access": s[1] or 0,
                "object_checks": s[2] or 0,
                "admin_share":  s[3] or 0,
                "suspicious":   s[4] or 0,
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "events": [], "error": str(e)})


@rt_api_bp.route("/smb/stats")
def smb_stats():
    """
    FR09-04 — SMB statistics: top accessed shares, top users, auth failure counts.
    """
    err = _auth()
    if err:
        return err
    try:
        from database.db import get_conn
        import re
        conn = get_conn()
        c    = conn.cursor()

        SMB_EIDS     = (5140, 5142, 5143, 5144, 5145, 4776, 1000, 1001, 1003, 3000)
        placeholders = ",".join("?" * len(SMB_EIDS))

        c.execute(
            f"""
            SELECT event_id, level, source, message
            FROM logs_security
            WHERE event_id IN ({placeholders})
               OR source LIKE '%SMB%'
               OR source LIKE '%SmbMonitor%'
            ORDER BY timestamp DESC LIMIT 2000
            """,
            list(SMB_EIDS)
        )
        rows = c.fetchall()
        conn.close()

        _re_share = re.compile(r"share=([^\s]+)", re.IGNORECASE)
        _re_user  = re.compile(r"user=([^\s]+)", re.IGNORECASE)
        _re_ip    = re.compile(r"from=([\d.:a-fA-F]+)", re.IGNORECASE)

        share_counts: dict = {}
        user_counts:  dict = {}
        src_ip_counts: dict = {}
        eid_counts:   dict = {}
        auth_fails    = 0

        for eid, level, src, msg in rows:
            msg = msg or ""
            eid_counts[eid] = eid_counts.get(eid, 0) + 1
            if eid in (3000, 4776) and level in ("WARNING", "ERROR", "CRITICAL"):
                auth_fails += 1
            sm = _re_share.search(msg)
            um = _re_user.search(msg)
            im = _re_ip.search(msg)
            if sm:
                s = sm.group(1).strip()
                share_counts[s] = share_counts.get(s, 0) + 1
            if um:
                u = um.group(1).strip()
                user_counts[u] = user_counts.get(u, 0) + 1
            if im:
                ip = im.group(1).strip()
                src_ip_counts[ip] = src_ip_counts.get(ip, 0) + 1

        return jsonify({
            "ok":              True,
            "total_events":    len(rows),
            "auth_failures":   auth_fails,
            "event_breakdown": [{"event_id": k, "count": v} for k, v in sorted(eid_counts.items())],
            "top_shares":      [{"share": k, "count": v}
                                 for k, v in sorted(share_counts.items(), key=lambda x: -x[1])[:15]],
            "top_users":       [{"user": k, "count": v}
                                 for k, v in sorted(user_counts.items(), key=lambda x: -x[1])[:15]],
            "top_source_ips":  [{"ip": k, "count": v}
                                 for k, v in sorted(src_ip_counts.items(), key=lambda x: -x[1])[:10]],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# FR09-06 — PowerShell Remoting / WinRM Monitoring Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@rt_api_bp.route("/psremoting/recent")
def psremoting_recent():
    """
    FR09-06 — Recent PowerShell remoting / WinRM session events.

    Query params:
      limit       int   (default 100, max 500)
      suspicious  bool  (filter suspicious only)
      external    bool  (filter external IP connections only)
    """
    err = _auth()
    if err:
        return err

    limit     = min(int(request.args.get("limit", 100)), 500)
    susp_only = request.args.get("suspicious", "0") in ("1", "true", "True")
    ext_only  = request.args.get("external",   "0") in ("1", "true", "True")

    try:
        from database.db import get_conn

        # WinRM EIDs + PS operational EIDs + security logon EIDs for remoting
        PSR_EIDS     = (6, 8, 15, 16, 91, 168, 169, 193,   # WinRM
                        4103, 4104, 53504, 40961, 40962)    # PS Operational
        placeholders = ",".join("?" * len(PSR_EIDS))

        conn = get_conn()
        c    = conn.cursor()

        extra_where = ""
        if susp_only:
            extra_where += " AND (message LIKE '%⚠%' OR level IN ('WARNING','ERROR','CRITICAL'))"
        if ext_only:
            extra_where += " AND message LIKE '%external_ip%'"

        c.execute(
            f"""
            SELECT timestamp, date, level, source, event_id, message
            FROM logs_security
            WHERE (
                event_id IN ({placeholders})
                OR source LIKE '%PSRemoting%'
                OR source LIKE '%WinRM%'
                OR source LIKE '%PowerShell%'
                OR (event_id IN (4624, 4634) AND (
                    message LIKE '%5985%'
                    OR message LIKE '%5986%'
                    OR message LIKE '%wsman%'
                    OR message LIKE '%winrm%'
                    OR message LIKE '%PowerShell%'
                ))
            )
            {extra_where}
            ORDER BY timestamp DESC LIMIT ?
            """,
            list(PSR_EIDS) + [limit]
        )
        rows = [
            {
                "timestamp": r[0], "date": r[1], "level": r[2],
                "source":    r[3], "event_id": r[4],
                "message":   (r[5] or "")[:400],
            }
            for r in c.fetchall()
        ]

        # Summary stats
        c.execute(
            f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN event_id=169 THEN 1 ELSE 0 END) as auth_success,
                SUM(CASE WHEN event_id=193 THEN 1 ELSE 0 END) as auth_fail,
                SUM(CASE WHEN event_id=4104 THEN 1 ELSE 0 END) as script_blocks,
                SUM(CASE WHEN (message LIKE '%obfuscated_script%'
                               OR message LIKE '%OBFUSCATED%') THEN 1 ELSE 0 END) as obfuscated,
                SUM(CASE WHEN message LIKE '%external_ip%' THEN 1 ELSE 0 END) as external_conns
            FROM logs_security
            WHERE (
                event_id IN ({placeholders})
                OR source LIKE '%PSRemoting%'
                OR source LIKE '%WinRM%'
                OR source LIKE '%PowerShell%'
            )
            """,
            list(PSR_EIDS)
        )
        s = c.fetchone()
        conn.close()

        return jsonify({
            "ok":     True,
            "events": rows,
            "count":  len(rows),
            "stats": {
                "total":           s[0] or 0,
                "auth_success":    s[1] or 0,
                "auth_failures":   s[2] or 0,
                "script_blocks":   s[3] or 0,
                "obfuscated":      s[4] or 0,
                "external_conns":  s[5] or 0,
            },
            "channels": {
                "winrm":      "Microsoft-Windows-WinRM/Operational",
                "ps_op":      "Microsoft-Windows-PowerShell/Operational",
                "note":       "Channels polled by PsRemotingCollector if available. "
                              "EID 4103/4104 require PS script block logging to be enabled via Group Policy.",
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "events": [], "error": str(e)})


@rt_api_bp.route("/psremoting/stats")
def psremoting_stats():
    """
    FR09-06 — PS Remoting statistics: top source IPs, users, obfuscated scripts.
    """
    err = _auth()
    if err:
        return err
    try:
        from database.db import get_conn
        import re
        conn = get_conn()
        c    = conn.cursor()

        PSR_EIDS     = (6, 8, 15, 91, 168, 169, 193, 4103, 4104, 53504)
        placeholders = ",".join("?" * len(PSR_EIDS))

        c.execute(
            f"""
            SELECT event_id, level, message, timestamp
            FROM logs_security
            WHERE event_id IN ({placeholders})
               OR source LIKE '%PSRemoting%'
               OR source LIKE '%WinRM%'
            ORDER BY timestamp DESC LIMIT 2000
            """,
            list(PSR_EIDS)
        )
        rows = c.fetchall()
        conn.close()

        _re_ip      = re.compile(r"from=([\d.:a-fA-F]+)", re.IGNORECASE)
        _re_user    = re.compile(r"user=([^\s|,]+)", re.IGNORECASE)
        _re_host    = re.compile(r"host=([^\s|,]+)", re.IGNORECASE)

        ip_counts:   dict = {}
        user_counts: dict = {}
        host_counts: dict = {}
        eid_counts:  dict = {}
        auth_fails   = 0
        obfuscated   = 0
        session_days: dict = {}

        for eid, level, msg, ts in rows:
            msg = msg or ""
            eid_counts[eid] = eid_counts.get(eid, 0) + 1
            if eid == 193 or (level in ("WARNING", "CRITICAL") and "auth" in msg.lower()):
                auth_fails += 1
            if "obfuscated" in msg.lower():
                obfuscated += 1
            im = _re_ip.search(msg)
            um = _re_user.search(msg)
            hm = _re_host.search(msg)
            if im:
                ip = im.group(1).strip()
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if um:
                u = um.group(1).strip()
                user_counts[u] = user_counts.get(u, 0) + 1
            if hm:
                h = hm.group(1).strip()
                host_counts[h] = host_counts.get(h, 0) + 1
            if ts:
                day = ts[:10]
                session_days[day] = session_days.get(day, 0) + 1

        return jsonify({
            "ok":              True,
            "total_events":    len(rows),
            "auth_failures":   auth_fails,
            "obfuscated_scripts": obfuscated,
            "event_breakdown": [{"event_id": k, "count": v}
                                  for k, v in sorted(eid_counts.items())],
            "top_source_ips":  [{"ip": k, "count": v}
                                  for k, v in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]],
            "top_users":       [{"user": k, "count": v}
                                  for k, v in sorted(user_counts.items(), key=lambda x: -x[1])[:10]],
            "top_source_hosts":[{"host": k, "count": v}
                                  for k, v in sorted(host_counts.items(), key=lambda x: -x[1])[:10]],
            "daily_sessions":  [{"date": k, "count": v}
                                  for k, v in sorted(session_days.items())[-14:]],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
