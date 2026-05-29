"""
File Integrity Monitoring — reads real Windows Security audit events
Event IDs: 4663 (file access/modify/delete), 4656 (handle request), 4660 (delete)
Requires: Object Access auditing enabled in Windows + run as Administrator
"""
import os, re, sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

# Critical files/paths to watch — these are high-value targets
CRITICAL_PATHS = [
    # System files
    r"lsass.exe", r"sam", r"system32", r"ntds.dit", r"hosts",
    r"config.sys", r"boot.ini", r"win.ini", r"autoexec.bat",
    # Registry hives exported
    r"sam.hive", r"security.hive", r"system.hive",
    # Common config files
    r"web.config", r"httpd.conf", r"nginx.conf", r"sshd_config",
    r"passwd", r"shadow", r"sudoers",
    # Executables in sensitive dirs
    r"\\windows\\system32\\", r"\\windows\\syswow64\\",
    r"\\system32\\drivers\\",
    # PowerShell / scripts
    r"\.ps1", r"\.bat", r"\.cmd", r"\.vbs",
]

ACTION_MAP = {
    "%%4416": "READ",      "%%4417": "WRITE",
    "%%4418": "APPEND",    "%%4419": "READ_EA",
    "%%4420": "WRITE_EA",  "%%4421": "EXECUTE",
    "%%4422": "READ_ATTR", "%%4423": "WRITE_ATTR",
    "%%1537": "DELETE",    "%%1538": "READ_CONTROL",
    "%%1539": "WRITE_DAC", "%%1540": "WRITE_OWNER",
    "%%1541": "SYNC",      "%%4432": "ACCESS",
    "1537":   "DELETE",    "4416":   "READ",
    "4417":   "WRITE/MODIFIED",
}

SEVERITY_MAP = {
    "DELETE":        "CRITICAL",
    "WRITE/MODIFIED":"HIGH",
    "MODIFIED":      "HIGH",
    "WRITE":         "HIGH",
    "EXECUTE":       "HIGH",
    "READ":          "MEDIUM",
    "ACCESS":        "MEDIUM",
    "READ_ATTR":     "LOW",
}

def _is_critical(path):
    if not path:
        return False
    path_low = path.lower()
    return any(kw.lower() in path_low for kw in CRITICAL_PATHS)

def _parse_fim_from_security_log(conn, since_hours=24):
    """
    Pull file access events from logs_security table.
    EID 4663 = file access audit, 4660 = object deleted, 4656 = handle request
    """
    c = conn.cursor()
    since = (datetime.now() - timedelta(hours=since_hours)).strftime("%Y-%m-%d %H:%M:%S")
    events = []

    # Check table exists
    c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='logs_security'")
    if not c.fetchone():
        return []

    try:
        c.execute("""
            SELECT timestamp, message, source, level
            FROM logs_security
            WHERE (event_id IN (4663, 4660, 4656, 4670)
                   OR message LIKE '%4663%'
                   OR message LIKE '%Object Name%'
                   OR message LIKE '%File%Access%'
                   OR message LIKE '%lsass%'
                   OR message LIKE '%system32%'
                   OR message LIKE '%.exe%'
                   OR message LIKE '%.dll%'
                   OR message LIKE '%sam%'
                   OR message LIKE '%hosts%'
                   OR message LIKE '%config%')
              AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 500
        """, (since,))
        rows = c.fetchall()
    except Exception:
        rows = []

    for row in rows:
        ts, msg, source, level = row[0], row[1] or "", row[2] or "", row[3] or ""

        # Extract file path
        file_path = ""
        for pattern in [
            r"Object Name[:\s]+([^\n\r]+)",
            r"File Name[:\s]+([^\n\r]+)",
            r"Object Path[:\s]+([^\n\r]+)",
        ]:
            m = re.search(pattern, msg, re.I)
            if m:
                file_path = m.group(1).strip()
                break

        if not file_path:
            # Try to extract any path-like string
            m = re.search(r'[A-Za-z]:\\[^\s\n\r"\']{4,}', msg)
            if m:
                file_path = m.group(0).strip()

        # Extract user
        user = ""
        for pattern in [
            r"Account Name[:\s]+([^\n\r\s]+)",
            r"Subject[^\n]*\n[^\n]*Account Name[:\s]+([^\n\r]+)",
            r"User[:\s]+([A-Za-z0-9_\\-]+)",
        ]:
            m = re.search(pattern, msg, re.I)
            if m:
                user = m.group(1).strip()
                break
        if not user:
            user = source or "UNKNOWN"

        # Extract action
        action = "ACCESS"
        msg_low = msg.lower()
        if "delet" in msg_low or "4660" in msg:
            action = "DELETE"
        elif "write" in msg_low or "modif" in msg_low or "4417" in msg:
            action = "MODIFIED"
        elif "execut" in msg_low or "4421" in msg:
            action = "EXECUTE"
        elif "read" in msg_low or "4416" in msg:
            action = "READ"

        # Check for access rights codes
        for code, mapped in ACTION_MAP.items():
            if code in msg:
                action = mapped
                break

        # Extract hostname from message or source
        host = ""
        m = re.search(r"Workstation Name[:\s]+([^\n\r\s]+)", msg, re.I)
        if m:
            host = m.group(1).strip()
        if not host:
            m = re.search(r"Computer Name[:\s]+([^\n\r\s]+)", msg, re.I)
            if m:
                host = m.group(1).strip()
        if not host:
            try:
                import socket
                host = socket.gethostname()
            except Exception:
                host = "LOCAL"

        # Get just filename
        fname = os.path.basename(file_path) if file_path else ""
        if not fname and file_path:
            fname = file_path.split("\\")[-1].split("/")[-1]

        severity = SEVERITY_MAP.get(action, "LOW")
        is_crit  = _is_critical(file_path) or _is_critical(fname)

        events.append({
            "timestamp": (ts or "")[:19],
            "file":      fname[:40] if fname else (file_path[:40] if file_path else "—"),
            "full_path": file_path[:120],
            "host":      host[:20] or "LOCAL",
            "action":    action,
            "user":      (user[:25] if user else "UNKNOWN"),
            "severity":  severity,
            "critical":  is_crit,
            "message":   msg[:200],
        })

    # Sort: critical files first, then by time
    events.sort(key=lambda x: (not x["critical"], x["timestamp"]), reverse=False)
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events[:100]


def _simulate_fim_from_message_search(conn, since_hours=24):
    """
    Fallback: search ALL log tables for file-related messages
    even when proper audit EIDs aren't present.
    """
    c = conn.cursor()
    since = (datetime.now() - timedelta(hours=since_hours)).strftime("%Y-%m-%d")
    results = []

    tables = ["logs_security", "logs_system", "logs_application"]
    for tbl in tables:
        c.execute(f"SELECT 1 FROM sqlite_master WHERE type='table' AND name='{tbl}'")
        if not c.fetchone():
            continue
        try:
            c.execute(f"""
                SELECT timestamp, level, source, message FROM {tbl}
                WHERE date >= ?
                  AND (message LIKE '%lsass%' OR message LIKE '%system32%'
                    OR message LIKE '%.exe%' OR message LIKE '%.dll%'
                    OR message LIKE '%sam%hive%' OR message LIKE '%ntds%'
                    OR message LIKE '%hosts%file%' OR message LIKE '%modified%'
                    OR message LIKE '%deleted%' OR message LIKE '%file%access%'
                    OR message LIKE '%4663%' OR message LIKE '%4660%')
                ORDER BY timestamp DESC LIMIT 200
            """, (since,))
            for row in c.fetchall():
                ts, level, src, msg = row
                msg = msg or ""
                # Determine action from level/message
                if level in ("CRITICAL", "ERROR") or "delet" in msg.lower():
                    action = "DELETE" if "delet" in msg.lower() else "MODIFIED"
                elif "modif" in msg.lower() or "write" in msg.lower():
                    action = "MODIFIED"
                else:
                    action = "ACCESS"

                # Try to extract a filename
                fname = ""
                m = re.search(r'([A-Za-z0-9_\-]+\.(exe|dll|sys|hive|ini|cfg|conf|bat|ps1|cmd|vbs|log))', msg, re.I)
                if m:
                    fname = m.group(0)

                if not fname:
                    continue

                try:
                    import socket; host = socket.gethostname()
                except Exception:
                    host = "LOCAL"

                results.append({
                    "timestamp": (ts or "")[:19],
                    "file":      fname[:40],
                    "full_path": "",
                    "host":      host[:20],
                    "action":    action,
                    "user":      src[:25] if src else "SYSTEM",
                    "severity":  SEVERITY_MAP.get(action, "LOW"),
                    "critical":  _is_critical(fname),
                    "message":   msg[:200],
                })
        except Exception:
            pass

    results.sort(key=lambda x: x["timestamp"], reverse=True)
    return results[:100]


def get_fim_events(conn, since_hours=24):
    """Main entry — try real audit events first, fall back to message search."""
    events = _parse_fim_from_security_log(conn, since_hours)
    if not events:
        events = _simulate_fim_from_message_search(conn, since_hours)
    return events


def get_fim_summary(events):
    """Summarise FIM events for report."""
    total      = len(events)
    critical   = sum(1 for e in events if e["severity"] == "CRITICAL")
    high       = sum(1 for e in events if e["severity"] == "HIGH")
    by_action  = defaultdict(int)
    by_file    = defaultdict(int)
    for e in events:
        by_action[e["action"]] += 1
        by_file[e["file"]]     += 1
    top_files = sorted(by_file.items(), key=lambda x: -x[1])[:10]
    return {
        "total": total, "critical": critical, "high": high,
        "by_action": dict(by_action),
        "top_files": [{"file": f, "count": c} for f, c in top_files],
        "events": events,
    }
