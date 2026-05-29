"""
core/analysis_engine/sigma_engine.py
======================================
Native Sigma-compatible detection engine.

Zircolite is a standalone CLI tool (not a Python package) so we implement
Sigma matching natively in Python against the logs_sysmon table.

Sigma rules are defined as Python dicts matching the Sigma spec:
  - detection.selection: field conditions
  - detection.condition: "selection" or "selection and not filter"
  - logsource.category: process_creation | network_connection | file_event | registry_event

Results are written to sigma_hits table and AlertBus.

Public API:
    from core.analysis_engine.sigma_engine import run_sigma_detection, get_sigma_stats
    hits = run_sigma_detection(since_iso="2025-01-01")
"""

from datetime import datetime
from typing import Optional
from utils.logger import get_logger

log = get_logger("sigma_engine")


# ── Built-in Sigma rules ──────────────────────────────────────────────────────

SIGMA_RULES = [
    {
        "id":       "SIGMA_OFFICE_SPAWN_SHELL",
        "name":     "Office Application Spawning Shell Interpreter",
        "severity": "CRITICAL",
        "mitre":    "T1566.001",
        "category": "process_creation",
        "eid":      1,
        "logic": {
            "parent_field":  "sysmon_parent_image",
            "parent_values": ["winword.exe", "excel.exe", "powerpnt.exe",
                              "outlook.exe", "msaccess.exe", "mspub.exe"],
            "child_field":   "sysmon_image",
            "child_values":  ["powershell.exe", "pwsh.exe", "cmd.exe",
                              "wscript.exe", "cscript.exe", "mshta.exe",
                              "regsvr32.exe", "rundll32.exe", "certutil.exe"],
        },
        "description": (
            "An Office application (Word, Excel, Outlook) spawned a shell interpreter. "
            "This is the primary indicator of a malicious macro or exploit document. "
            "MITRE ATT&CK: T1566.001 (Spearphishing Attachment)."
        ),
    },
    {
        "id":       "SIGMA_ENCODED_POWERSHELL",
        "name":     "Suspicious Encoded PowerShell Command",
        "severity": "HIGH",
        "mitre":    "T1027",
        "category": "process_creation",
        "eid":      1,
        "logic": {
            "cmd_field":    "sysmon_command_line",
            "cmd_keywords": ["-encodedcommand", "-enc ", " -e "],
        },
        "description": (
            "PowerShell ran with an encoded command argument — "
            "a common obfuscation technique to hide malicious payloads."
        ),
    },
    {
        "id":       "SIGMA_REGISTRY_RUN_PERSIST",
        "name":     "Registry Run Key Persistence",
        "severity": "HIGH",
        "mitre":    "T1547.001",
        "category": "registry_event",
        "eid":      13,
        "logic": {
            "key_field":    "sysmon_target_object",
            "key_keywords": [
                "currentversion\\run",
                "currentversion\\runonce",
                "userinit",
                "winlogon\\shell",
            ],
        },
        "description": (
            "A registry Run or RunOnce key was modified — "
            "the most common persistence mechanism used by malware."
        ),
    },
    {
        "id":       "SIGMA_SUSPICIOUS_FILE_DROP",
        "name":     "Executable Dropped in User-Writable Directory",
        "severity": "HIGH",
        "mitre":    "T1105",
        "category": "file_event",
        "eid":      11,
        "logic": {
            "path_field":    "sysmon_target_file",
            "path_keywords": ["\\downloads\\", "\\temp\\", "\\appdata\\"],
            "ext_keywords":  [".exe", ".dll", ".ps1", ".vbs", ".bat", ".scr"],
        },
        "description": (
            "An executable or script was written to a user-writable directory. "
            "Indicates ingress tool transfer or dropper activity."
        ),
    },
    {
        "id":       "SIGMA_NET_SHELL_EXTERNAL",
        "name":     "Shell Process Connecting to External IP",
        "severity": "HIGH",
        "mitre":    "T1071",
        "category": "network_connection",
        "eid":      3,
        "logic": {
            "image_field":  "sysmon_image",
            "image_values": ["powershell.exe", "pwsh.exe", "cmd.exe",
                             "wscript.exe", "certutil.exe", "mshta.exe"],
            "exclude_ips":  ["10.", "192.168.", "172.1", "172.2", "172.3",
                             "127.", "::1"],
        },
        "description": (
            "A shell or scripting process initiated an outbound connection "
            "to a non-private IP address — likely C2 or payload download."
        ),
    },
    {
        "id":       "SIGMA_CERTUTIL_DOWNLOAD",
        "name":     "CertUtil Used for Download (LOLBin Abuse)",
        "severity": "HIGH",
        "mitre":    "T1218.004",
        "category": "process_creation",
        "eid":      1,
        "logic": {
            "cmd_field":    "sysmon_command_line",
            "cmd_keywords": ["certutil", "-urlcache", "-decode"],
        },
        "description": (
            "CertUtil was used with download or decode arguments — "
            "a classic Living-Off-the-Land Binary (LOLBin) technique."
        ),
    },
    {
        "id":       "SIGMA_SCHTASKS_PERSIST",
        "name":     "Scheduled Task Created via Schtasks",
        "severity": "MEDIUM",
        "mitre":    "T1053.005",
        "category": "process_creation",
        "eid":      1,
        "logic": {
            "cmd_field":    "sysmon_command_line",
            "cmd_keywords": ["schtasks", "/create"],
        },
        "description": (
            "Schtasks.exe was used to create a scheduled task — "
            "a common persistence and execution technique."
        ),
    },
    {
        "id":       "SIGMA_UNSIGNED_TEMP_EXE",
        "name":     "Unsigned Executable Running from Temp Location",
        "severity": "HIGH",
        "mitre":    "T1204.002",
        "category": "process_creation",
        "eid":      1,
        "logic": {
            "signed_field":  "sysmon_signed",
            "signed_value":  0,  # false = unsigned
            "path_field":    "sysmon_image",
            "path_keywords": ["\\temp\\", "\\downloads\\", "\\appdata\\"],
        },
        "description": (
            "An unsigned executable ran from a temporary or download location. "
            "Legitimate software is almost always signed."
        ),
    },
]


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_sigma_table():
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sigma_hits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT,
                rule_id     TEXT,
                rule_name   TEXT,
                severity    TEXT,
                mitre       TEXT,
                category    TEXT,
                sysmon_eid  INTEGER,
                timestamp   TEXT,
                detail      TEXT,
                row_id      INTEGER
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sigma_time ON sigma_hits(detected_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sigma_rule ON sigma_hits(rule_id)")
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"sigma_hits table init: {e}")


def _table_exists(conn, name: str) -> bool:
    conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return bool(conn.fetchone() if hasattr(conn, "fetchone") else True)


def _push_sigma_alert(rule: dict, detail: str, ts: str):
    try:
        from core.pipeline.alert_bus import get_alert_bus
        get_alert_bus().push({
            "type":        "sigma_hit",
            "severity":    rule["severity"],
            "category":    "malware",
            "title":       f"Sigma: {rule['name']}",
            "description": f"{rule['description']} — {detail}",
            "risk_score":  90 if rule["severity"] == "CRITICAL" else 70,
            "source":      "SigmaEngine",
            "mitre":       rule["mitre"],
            "rule_id":     rule["id"],
        })
    except Exception:
        pass


# ── Rule matching ─────────────────────────────────────────────────────────────

def _match_rule(c, rule: dict, since: str) -> list[dict]:
    """Run one Sigma rule against logs_sysmon. Returns list of hit dicts."""
    logic  = rule["logic"]
    eid    = rule["eid"]
    hits   = []

    try:
        # Build WHERE clauses based on logic type
        where_parts = [f"event_id = {eid}", f"timestamp >= '{since}'"]
        row_fields  = "id, timestamp, sysmon_image, sysmon_command_line, sysmon_parent_image, sysmon_target_file, sysmon_target_object, sysmon_dest_ip, sysmon_signed"

        if "parent_field" in logic and "child_field" in logic:
            parent_conds = " OR ".join(
                f"LOWER(COALESCE({logic['parent_field']},'')) LIKE '%{v}%'"
                for v in logic["parent_values"]
            )
            child_conds  = " OR ".join(
                f"LOWER(COALESCE({logic['child_field']},'')) LIKE '%{v}%'"
                for v in logic["child_values"]
            )
            where_parts.append(f"({parent_conds})")
            where_parts.append(f"({child_conds})")

        elif "cmd_field" in logic and "cmd_keywords" in logic:
            kw_conds = " OR ".join(
                f"LOWER(COALESCE({logic['cmd_field']},'')) LIKE '%{k}%'"
                for k in logic["cmd_keywords"]
            )
            where_parts.append(f"({kw_conds})")

        elif "key_field" in logic and "key_keywords" in logic:
            kw_conds = " OR ".join(
                f"LOWER(COALESCE({logic['key_field']},'')) LIKE '%{k}%'"
                for k in logic["key_keywords"]
            )
            where_parts.append(f"({kw_conds})")

        elif "path_field" in logic and "path_keywords" in logic:
            path_conds = " OR ".join(
                f"LOWER(COALESCE({logic['path_field']},'')) LIKE '%{k}%'"
                for k in logic["path_keywords"]
            )
            ext_conds  = " OR ".join(
                f"LOWER(COALESCE({logic['path_field']},'')) LIKE '%{k}'"
                for k in logic.get("ext_keywords", [])
            )
            where_parts.append(f"({path_conds})")
            if ext_conds:
                where_parts.append(f"({ext_conds})")

        elif "image_field" in logic and "image_values" in logic:
            img_conds = " OR ".join(
                f"LOWER(COALESCE({logic['image_field']},'')) LIKE '%{v}%'"
                for v in logic["image_values"]
            )
            where_parts.append(f"({img_conds})")
            if "exclude_ips" in logic:
                excl = " AND ".join(
                    f"COALESCE(sysmon_dest_ip,'') NOT LIKE '{p}%'"
                    for p in logic["exclude_ips"]
                )
                where_parts.append(f"({excl})")

        elif "signed_field" in logic:
            where_parts.append(f"{logic['signed_field']} = {logic['signed_value']}")
            if "path_keywords" in logic:
                pk = " OR ".join(
                    f"LOWER(COALESCE({logic['path_field']},'')) LIKE '%{k}%'"
                    for k in logic["path_keywords"]
                )
                where_parts.append(f"({pk})")

        sql = f"""
            SELECT {row_fields}
            FROM logs_sysmon
            WHERE {' AND '.join(where_parts)}
            ORDER BY timestamp DESC LIMIT 50
        """
        c.execute(sql)
        rows = c.fetchall()

        for row in rows:
            row_id   = row[0]
            ts       = str(row[1] or "")
            image    = str(row[2] or "")
            cmd      = str(row[3] or "")[:100]
            parent   = str(row[4] or "")
            tfile    = str(row[5] or "")
            tobj     = str(row[6] or "")
            dest_ip  = str(row[7] or "")

            detail = (
                f"Image: {image.rsplit(chr(92),1)[-1]}"
                if image else
                f"File: {tfile.rsplit(chr(92),1)[-1]}"
                if tfile else
                f"Key: {tobj[-60:]}"
                if tobj else
                f"CMD: {cmd[:60]}"
                if cmd else
                f"DestIP: {dest_ip}"
            )

            hits.append({
                "rule_id":     rule["id"],
                "rule_name":   rule["name"],
                "severity":    rule["severity"],
                "mitre":       rule["mitre"],
                "category":    rule["category"],
                "sysmon_eid":  eid,
                "timestamp":   ts,
                "detail":      detail,
                "row_id":      row_id,
                "description": rule["description"],
            })

    except Exception as e:
        log.debug(f"sigma rule {rule['id']} error: {e}")

    return hits


# ── Main detection function ───────────────────────────────────────────────────

def run_sigma_detection(since_iso: Optional[str] = None) -> list[dict]:
    """
    Run all built-in Sigma rules against logs_sysmon.
    Returns list of hit dicts (deduplicated by rule_id+timestamp).
    Also writes new hits to sigma_hits table.
    """
    if since_iso is None:
        since_iso = (datetime.now().replace(
            hour=0, minute=0, second=0
        )).isoformat()[:10] + " 00:00:00"

    _ensure_sigma_table()

    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()

        # Check logs_sysmon exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
        if not c.fetchone():
            conn.close()
            return []

        all_hits = []
        seen     = set()  # (rule_id, row_id) dedup

        for rule in SIGMA_RULES:
            rule_hits = _match_rule(c, rule, since_iso)
            for h in rule_hits:
                key = (h["rule_id"], h.get("row_id", h["timestamp"]))
                if key in seen:
                    continue
                seen.add(key)
                all_hits.append(h)

                # Store in sigma_hits table
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO sigma_hits
                            (detected_at, rule_id, rule_name, severity, mitre,
                             category, sysmon_eid, timestamp, detail, row_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                    """, (
                        datetime.now().isoformat(),
                        h["rule_id"], h["rule_name"], h["severity"], h["mitre"],
                        h["category"], h["sysmon_eid"], h["timestamp"],
                        h["detail"], h.get("row_id"),
                    ))
                except Exception:
                    pass

                # Alert for new CRITICAL/HIGH hits
                _push_sigma_alert(rule, h["detail"], h["timestamp"])

        conn.commit()
        conn.close()

        # Sort: CRITICAL first
        SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_hits.sort(key=lambda h: (SEV.get(h["severity"], 9), h["timestamp"]))

        if all_hits:
            log.info(f"[Sigma] {len(all_hits)} hits from {len(SIGMA_RULES)} rules")

        return all_hits

    except Exception as e:
        log.error(f"run_sigma_detection error: {e}")
        return []


def get_sigma_stats(since_iso: str) -> dict:
    """Return sigma stats for the perform_analysis report."""
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()

        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sigma_hits'")
        if not c.fetchone():
            conn.close()
            return {"available": False, "total": 0, "hits": []}

        c.execute(
            "SELECT COUNT(*) FROM sigma_hits WHERE detected_at >= ?", (since_iso,)
        )
        total = c.fetchone()[0] or 0

        c.execute("""
            SELECT rule_id, rule_name, severity, mitre, category,
                   sysmon_eid, timestamp, detail
            FROM sigma_hits
            WHERE detected_at >= ?
            ORDER BY detected_at DESC LIMIT 50
        """, (since_iso,))
        hits = [
            {
                "rule":      r[0], "name": r[1], "severity": r[2],
                "mitre":     r[3], "category": r[4], "sysmon_eid": r[5],
                "timestamp": r[6], "detail": r[7],
            }
            for r in c.fetchall()
        ]
        conn.close()
        return {"available": True, "total": total, "hits": hits}
    except Exception as e:
        return {"available": False, "total": 0, "hits": [], "error": str(e)}
