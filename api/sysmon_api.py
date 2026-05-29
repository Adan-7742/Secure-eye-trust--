"""
api/sysmon_api.py
==================
Flask blueprint for Sysmon event data endpoints.

Endpoints:
    GET /api/sysmon/processes        Recent process creations  (EID 1)
    GET /api/sysmon/process-tree/<pid>  Parent-child tree for a PID
    GET /api/sysmon/network          Recent network connections (EID 3)
    GET /api/sysmon/file-drops       Files in suspicious locations (EID 11)
    GET /api/sysmon/registry         Registry persistence changes (EID 13)
    GET /api/sysmon/dns              Recent DNS queries (EID 22)
    GET /api/sysmon/stats            Summary counts for dashboard widgets

Registration — add to app.py:
    from api.sysmon_api import sysmon_bp
    app.register_blueprint(sysmon_bp)
"""

from __future__ import annotations

import json
from datetime import datetime
from flask import Blueprint, jsonify, request
from utils.logger import get_logger

log = get_logger("sysmon_api")
sysmon_bp = Blueprint("sysmon", __name__)

# ── Suspicious-path heuristic (mirrors collector logic) ───────────────────────

_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\downloads\\", "\\temp\\", "\\tmp\\",
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
    "\\public\\", "\\programdata\\",
)

_SUSPICIOUS_EXTENSIONS = (".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".scr", ".hta")

_REGISTRY_PERSISTENCE_KEYS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "userinit",
    "winlogon",
)

_SHELL_PROCESSES = (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "certutil.exe", "regsvr32.exe", "rundll32.exe",
)


def _get_conn():
    from database.db import get_conn
    return get_conn()


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a plain dict."""
    try:
        return dict(row)
    except Exception:
        return {}


def _is_suspicious_file(filename: str | None) -> bool:
    if not filename:
        return False
    fl = filename.lower()
    return (
        any(p in fl for p in _SUSPICIOUS_PATH_FRAGMENTS) and
        any(fl.endswith(e) for e in _SUSPICIOUS_EXTENSIONS)
    )


def _is_persistence_key(target_object: str | None) -> bool:
    if not target_object:
        return False
    tl = target_object.lower()
    return any(k in tl for k in _REGISTRY_PERSISTENCE_KEYS)


# ── Helper: check table exists ────────────────────────────────────────────────

def _sysmon_table_exists(conn) -> bool:
    try:
        conn.execute("SELECT 1 FROM logs_sysmon LIMIT 1")
        return True
    except Exception:
        return False


# ── GET /api/sysmon/processes ─────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/processes")
def sysmon_processes():
    """
    Recent process creations (Sysmon EID 1).
    Query params:
        limit     int  default 100
        hours     int  default 24
        suspicious bool  if 'true', filter to Office→shell spawns only
    """
    try:
        limit     = min(int(request.args.get("limit", 100)), 500)
        hours     = min(int(request.args.get("hours", 24)), 168)
        suspicious_only = request.args.get("suspicious", "false").lower() == "true"

        conn = _get_conn()
        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"processes": [], "total": 0, "sysmon_installed": False})

        sql = """
            SELECT id, timestamp, level, command_line, parent_image,
                   process_id, process_guid, hashes, message
            FROM logs_sysmon
            WHERE event_id = 1
              AND timestamp >= datetime('now', ? || ' hours')
        """
        params: list = [f"-{hours}"]

        if suspicious_only:
            sql += """
              AND (
                LOWER(parent_image) LIKE '%winword.exe%'
                OR LOWER(parent_image) LIKE '%excel.exe%'
                OR LOWER(parent_image) LIKE '%powerpnt.exe%'
                OR LOWER(parent_image) LIKE '%outlook.exe%'
              )
              AND (
                LOWER(message) LIKE '%powershell%'
                OR LOWER(message) LIKE '%cmd.exe%'
                OR LOWER(message) LIKE '%wscript%'
                OR LOWER(message) LIKE '%mshta%'
              )
            """

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        c = conn.cursor()
        c.execute(sql, params)
        rows = [_row_to_dict(r) for r in c.fetchall()]

        # Annotate each row with a suspicion flag
        for row in rows:
            parent = (row.get("parent_image") or "").lower().rsplit("\\", 1)[-1]
            cmd    = (row.get("command_line") or "").lower()
            row["suspicious"] = (
                parent in {p.replace(".exe", "") for p in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")}
                or any(s in cmd for s in _SHELL_PROCESSES)
            )

        conn.close()
        return jsonify({"processes": rows, "total": len(rows), "sysmon_installed": True})

    except Exception as e:
        log.error(f"sysmon_processes error: {e}")
        return jsonify({"error": str(e), "processes": []}), 500


# ── GET /api/sysmon/process-tree/<pid> ────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/process-tree/<int:pid>")
def sysmon_process_tree(pid: int):
    """
    Build a parent-child process tree for a given PID.
    Returns up to 3 levels: grandparent → parent → children.
    Query params:
        hours int default 24
    """
    try:
        hours = min(int(request.args.get("hours", 24)), 168)
        conn  = _get_conn()

        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"tree": None, "sysmon_installed": False})

        c = conn.cursor()

        def _fetch_proc(pid_val):
            c.execute("""
                SELECT id, timestamp, process_id, process_guid,
                       command_line, parent_image, hashes, level, message
                FROM logs_sysmon
                WHERE event_id = 1
                  AND process_id = ?
                  AND timestamp >= datetime('now', ? || ' hours')
                ORDER BY timestamp DESC LIMIT 1
            """, (pid_val, f"-{hours}"))
            row = c.fetchone()
            return _row_to_dict(row) if row else None

        def _fetch_children(proc_guid_val):
            if not proc_guid_val:
                return []
            # There's no parent_guid column — approximate via parent_image + time window
            return []

        # Root: requested PID
        root = _fetch_proc(pid)
        if not root:
            conn.close()
            return jsonify({"tree": None, "pid": pid, "found": False})

        tree = dict(root)
        tree["children"] = _fetch_children(root.get("process_guid"))

        # Attempt to fetch children by looking at processes created shortly after root
        # Fixed: Properly escape backslashes in the LIKE pattern
        command = root.get('command_line') or ''
        command_parts = command.rsplit('\\', 1)
        search_term = command_parts[-1].lower()[:20] if command_parts else ''
        
        c.execute("""
            SELECT id, timestamp, process_id, process_guid,
                   command_line, parent_image, hashes, level
            FROM logs_sysmon
            WHERE event_id = 1
              AND LOWER(parent_image) LIKE ?
              AND timestamp >= ?
              AND timestamp <= datetime(?, '+60 seconds')
            ORDER BY timestamp ASC LIMIT 20
        """, (
            f"%{search_term}%",
            root.get("timestamp", ""),
            root.get("timestamp", ""),
        ))
        children_rows = [_row_to_dict(r) for r in c.fetchall()]
        tree["children"] = children_rows

        conn.close()
        return jsonify({"tree": tree, "pid": pid, "found": True})

    except Exception as e:
        log.error(f"sysmon_process_tree error: {e}")
        return jsonify({"error": str(e), "tree": None}), 500


# ── GET /api/sysmon/network ───────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/network")
def sysmon_network():
    """
    Recent network connections (Sysmon EID 3).
    Query params:
        limit       int   default 100
        hours       int   default 6
        external    bool  if 'true', show only non-RFC1918 destinations
    """
    try:
        limit    = min(int(request.args.get("limit", 100)), 500)
        hours    = min(int(request.args.get("hours", 6)), 168)
        ext_only = request.args.get("external", "false").lower() == "true"

        conn = _get_conn()
        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"connections": [], "total": 0, "sysmon_installed": False})

        sql = """
            SELECT id, timestamp, source_ip, dest_ip, source_port, dest_port,
                   protocol, process_guid, message
            FROM logs_sysmon
            WHERE event_id = 3
              AND timestamp >= datetime('now', ? || ' hours')
        """
        params: list = [f"-{hours}"]

        if ext_only:
            sql += """
              AND dest_ip IS NOT NULL
              AND dest_ip NOT LIKE '10.%'
              AND dest_ip NOT LIKE '192.168.%'
              AND dest_ip NOT LIKE '172.1%'
              AND dest_ip NOT LIKE '172.2%'
              AND dest_ip NOT LIKE '172.3%'
              AND dest_ip != '127.0.0.1'
              AND dest_ip != '::1'
            """

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        c = conn.cursor()
        c.execute(sql, params)
        rows = [_row_to_dict(r) for r in c.fetchall()]
        conn.close()

        return jsonify({"connections": rows, "total": len(rows), "sysmon_installed": True})

    except Exception as e:
        log.error(f"sysmon_network error: {e}")
        return jsonify({"error": str(e), "connections": []}), 500


# ── GET /api/sysmon/file-drops ────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/file-drops")
def sysmon_file_drops():
    """
    Files created in suspicious locations (Sysmon EID 11).
    Filters to Downloads/Temp/AppData with executable extensions.
    Query params:
        limit   int  default 100
        hours   int  default 24
        all     bool if 'true', return all EID 11 events (no path filter)
    """
    try:
        limit   = min(int(request.args.get("limit", 100)), 500)
        hours   = min(int(request.args.get("hours", 24)), 168)
        show_all = request.args.get("all", "false").lower() == "true"

        conn = _get_conn()
        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"file_drops": [], "total": 0, "sysmon_installed": False})

        if show_all:
            sql = """
                SELECT id, timestamp, target_filename, process_guid, level, message
                FROM logs_sysmon
                WHERE event_id = 11
                  AND timestamp >= datetime('now', ? || ' hours')
                ORDER BY timestamp DESC LIMIT ?
            """
            params: list = [f"-{hours}", limit]
        else:
            sql = """
                SELECT id, timestamp, target_filename, process_guid, level, message
                FROM logs_sysmon
                WHERE event_id = 11
                  AND timestamp >= datetime('now', ? || ' hours')
                  AND (
                      LOWER(target_filename) LIKE '%\\downloads\\%'
                      OR LOWER(target_filename) LIKE '%\\temp\\%'
                      OR LOWER(target_filename) LIKE '%\\tmp\\%'
                      OR LOWER(target_filename) LIKE '%appdata%'
                      OR LOWER(target_filename) LIKE '%\\public\\%'
                      OR LOWER(target_filename) LIKE '%\\programdata\\%'
                  )
                  AND (
                      LOWER(target_filename) LIKE '%.exe'
                      OR LOWER(target_filename) LIKE '%.dll'
                      OR LOWER(target_filename) LIKE '%.ps1'
                      OR LOWER(target_filename) LIKE '%.vbs'
                      OR LOWER(target_filename) LIKE '%.js'
                      OR LOWER(target_filename) LIKE '%.bat'
                      OR LOWER(target_filename) LIKE '%.scr'
                      OR LOWER(target_filename) LIKE '%.hta'
                  )
                ORDER BY timestamp DESC LIMIT ?
            """
            params = [f"-{hours}", limit]

        c = conn.cursor()
        c.execute(sql, params)
        rows = [_row_to_dict(r) for r in c.fetchall()]

        # Annotate suspicion level
        for row in rows:
            fn = row.get("target_filename") or ""
            row["suspicious"]  = _is_suspicious_file(fn)
            row["filename_only"] = fn.rsplit("\\", 1)[-1] if "\\" in fn else fn

        conn.close()
        return jsonify({"file_drops": rows, "total": len(rows), "sysmon_installed": True})

    except Exception as e:
        log.error(f"sysmon_file_drops error: {e}")
        return jsonify({"error": str(e), "file_drops": []}), 500


# ── GET /api/sysmon/registry ──────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/registry")
def sysmon_registry():
    """
    Registry persistence changes (Sysmon EID 13).
    Filters to Run/RunOnce/Userinit/Winlogon keys by default.
    Query params:
        limit       int  default 100
        hours       int  default 24
        all         bool if 'true', return all EID 13 events
    """
    try:
        limit    = min(int(request.args.get("limit", 100)), 500)
        hours    = min(int(request.args.get("hours", 24)), 168)
        show_all = request.args.get("all", "false").lower() == "true"

        conn = _get_conn()
        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"registry_changes": [], "total": 0, "sysmon_installed": False})

        if show_all:
            sql = """
                SELECT id, timestamp, target_object, process_guid, level, message
                FROM logs_sysmon
                WHERE event_id = 13
                  AND timestamp >= datetime('now', ? || ' hours')
                ORDER BY timestamp DESC LIMIT ?
            """
            params: list = [f"-{hours}", limit]
        else:
            sql = """
                SELECT id, timestamp, target_object, process_guid, level, message
                FROM logs_sysmon
                WHERE event_id = 13
                  AND timestamp >= datetime('now', ? || ' hours')
                  AND (
                      LOWER(target_object) LIKE '%\\currentversion\\run%'
                      OR LOWER(target_object) LIKE '%\\currentversion\\runonce%'
                      OR LOWER(target_object) LIKE '%userinit%'
                      OR LOWER(target_object) LIKE '%winlogon%'
                      OR LOWER(target_object) LIKE '%\\environment%'
                  )
                ORDER BY timestamp DESC LIMIT ?
            """
            params = [f"-{hours}", limit]

        c = conn.cursor()
        c.execute(sql, params)
        rows = [_row_to_dict(r) for r in c.fetchall()]

        for row in rows:
            row["is_persistence_key"] = _is_persistence_key(row.get("target_object"))

        conn.close()
        return jsonify({
            "registry_changes": rows,
            "total": len(rows),
            "sysmon_installed": True,
        })

    except Exception as e:
        log.error(f"sysmon_registry error: {e}")
        return jsonify({"error": str(e), "registry_changes": []}), 500


# ── GET /api/sysmon/dns ───────────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/dns")
def sysmon_dns():
    """
    Recent DNS queries (Sysmon EID 22).
    Query params:
        limit int default 100
        hours int default 6
    """
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        hours = min(int(request.args.get("hours", 6)), 168)

        conn = _get_conn()
        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({"dns_queries": [], "total": 0, "sysmon_installed": False})

        c = conn.cursor()
        c.execute("""
            SELECT id, timestamp, query_name, process_guid, level, message
            FROM logs_sysmon
            WHERE event_id = 22
              AND timestamp >= datetime('now', ? || ' hours')
            ORDER BY timestamp DESC LIMIT ?
        """, (f"-{hours}", limit))
        rows = [_row_to_dict(r) for r in c.fetchall()]
        conn.close()

        return jsonify({"dns_queries": rows, "total": len(rows), "sysmon_installed": True})

    except Exception as e:
        log.error(f"sysmon_dns error: {e}")
        return jsonify({"error": str(e), "dns_queries": []}), 500


# ── GET /api/sysmon/stats ─────────────────────────────────────────────────────

@sysmon_bp.route("/api/sysmon/stats")
def sysmon_stats():
    """
    Summary counts for the dashboard Sysmon widgets.
    Returns counts per EID for the last 24 hours,
    plus suspicious-file and persistence-registry counts.
    """
    try:
        conn = _get_conn()

        if not _sysmon_table_exists(conn):
            conn.close()
            return jsonify({
                "sysmon_installed": False,
                "stats": {},
                "message": "Sysmon not installed or logs_sysmon table missing.",
            })

        c = conn.cursor()

        stats: dict = {
            "sysmon_installed": True,
            "window_hours":     24,
        }

        # Counts per EID
        for eid, label in [(1, "process_creates"), (3, "network_connections"),
                            (11, "file_creates"), (13, "registry_sets"), (22, "dns_queries")]:
            try:
                c.execute("""
                    SELECT COUNT(*) FROM logs_sysmon
                    WHERE event_id = ?
                      AND timestamp >= datetime('now', '-24 hours')
                """, (eid,))
                stats[label] = c.fetchone()[0] or 0
            except Exception:
                stats[label] = 0

        # Suspicious file drops (EID 11 with bad path+ext)
        try:
            c.execute("""
                SELECT COUNT(*) FROM logs_sysmon
                WHERE event_id = 11
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                      LOWER(target_filename) LIKE '%\\downloads\\%'
                      OR LOWER(target_filename) LIKE '%\\temp\\%'
                      OR LOWER(target_filename) LIKE '%appdata%'
                  )
                  AND (
                      LOWER(target_filename) LIKE '%.exe'
                      OR LOWER(target_filename) LIKE '%.dll'
                      OR LOWER(target_filename) LIKE '%.ps1'
                      OR LOWER(target_filename) LIKE '%.vbs'
                      OR LOWER(target_filename) LIKE '%.bat'
                  )
            """)
            stats["suspicious_file_drops"] = c.fetchone()[0] or 0
        except Exception:
            stats["suspicious_file_drops"] = 0

        # Registry persistence keys
        try:
            c.execute("""
                SELECT COUNT(*) FROM logs_sysmon
                WHERE event_id = 13
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                      LOWER(target_object) LIKE '%\\currentversion\\run%'
                      OR LOWER(target_object) LIKE '%userinit%'
                      OR LOWER(target_object) LIKE '%winlogon%'
                  )
            """)
            stats["persistence_registry_hits"] = c.fetchone()[0] or 0
        except Exception:
            stats["persistence_registry_hits"] = 0

        # Office → shell spawns (Chain 9 trigger)
        try:
            c.execute("""
                SELECT COUNT(*) FROM logs_sysmon
                WHERE event_id = 1
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                      LOWER(parent_image) LIKE '%winword.exe%'
                      OR LOWER(parent_image) LIKE '%excel.exe%'
                      OR LOWER(parent_image) LIKE '%powerpnt.exe%'
                      OR LOWER(parent_image) LIKE '%outlook.exe%'
                  )
                  AND (
                      LOWER(message) LIKE '%powershell%'
                      OR LOWER(message) LIKE '%cmd.exe%'
                      OR LOWER(message) LIKE '%wscript%'
                  )
            """)
            stats["office_shell_spawns"] = c.fetchone()[0] or 0
        except Exception:
            stats["office_shell_spawns"] = 0

        # Total events last 24h
        try:
            c.execute("""
                SELECT COUNT(*) FROM logs_sysmon
                WHERE timestamp >= datetime('now', '-24 hours')
            """)
            stats["total_24h"] = c.fetchone()[0] or 0
        except Exception:
            stats["total_24h"] = 0

        # Latest event timestamp
        try:
            c.execute("SELECT MAX(timestamp) FROM logs_sysmon")
            stats["latest_event"] = c.fetchone()[0] or None
        except Exception:
            stats["latest_event"] = None

        conn.close()
        return jsonify(stats)

    except Exception as e:
        log.error(f"sysmon_stats error: {e}")
        return jsonify({"error": str(e), "sysmon_installed": False}), 500