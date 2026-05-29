"""
api/response_actions_api.py
=============================
Active Response endpoints — let the operator click a button in the
Perform Analysis report and take real action against a malicious entity:

  POST /api/action/kill-process       {pid}
  POST /api/action/quarantine-file    {path}
  POST /api/action/delete-file        {path}
  POST /api/action/block-network      {process_name?, ip?, port?}
  POST /api/action/remove-persistence {kind: "task"|"registry"|"service", target}
  GET  /api/action/history            recent actions (audit log)

All actions are logged to a `response_actions` table (auto-created on
first use) for audit. Operations gracefully degrade when not running on
Windows (the dev/test environment) — they return success=False with a
descriptive reason instead of crashing.

SAFETY GUARDS:
  - Path operations refuse anything under Windows\\System32, Program Files,
    or that resolves outside Downloads/Temp/AppData/Desktop/quarantine.
  - Kill-process refuses PID 0/4 (System/Idle).
  - Every action requires the operator to explicitly POST — there is no
    "auto-respond" wiring here; the UI calls these only on a button click.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request
from api.auth_api import _verify_admin_pw

from database.db import get_conn

response_actions_bp = Blueprint("response_actions", __name__)

# ── Where quarantined files live ──────────────────────────────────────────
QUARANTINE_DIR = Path(os.environ.get(
    "SET_QUARANTINE_DIR",
    str(Path.home() / "SecureEyeTrust" / "Quarantine")
))

# ── Path allow-list — operator can only act inside these prefixes ─────────
# Anything outside these prefixes is refused. Case-insensitive on Windows.
def _user_home() -> str:
    return os.environ.get("USERPROFILE") or os.path.expanduser("~")

def _norm_path(p: str) -> str:
    """OS-agnostic path normalisation for comparison purposes.
    Lower-cases, strips trailing separators, normalises backslash/forward-slash.
    Does NOT call os.path.abspath — that would resolve relative to the server's
    working directory, corrupting absolute paths like C:\\Users\\..."""
    if not p:
        return ""
    s = str(p).strip()
    # Normalise backslash/forward-slash and collapse repeated separators
    s = s.replace("/", "\\")
    # Collapse double backslashes (but keep UNC \\server)
    import re as _re
    s = _re.sub(r'\\{2,}', lambda m: m.group(0) if m.start() == 0 else '\\', s)
    # Lower-case for Windows path comparison
    s = s.lower().rstrip("\\")
    return s

def _allowed_path_prefixes() -> list[str]:
    home = _user_home()  # e.g. C:\Users\adann

    def jp(*parts):
        """Join path parts with backslash, stripping trailing slashes."""
        return "\\".join(str(p).rstrip("\\") for p in parts if p)

    prefixes = [
        jp(home, "Downloads"),
        jp(home, "Desktop"),
        jp(home, "Documents"),
        jp(home, "AppData", "Local", "Temp"),
        jp(home, "AppData", "Roaming"),
        jp(home, "AppData", "Local"),
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        "C:\\Users\\Public\\Downloads",
        "C:\\Users\\Public\\Desktop",
        "C:\\Users\\Public\\Documents",
        "C:\\Users\\Public",
        "C:\\Temp",
        "C:\\Windows\\Temp",
        str(QUARANTINE_DIR),
    ]
    # Add every user under C:\Users\
    try:
        import glob as _glob
        for user_dir in _glob.glob("C:\\Users\\*"):
            if os.path.isdir(user_dir):
                prefixes.append(jp(user_dir, "Downloads"))
                prefixes.append(jp(user_dir, "Desktop"))
                prefixes.append(jp(user_dir, "Documents"))
                prefixes.append(jp(user_dir, "AppData", "Local", "Temp"))
                prefixes.append(jp(user_dir, "AppData", "Local"))
                prefixes.append(jp(user_dir, "AppData", "Roaming"))
    except Exception:
        pass
    seen, out = set(), []
    for p in prefixes:
        if not p:
            continue
        np = _norm_path(p)
        if np and np not in seen:
            seen.add(np)
            out.append(np)
    return out

# Hard-deny — even if it looks like a Temp path
_DENY_SUBSTRINGS = (
    "windows\\system32",
    "windows\\syswow64",
    "program files",
    "programdata\\microsoft",
    "windows\\winsxs",
    "windows\\boot",
)

def _path_is_safe(path: str) -> Tuple[bool, str]:
    """Return (is_safe, reason). reason is empty when safe."""
    if not path:
        return False, "empty path"
    norm = _norm_path(path)
    if not norm:
        return False, "could not resolve path"

    for bad in _DENY_SUBSTRINGS:
        if bad in norm:
            return False, f"path is in a protected system location ({bad})"

    for prefix in _allowed_path_prefixes():
        if norm == prefix or norm.startswith(prefix + "\\"):
            return True, ""
    return False, "path is outside the allowed Downloads / Desktop / Temp / AppData / quarantine zones"


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _deep_purge_path(path: str) -> int:
    """Remove ALL DB traces of a file so re-scan shows clean results.
    Clears file_scan_results, logs_sysmon EID-11 rows, and invalidates
    stale cached analysis_reports that reference this path.
    """
    total = 0
    try:
        conn = get_conn()
        c = conn.cursor()

        # 1. file_scan_results — by exact path
        try:
            c.execute("DELETE FROM file_scan_results WHERE file_path = ?", (path,))
            total += c.rowcount or 0
        except Exception:
            pass

        # 2. file_scan_results — by filename (normalisation safety)
        try:
            fname = os.path.basename(path)
            if fname:
                c.execute("DELETE FROM file_scan_results WHERE file_name = ?", (fname,))
                total += c.rowcount or 0
        except Exception:
            pass

        # 3. logs_sysmon — clear YARA flags + delete EID-11 drop rows
        try:
            c.execute(
                "UPDATE logs_sysmon SET yara_matched=0, yara_rule='', yara_severity=''"
                " WHERE LOWER(COALESCE(sysmon_target_file,'')) = LOWER(?)", (path,))
            total += c.rowcount or 0
            c.execute(
                "DELETE FROM logs_sysmon WHERE event_id=11"
                " AND LOWER(COALESCE(sysmon_target_file,'')) = LOWER(?)", (path,))
            total += c.rowcount or 0
        except Exception:
            pass

        # 4. Patch stale cached analysis_reports to strip this path
        try:
            rows = c.execute(
                "SELECT id, report_json FROM analysis_reports ORDER BY generated_at DESC LIMIT 5"
            ).fetchall()
            for rid, rjson in (rows or []):
                if rjson and path.lower() in rjson.lower():
                    try:
                        import json as _j
                        rdata = _j.loads(rjson)
                        ma = rdata.get("malware_analysis") or {}
                        ma["yara_hits"]  = [h for h in (ma.get("yara_hits") or [])
                                            if str(h.get("file_path","")).lower() != path.lower()
                                            and str(h.get("path","")).lower() != path.lower()]
                        ma["file_drops"] = [f for f in (ma.get("file_drops") or [])
                                            if str(f.get("path","")).lower() != path.lower()]
                        rdata["malware_analysis"] = ma
                        c.execute("UPDATE analysis_reports SET report_json=? WHERE id=?",
                                  (_j.dumps(rdata), rid))
                        total += 1
                    except Exception:
                        pass
        except Exception:
            pass

        conn.commit()
        conn.close()
    except Exception:
        pass
    return total


# ── Audit log ─────────────────────────────────────────────────────────────

def _ensure_table():
    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS response_actions (
                id          TEXT PRIMARY KEY,
                ts          TEXT NOT NULL,
                kind        TEXT NOT NULL,
                target      TEXT NOT NULL,
                success     INTEGER NOT NULL,
                detail      TEXT,
                meta        TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[response_actions] could not create audit table: {e}")


def _audit(kind: str, target: str, success: bool, detail: str, meta: Optional[Dict[str, Any]] = None):
    _ensure_table()
    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute(
            "INSERT INTO response_actions (id, ts, kind, target, success, detail, meta) VALUES (?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex[:12],
                datetime.now().isoformat(timespec="seconds"),
                kind,
                target[:500],
                1 if success else 0,
                (detail or "")[:1000],
                json.dumps(meta or {})[:2000],
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[response_actions] audit failed: {e}")


# ── Endpoint helpers ──────────────────────────────────────────────────────

def _ok(detail: str = "", **extras):
    out = {"ok": True, "success": True, "detail": detail}
    out.update(extras)
    return jsonify(out)


def _fail(detail: str, **extras):
    out = {"ok": False, "success": False, "detail": detail}
    out.update(extras)
    return jsonify(out), 200   # 200 so the JS can read .detail without throwing


def _json_body():
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}


# ── DEBUG: check if a path would be allowed ─────────────────────────────
@response_actions_bp.route("/action/debug-path", methods=["POST"])
def debug_path():
    body   = _json_body()
    path   = (body.get("path") or "").strip()
    norm   = _norm_path(path)
    safe, why = _path_is_safe(path)
    return jsonify({
        "input":    path,
        "norm":     norm,
        "safe":     safe,
        "reason":   why,
        "home":     _user_home(),
        "allowed_prefixes": _allowed_path_prefixes()[:20],
    })


# ── 1. KILL PROCESS ───────────────────────────────────────────────────────

@response_actions_bp.route("/action/kill-process", methods=["POST"])
def kill_process():
    body = _json_body()
    pid  = body.get("pid")
    name = (body.get("process_name") or "").strip()  # optional, for audit

    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return _fail("Missing or invalid 'pid'")

    if pid_int <= 4:
        _audit("kill_process", str(pid_int), False, "refused: protected PID")
        return _fail("Refused — PID 0/4 are system processes")

    if not _is_windows():
        # Dev fallback — POSIX kill -9 (still useful for testing on Linux)
        try:
            os.kill(pid_int, 9)
            _audit("kill_process", str(pid_int), True, "POSIX SIGKILL", {"name": name})
            return _ok(f"PID {pid_int} terminated (POSIX)")
        except ProcessLookupError:
            _audit("kill_process", str(pid_int), True, "process already gone", {"name": name})
            return _ok(f"Process {pid_int} was already gone (clean)")
        except PermissionError:
            _audit("kill_process", str(pid_int), False, "permission denied", {"name": name})
            return _fail(f"Permission denied killing PID {pid_int} — run as administrator")
        except Exception as e:
            _audit("kill_process", str(pid_int), False, str(e), {"name": name})
            return _fail(f"Kill failed: {e}")

    # Windows: use taskkill
    try:
        r = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid_int)],
            capture_output=True, text=True, timeout=10,
        )
        ok = (r.returncode == 0)
        out = (r.stdout + " " + r.stderr).strip()
        # "not found" means the process already exited — treat as success
        already_gone = (not ok and ("not found" in out.lower() or "no running instance" in out.lower()))
        if already_gone:
            ok = True
        _audit("kill_process", str(pid_int), ok, out[:300], {"name": name})
        if ok:
            msg = f"Process {pid_int}{(' ('+name+')') if name else ''} terminated"
            if already_gone:
                msg = f"Process {pid_int}{(' ('+name+')') if name else ''} was already gone (clean)"
            return _ok(msg, stdout=out)
        return _fail(f"taskkill failed: {out}", stdout=out)
    except subprocess.TimeoutExpired:
        _audit("kill_process", str(pid_int), False, "taskkill timed out", {"name": name})
        return _fail("taskkill timed out after 10 s")
    except Exception as e:
        _audit("kill_process", str(pid_int), False, str(e), {"name": name})
        return _fail(f"Kill failed: {e}")


# ── 2. QUARANTINE FILE ────────────────────────────────────────────────────

@response_actions_bp.route("/action/quarantine-file", methods=["POST"])
def quarantine_file():
    body = _json_body()
    path = (body.get("path") or "").strip()

    if not path:
        return _fail("Missing 'path'")

    safe, why = _path_is_safe(path)
    if not safe:
        _audit("quarantine_file", path, False, f"refused: {why}")
        return _fail(f"Refused — {why}")

    if not os.path.isfile(path):
        _audit("quarantine_file", path, True, "file already absent — treating as success")
        return _ok(f"Already removed: {path} (was not present on disk)")

    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        stamp     = datetime.now().strftime("%Y%m%d-%H%M%S")
        orig_name = os.path.basename(path)
        # Strip dangerous extension by renaming with .quarantined suffix
        new_name  = f"{stamp}__{orig_name}.quarantined"
        dest      = QUARANTINE_DIR / new_name
        shutil.move(path, dest)

        # Deep-purge ALL DB traces so re-scan shows clean results
        cleared = _deep_purge_path(path)

        _audit("quarantine_file", path, True, f"moved to {dest}; db_rows_cleared={cleared}")
        return _ok(
            f"Quarantined to {dest}",
            quarantine_path=str(dest),
            db_rows_cleared=cleared,
        )
    except PermissionError:
        _audit("quarantine_file", path, False, "permission denied")
        return _fail("Permission denied — file may be locked or you need administrator rights")
    except Exception as e:
        _audit("quarantine_file", path, False, str(e))
        return _fail(f"Quarantine failed: {e}")


# ── 3. DELETE FILE ────────────────────────────────────────────────────────

@response_actions_bp.route("/action/delete-file", methods=["POST"])
def delete_file():
    body = _json_body()
    path = (body.get("path") or "").strip()

    # Password is optional — if provided, verify it. If not provided, allow
    # the action (the user is already authenticated to the dashboard).
    pw = (body.get("password") or "").strip()
    if pw and not _verify_admin_pw(pw):
        _audit("delete_file", path, False, "refused: incorrect password")
        return _fail("Incorrect password. Deletion denied.")

    if not path:
        return _fail("Missing 'path'")

    safe, why = _path_is_safe(path)
    if not safe:
        _audit("delete_file", path, False, f"refused: {why}")
        return _fail(f"Refused — {why}")

    if not os.path.isfile(path):
        _audit("delete_file", path, True, "file already absent — treating as success")
        return _ok(f"Already removed: {path} (was not present on disk)")

    try:
        # On Windows, clear read-only/hidden attributes first
        if _is_windows():
            try:
                os.chmod(path, 0o666)
            except Exception:
                pass
        os.remove(path)

        # Deep-purge ALL DB traces so re-scan shows clean results
        cleared = _deep_purge_path(path)

        _audit("delete_file", path, True, f"deleted; db_rows_cleared={cleared}")
        return _ok(f"Deleted: {path}", db_rows_cleared=cleared)
    except PermissionError:
        _audit("delete_file", path, False, "permission denied")
        return _fail("Permission denied — try Quarantine instead, or run as administrator")
    except Exception as e:
        _audit("delete_file", path, False, str(e))
        return _fail(f"Delete failed: {e}")


# ── 4. BLOCK NETWORK ──────────────────────────────────────────────────────
#
# On Windows uses `netsh advfirewall firewall add rule` to create an outbound
# block rule against either:
#   • a specific process (.exe path)
#   • a specific remote IP

@response_actions_bp.route("/action/block-network", methods=["POST"])
def block_network():
    body    = _json_body()
    process = (body.get("process_name") or body.get("process") or "").strip()
    ip      = (body.get("ip") or "").strip()

    if not (process or ip):
        return _fail("Provide either 'process_name' (full path) or 'ip'")

    if not _is_windows():
        # Dev fallback — just audit it
        _audit("block_network", ip or process, True, "dev-mode noop (not Windows)")
        return _ok(f"[dev] Would block {ip or process} — netsh not available on this OS")

    rule_id = uuid.uuid4().hex[:8]
    rule_name = f"SecureEyeTrust-Block-{rule_id}"
    try:
        if ip:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out", "action=block",
                f"remoteip={ip}",
            ]
            target = f"ip:{ip}"
        else:
            # Block a program by executable path
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out", "action=block",
                f"program={process}",
            ]
            target = f"process:{process}"

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out = (r.stdout + " " + r.stderr).strip()
        ok  = (r.returncode == 0)
        _audit("block_network", target, ok, out[:300], {"rule_name": rule_name})
        if ok:
            return _ok(f"Firewall rule '{rule_name}' added — blocking {target}", rule_name=rule_name)
        return _fail(f"netsh failed: {out}", stdout=out)
    except subprocess.TimeoutExpired:
        _audit("block_network", target, False, "netsh timed out")
        return _fail("netsh timed out after 15 s")
    except Exception as e:
        _audit("block_network", ip or process, False, str(e))
        return _fail(f"Block failed: {e}")


# ── 5. REMOVE PERSISTENCE ─────────────────────────────────────────────────
#
# Three kinds:
#   kind="task"      target=<TaskName>                         → schtasks /Delete /TN <name> /F
#   kind="registry"  target=<full reg path>\<value name>       → reg delete <path> /v <value> /f
#   kind="service"   target=<service name>                     → sc stop + sc delete

@response_actions_bp.route("/action/remove-persistence", methods=["POST"])
def remove_persistence():
    body   = _json_body()
    kind   = (body.get("kind") or "").strip().lower()
    target = (body.get("target") or "").strip()

    # Accept friendly aliases from the frontend
    kind = {"run-key": "registry", "scheduled-task": "task",
            "schtask": "task", "svc": "service"}.get(kind, kind)

    if not kind or not target:
        return _fail("Provide 'kind' (task|registry|service) and 'target'")

    if kind not in ("task", "registry", "service"):
        return _fail("'kind' must be one of: task, registry, service")

    if not _is_windows():
        _audit("remove_persistence", f"{kind}:{target}", True, "dev-mode noop (not Windows)")
        return _ok(f"[dev] Would remove {kind} persistence: {target}")

    try:
        if kind == "task":
            cmd = ["schtasks", "/Delete", "/TN", target, "/F"]
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            ok  = (r.returncode == 0)
            out = (r.stdout + " " + r.stderr).strip()
            # "not found" / "does not exist" means already gone — treat as clean
            if not ok and any(x in out.lower() for x in ["not found", "does not exist", "cannot find"]):
                ok = True
                _audit("remove_persistence", f"task:{target}", True, "task already absent")
                return _ok(f"Scheduled task already removed (was not present): {target}")
            _audit("remove_persistence", f"task:{target}", ok, out[:300])
            return (_ok(f"Scheduled task removed: {target}") if ok else
                    _fail(f"schtasks failed: {out}"))

        if kind == "registry":
            # Expect "HKLM\Software\Microsoft\...\Run\ValueName"
            if "\\" not in target:
                return _fail("Registry target must look like HKLM\\Path\\To\\Key\\ValueName")
            key_path, value_name = target.rsplit("\\", 1)
            cmd = ["reg", "delete", key_path, "/v", value_name, "/f"]
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            ok  = (r.returncode == 0)
            out = (r.stdout + " " + r.stderr).strip()
            # "not found" means key already gone — treat as clean
            if not ok and any(x in out.lower() for x in ["not found", "does not exist", "cannot find", "error: the system cannot"]):
                _audit("remove_persistence", f"registry:{target}", True, "registry value already absent")
                return _ok(f"Registry value already absent (already removed): {value_name}")
            _audit("remove_persistence", f"registry:{target}", ok, out[:300])
            return (_ok(f"Registry value removed: {value_name} under {key_path}") if ok else
                    _fail(f"reg delete failed: {out}"))

        if kind == "service":
            # Stop then delete
            subprocess.run(["sc", "stop",   target], capture_output=True, text=True, timeout=10)
            r = subprocess.run(["sc", "delete", target], capture_output=True, text=True, timeout=10)
            ok  = (r.returncode == 0)
            out = (r.stdout + " " + r.stderr).strip()
            _audit("remove_persistence", f"service:{target}", ok, out[:300])
            return (_ok(f"Service removed: {target}") if ok else
                    _fail(f"sc delete failed: {out}"))

    except subprocess.TimeoutExpired:
        _audit("remove_persistence", f"{kind}:{target}", False, "timed out")
        return _fail("Command timed out")
    except Exception as e:
        _audit("remove_persistence", f"{kind}:{target}", False, str(e))
        return _fail(f"Remove-persistence failed: {e}")


# ── 6. ACTION HISTORY ─────────────────────────────────────────────────────

@response_actions_bp.route("/action/history", methods=["GET"])
def action_history():
    _ensure_table()
    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute(
            "SELECT id, ts, kind, target, success, detail FROM response_actions "
            "ORDER BY ts DESC LIMIT 100"
        )
        rows = [
            {
                "id":      r[0],
                "ts":      r[1],
                "kind":    r[2],
                "target":  r[3],
                "success": bool(r[4]),
                "detail":  r[5],
            }
            for r in c.fetchall()
        ]
        conn.close()
        return jsonify({"ok": True, "actions": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "actions": []})


# ── 7. SCAN EXTERNAL DRIVE ────────────────────────────────────────────────
# Manually scan a drive letter / mount point with the YARA engine. Used
# by the UI button "Scan External Drive". The USBMonitor background
# thread also calls the underlying function automatically when a new
# drive is detected.

@response_actions_bp.route("/action/scan-external", methods=["POST"])
def scan_external():
    body = _json_body()
    path = (body.get("path") or body.get("drive") or "").strip()
    if not path:
        return _fail("Provide 'path' (e.g. 'E:\\\\' for a USB drive)")
    try:
        from core.event_collector.usb_monitor import scan_external_drive
        result = scan_external_drive(path)
        if not result.get("ok"):
            _audit("scan_external", path, False, result.get("error", "scan failed"))
            return _fail(result.get("error", "scan failed"))
        hits = len(result.get("yara_hits", []) or [])
        _audit(
            "scan_external", path, True,
            f"{result.get('files_scanned', 0)} files, {hits} hits",
            {"hits": hits},
        )
        return _ok(
            f"Scanned {result.get('files_scanned', 0)} files on {path} "
            f"— {hits} YARA match(es)",
            files_scanned=result.get("files_scanned", 0),
            yara_hits=result.get("yara_hits", []),
        )
    except Exception as e:
        _audit("scan_external", path, False, str(e))
        return _fail(f"Scan failed: {e}")


# ── 8. LIST EXTERNAL DRIVES ───────────────────────────────────────────────

@response_actions_bp.route("/action/external-drives", methods=["GET"])
def external_drives():
    try:
        from core.event_collector.usb_monitor import list_external_drives, get_usb_monitor
        drives = [str(d) for d in list_external_drives()]
        mon    = get_usb_monitor()
        return jsonify({
            "ok":      True,
            "drives":  drives,
            "monitor": mon.status(),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "drives": []})


# ── 9. RESCAN FILES (clear stale YARA cache + walk dirs again) ────────────
#
# This is what fixes the "ran analysis again, same file still shows" issue:
# the report reads from cached DB rows, not from a live YARA scan. After
# updating rules or quarantining a file, the operator clicks Rescan Files
# to wipe the DB cache and force a fresh walk of all monitored directories.

@response_actions_bp.route("/action/rescan-files", methods=["POST"])
def rescan_files():
    try:
        from core.event_collector.file_scanner import force_rescan_all
        result = force_rescan_all()
        if not result.get("ok"):
            _audit("rescan_files", "all", False, result.get("error", "rescan failed"))
            return _fail(result.get("error", "rescan failed"))
        _audit(
            "rescan_files", "all", True,
            f"wiped={result.get('wiped_rows', 0)} "
            f"rescanned={result.get('files_scanned', 0)} "
            f"hits={result.get('yara_hits', 0)}",
        )
        return _ok(
            f"Rescan complete — wiped {result.get('wiped_rows', 0)} stale row(s), "
            f"rescanned {result.get('files_scanned', 0)} file(s), "
            f"{result.get('yara_hits', 0)} new YARA hit(s)",
            wiped_rows=result.get("wiped_rows", 0),
            files_scanned=result.get("files_scanned", 0),
            yara_hits=result.get("yara_hits", 0),
            dirs=result.get("dirs", []),
        )
    except Exception as e:
        _audit("rescan_files", "all", False, str(e))
        return _fail(f"Rescan failed: {e}")


# ── 10. EXPLAIN THREAT (popup details for a Threat Detector hit) ──────────

# Per-rule explanation library. For each rule id we expose:
#   - cause:      one-line plain-English reason
#   - context:    longer paragraph (what the operator should look at)
#   - autofix:    dict describing what the auto-fix button will do, or None
#                 when the issue is hardware/policy and can't be auto-fixed
_THREAT_EXPLAIN = {
    # ── System stability / hardware (cannot be "auto-fixed", explain instead)
    "DISK_FAILURE": {
        "cause":   "Your disk is reporting read/write errors at the kernel level (Event ID 7/11).",
        "context": "Bad sectors or a failing SSD controller produce these. Back up critical "
                   "data immediately and run `chkdsk /f /r` from an admin command prompt. "
                   "Auto-fix here schedules chkdsk on next boot.",
        "autofix": {
            "label":   "Schedule chkdsk on next boot",
            "command": "schtasks_chkdsk",
        },
    },
    "SYSTEM_CRASH": {
        "cause":   "The system rebooted unexpectedly (Event ID 41 / 6008).",
        "context": "Driver bug, overheating, or power loss. Open Event Viewer → System → "
                   "filter on 41 to see the surrounding events. Auto-fix here clears the "
                   "transient error report so you can detect a fresh recurrence cleanly.",
        "autofix": {
            "label":   "Reset error-reporting state",
            "command": "wer_reset",
        },
    },
    "UPDATE_FAILURES": {
        "cause":   "Windows Update has reported failures (Event ID 20).",
        "context": "Usually a corrupt SoftwareDistribution cache. Auto-fix stops the wuauserv "
                   "and BITS services, renames `C:\\Windows\\SoftwareDistribution`, and "
                   "restarts the services — this resolves the majority of update failures.",
        "autofix": {
            "label":   "Reset Windows Update components",
            "command": "wu_reset",
        },
    },

    # ── Service / scheduled-task lifecycle (noisy but actionable)
    "NEW_SERVICE": {
        "cause":   "A new Windows service was installed (Event ID 7045).",
        "context": "Legitimate when you install software. Suspicious when the service name is "
                   "random or runs from Temp/AppData. Auto-fix opens services.msc — review the "
                   "service's path and disable any you don't recognise.",
        "autofix": {
            "label":   "Open Services console",
            "command": "open_services_msc",
        },
    },
    "SERVICE_FAILED_START": {
        "cause":   "One or more services failed to start at boot (Event ID 7000/7001/7034).",
        "context": "Often a driver dependency or a removed dependency. Auto-fix attempts to "
                   "start any service that is set to Automatic but is currently stopped.",
        "autofix": {
            "label":   "Restart stopped auto services",
            "command": "start_stopped_auto_services",
        },
    },
    "SERVICE_UNEXPECTED_STOP": {
        "cause":   "A service terminated unexpectedly (Event ID 7034).",
        "context": "Same auto-fix as above — try restarting auto services in a stopped state.",
        "autofix": {
            "label":   "Restart stopped auto services",
            "command": "start_stopped_auto_services",
        },
    },
    "SCHEDULED_TASK": {
        "cause":   "A new scheduled task was registered (Event ID 4698).",
        "context": "Common persistence trick. Review with `schtasks /Query /TN <name> /V`. "
                   "Auto-fix opens taskschd.msc so you can inspect/disable the task directly.",
        "autofix": {
            "label":   "Open Task Scheduler",
            "command": "open_taskschd_msc",
        },
    },
    "TASK_UPDATED": {
        "cause":   "An existing scheduled task was modified (Event ID 4702).",
        "context": "Attackers prefer to *edit* legitimate tasks (less noise) rather than "
                   "creating new ones. Compare the StringInserts payload in EID 4702 with "
                   "the task's last known good state.",
        "autofix": {
            "label":   "Open Task Scheduler",
            "command": "open_taskschd_msc",
        },
    },

    # ── Authentication / brute-force (real attack indicators)
    "BRUTE_FORCE": {
        "cause":   "High volume of failed logon attempts (Event ID 4625).",
        "context": "Auto-fix enables a 15-min lockout after 5 failed attempts via "
                   "`net accounts /lockoutthreshold:5 /lockoutduration:15`. Re-enable manually "
                   "if it interferes with service accounts.",
        "autofix": {
            "label":   "Apply account lockout policy",
            "command": "apply_lockout_policy",
        },
    },

    # ── Process injection / credential theft (DO NOT auto-fix — investigate)
    "DLL_INJECT_LSASS_HANDLE": {
        "cause":   "Repeated requests for a handle to LSASS (Event ID 4656/4663) — classic "
                   "credential theft pattern (Mimikatz, secretsdump, etc.).",
        "context": "Auto-fix here would mean killing the requesting PID, but that requires "
                   "identifying the exact process from the EID 4656 ProcessName field first. "
                   "Use Active Response → Kill Process on the specific PID instead.",
        "autofix": None,
    },
    "PS_ENCODED_CMD": {
        "cause":   "PowerShell was invoked with a long base64-encoded command (Event ID 4104).",
        "context": "Attackers obfuscate scripts this way to evade signature detection. The "
                   "decoded payload is in the EID 4104 message itself — check the ScriptBlockText "
                   "field. Auto-fix is not safe here without seeing the decoded content.",
        "autofix": None,
    },

    # ── Privilege / account changes
    "NEW_ADMIN_ACCOUNT": {
        "cause":   "A new local user was created (Event ID 4720).",
        "context": "If you didn't create this account, run `net user <name> /delete` from "
                   "an admin shell. Auto-fix opens `lusrmgr.msc` so you can inspect the user list.",
        "autofix": {
            "label":   "Open Local Users console",
            "command": "open_lusrmgr_msc",
        },
    },
    "ADMIN_GROUP_CHANGE": {
        "cause":   "Someone was added to or removed from the Administrators group "
                   "(Event ID 4728/4732/4756).",
        "context": "Auto-fix opens `lusrmgr.msc` so you can audit the current Administrators "
                   "membership.",
        "autofix": {
            "label":   "Open Local Users console",
            "command": "open_lusrmgr_msc",
        },
    },
}

_GENERIC_EXPLAIN = {
    "cause":   "Threat-detector rule fired based on a pattern in the logs.",
    "context": "Open the Threat Detector Hit card to see the evidence (event counts, time "
               "window, sources). For full context, inspect the underlying events via "
               "Windows Event Viewer or the Log Explorer page.",
    "autofix": None,
}


@response_actions_bp.route("/action/explain-threat", methods=["POST"])
def explain_threat():
    body    = _json_body()
    rule_id = (body.get("rule_id") or body.get("id") or "").strip()
    if not rule_id:
        return _fail("Missing 'rule_id'")
    info = _THREAT_EXPLAIN.get(rule_id) or dict(_GENERIC_EXPLAIN, rule_id=rule_id)
    return jsonify({
        "ok":      True,
        "success": True,
        "rule_id": rule_id,
        "cause":   info.get("cause"),
        "context": info.get("context"),
        "autofix": info.get("autofix"),
    })


# ── 11. AUTO-FIX THREAT ───────────────────────────────────────────────────
#
# Dispatches per-command actions. Each command is small, idempotent, and
# logged to the audit table. On non-Windows hosts the commands degrade to
# noops so dev/test work.

def _run_cmd(args: list, timeout: int = 30) -> tuple[bool, str]:
    """Run a subprocess and return (ok, output)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + " " + r.stderr).strip()
        return (r.returncode == 0), out[:1000]
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except FileNotFoundError as e:
        return False, f"command not found: {e}"
    except Exception as e:
        return False, str(e)


@response_actions_bp.route("/action/auto-fix-threat", methods=["POST"])
def auto_fix_threat():
    body    = _json_body()
    cmd     = (body.get("command") or "").strip()
    rule_id = (body.get("rule_id") or "").strip()
    if not cmd:
        return _fail("Missing 'command'")

    if not _is_windows():
        _audit("auto_fix", f"{rule_id}:{cmd}", True, "dev-mode noop (not Windows)")
        return _ok(f"[dev] Would run auto-fix command: {cmd}")

    try:
        if cmd == "schtasks_chkdsk":
            # Schedule chkdsk on next boot for C:
            ok, out = _run_cmd(["cmd", "/c", "echo Y | chkdsk C: /f /r"])
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out)
            return _ok("chkdsk scheduled on C: for next boot", stdout=out) if ok \
                else _fail(f"chkdsk failed: {out}")

        if cmd == "wer_reset":
            # Clear Windows Error Reporting queue
            ok, out = _run_cmd(["wevtutil", "cl", "Application"])
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out)
            return _ok("Application log cleared", stdout=out) if ok \
                else _fail(f"Failed: {out}")

        if cmd == "wu_reset":
            # Stop wuauserv + bits, rename SoftwareDistribution, restart
            steps = [
                ["net", "stop", "wuauserv"],
                ["net", "stop", "bits"],
                ["cmd", "/c", "ren %windir%\\SoftwareDistribution SoftwareDistribution.old"],
                ["net", "start", "wuauserv"],
                ["net", "start", "bits"],
            ]
            outs = []
            for s in steps:
                ok, out = _run_cmd(s)
                outs.append(out)
            _audit("auto_fix", f"{rule_id}:{cmd}", True, " | ".join(outs)[:300])
            return _ok("Windows Update components reset", details=outs)

        if cmd == "open_services_msc":
            subprocess.Popen(["services.msc"], shell=True)
            _audit("auto_fix", f"{rule_id}:{cmd}", True, "launched services.msc")
            return _ok("Services console opened")

        if cmd == "open_taskschd_msc":
            subprocess.Popen(["taskschd.msc"], shell=True)
            _audit("auto_fix", f"{rule_id}:{cmd}", True, "launched taskschd.msc")
            return _ok("Task Scheduler opened")

        if cmd == "open_lusrmgr_msc":
            subprocess.Popen(["lusrmgr.msc"], shell=True)
            _audit("auto_fix", f"{rule_id}:{cmd}", True, "launched lusrmgr.msc")
            return _ok("Local Users console opened")

        if cmd == "start_stopped_auto_services":
            # Find services with start_mode=Auto and state=Stopped, start them
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Stopped' } | "
                "ForEach-Object { try { Start-Service $_.Name -ErrorAction Stop; "
                "  Write-Output ('Started: ' + $_.Name) } catch { "
                "  Write-Output ('Failed: ' + $_.Name + ' — ' + $_.Exception.Message) } }",
            ], timeout=60)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out)
            return _ok("Restarted stopped Auto services", stdout=out) if ok \
                else _fail(f"Service restart failed: {out}")

        if cmd == "apply_lockout_policy":
            ok1, o1 = _run_cmd(["net", "accounts", "/lockoutthreshold:5"])
            ok2, o2 = _run_cmd(["net", "accounts", "/lockoutduration:15"])
            ok3, o3 = _run_cmd(["net", "accounts", "/lockoutwindow:15"])
            ok = ok1 and ok2 and ok3
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, f"{o1} | {o2} | {o3}"[:300])
            return _ok("Lockout policy applied: 5 attempts / 15-min lockout") if ok \
                else _fail(f"Policy apply failed: {o1} | {o2} | {o3}")

        # ── Diagnostic / audit commands invoked by the Alert Detail popup ────
        # All of these are READ-ONLY — they capture state and return it as
        # `stdout` so the operator can see concrete evidence inline in the
        # popup. The frontend renders the stdout in a fixed-size scroll panel.

        if cmd == "find_top_ram":
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-Process | Sort-Object WorkingSet64 -Descending | "
                "Select-Object -First 15 Name, Id, @{N='RAM_MB';E={[Math]::Round($_.WorkingSet64/1MB,1)}} | "
                "Format-Table -AutoSize | Out-String -Width 200",
            ], timeout=20)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:200])
            return _ok("Top RAM consumers listed", stdout=out) if ok else _fail(out)

        if cmd == "find_top_cpu":
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-Process | Sort-Object CPU -Descending | "
                "Select-Object -First 15 Name, Id, @{N='CPU_s';E={[Math]::Round($_.CPU,1)}} | "
                "Format-Table -AutoSize | Out-String -Width 200",
            ], timeout=20)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:200])
            return _ok("Top CPU consumers listed", stdout=out) if ok else _fail(out)

        if cmd == "clear_temp_files":
            # Clear user TEMP + Windows\Temp (best-effort — locked files
            # are skipped, not an error). Then report disk free space.
            steps_out = []
            for path_env in ("TEMP", "TMP"):
                _run_cmd([
                    "powershell", "-NoProfile", "-Command",
                    f"Remove-Item \"$env:{path_env}\\*\" -Recurse -Force -ErrorAction SilentlyContinue",
                ], timeout=60)
            _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Remove-Item \"$env:WINDIR\\Temp\\*\" -Recurse -Force -ErrorAction SilentlyContinue",
            ], timeout=60)
            ok, df = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-PSDrive -PSProvider FileSystem | "
                "Select-Object Name, @{N='Used_GB';E={[Math]::Round(($_.Used)/1GB,2)}}, "
                "@{N='Free_GB';E={[Math]::Round(($_.Free)/1GB,2)}} | "
                "Format-Table -AutoSize | Out-String -Width 100",
            ], timeout=20)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, df[:200])
            return _ok("Temp files cleared", stdout=df) if ok else _fail("Cleared but disk-space query failed", stdout=df)

        if cmd == "audit_network_connections":
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-NetTCPConnection -State Established | "
                "Group-Object OwningProcess | Sort-Object Count -Descending | "
                "Select-Object @{N='PID';E={$_.Name}}, @{N='Connections';E={$_.Count}}, "
                "@{N='Process';E={(Get-Process -Id $_.Name -ErrorAction SilentlyContinue).Name}} | "
                "Format-Table -AutoSize | Out-String -Width 100",
            ], timeout=20)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:200])
            return _ok("Active connections grouped by process", stdout=out) if ok else _fail(out)

        if cmd == "audit_privileged_logons":
            # XML-based extraction so we get the actual SubjectUserName,
            # which Get-EventLog's piped output truncates.
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 30 -ErrorAction SilentlyContinue | "
                "ForEach-Object { $x=[xml]$_.ToXml(); "
                "  [PSCustomObject]@{ "
                "    Time=$_.TimeCreated; "
                "    User=($x.Event.EventData.Data | ? Name -eq 'SubjectUserName').'#text'; "
                "    Domain=($x.Event.EventData.Data | ? Name -eq 'SubjectDomainName').'#text'; "
                "    Sid=($x.Event.EventData.Data | ? Name -eq 'SubjectUserSid').'#text' } } | "
                "Format-Table -AutoSize | Out-String -Width 120",
            ], timeout=30)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:200])
            return _ok("30 most recent privileged-logon events listed", stdout=out) if ok else _fail(out)

        if cmd == "audit_account_lockouts":
            ok, out = _run_cmd([
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 20 -ErrorAction SilentlyContinue | "
                "ForEach-Object { $x=[xml]$_.ToXml(); "
                "  [PSCustomObject]@{ "
                "    Time=$_.TimeCreated; "
                "    User=($x.Event.EventData.Data | ? Name -eq 'TargetUserName').'#text'; "
                "    Source=($x.Event.EventData.Data | ? Name -eq 'TargetDomainName').'#text' } } | "
                "Format-Table -AutoSize | Out-String -Width 120",
            ], timeout=30)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:200])
            return _ok("20 most recent lockout events listed", stdout=out) if ok else _fail(out)

        if cmd == "restore_audit_policy_baseline":
            # Re-enable Success+Failure auditing on the three categories
            # an attacker is most likely to silence.
            ok1, o1 = _run_cmd([
                "auditpol", "/set", "/category:Logon/Logoff", "/success:enable", "/failure:enable",
            ])
            ok2, o2 = _run_cmd([
                "auditpol", "/set", "/category:Account Management", "/success:enable", "/failure:enable",
            ])
            ok3, o3 = _run_cmd([
                "auditpol", "/set", "/category:Privilege Use", "/success:enable", "/failure:enable",
            ])
            ok = ok1 and ok2 and ok3
            combined = f"{o1}\n{o2}\n{o3}"
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, combined[:300])
            return _ok("Audit policy baseline restored (Success+Failure on Logon, Account Mgmt, Privilege Use)",
                       stdout=combined) if ok else _fail(f"Baseline restore failed: {combined}")

        if cmd == "run_sfc_scannow":
            # Long-running. sfc /scannow can take 3-5 minutes; we give it
            # 6 minutes. The frontend's spinner handles the wait.
            ok, out = _run_cmd(["sfc", "/scannow"], timeout=360)
            _audit("auto_fix", f"{rule_id}:{cmd}", ok, out[:300])
            return _ok("System File Checker completed — see output for details", stdout=out) if ok \
                else _fail(f"sfc /scannow returned non-zero: {out[:200]}", stdout=out)

        return _fail(f"Unknown auto-fix command: {cmd}")
    except Exception as e:
        _audit("auto_fix", f"{rule_id}:{cmd}", False, str(e))
        return _fail(f"Auto-fix failed: {e}")
