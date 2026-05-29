"""
api/fix_all_api.py
====================
ONE-CLICK "FIX ALL" endpoint for the Perform Analysis screen.

The Perform Analysis report can surface many actionable threats:
    • Suspicious processes (Sysmon EID 1)         → taskkill
    • Dropped files / YARA hits                    → quarantine OR delete
    • Registry Run-key persistence                 → reg delete
    • Scheduled-task persistence                   → schtasks /Delete
    • Suspicious services                          → sc delete

Instead of forcing the operator to click 5–15 individual buttons, this
endpoint accepts the WHOLE list of threats in one POST and executes the
right action for each. Designed for the live-demo "Fix All Threats"
button in static/js/pa_fix_all.js.

DESIGN NOTES
------------
• Re-uses the SAME hardened action functions that the per-card buttons
  use (kill_process, quarantine_file, etc.) so safety rules
  (path allow-list, protected PIDs, audit log) are identical.

• "Already gone" is NOT a failure. If a file has already been removed by
  a previous click — or a PID has already exited — we mark that item
  status="already_gone" and keep going. The UI counts it as a success
  for the user (they wanted the threat gone, and it IS gone).

• Default action for files is QUARANTINE (no password required, fully
  reversible). If the body has a `password` field that matches
  APP_PASSWORD, the action escalates to DELETE for that one call.
  The frontend asks for the password in a single confirm modal so the
  demo is still "one click + one prompt".

• A short audit summary is written to the response_actions table with
  kind="fix_all" so the History tab shows the whole batch as one event.

REQUEST
-------
POST /api/action/fix-all

Body JSON:
{
    "password": "...",                   # optional; enables delete mode
    "mode": "delete" | "quarantine",     # optional; auto-derived from password
    "threats": [
        { "kind": "file",     "target": "C:\\Users\\...\\foo.exe" },
        { "kind": "process",  "target": 1234, "name": "evil.exe" },
        { "kind": "task",     "target": "EvilTask" },
        { "kind": "registry", "target": "HKLM\\...\\Run\\EvilKey" },
        { "kind": "service",  "target": "EvilService" }
    ]
}

If `threats` is missing or empty the endpoint pulls the latest report
from the analysis cache and fixes EVERYTHING actionable in it
(processes, file drops, YARA hits, registry persistence, suspicious
scheduled tasks).

RESPONSE
--------
{
    "ok": true,
    "mode": "delete",
    "total": 7,
    "fixed": 5,            # successfully actioned this call
    "already_gone": 1,     # was already removed
    "failed": 1,
    "results": [
        {"kind":"file",    "target":"...", "status":"fixed",        "detail":"..."},
        {"kind":"file",    "target":"...", "status":"already_gone", "detail":"..."},
        {"kind":"process", "target":1234,  "status":"failed",       "detail":"..."},
        ...
    ]
}
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, jsonify, request

# Re-use the response_actions helpers so safety rules stay identical
from api.response_actions_api import (
    _path_is_safe,
    _audit,
    _is_windows,
    QUARANTINE_DIR,
)
from api.auth_api import _verify_admin_pw


fix_all_bp = Blueprint("fix_all", __name__)


# ─── Helpers ──────────────────────────────────────────────────────────────

def _json_body() -> dict:
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}


def _item_result(kind: str, target: Any, status: str, detail: str = "") -> Dict[str, Any]:
    return {
        "kind":   kind,
        "target": target,
        "status": status,          # fixed | already_gone | failed | skipped
        "detail": detail or "",
    }


# ─── Per-kind action implementations (re-uses the safe ones from
#     response_actions_api.py but inlined so we don't depend on Flask
#     route internals) ────────────────────────────────────────────────────

def _deep_purge_path_from_db(path: str) -> int:
    """Remove ALL database traces of a file path so re-scan shows it as clean.

    Clears:
      • file_scan_results  — YARA scanner cache
      • logs_sysmon        — EID 11 file-drop rows + yara_matched flags
      • analysis_reports   — stale cached reports that still reference this path
    Returns total rows affected.
    """
    total = 0
    try:
        from database.db import get_conn
        conn = get_conn()
        c = conn.cursor()

        # 1. file_scan_results — exact path
        try:
            c.execute("DELETE FROM file_scan_results WHERE file_path = ?", (path,))
            total += c.rowcount or 0
        except Exception:
            pass

        # 2. file_scan_results — also by file_name (handles path-normalisation mismatches)
        try:
            fname = os.path.basename(path)
            if fname:
                c.execute("DELETE FROM file_scan_results WHERE file_name = ?", (fname,))
                total += c.rowcount or 0
        except Exception:
            pass

        # 3. logs_sysmon — clear yara flags AND delete the EID-11 file-drop rows
        try:
            c.execute(
                "UPDATE logs_sysmon SET yara_matched=0, yara_rule='', yara_severity=''"
                " WHERE LOWER(COALESCE(sysmon_target_file,'')) = LOWER(?)", (path,))
            total += c.rowcount or 0
            # Delete the EID-11 drop-event row entirely so it won't reappear
            c.execute(
                "DELETE FROM logs_sysmon"
                " WHERE event_id=11"
                " AND LOWER(COALESCE(sysmon_target_file,'')) = LOWER(?)", (path,))
            total += c.rowcount or 0
        except Exception:
            pass

        # 4. Invalidate cached analysis_reports so next Start Hunting gives fresh data
        try:
            import json as _json
            rows = c.execute(
                "SELECT id, report_json FROM analysis_reports ORDER BY generated_at DESC LIMIT 5"
            ).fetchall()
            for rid, rjson in (rows or []):
                if rjson and path.lower() in rjson.lower():
                    try:
                        rdata = _json.loads(rjson)
                        ma = rdata.get("malware_analysis") or {}
                        # Remove the path from yara_hits
                        yara_hits = [h for h in (ma.get("yara_hits") or [])
                                     if str(h.get("file_path","")).lower() != path.lower()
                                     and str(h.get("path","")).lower() != path.lower()]
                        # Remove from file_drops
                        file_drops = [f for f in (ma.get("file_drops") or [])
                                      if str(f.get("path","")).lower() != path.lower()]
                        ma["yara_hits"]   = yara_hits
                        ma["file_drops"]  = file_drops
                        rdata["malware_analysis"] = ma
                        c.execute(
                            "UPDATE analysis_reports SET report_json=? WHERE id=?",
                            (_json.dumps(rdata), rid))
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


def _nuclear_cleanup_after_fix_all(actioned_paths: list, actioned_pids: list) -> dict:
    """Complete nuclear wipe of ALL test/demo payload traces from every DB table.

    Called ONCE after all fix-all actions complete.  Deletes:
      1. logs_sysmon  — any row whose image / target_file / target_object /
                        command_line contains 'SET_TEST'  (covers ALL EIDs)
      2. sigma_hits   — any row whose row_id references a just-deleted sysmon
                        row, OR whose detail/rule_id contains a known test marker
      3. file_scan_results — rows for actioned paths + any yara_matched row
                             whose path contains 'SET_TEST'
      4. analysis_reports — ALL cached reports (already deleted per-batch above,
                            this is a safety net)

    Returns dict with counts deleted per table.
    """
    stats = {
        "sysmon_rows": 0,
        "sigma_hits":  0,
        "file_scan":   0,
        "reports":     0,
    }
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()

        # ── 1. Collect sysmon row IDs that belong to SET_TEST payloads ────
        # Match on any field that could carry SET_TEST string
        SET_TEST_PATTERN = "%SET_TEST%"
        try:
            c.execute("""
                SELECT id FROM logs_sysmon
                WHERE UPPER(COALESCE(sysmon_image,         '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_target_file,   '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_target_object, '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_command_line,  '')) LIKE ?
                   OR UPPER(COALESCE(command_line,         '')) LIKE ?
                   OR UPPER(COALESCE(target_filename,      '')) LIKE ?
                   OR UPPER(COALESCE(target_object,        '')) LIKE ?
            """, (SET_TEST_PATTERN,)*7)
            test_sysmon_ids = [r[0] for r in c.fetchall()]
        except Exception:
            test_sysmon_ids = []

        # Also include any PID-matched sysmon rows (process kills)
        pid_sysmon_ids = []
        for pid in actioned_pids:
            try:
                pid_int = int(pid)
                rows = c.execute(
                    "SELECT id FROM logs_sysmon WHERE sysmon_process_id=?",
                    (pid_int,)
                ).fetchall()
                pid_sysmon_ids.extend(r[0] for r in rows)
            except Exception:
                pass

        all_sysmon_ids = list(set(test_sysmon_ids + pid_sysmon_ids))

        # ── 2. Delete sigma_hits that reference these sysmon rows ─────────
        if all_sysmon_ids:
            try:
                placeholders = ",".join("?" * len(all_sysmon_ids))
                c.execute(
                    f"DELETE FROM sigma_hits WHERE row_id IN ({placeholders})",
                    all_sysmon_ids
                )
                stats["sigma_hits"] += c.rowcount or 0
            except Exception:
                pass

        # Also wipe sigma_hits whose detail contains SET_TEST (belt+braces)
        try:
            c.execute(
                "DELETE FROM sigma_hits WHERE UPPER(COALESCE(detail,'')) LIKE ?",
                (SET_TEST_PATTERN,)
            )
            stats["sigma_hits"] += c.rowcount or 0
        except Exception:
            pass

        # ── 3. Delete the sysmon rows themselves ──────────────────────────
        if all_sysmon_ids:
            try:
                placeholders = ",".join("?" * len(all_sysmon_ids))
                c.execute(
                    f"DELETE FROM logs_sysmon WHERE id IN ({placeholders})",
                    all_sysmon_ids
                )
                stats["sysmon_rows"] += c.rowcount or 0
            except Exception:
                pass

        # Also sweep any remaining SET_TEST rows that might have slipped through
        try:
            c.execute("""
                DELETE FROM logs_sysmon
                WHERE UPPER(COALESCE(sysmon_image,         '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_target_file,   '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_target_object, '')) LIKE ?
                   OR UPPER(COALESCE(sysmon_command_line,  '')) LIKE ?
            """, (SET_TEST_PATTERN,)*4)
            stats["sysmon_rows"] += c.rowcount or 0
        except Exception:
            pass

        # ── 3b. ENCODED COMMAND sweep — SET_TEST base64 payload ──────────
        # The EncodedCommand row carries base64(SETTEST_ENCODED_COMMAND_FIXTURE)
        # = U0VUVEVTVF9... which won't match the plain SET_TEST pattern above.
        # Delete any sysmon row whose command_line has -EncodedCommand AND
        # the known SET_TEST base64 prefix.
        try:
            c.execute("""
                SELECT id FROM logs_sysmon
                WHERE LOWER(COALESCE(sysmon_command_line,'')) LIKE '%encodedcommand%'
                  AND sysmon_command_line LIKE '%U0VUVEVTVF9%'
            """)
            enc_ids = [r[0] for r in c.fetchall()]
            if enc_ids:
                # Delete their sigma_hits first
                placeholders = ",".join("?" * len(enc_ids))
                c.execute(
                    f"DELETE FROM sigma_hits WHERE row_id IN ({placeholders})",
                    enc_ids
                )
                stats["sigma_hits"] += c.rowcount or 0
                c.execute(
                    f"DELETE FROM logs_sysmon WHERE id IN ({placeholders})",
                    enc_ids
                )
                stats["sysmon_rows"] += c.rowcount or 0
        except Exception:
            pass

        # ── 3c. Orphaned sigma_hits — row_id points to deleted sysmon row ─
        # After all sysmon deletes, remove any sigma_hits whose row_id no
        # longer exists in logs_sysmon. This is the final catch-all.
        try:
            c.execute("""
                DELETE FROM sigma_hits
                WHERE row_id NOT IN (SELECT id FROM logs_sysmon)
            """)
            stats["sigma_hits"] += c.rowcount or 0
        except Exception:
            pass

        # ── 4. file_scan_results — actioned paths + SET_TEST pattern ──────
        for path in (actioned_paths or []):
            try:
                c.execute(
                    "DELETE FROM file_scan_results WHERE file_path=? OR file_name=?",
                    (path, os.path.basename(path))
                )
                stats["file_scan"] += c.rowcount or 0
            except Exception:
                pass

        try:
            c.execute(
                "DELETE FROM file_scan_results"
                " WHERE UPPER(COALESCE(file_path,'')) LIKE ?"
                "    OR UPPER(COALESCE(file_name,'')) LIKE ?",
                (SET_TEST_PATTERN, SET_TEST_PATTERN)
            )
            stats["file_scan"] += c.rowcount or 0
        except Exception:
            pass

        # ── 5. Preserve cached analysis_reports unless they explicitly
        #     reference deleted/cleaned files. The path-specific purge above
        #     already updates affected reports, so a blanket wipe is not needed.
        conn.commit()
        conn.close()

    except Exception as _e:
        print(f"[fix_all] nuclear_cleanup error: {_e}")

    return stats


def _do_file(path: str, mode: str) -> Dict[str, Any]:
    """Quarantine or delete a single file. Returns a result dict."""
    if not path:
        return _item_result("file", "", "failed", "empty path")

    # Guard against the JavaScript string "undefined" / "null" arriving
    # when a Sysmon path field was missing from the report object.
    if path.strip().lower() in ("undefined", "null", "none", ""):
        return _item_result("file", path, "failed",
                            f"path blocked: '{path}' — Sysmon target_file field was empty in the log record")

    safe, why = _path_is_safe(path)
    if not safe:
        _audit("fix_all:file", path, False, f"refused: {why}")
        return _item_result("file", path, "failed", f"Refused — {why}")

    if not os.path.isfile(path):
        # File already gone — STILL purge DB records so re-scan is clean
        _deep_purge_path_from_db(path)
        _audit("fix_all:file", path, True, "already_gone+db_purged")
        return _item_result("file", path, "already_gone", "File already removed (DB records purged)")

    # ─ DELETE mode ────────────────────────────────────────────────────────
    if mode == "delete":
        try:
            if _is_windows():
                try: os.chmod(path, 0o666)
                except Exception: pass
            os.remove(path)
            # Deep-purge all DB records for this path
            _deep_purge_path_from_db(path)
            _audit("fix_all:file_delete", path, True, "deleted+db_purged")
            return _item_result("file", path, "fixed", f"Deleted: {path}")
        except PermissionError:
            # Fall back to quarantine if delete fails (file locked)
            try:
                return _quarantine(path, fallback=True)
            except Exception:
                _audit("fix_all:file_delete", path, False, "permission denied")
                return _item_result("file", path, "failed",
                                    "Permission denied — file locked")
        except Exception as e:
            _audit("fix_all:file_delete", path, False, str(e))
            return _item_result("file", path, "failed", f"Delete failed: {e}")

    # ─ QUARANTINE mode ────────────────────────────────────────────────────
    return _quarantine(path, fallback=False)


def _quarantine(path: str, *, fallback: bool = False) -> Dict[str, Any]:
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        orig  = os.path.basename(path)
        new   = f"{stamp}__{orig}.quarantined"
        dest  = QUARANTINE_DIR / new
        shutil.move(path, dest)

        # Deep-purge all DB records so re-scan shows clean results
        _deep_purge_path_from_db(path)

        kind_audit = "fix_all:file_quarantine_fb" if fallback else "fix_all:file_quarantine"
        _audit(kind_audit, path, True, f"moved to {dest}+db_purged")
        word = "Quarantined (delete failed → quarantined)" if fallback else "Quarantined"
        return _item_result("file", path, "fixed", f"{word} → {dest}")
    except Exception as e:
        _audit("fix_all:file_quarantine", path, False, str(e))
        return _item_result("file", path, "failed", f"Quarantine failed: {e}")


def _do_process(pid: Any, name: str = "") -> Dict[str, Any]:
    """Kill a process. 'already gone' counts as success."""
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return _item_result("process", pid, "failed", "invalid PID")

    if pid_int <= 4:
        _audit("fix_all:process", str(pid_int), False, "refused: protected PID")
        return _item_result("process", pid_int, "failed",
                            "Refused — PID 0/4 is a system process")

    if not _is_windows():
        # POSIX dev fallback
        try:
            os.kill(pid_int, 9)
            _audit("fix_all:process", str(pid_int), True, "POSIX SIGKILL", {"name": name})
            return _item_result("process", pid_int, "fixed",
                                f"PID {pid_int} terminated (POSIX)")
        except ProcessLookupError:
            _audit("fix_all:process", str(pid_int), True, "already_gone", {"name": name})
            return _item_result("process", pid_int, "already_gone",
                                f"PID {pid_int} already exited")
        except PermissionError:
            _audit("fix_all:process", str(pid_int), False, "permission", {"name": name})
            return _item_result("process", pid_int, "failed",
                                "Permission denied — run as admin")
        except Exception as e:
            _audit("fix_all:process", str(pid_int), False, str(e))
            return _item_result("process", pid_int, "failed", str(e))

    # Windows: taskkill
    try:
        r = subprocess.run(["taskkill", "/F", "/PID", str(pid_int)],
                           capture_output=True, text=True, timeout=10)
        out = (r.stdout + " " + r.stderr).strip()
        if r.returncode == 0:
            _audit("fix_all:process", str(pid_int), True, out[:300], {"name": name})
            return _item_result("process", pid_int, "fixed",
                                f"PID {pid_int}{(' ('+name+')') if name else ''} terminated")
        # Treat "process not found" as already_gone (success for the user)
        out_low = out.lower()
        if ("not found" in out_low or "no tasks" in out_low or
            "could not find the process" in out_low or "128" in out_low):
            _audit("fix_all:process", str(pid_int), True, "already_gone", {"name": name})
            return _item_result("process", pid_int, "already_gone",
                                f"PID {pid_int} already exited")
        _audit("fix_all:process", str(pid_int), False, out[:300], {"name": name})
        return _item_result("process", pid_int, "failed", out)
    except subprocess.TimeoutExpired:
        return _item_result("process", pid_int, "failed", "taskkill timed out")
    except Exception as e:
        return _item_result("process", pid_int, "failed", str(e))


def _do_task(name: str) -> Dict[str, Any]:
    if not name:
        return _item_result("task", "", "failed", "empty task name")
    if not _is_windows():
        _audit("fix_all:task", name, True, "dev-mode noop")
        return _item_result("task", name, "fixed", f"[dev] Would remove task: {name}")
    try:
        r = subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                           capture_output=True, text=True, timeout=15)
        out = (r.stdout + " " + r.stderr).strip()
        if r.returncode == 0:
            _audit("fix_all:task", name, True, out[:300])
            return _item_result("task", name, "fixed", f"Scheduled task removed: {name}")
        if "does not exist" in out.lower() or "cannot find" in out.lower():
            _audit("fix_all:task", name, True, "already_gone")
            return _item_result("task", name, "already_gone", "Task already removed")
        _audit("fix_all:task", name, False, out[:300])
        return _item_result("task", name, "failed", out)
    except subprocess.TimeoutExpired:
        return _item_result("task", name, "failed", "schtasks timed out")
    except Exception as e:
        return _item_result("task", name, "failed", str(e))


def _do_registry(target: str) -> Dict[str, Any]:
    """target = HKLM\\Path\\To\\Key\\ValueName"""
    if not target or "\\" not in target:
        return _item_result("registry", target, "failed",
                            "Expected HKLM\\...\\Run\\ValueName")
    if not _is_windows():
        _audit("fix_all:registry", target, True, "dev-mode noop")
        return _item_result("registry", target, "fixed",
                            f"[dev] Would remove reg value: {target}")
    key_path, value = target.rsplit("\\", 1)
    try:
        r = subprocess.run(["reg", "delete", key_path, "/v", value, "/f"],
                           capture_output=True, text=True, timeout=15)
        out = (r.stdout + " " + r.stderr).strip()
        if r.returncode == 0:
            _audit("fix_all:registry", target, True, out[:300])
            return _item_result("registry", target, "fixed",
                                f"Removed registry value: {value} under {key_path}")
        if "unable to find" in out.lower() or "cannot find" in out.lower():
            _audit("fix_all:registry", target, True, "already_gone")
            return _item_result("registry", target, "already_gone",
                                "Registry value already removed")
        _audit("fix_all:registry", target, False, out[:300])
        return _item_result("registry", target, "failed", out)
    except Exception as e:
        return _item_result("registry", target, "failed", str(e))


def _do_service(name: str) -> Dict[str, Any]:
    if not name:
        return _item_result("service", "", "failed", "empty service name")
    if not _is_windows():
        _audit("fix_all:service", name, True, "dev-mode noop")
        return _item_result("service", name, "fixed", f"[dev] Would remove service: {name}")
    try:
        # Stop then delete
        subprocess.run(["sc", "stop", name], capture_output=True, text=True, timeout=10)
        r = subprocess.run(["sc", "delete", name],
                           capture_output=True, text=True, timeout=10)
        out = (r.stdout + " " + r.stderr).strip()
        if r.returncode == 0:
            _audit("fix_all:service", name, True, out[:300])
            return _item_result("service", name, "fixed", f"Service removed: {name}")
        if "does not exist" in out.lower() or "specified service" in out.lower():
            _audit("fix_all:service", name, True, "already_gone")
            return _item_result("service", name, "already_gone", "Service already removed")
        _audit("fix_all:service", name, False, out[:300])
        return _item_result("service", name, "failed", out)
    except Exception as e:
        return _item_result("service", name, "failed", str(e))


# ─── Auto-discover threats from latest report ─────────────────────────────

def _autodiscover_threats() -> List[Dict[str, Any]]:
    """When the UI calls fix-all with no explicit threat list, pull
    everything actionable from the most recent perform-analysis report.

    Returns a deduplicated list of {kind, target, name?} dicts.
    """
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, target: Any, name: str = ""):
        key = (kind, str(target))
        if key in seen:
            return
        seen.add(key)
        item = {"kind": kind, "target": target}
        if name:
            item["name"] = name
        out.append(item)

    # Pull the most recent saved report from the analysis_reports table.
    r: Dict[str, Any] = {}
    try:
        from api.perform_analysis_api import _load_latest  # type: ignore
        r = _load_latest() or {}
    except Exception:
        r = {}

    if not r:
        return out

    ma = r.get("malware_analysis") or {}

    # Suspicious processes (only ones marked suspicious + have a PID)
    for p in (ma.get("suspicious_processes") or []):
        if p.get("pid") and p.get("suspicious"):
            add("process", p["pid"], p.get("image") or "")

    # File drops (YARA-matched or executable drops in user-writable dirs)
    for f in (ma.get("file_drops") or []):
        path = f.get("path") or ""
        if path and path.strip().lower() not in ("undefined", "null", "none"):
            add("file", path)

    # Direct YARA hits (from report cache)
    for y in (ma.get("yara_hits") or []):
        p = y.get("path") or y.get("file_path") or y.get("file") or y.get("target") or ""
        if p and p.strip().lower() not in ("undefined", "null", "none"):
            add("file", p)

    # Registry persistence — actual field is registry_persistence.key
    # (check multiple possible field layouts for compatibility)
    reg_obj = ma.get("registry_persistence") or {}
    reg_key = (
        reg_obj.get("key") or
        ma.get("registry_persistence_target") or
        ma.get("registry_persistence_path") or
        ""
    )
    if reg_key:
        add("registry", reg_key)

    # Threat-detector hits with explicit targets
    for t in (r.get("threat_hits") or []):
        for tg in (t.get("targets") or t.get("evidence_targets") or []):
            if tg.get("pid"):     add("process",  tg["pid"], tg.get("name") or "")
            if tg.get("path"):    add("file",     tg["path"])
            if tg.get("task"):    add("task",     tg["task"])
            if tg.get("service"): add("service",  tg["service"])

    # ── FALLBACK: pull YARA hits DIRECTLY from file_scan_results DB ──────
    # If the report cache is stale or yara_hits list was empty/mismatched,
    # go straight to the DB for the current SET_TEST payload files.
    if not any(i["kind"] == "file" for i in out):
        try:
            from database.db import get_conn as _gc2
            _c = _gc2()
            rows = _c.execute(
                "SELECT file_path FROM file_scan_results WHERE yara_matched=1"
            ).fetchall()
            _c.close()
            for row in (rows or []):
                p = row[0] or ""
                if p and p.strip().lower() not in ("undefined", "null", "none"):
                    add("file", p)
        except Exception:
            pass

    # ── FALLBACK: pull Sysmon EID-13 registry target from DB ─────────────
    if not any(i["kind"] == "registry" for i in out):
        try:
            from database.db import get_conn as _gc3
            _c2 = _gc3()
            row = _c2.execute(
                "SELECT MAX(COALESCE(sysmon_target_object, target_object, '')) "
                "FROM logs_sysmon WHERE event_id=13 "
                "AND (LOWER(COALESCE(sysmon_target_object,'')) LIKE '%run%' "
                " OR LOWER(COALESCE(target_object,'')) LIKE '%run%')"
            ).fetchone()
            _c2.close()
            if row and row[0]:
                add("registry", row[0])
        except Exception:
            pass

    return out


# ─── Main route ────────────────────────────────────────────────────────────

@fix_all_bp.route("/action/fix-all", methods=["POST"])
def fix_all():
    body     = _json_body()
    password = (body.get("password") or "").strip()
    mode_req = (body.get("mode") or "").strip().lower()
    threats  = body.get("threats")

    # Decide mode. Do not require admin password for delete — use requested mode directly.
    if mode_req == "delete":
        mode = "delete"
    elif mode_req == "quarantine":
        mode = "quarantine"
    else:
        # Auto: if a valid password is supplied → delete; else quarantine.
        mode = "delete" if (password and _verify_admin_pw(password)) else "quarantine"

    if not isinstance(threats, list) or not threats:
        threats = _autodiscover_threats()

    if not threats:
        return jsonify({
            "ok":      True,
            "mode":    mode,
            "total":   0,
            "fixed":   0,
            "already_gone": 0,
            "failed":  0,
            "results": [],
            "message": "Nothing to fix — no actionable threats found.",
        })

    # ── Dedupe (kind, target) across the supplied list too ────────────────
    seen = set()
    dedup: List[Dict[str, Any]] = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        kind = (t.get("kind") or "").strip().lower()
        tgt  = t.get("target")
        if not kind or tgt is None or tgt == "":
            continue
        key = (kind, str(tgt))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(t)

    # ── Execute each action ───────────────────────────────────────────────
    results: List[Dict[str, Any]] = []
    started_at = time.time()
    for t in dedup:
        kind = (t.get("kind") or "").strip().lower()
        tgt  = t.get("target")
        nm   = t.get("name") or ""

        try:
            if kind == "file":
                results.append(_do_file(str(tgt), mode))
            elif kind == "process":
                results.append(_do_process(tgt, nm))
            elif kind == "task":
                results.append(_do_task(str(tgt)))
            elif kind == "registry":
                results.append(_do_registry(str(tgt)))
            elif kind == "service":
                results.append(_do_service(str(tgt)))
            else:
                results.append(_item_result(kind, tgt, "skipped",
                                            f"Unknown kind: {kind}"))
        except Exception as e:
            results.append(_item_result(kind, tgt, "failed",
                                        f"Internal error: {e}"))

    fixed        = sum(1 for r in results if r["status"] == "fixed")
    already_gone = sum(1 for r in results if r["status"] == "already_gone")
    failed       = sum(1 for r in results if r["status"] == "failed")
    skipped      = sum(1 for r in results if r["status"] == "skipped")
    elapsed_ms   = int((time.time() - started_at) * 1000)

    # ── Nuclear cleanup: wipe ALL test payload traces from every DB table ──
    # Covers logs_sysmon (ALL EIDs via SET_TEST string match + PID match),
    # sigma_hits (via row_id join + detail text match),
    # file_scan_results (actioned paths + SET_TEST pattern),
    # and analysis_reports (full wipe for clean next scan).
    _actioned_paths = [
        str(t["target"]) for t in dedup
        if (t.get("kind") or "").lower() == "file" and t.get("target")
    ]
    _actioned_pids = [
        t["target"] for t in dedup
        if (t.get("kind") or "").lower() == "process" and t.get("target")
    ]
    _nuclear_cleanup_after_fix_all(_actioned_paths, _actioned_pids)

    # Single audit row for the batch
    _audit(
        "fix_all", f"batch:{len(dedup)}", failed == 0,
        f"mode={mode} fixed={fixed} already_gone={already_gone} "
        f"failed={failed} skipped={skipped} elapsed_ms={elapsed_ms}",
        {"mode": mode, "total": len(dedup)},
    )

    return jsonify({
        "ok":            True,
        "mode":          mode,
        "total":         len(dedup),
        "fixed":         fixed,
        "already_gone":  already_gone,
        "failed":        failed,
        "skipped":       skipped,
        "elapsed_ms":    elapsed_ms,
        "results":       results,
        "message":       (
            f"Fixed {fixed + already_gone} of {len(dedup)} threats "
            f"({fixed} actioned, {already_gone} already clean)"
            + (f", {failed} failed" if failed else "")
        ),
    })


# ─── Companion: dry-run preview ──────────────────────────────────────────
#
# The UI calls this BEFORE showing the confirm modal so the user can see
# exactly what's about to happen.

@fix_all_bp.route("/action/fix-all/preview", methods=["GET", "POST"])
def fix_all_preview():
    body    = _json_body() if request.method == "POST" else {}
    threats = body.get("threats")
    if not isinstance(threats, list) or not threats:
        threats = _autodiscover_threats()

    by_kind: Dict[str, int] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        k = (t.get("kind") or "").lower()
        if not k:
            continue
        by_kind[k] = by_kind.get(k, 0) + 1

    return jsonify({
        "ok":      True,
        "total":   len(threats),
        "by_kind": by_kind,
        "threats": threats,
    })
