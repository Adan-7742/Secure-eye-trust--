"""
api/threat_actions_api.py
=========================
User-facing actions for the Threat Detector modal:

  POST /api/threat/whitelist-caller   — mark a caller process as benign
  POST /api/threat/suppress-rule      — dismiss a rule for N days
  POST /api/threat/unsuppress-rule    — re-enable a previously dismissed rule
  GET  /api/threat/whitelist          — list current entries (for settings page)
  POST /api/threat/whitelist/delete   — remove an entry by id

Whitelist entries are persisted in the `threat_whitelist` table and read at
detection time by core/analysis_engine/threat_detector.py.
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

from database.db import get_conn, log_activity
from utils.logger import get_logger

threat_actions_bp = Blueprint("threat_actions", __name__)
log = get_logger("threat_actions_api")


# ── Schema bootstrap ────────────────────────────────────────────────────────

_TBL_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,        -- 'caller_process' or 'rule_suppress'
    value       TEXT NOT NULL,        -- process basename OR rule_id
    rule_id     TEXT,                 -- which rule the user was looking at
    note        TEXT,
    expires_at  TEXT,                 -- ISO timestamp; NULL = never
    added_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tw_kind_value ON threat_whitelist(kind, value);

-- ──────────────────────────────────────────────────────────────────────
-- threat_baseline: when the user clicks "Re-scan Now" after Fix All,
-- we stamp the current timestamp here. The threat detector then ignores
-- any event whose timestamp is at or before this baseline — only NEW
-- activity that arrives after the user's acknowledgement is reported.
--
-- Single-row table (one global baseline). 'scope' is reserved for future
-- per-rule baselines; for now everything writes scope='global'.
-- ──────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_baseline (
    scope        TEXT PRIMARY KEY,    -- 'global' for now (future: rule_id)
    baseline_ts  TEXT NOT NULL,       -- ISO 8601 timestamp
    reason       TEXT,                -- e.g. 'fix_all_rescan', 'manual_ack'
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def ensure_threat_whitelist_table(conn=None):
    close = conn is None
    if conn is None:
        conn = get_conn()
    conn.executescript(_TBL_SCHEMA)
    conn.commit()
    if close:
        conn.close()


def get_threat_baseline_ts(scope: str = "global") -> str:
    """Return the active baseline timestamp (ISO string) or '' if none set.

    The threat detector calls this and adds `AND timestamp > <baseline>`
    to its queries so previously-acknowledged events no longer fire rules.
    """
    try:
        conn = get_conn()
        ensure_threat_whitelist_table(conn)
        r = conn.execute(
            "SELECT baseline_ts FROM threat_baseline WHERE scope = ? LIMIT 1",
            (scope,),
        ).fetchone()
        conn.close()
        return r[0] if r and r[0] else ""
    except Exception:
        return ""


# ── Helpers used by threat_detector.py ──────────────────────────────────────

def get_user_whitelist_callers() -> set[str]:
    """Active 'caller_process' entries — caller basenames the user marked benign."""
    try:
        conn = get_conn()
        ensure_threat_whitelist_table(conn)
        c = conn.cursor()
        c.execute("""
            SELECT value FROM threat_whitelist
            WHERE kind='caller_process'
              AND (expires_at IS NULL OR expires_at > datetime('now'))
        """)
        rows = {r[0].lower() for r in c.fetchall() if r and r[0]}
        conn.close()
        return rows
    except Exception:
        return set()


def is_rule_suppressed(rule_id: str) -> bool:
    """True if the user has dismissed this rule and the suppression is still active."""
    if not rule_id:
        return False
    try:
        conn = get_conn()
        ensure_threat_whitelist_table(conn)
        r = conn.execute("""
            SELECT 1 FROM threat_whitelist
            WHERE kind='rule_suppress' AND value=?
              AND (expires_at IS NULL OR expires_at > datetime('now'))
            LIMIT 1
        """, (rule_id,)).fetchone()
        conn.close()
        return bool(r)
    except Exception:
        return False


# ── API endpoints ───────────────────────────────────────────────────────────

@threat_actions_bp.route("/threat/whitelist-caller", methods=["POST"])
def whitelist_caller():
    """
    Body: { caller: 'code.exe', rule_id: 'DLL_INJECT_LSASS_HANDLE',
            days: 0 (never expire) | 30, note: 'VS Code credential helper' }
    """
    body    = request.get_json(silent=True) or {}
    caller  = (body.get("caller") or "").strip().lower()
    rule_id = (body.get("rule_id") or "").strip()
    days    = int(body.get("days") or 0)
    note    = (body.get("note") or "").strip() or None

    if not caller:
        return jsonify({"ok": False, "error": "Missing 'caller'"}), 400
    if "\\" in caller or "/" in caller:
        # Defensive — we only store basenames; strip any path
        caller = caller.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]

    expires_at = None
    if days > 0:
        expires_at = (datetime.now() + timedelta(days=days)).isoformat()

    conn = get_conn()
    ensure_threat_whitelist_table(conn)
    conn.execute("""
        INSERT INTO threat_whitelist (kind, value, rule_id, note, expires_at)
        VALUES ('caller_process', ?, ?, ?, ?)
    """, (caller, rule_id or None, note, expires_at))
    conn.commit()
    conn.close()

    log_activity("threat_whitelist_caller", {
        "caller": caller, "rule_id": rule_id, "days": days, "note": note,
    })
    log.info(f"Whitelisted caller '{caller}' for rule '{rule_id}' ({'permanent' if days==0 else f'{days}d'})")

    return jsonify({
        "ok": True,
        "message": (f"'{caller}' marked benign — this detection will not fire "
                    f"for it again" + (f" for {days} days." if days>0 else " (permanent).")),
    })


@threat_actions_bp.route("/threat/suppress-rule", methods=["POST"])
def suppress_rule():
    """
    Body: { rule_id: 'DLL_INJECT_LSASS_HANDLE', days: 30, note: '...' }
    Dismisses an entire rule for N days. Use this when the user has investigated
    a finding and wants to acknowledge it.
    """
    body    = request.get_json(silent=True) or {}
    rule_id = (body.get("rule_id") or "").strip()
    days    = int(body.get("days") or 30)
    note    = (body.get("note") or "").strip() or None

    if not rule_id:
        return jsonify({"ok": False, "error": "Missing 'rule_id'"}), 400
    if days < 1:
        days = 1
    if days > 365:
        days = 365

    expires_at = (datetime.now() + timedelta(days=days)).isoformat()

    conn = get_conn()
    ensure_threat_whitelist_table(conn)
    conn.execute("""
        INSERT INTO threat_whitelist (kind, value, rule_id, note, expires_at)
        VALUES ('rule_suppress', ?, ?, ?, ?)
    """, (rule_id, rule_id, note, expires_at))
    conn.commit()
    conn.close()

    log_activity("threat_suppress_rule", {
        "rule_id": rule_id, "days": days, "note": note,
    })
    log.info(f"Suppressed rule '{rule_id}' for {days} days")

    return jsonify({
        "ok": True,
        "message": f"Rule '{rule_id}' dismissed for {days} days.",
    })


@threat_actions_bp.route("/threat/unsuppress-rule", methods=["POST"])
def unsuppress_rule():
    body    = request.get_json(silent=True) or {}
    rule_id = (body.get("rule_id") or "").strip()
    if not rule_id:
        return jsonify({"ok": False, "error": "Missing 'rule_id'"}), 400

    conn = get_conn()
    ensure_threat_whitelist_table(conn)
    conn.execute("""
        DELETE FROM threat_whitelist
        WHERE kind='rule_suppress' AND value=?
    """, (rule_id,))
    conn.commit()
    conn.close()

    log_activity("threat_unsuppress_rule", {"rule_id": rule_id})
    return jsonify({"ok": True, "message": f"Rule '{rule_id}' re-enabled."})


@threat_actions_bp.route("/threat/whitelist", methods=["GET"])
def list_whitelist():
    """Return all whitelist entries (active and expired) for a settings page."""
    conn = get_conn()
    ensure_threat_whitelist_table(conn)
    c = conn.cursor()
    c.execute("""
        SELECT id, kind, value, rule_id, note, expires_at, added_at,
               CASE
                 WHEN expires_at IS NULL THEN 1
                 WHEN expires_at > datetime('now') THEN 1
                 ELSE 0
               END AS is_active
        FROM threat_whitelist
        ORDER BY added_at DESC
    """)
    rows = [{
        "id":         r[0],
        "kind":       r[1],
        "value":      r[2],
        "rule_id":    r[3],
        "note":       r[4],
        "expires_at": r[5],
        "added_at":   r[6],
        "is_active":  bool(r[7]),
    } for r in c.fetchall()]
    conn.close()
    return jsonify({"ok": True, "entries": rows, "count": len(rows)})


@threat_actions_bp.route("/threat/whitelist/delete", methods=["POST"])
def delete_whitelist_entry():
    body  = request.get_json(silent=True) or {}
    eid   = body.get("id")
    if not eid:
        return jsonify({"ok": False, "error": "Missing 'id'"}), 400
    conn = get_conn()
    conn.execute("DELETE FROM threat_whitelist WHERE id=?", (eid,))
    conn.commit()
    conn.close()
    log_activity("threat_whitelist_delete", {"id": eid})
    return jsonify({"ok": True, "message": "Entry removed."})


# ─────────────────────────────────────────────────────────────────────────────
# RUN FIX SCRIPT — actually execute the PowerShell remediation script that
# the Explain modal shows. Previously the user could only "Copy to clipboard"
# and paste into an Admin terminal manually. Now the [▶ Run Now] button POSTs
# the script here and we shell out to PowerShell with the appropriate guards.
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import platform

# Block-list of obviously dangerous commands. The fix scripts come from the
# Explain AI's `powershell_commands[]` array which is meant to be safe, but
# we add belt-and-braces defense in case the AI hallucinates a destructive
# command or someone tampers with the request.
_DANGEROUS_TOKENS = [
    # Format / wipe
    "format ",       "format-volume",
    "remove-item c:\\", "remove-item /",  "rm -rf /",  "rd /s /q c:\\",
    "del /s /q c:\\",
    "diskpart",      "clean all",
    # User/account destruction
    "net user administrator /delete",
    "net localgroup administrators /delete",
    # Shadow copy wipe (ransomware pattern)
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    # Bootloader / BCD
    "bcdedit /deletevalue",
    "bcdedit /delete",
    # Encryption / ransomware-y
    "cipher /w:",
    "manage-bde -off",
    # Network destruction
    "netsh winsock reset",  # Allowed *in* the recipe but blocked here for safety
    "ipconfig /flushdns ; shutdown",
    # Reboot inside a fix is sketchy
    "shutdown /r /t 0",
    "shutdown /s /t 0",
    "stop-computer",
    "restart-computer",
    # Disable Defender / firewall completely
    "set-mppreference -disablerealtimemonitoring $true",
    "netsh advfirewall set allprofiles state off",
]

# Allow-list of well-known prefixes. We don't require these — anything that
# isn't on the deny-list is permitted — but seeing only allow-listed prefixes
# is a strong signal that the script is safe.
_KNOWN_SAFE_PREFIXES = [
    "get-",          # Get-WinEvent, Get-Process, Get-Service, Get-MpThreat
    "where-",
    "select-",
    "format-",
    "out-",
    "wevtutil",      # wevtutil qe / cl
    "reg query",     # Registry inspection only
    "auditpol",      # Audit policy inspection
    "secedit /export",
    "powershell get-",
    "eventvwr",
    "tasklist",
    "tasklist /v",
    "sc query",
    "sc qc",
    "schtasks /query",
    "whoami",
    "net session",
    "net statistics",
    "ipconfig /all",
    "netstat",
    "tracert",
    "ping",
    "nslookup",
    "systeminfo",
    "driverquery",
    "echo",
    "#",             # Comments are obviously fine
]


def _script_is_safe(script: str) -> tuple[bool, str]:
    """Return (ok, reason). False if the script contains anything on the deny-list."""
    if not script or not script.strip():
        return False, "Empty script"
    lowered = script.lower()
    for token in _DANGEROUS_TOKENS:
        if token in lowered:
            return False, f"Refused: script contains a dangerous command ('{token.strip()}')"
    return True, ""


@threat_actions_bp.route("/threat/run-fix-script", methods=["POST"])
def run_fix_script():
    """
    Execute the PowerShell remediation script that the Explain modal shows.

    Body:
      {
        "script":      "Get-WinEvent ...\\nGet-MpThreat ...",
        "event_id":    "4625",
        "rule_id":     "DLL_INJECT_LSASS_HANDLE",
        "confirmed":   true        # client must echo this
      }

    Behavior:
      * Required: confirmed=true (the UI prompts the user with the actual script
        before this endpoint is hit).
      * Deny-list check: scripts containing format, vssadmin delete, etc. are refused.
      * On Windows: runs via powershell.exe -NoProfile -ExecutionPolicy Bypass
        with a 60s timeout. stdout/stderr returned to the client.
      * On non-Windows: dry-run, echoes the script back (for developer testing).
      * All runs are logged to the audit trail.
    """
    body      = request.get_json(silent=True) or {}
    script    = (body.get("script") or "").strip()
    event_id  = str(body.get("event_id") or "").strip()
    rule_id   = (body.get("rule_id") or "").strip()
    confirmed = bool(body.get("confirmed"))

    if not script:
        return jsonify({"ok": False, "error": "Missing 'script'"}), 400
    if not confirmed:
        return jsonify({
            "ok":      False,
            "error":   "Client must set confirmed=true after showing the script to the user",
            "preview": script[:500],
        }), 400

    # Safety check — refuse known-destructive commands even with confirmation
    safe, reason = _script_is_safe(script)
    if not safe:
        log_activity("fix_script_blocked", {
            "event_id": event_id, "rule_id": rule_id, "reason": reason,
            "script":   script[:300],
        })
        log.warning(f"Refused fix script for rule {rule_id}: {reason}")
        return jsonify({"ok": False, "error": reason, "blocked": True}), 403

    is_windows = platform.system() == "Windows"

    if not is_windows:
        # Developer / non-Windows host — don't actually run anything
        log_activity("fix_script_run", {
            "event_id": event_id, "rule_id": rule_id,
            "host":     platform.system(),
            "mode":     "dev-noop",
            "script":   script[:300],
        })
        return jsonify({
            "ok":     True,
            "ran":    False,
            "mode":   "dev-noop",
            "stdout": "[dev mode — this host is not Windows]\n" + script,
            "stderr": "",
            "rc":     0,
            "message": "Dry run completed. Run on Windows to execute the actual commands.",
        })

    # ── Windows: execute via PowerShell with safety guards ─────────────────
    try:
        # We pass the entire script via -Command. Wrapping in a try/catch in
        # PowerShell so syntax errors surface in stderr instead of crashing
        # the host.
        ps_wrapped = (
            "$ErrorActionPreference = 'Continue';\n"
            "try {\n" + script + "\n} catch { Write-Error $_; exit 1 }"
        )
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_wrapped,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
        ok       = (proc.returncode == 0)
        stdout   = (proc.stdout or "")[:8000]
        stderr   = (proc.stderr or "")[:8000]
        rc       = proc.returncode

        log_activity("fix_script_run", {
            "event_id": event_id, "rule_id": rule_id,
            "rc":       rc, "ok": ok,
            "script":   script[:300],
            "stdout":   stdout[:300],
            "stderr":   stderr[:300],
        })
        log.info(f"Ran fix script for rule {rule_id} (rc={rc}, ok={ok})")

        return jsonify({
            "ok":      ok,
            "ran":     True,
            "rc":      rc,
            "stdout":  stdout,
            "stderr":  stderr,
            "message": (
                f"Script executed (exit code {rc})."
                if ok else f"Script exited with code {rc}. See stderr."
            ),
        })

    except subprocess.TimeoutExpired:
        log_activity("fix_script_timeout", {
            "event_id": event_id, "rule_id": rule_id,
            "script":   script[:300],
        })
        return jsonify({
            "ok":    False,
            "error": "Script timed out after 60 seconds",
        }), 504

    except FileNotFoundError:
        return jsonify({
            "ok":    False,
            "error": "powershell.exe not found on this system",
        }), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        log_activity("fix_script_error", {
            "event_id": event_id, "rule_id": rule_id,
            "error":    str(e),
        })
        return jsonify({"ok": False, "error": str(e)}), 500



# ─────────────────────────────────────────────────────────────────────────────
# THREAT BASELINE — only NEW events count after acknowledgement
#
# Problem this solves:
#   Threat Detector Hits like "Scheduled Task Modified", "Privilege Escalation
#   Spike", "Account & Group Enumeration" are *event-log driven*. They count
#   rows in logs_security / logs_system / logs_application / logs_sysmon over
#   a sliding time window. Fix All can delete the malicious files/processes,
#   but the event-log rows themselves are part of Windows' audit trail and
#   stay on disk. So a fresh analysis keeps reporting the same hits.
#
#   The user wants: "old ones gone, new ones still detected".
#
# Solution:
#   Stamp a baseline timestamp at the moment the user clicks "Re-scan Now"
#   in the Fix All results modal. The detector adds an extra
#   `AND timestamp > <baseline>` clause to every threat-rule query, so
#   pre-acknowledgement events no longer feed the counters. As soon as new
#   activity arrives after the baseline, those rules can fire again on the
#   genuinely new evidence.
# ─────────────────────────────────────────────────────────────────────────────

@threat_actions_bp.route("/threat/acknowledge-current", methods=["POST"])
def acknowledge_current_baseline():
    """Mark every threat detector event seen so far as "acknowledged".

    Body (all optional):
        { reason: 'fix_all_rescan' | 'manual_ack' | ...,
          scope:  'global' (default) }

    After this call, run_threat_detection() will only count events whose
    timestamp is strictly greater than the stored baseline.
    """
    body   = request.get_json(silent=True) or {}
    scope  = (body.get("scope") or "global").strip() or "global"
    reason = (body.get("reason") or "manual_ack").strip()

    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_conn()
        ensure_threat_whitelist_table(conn)
        # Upsert — one row per scope. SQLite's ON CONFLICT (3.24+) handles it.
        conn.execute("""
            INSERT INTO threat_baseline (scope, baseline_ts, reason, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(scope) DO UPDATE SET
                baseline_ts = excluded.baseline_ts,
                reason      = excluded.reason,
                updated_at  = excluded.updated_at
        """, (scope, now_iso, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"acknowledge_current_baseline failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

    log_activity("threat_baseline_set", {
        "scope": scope, "baseline_ts": now_iso, "reason": reason,
    })
    log.info(f"Threat baseline ({scope}) set to {now_iso} — reason={reason}")

    return jsonify({
        "ok":          True,
        "scope":       scope,
        "baseline_ts": now_iso,
        "reason":      reason,
        "message":     (
            "Current threat events acknowledged. Only NEW activity "
            f"after {now_iso} will be reported."
        ),
    })


@threat_actions_bp.route("/threat/baseline", methods=["GET"])
def get_baseline():
    """Return the active baseline timestamp (or empty string if none set)."""
    scope = (request.args.get("scope") or "global").strip() or "global"
    ts    = get_threat_baseline_ts(scope)
    return jsonify({
        "ok":          True,
        "scope":       scope,
        "baseline_ts": ts,
        "active":      bool(ts),
    })


@threat_actions_bp.route("/threat/baseline/clear", methods=["POST"])
def clear_baseline():
    """Forget the baseline — every event since the start of the retention
    window will be considered again. Useful after a system upgrade or when
    the operator wants a full historical view.
    """
    body  = request.get_json(silent=True) or {}
    scope = (body.get("scope") or "global").strip() or "global"
    try:
        conn = get_conn()
        ensure_threat_whitelist_table(conn)
        conn.execute("DELETE FROM threat_baseline WHERE scope = ?", (scope,))
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    log_activity("threat_baseline_clear", {"scope": scope})
    return jsonify({"ok": True, "scope": scope,
                    "message": f"Baseline ({scope}) cleared."})
