"""
api/reports_api.py
==================
Blueprint: /api/reports/*

Generates real reports from live system data.
All report data pulled from SQLite + psutil — no dummy data.

ENDPOINTS:
  POST /api/reports/generate        → generate a report, returns report obj
  GET  /api/reports/list             → list all generated reports this session
  POST /api/reports/export           → export report as html / json / csv
  GET  /api/reports/preview/<rid>    → get report data as JSON for preview

FR08-03: Compliance report now runs real NIST SP 800-53 / CIS Controls v8
         checks derived from live Windows Event Log data in the database.
"""

import json, time, os, csv, io
from datetime import datetime
from flask import Blueprint, jsonify, request, Response
from api.auth_api import _verify_admin_pw
from database.db import get_conn, CATEGORIES

reports_bp    = Blueprint("reports", __name__)
_report_store = []   # in-memory session store (no file I/O needed)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _date():
    return datetime.now().strftime("%Y-%m-%d")

def _new_id():
    return f"rpt_{int(time.time()*1000)}"

def _log_stats():
    """Pull real counts from the DB for every category."""
    conn = get_conn(); c = conn.cursor()
    result = {}
    for cat in CATEGORIES:
        try:
            c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
            total = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level IN ('ERROR','CRITICAL','FAILURE')")
            errors = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level='WARNING'")
            warnings = c.fetchone()[0]
            result[cat] = {"total": total, "errors": errors, "warnings": warnings}
        except:
            result[cat] = {"total": 0, "errors": 0, "warnings": 0}
    conn.close()
    return result

def _sys_stats():
    """CPU / RAM / Disk snapshot."""
    try:
        import psutil
        cpu  = psutil.cpu_percent(interval=0.3)
        vm   = psutil.virtual_memory()
        disk = psutil.disk_usage('C:\\' if os.name == 'nt' else '/')
        return {
            "cpu_percent":    round(cpu, 1),
            "ram_percent":    round(vm.percent, 1),
            "ram_used_gb":    round(vm.used  / 1e9, 1),
            "ram_total_gb":   round(vm.total / 1e9, 1),
            "disk_percent":   round(disk.percent, 1),
            "disk_free_gb":   round(disk.free  / 1e9, 1),
            "disk_total_gb":  round(disk.total / 1e9, 1),
        }
    except:
        return {}

def _security_events():
    """Pull top security events from the security log."""
    conn = get_conn(); c = conn.cursor()
    out = {"failed_logons": 0, "lockouts": 0, "priv_events": 0, "top_events": []}
    try:
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4625")
        out["failed_logons"] = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4740")
        out["lockouts"] = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id IN (4672,4673)")
        out["priv_events"] = c.fetchone()[0]
        c.execute("""SELECT event_id, COUNT(*) cnt, level FROM logs_security
                     GROUP BY event_id ORDER BY cnt DESC LIMIT 10""")
        out["top_events"] = [{"event_id": r[0], "count": r[1], "level": r[2]} for r in c.fetchall()]
    except:
        pass
    conn.close()
    return out

def _net_snapshot():
    """Live connection count."""
    try:
        import psutil
        conns = psutil.net_connections(kind='inet')
        return {"connection_count": len(conns)}
    except:
        return {"connection_count": 0}

def _recent_errors(limit=20):
    """Most recent critical/error events across all logs."""
    conn = get_conn(); c = conn.cursor()
    rows = []
    for cat in CATEGORIES:
        try:
            c.execute(f"""SELECT timestamp, level, source, message, event_id,
                                 '{cat}' as category
                          FROM logs_{cat}
                          WHERE level IN ('ERROR','CRITICAL','FAILURE')
                          ORDER BY timestamp DESC LIMIT {limit}""")
            rows += [dict(zip(['timestamp','level','source','message','event_id','category'], r))
                     for r in c.fetchall()]
        except:
            pass
    conn.close()
    rows.sort(key=lambda x: x.get('timestamp') or '', reverse=True)
    return rows[:limit]


# ══════════════════════════════════════════════════════════════════════════════
# FR08-03 — NIST SP 800-53 / CIS Controls v8 Compliance Engine
# ══════════════════════════════════════════════════════════════════════════════
#
# Each control is evaluated by querying live event data already stored in the
# SQLite database by the collectors (windows_reader, stream_collector, etc.).
#
# Result schema per control:
#   {
#     "id":          str   — NIST control ID  (e.g. "AC-7")
#     "cis":         str   — CIS Control mapping (e.g. "CIS 5.2")
#     "family":      str   — Control family name
#     "title":       str   — Short title
#     "description": str   — What this control checks
#     "status":      str   — "PASS" | "FAIL" | "WARN" | "UNKNOWN"
#     "finding":     str   — Human-readable finding from live data
#     "evidence":    str   — Raw metric used to decide status
#     "remediation": str   — How to fix a FAIL/WARN
#   }
# ──────────────────────────────────────────────────────────────────────────────

def _count(c, table, where="1=1"):
    """Safe COUNT helper — returns 0 if table doesn't exist."""
    try:
        c.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}")
        return c.fetchone()[0] or 0
    except Exception:
        return -1   # -1 = table missing / unknown


def _run_compliance_checks() -> dict:
    """
    Execute all NIST/CIS checks against live DB data.
    Returns a dict with per-family results and rolled-up score.
    """
    conn = get_conn()
    c    = conn.cursor()

    controls = []

    # ── FAMILY: AC — Access Control ───────────────────────────────────────────

    # AC-2 / CIS 5.1 — Account Management: detect new account creations
    new_accounts = _count(c, "logs_security", "event_id IN (4720, 4726)")
    if new_accounts == -1:
        controls.append(_ctrl("AC-2", "CIS 5.1", "Access Control", "Account Management",
            "Monitor user account creation and deletion events (EID 4720, 4726).",
            "UNKNOWN", "Security log unavailable — run as Administrator.",
            "N/A", "Fetch Security logs as Administrator to enable this check."))
    elif new_accounts > 10:
        controls.append(_ctrl("AC-2", "CIS 5.1", "Access Control", "Account Management",
            "Monitor user account creation and deletion events (EID 4720, 4726).",
            "WARN", f"{new_accounts} account creation/deletion events detected.",
            f"EID 4720/4726 count = {new_accounts}",
            "Review all newly created accounts. Disable any unauthorised accounts immediately."))
    else:
        controls.append(_ctrl("AC-2", "CIS 5.1", "Access Control", "Account Management",
            "Monitor user account creation and deletion events (EID 4720, 4726).",
            "PASS", f"{new_accounts} account creation/deletion events — within normal range.",
            f"EID 4720/4726 count = {new_accounts}", ""))

    # AC-7 / CIS 4.1 — Unsuccessful Logon Attempts
    failed_logons = _count(c, "logs_security", "event_id=4625")
    lockouts      = _count(c, "logs_security", "event_id=4740")
    if failed_logons == -1:
        controls.append(_ctrl("AC-7", "CIS 4.1", "Access Control", "Unsuccessful Logon Attempts",
            "Enforce limits on consecutive failed logon attempts (EID 4625, 4740).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif failed_logons > 50 or lockouts > 0:
        status = "FAIL" if lockouts > 0 or failed_logons > 200 else "WARN"
        controls.append(_ctrl("AC-7", "CIS 4.1", "Access Control", "Unsuccessful Logon Attempts",
            "Enforce limits on consecutive failed logon attempts (EID 4625, 4740).",
            status,
            f"{failed_logons} failed logons and {lockouts} account lockout(s) detected.",
            f"EID 4625={failed_logons}, EID 4740={lockouts}",
            "Investigate source IPs for brute-force attempts. Verify account lockout policy is enabled "
            "(Computer Configuration → Windows Settings → Security Settings → Account Policies → "
            "Account Lockout Policy). Recommended: lockout threshold ≤ 5 attempts."))
    else:
        controls.append(_ctrl("AC-7", "CIS 4.1", "Access Control", "Unsuccessful Logon Attempts",
            "Enforce limits on consecutive failed logon attempts (EID 4625, 4740).",
            "PASS", f"{failed_logons} failed logons — no lockouts triggered.",
            f"EID 4625={failed_logons}, EID 4740={lockouts}", ""))

    # AC-6 / CIS 5.4 — Least Privilege: special privilege assignments
    priv_assigns = _count(c, "logs_security", "event_id IN (4672, 4673)")
    admin_group  = _count(c, "logs_security", "event_id IN (4728, 4732)")
    if priv_assigns == -1:
        controls.append(_ctrl("AC-6", "CIS 5.4", "Access Control", "Least Privilege",
            "Detect privilege assignments and admin group changes (EID 4672, 4673, 4728).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif admin_group > 5:
        controls.append(_ctrl("AC-6", "CIS 5.4", "Access Control", "Least Privilege",
            "Detect privilege assignments and admin group changes (EID 4672, 4673, 4728).",
            "FAIL", f"{admin_group} admin group membership change(s) detected.",
            f"EID 4672/4673={priv_assigns}, EID 4728/4732={admin_group}",
            "Review all admin group changes. Apply least-privilege principle — users should "
            "not have permanent admin rights. Use separate admin accounts for elevated tasks."))
    else:
        controls.append(_ctrl("AC-6", "CIS 5.4", "Access Control", "Least Privilege",
            "Detect privilege assignments and admin group changes (EID 4672, 4673, 4728).",
            "PASS" if admin_group == 0 else "WARN",
            f"{priv_assigns} privilege assignments, {admin_group} admin group changes.",
            f"EID 4672/4673={priv_assigns}, EID 4728/4732={admin_group}",
            "Verify each admin group change was authorised." if admin_group > 0 else ""))

    # AC-17 / CIS 12.1 — Remote Access (RDP logon events)
    rdp_logons = _count(c, "logs_security", "event_id IN (4624) AND source LIKE '%RemoteInteractive%'")
    rdp_fail   = _count(c, "logs_security", "event_id=4625 AND source LIKE '%RemoteInteractive%'")
    if rdp_logons == -1:
        controls.append(_ctrl("AC-17", "CIS 12.1", "Access Control", "Remote Access Monitoring",
            "Detect remote interactive (RDP) logon sessions (EID 4624 type 10).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif rdp_fail > 20:
        controls.append(_ctrl("AC-17", "CIS 12.1", "Access Control", "Remote Access Monitoring",
            "Detect remote interactive (RDP) logon sessions (EID 4624 type 10).",
            "WARN", f"{rdp_fail} failed RDP logon attempts — possible external brute-force.",
            f"RDP success={rdp_logons}, RDP fail={rdp_fail}",
            "Block RDP from the internet. Use VPN + MFA for remote access. "
            "Consider changing the RDP port and enabling NLA."))
    else:
        controls.append(_ctrl("AC-17", "CIS 12.1", "Access Control", "Remote Access Monitoring",
            "Detect remote interactive (RDP) logon sessions (EID 4624 type 10).",
            "PASS", f"{rdp_logons} RDP sessions, {rdp_fail} failures — within acceptable range.",
            f"RDP success={rdp_logons}, RDP fail={rdp_fail}", ""))

    # ── FAMILY: AU — Audit and Accountability ─────────────────────────────────

    # AU-2 / CIS 8.2 — Audit Events: check if audit policy was changed
    audit_changes = _count(c, "logs_security", "event_id=4719")
    if audit_changes == -1:
        controls.append(_ctrl("AU-2", "CIS 8.2", "Audit & Accountability", "Audit Policy Changes",
            "Detect changes to Windows audit policy (EID 4719).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif audit_changes > 0:
        controls.append(_ctrl("AU-2", "CIS 8.2", "Audit & Accountability", "Audit Policy Changes",
            "Detect changes to Windows audit policy (EID 4719).",
            "FAIL", f"{audit_changes} audit policy change(s) detected — logging may have been tampered with.",
            f"EID 4719 count = {audit_changes}",
            "Investigate who changed the audit policy and when. Restore audit policy to "
            "approved baseline. Protect audit settings with Group Policy."))
    else:
        controls.append(_ctrl("AU-2", "CIS 8.2", "Audit & Accountability", "Audit Policy Changes",
            "Detect changes to Windows audit policy (EID 4719).",
            "PASS", "No audit policy changes detected.",
            f"EID 4719 count = 0", ""))

    # AU-3 / CIS 8.5 — Audit Record Content: check log volume
    sec_total = _count(c, "logs_security")
    app_total = _count(c, "logs_application")
    sys_total = _count(c, "logs_system")
    total_ev  = max(sec_total, 0) + max(app_total, 0) + max(sys_total, 0)
    if total_ev == 0:
        controls.append(_ctrl("AU-3", "CIS 8.5", "Audit & Accountability", "Audit Log Collection",
            "Verify that Windows Event Logs (Application, System, Security) are actively collecting.",
            "WARN", "No event log data found — logs may not have been fetched yet.",
            f"security={sec_total}, application={app_total}, system={sys_total}",
            "Click 'Fetch Logs' in the dashboard to collect Windows Event Log data."))
    else:
        controls.append(_ctrl("AU-3", "CIS 8.5", "Audit & Accountability", "Audit Log Collection",
            "Verify that Windows Event Logs (Application, System, Security) are actively collecting.",
            "PASS", f"{total_ev:,} events collected across Security, Application, and System logs.",
            f"security={sec_total}, application={app_total}, system={sys_total}", ""))

    # AU-9 / CIS 8.3 — Audit Log Integrity: detect log clearing
    log_cleared = _count(c, "logs_security", "event_id IN (1102, 517)")
    sys_cleared = _count(c, "logs_system",   "event_id=104")
    if log_cleared == -1 and sys_cleared == -1:
        controls.append(_ctrl("AU-9", "CIS 8.3", "Audit & Accountability", "Audit Log Integrity",
            "Detect Windows Event Log clearing events (EID 1102, 517, 104).",
            "UNKNOWN", "Log tables unavailable.", "N/A",
            "Ensure logs have been fetched before running compliance checks."))
    elif (log_cleared or 0) > 0 or (sys_cleared or 0) > 0:
        controls.append(_ctrl("AU-9", "CIS 8.3", "Audit & Accountability", "Audit Log Integrity",
            "Detect Windows Event Log clearing events (EID 1102, 517, 104).",
            "FAIL",
            f"Event logs were cleared: {(log_cleared or 0)} Security clearing event(s), "
            f"{(sys_cleared or 0)} System log clearing event(s). This is a critical indicator of tampering.",
            f"EID 1102/517={log_cleared}, EID 104={sys_cleared}",
            "Investigate immediately — log clearing is a common attacker anti-forensics technique. "
            "Enable Windows Event Forwarding to a remote SIEM to protect log integrity."))
    else:
        controls.append(_ctrl("AU-9", "CIS 8.3", "Audit & Accountability", "Audit Log Integrity",
            "Detect Windows Event Log clearing events (EID 1102, 517, 104).",
            "PASS", "No log clearing events detected.",
            f"EID 1102/517={log_cleared}, EID 104={sys_cleared}", ""))

    # ── FAMILY: CM — Configuration Management ─────────────────────────────────

    # CM-3 / CIS 4.1 — Configuration Change Control: registry modifications
    reg_changes = _count(c, "logs_security", "event_id=4657")
    if reg_changes == -1:
        controls.append(_ctrl("CM-3", "CIS 4.1", "Config Management", "Registry Change Control",
            "Detect unauthorised Windows registry modifications (EID 4657).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif reg_changes > 50:
        controls.append(_ctrl("CM-3", "CIS 4.1", "Config Management", "Registry Change Control",
            "Detect unauthorised Windows registry modifications (EID 4657).",
            "WARN", f"{reg_changes} registry modification events detected — review for unauthorised changes.",
            f"EID 4657 count = {reg_changes}",
            "Review registry changes in Event Viewer. Focus on HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            "and other autorun keys for persistence mechanisms."))
    else:
        controls.append(_ctrl("CM-3", "CIS 4.1", "Config Management", "Registry Change Control",
            "Detect unauthorised Windows registry modifications (EID 4657).",
            "PASS" if reg_changes >= 0 else "UNKNOWN",
            f"{max(reg_changes, 0)} registry changes — within normal range.",
            f"EID 4657 count = {reg_changes}", ""))

    # CM-7 / CIS 4.8 — Scheduled Task Management
    sched_tasks = _count(c, "logs_security", "event_id IN (4698, 4702)")
    if sched_tasks == -1:
        controls.append(_ctrl("CM-7", "CIS 4.8", "Config Management", "Scheduled Task Management",
            "Detect new or modified scheduled tasks (EID 4698, 4702).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif sched_tasks > 10:
        controls.append(_ctrl("CM-7", "CIS 4.8", "Config Management", "Scheduled Task Management",
            "Detect new or modified scheduled tasks (EID 4698, 4702).",
            "WARN", f"{sched_tasks} scheduled task creation/modification events — verify each is authorised.",
            f"EID 4698/4702 count = {sched_tasks}",
            "Run 'schtasks /query /fo LIST /v' to review all scheduled tasks. "
            "Remove any unrecognised tasks — they are a common attacker persistence mechanism."))
    else:
        controls.append(_ctrl("CM-7", "CIS 4.8", "Config Management", "Scheduled Task Management",
            "Detect new or modified scheduled tasks (EID 4698, 4702).",
            "PASS" if sched_tasks >= 0 else "UNKNOWN",
            f"{max(sched_tasks, 0)} scheduled task events — no anomalies detected.",
            f"EID 4698/4702 count = {sched_tasks}", ""))

    # ── FAMILY: IA — Identification and Authentication ────────────────────────

    # IA-5 / CIS 5.2 — Authenticator Management: password reset events
    pw_resets = _count(c, "logs_security", "event_id IN (4723, 4724)")
    if pw_resets == -1:
        controls.append(_ctrl("IA-5", "CIS 5.2", "Identification & Auth", "Authenticator Management",
            "Monitor password reset events (EID 4723, 4724).",
            "UNKNOWN", "Security log unavailable.", "N/A",
            "Fetch Security logs as Administrator to enable this check."))
    elif pw_resets > 20:
        controls.append(_ctrl("IA-5", "CIS 5.2", "Identification & Auth", "Authenticator Management",
            "Monitor password reset events (EID 4723, 4724).",
            "WARN", f"{pw_resets} password reset events — elevated volume warrants review.",
            f"EID 4723/4724 count = {pw_resets}",
            "Review who reset passwords and whether the activity was authorised. "
            "Bulk resets may indicate an account takeover or insider threat."))
    else:
        controls.append(_ctrl("IA-5", "CIS 5.2", "Identification & Auth", "Authenticator Management",
            "Monitor password reset events (EID 4723, 4724).",
            "PASS" if pw_resets >= 0 else "UNKNOWN",
            f"{max(pw_resets, 0)} password reset events — normal range.",
            f"EID 4723/4724 count = {pw_resets}", ""))

    # ── FAMILY: SC — System and Communications Protection ─────────────────────

    # SC-5 / CIS 13.1 — Windows Defender / AV Status
    defender_alerts = _count(c, "logs_application",
        "source LIKE '%WinDefend%' AND level IN ('ERROR','CRITICAL','WARNING')")
    if defender_alerts == -1:
        controls.append(_ctrl("SC-5", "CIS 13.1", "System Protection", "Malware Defences",
            "Verify Windows Defender is active and has not raised critical alerts.",
            "UNKNOWN", "Application log unavailable.", "N/A",
            "Fetch Application logs to enable this check."))
    elif defender_alerts > 0:
        controls.append(_ctrl("SC-5", "CIS 13.1", "System Protection", "Malware Defences",
            "Verify Windows Defender is active and has not raised critical alerts.",
            "FAIL" if defender_alerts > 5 else "WARN",
            f"{defender_alerts} Windows Defender alert(s) — malware detections or protection issues.",
            f"WinDefend errors/warnings = {defender_alerts}",
            "Open Windows Security Centre and review the Protection History. "
            "Ensure Defender definitions are up to date. Quarantine or remove any detected threats."))
    else:
        controls.append(_ctrl("SC-5", "CIS 13.1", "System Protection", "Malware Defences",
            "Verify Windows Defender is active and has not raised critical alerts.",
            "PASS", "No Windows Defender error or warning events detected.",
            f"WinDefend errors/warnings = 0", ""))

    # ── FAMILY: SI — System and Information Integrity ─────────────────────────

    # SI-2 / CIS 7.3 — Patch Management: Windows Update failures
    wu_failures = _count(c, "logs_windows_update",
        "level IN ('ERROR','CRITICAL','FAILURE')")
    wu_success  = _count(c, "logs_windows_update",
        "level IN ('INFO','SUCCESS')")
    if wu_failures == -1 and wu_success == -1:
        controls.append(_ctrl("SI-2", "CIS 7.3", "System Integrity", "Patch Management",
            "Verify Windows Update is delivering patches without errors (WU event log).",
            "UNKNOWN", "Windows Update log unavailable — fetch logs to populate.",
            "N/A",
            "Fetch logs to populate the Windows Update category."))
    elif wu_failures > 0:
        controls.append(_ctrl("SI-2", "CIS 7.3", "System Integrity", "Patch Management",
            "Verify Windows Update is delivering patches without errors (WU event log).",
            "FAIL" if wu_failures > 3 else "WARN",
            f"{wu_failures} Windows Update failure(s) detected. Unpatched vulnerabilities increase attack surface.",
            f"WU failures={wu_failures}, WU success={wu_success}",
            "Open Windows Update (Settings → Windows Update) and check for errors. "
            "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' if updates keep failing. "
            "Ensure Windows Update service (wuauserv) is running."))
    else:
        controls.append(_ctrl("SI-2", "CIS 7.3", "System Integrity", "Patch Management",
            "Verify Windows Update is delivering patches without errors (WU event log).",
            "PASS", f"No Windows Update failures. {max(wu_success,0)} successful update event(s).",
            f"WU failures=0, WU success={wu_success}", ""))

    # SI-3 / CIS 10.1 — Malicious Code Protection: application crashes
    app_crashes = _count(c, "logs_application", "event_id=1000")
    if app_crashes == -1:
        controls.append(_ctrl("SI-3", "CIS 10.1", "System Integrity", "Application Integrity",
            "Monitor for unexpected application crashes (EID 1000) as an indicator of exploitation.",
            "UNKNOWN", "Application log unavailable.", "N/A",
            "Fetch Application logs to enable this check."))
    elif app_crashes > 20:
        controls.append(_ctrl("SI-3", "CIS 10.1", "System Integrity", "Application Integrity",
            "Monitor for unexpected application crashes (EID 1000) as an indicator of exploitation.",
            "WARN", f"{app_crashes} application crash event(s) — elevated crash rate may indicate exploitation.",
            f"EID 1000 count = {app_crashes}",
            "Review Event Viewer Application log for crashing process names. "
            "Repeated crashes of the same process may indicate a memory corruption exploit attempt. "
            "Update the affected applications and ensure DEP/ASLR are enabled."))
    else:
        controls.append(_ctrl("SI-3", "CIS 10.1", "System Integrity", "Application Integrity",
            "Monitor for unexpected application crashes (EID 1000) as an indicator of exploitation.",
            "PASS" if app_crashes >= 0 else "UNKNOWN",
            f"{max(app_crashes, 0)} application crash(es) — within normal range.",
            f"EID 1000 count = {app_crashes}", ""))

    # SI-6 / CIS 6.2 — Security Function Verification: service failures
    svc_failures = _count(c, "logs_system",
        "event_id IN (7034, 7035, 7036, 7040) AND level IN ('ERROR','CRITICAL')")
    if svc_failures == -1:
        controls.append(_ctrl("SI-6", "CIS 6.2", "System Integrity", "Service Integrity",
            "Monitor Windows service failures and unexpected state changes (EID 7034, 7035).",
            "UNKNOWN", "System log unavailable.", "N/A",
            "Fetch System logs to enable this check."))
    elif svc_failures > 10:
        controls.append(_ctrl("SI-6", "CIS 6.2", "System Integrity", "Service Integrity",
            "Monitor Windows service failures and unexpected state changes (EID 7034, 7035).",
            "WARN", f"{svc_failures} service failure/state-change events detected.",
            f"EID 7034/7035 error count = {svc_failures}",
            "Open Services (services.msc) and check for stopped or failing services. "
            "Ensure security-critical services (Windows Defender, Windows Update, Event Log) are running."))
    else:
        controls.append(_ctrl("SI-6", "CIS 6.2", "System Integrity", "Service Integrity",
            "Monitor Windows service failures and unexpected state changes (EID 7034, 7035).",
            "PASS" if svc_failures >= 0 else "UNKNOWN",
            f"{max(svc_failures, 0)} service failure events — no significant issues.",
            f"EID 7034/7035 error count = {svc_failures}", ""))

    conn.close()

    # ── Roll up score ──────────────────────────────────────────────────────────
    status_weight = {"PASS": 0, "WARN": 1, "FAIL": 2, "UNKNOWN": 0}
    total    = len(controls)
    passed   = sum(1 for x in controls if x["status"] == "PASS")
    warned   = sum(1 for x in controls if x["status"] == "WARN")
    failed   = sum(1 for x in controls if x["status"] == "FAIL")
    unknown  = sum(1 for x in controls if x["status"] == "UNKNOWN")
    scored   = total - unknown
    score    = round(passed / max(scored, 1) * 100)

    if score >= 90:
        grade, grade_color = "A", "#10b981"
    elif score >= 75:
        grade, grade_color = "B", "#4ade80"
    elif score >= 60:
        grade, grade_color = "C", "#f59e0b"
    elif score >= 40:
        grade, grade_color = "D", "#f97316"
    else:
        grade, grade_color = "F", "#ef4444"

    # Group by family
    families = {}
    for ctrl in controls:
        fam = ctrl["family"]
        families.setdefault(fam, []).append(ctrl)

    return {
        "controls":    controls,
        "families":    families,
        "score":       score,
        "grade":       grade,
        "grade_color": grade_color,
        "total":       total,
        "passed":      passed,
        "warned":      warned,
        "failed":      failed,
        "unknown":     unknown,
        "framework":   "NIST SP 800-53 Rev 5 / CIS Controls v8",
    }


def _ctrl(nist_id, cis_id, family, title, description, status, finding, evidence, remediation):
    """Convenience constructor for a control result dict."""
    return {
        "id":          nist_id,
        "cis":         cis_id,
        "family":      family,
        "title":       title,
        "description": description,
        "status":      status,
        "finding":     finding,
        "evidence":    evidence,
        "remediation": remediation,
    }


# ── Build report payload ───────────────────────────────────────────────────────

def _build_report(report_type, include_details=True):
    """Assemble a full report dict from live data."""
    logs    = _log_stats()
    sys     = _sys_stats()
    sec     = _security_events()
    net     = _net_snapshot()
    errors  = _recent_errors(25)

    total_logs   = sum(v["total"]   for v in logs.values())
    total_errors = sum(v["errors"]  for v in logs.values())
    total_warns  = sum(v["warnings"] for v in logs.values())

    # Risk score 0-100
    risk = min(100, int(
        (total_errors / max(total_logs, 1)) * 40 +
        (sec["failed_logons"] / max(1, 1)) * 5 +
        sec["lockouts"] * 20 +
        ((sys.get("cpu_percent", 0) - 70) * 0.5 if sys.get("cpu_percent", 0) > 70 else 0) +
        ((sys.get("ram_percent", 0) - 80) * 0.3 if sys.get("ram_percent", 0) > 80 else 0)
    ))
    risk_label = "Critical" if risk >= 75 else "High" if risk >= 50 else "Medium" if risk >= 25 else "Low"
    risk_color = {"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#10b981"}[risk_label]

    report = {
        "id":           _new_id(),
        "type":         report_type,
        "name":         _report_name(report_type),
        "generated_at": _ts(),
        "date":         _date(),
        "generated_by": "Secure Eye Trust+ v2.0",
        "include_details": include_details,
        "risk_score":   risk,
        "risk_label":   risk_label,
        "risk_color":   risk_color,
        "summary": {
            "total_logs":    total_logs,
            "total_errors":  total_errors,
            "total_warnings":total_warns,
            "error_rate":    round(total_errors / max(total_logs, 1) * 100, 1),
        },
        "logs":    logs,
        "system":  sys,
        "security":sec,
        "network": net,
        "recent_errors": errors if include_details else [],
    }

    # FR08-03 — Attach compliance data only for the compliance report type
    if report_type == "compliance":
        report["compliance"] = _run_compliance_checks()

    return report

def _report_name(rtype):
    d = _date()
    names = {
        "security":    f"Security Audit Report — {d}",
        "performance": f"Performance Analysis — {d}",
        "compliance":  f"Compliance Check — {d}",
        "daily":       f"Daily Summary — {d}",
        "network":     f"Network Report — {d}",
        "executive":   f"Executive Summary — {d}",
        "technical":   f"Technical Deep Dive — {d}",
    }
    return names.get(rtype, f"Security Report — {d}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@reports_bp.route("/generate", methods=["POST"])
def generate():
    data    = request.get_json(silent=True) or {}
    rtype   = data.get("type", "security")
    details = data.get("include_details", True)
    report  = _build_report(rtype, details)
    _report_store.insert(0, report)
    if len(_report_store) > 50:
        _report_store.pop()
    return jsonify({"ok": True, "report": report})


@reports_bp.route("/list")
def list_reports():
    # Merge in persisted analysis reports from DB
    try:
        from api.perform_analysis_api import _load_all, _make_reports_entry, _load_latest
        import json
        from database.db import get_conn
        conn = get_conn()
        rows = conn.execute(
            "SELECT report_json FROM analysis_reports ORDER BY generated_at DESC LIMIT 20"
        ).fetchall()
        conn.close()
        pa_ids = {r["id"] for r in _report_store}
        for row in rows:
            try:
                rpt = json.loads(row[0])
                entry = _make_reports_entry(rpt)
                if entry["id"] not in pa_ids:
                    _report_store.append(entry)
                    pa_ids.add(entry["id"])
            except Exception:
                pass
        _report_store.sort(key=lambda x: x.get("generated_at",""), reverse=True)
    except Exception:
        pass
    return jsonify({"reports": _report_store})


@reports_bp.route("/preview/<rid>")
def preview(rid):
    rpt = next((r for r in _report_store if r["id"] == rid), None)
    if not rpt:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(rpt)


@reports_bp.route("/export", methods=["POST"])
def export():
    data   = request.get_json(silent=True) or {}
    rid    = data.get("id", "")
    fmt    = data.get("format", "json")

    # find or build on-the-fly
    rpt = next((r for r in _report_store if r["id"] == rid), None)
    if not rpt:
        rtype = data.get("type", "security")
        rpt   = _build_report(rtype, True)
        _report_store.insert(0, rpt)

    if fmt == "json":
        return Response(
            json.dumps(rpt, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={rpt['id']}.json"}
        )

    if fmt == "csv":
        output = io.StringIO()
        w = csv.writer(output)
        w.writerow(["Field", "Value"])
        w.writerow(["Report Name",    rpt["name"]])
        w.writerow(["Generated At",   rpt["generated_at"]])
        w.writerow(["Type",           rpt["type"]])
        w.writerow(["Risk Score",     rpt["risk_score"]])
        w.writerow(["Risk Level",     rpt["risk_label"]])
        w.writerow([])
        w.writerow(["Category", "Total Logs", "Errors", "Warnings"])
        for cat, s in rpt["logs"].items():
            w.writerow([cat, s["total"], s["errors"], s["warnings"]])

        # FR08-03 — Compliance controls in CSV export
        if rpt.get("compliance"):
            comp = rpt["compliance"]
            w.writerow([])
            w.writerow(["=== COMPLIANCE REPORT ==="])
            w.writerow(["Framework", comp.get("framework", "")])
            w.writerow(["Score", f"{comp.get('score',0)}%  (Grade: {comp.get('grade','?')})"])
            w.writerow(["Passed", comp.get("passed",0)])
            w.writerow(["Warnings", comp.get("warned",0)])
            w.writerow(["Failed", comp.get("failed",0)])
            w.writerow([])
            w.writerow(["Control ID", "CIS Mapping", "Family", "Title",
                        "Status", "Finding", "Evidence", "Remediation"])
            for ctrl in comp.get("controls", []):
                w.writerow([
                    ctrl["id"], ctrl["cis"], ctrl["family"], ctrl["title"],
                    ctrl["status"], ctrl["finding"], ctrl["evidence"], ctrl["remediation"]
                ])

        if rpt.get("recent_errors"):
            w.writerow([])
            w.writerow(["Timestamp","Level","Category","Source","Message"])
            for e in rpt["recent_errors"]:
                w.writerow([e.get("timestamp",""), e.get("level",""),
                            e.get("category",""), e.get("source",""),
                            e.get("message","")])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={rpt['id']}.csv"}
        )

    if fmt == "pdf":
        try:
            pdf = _build_report_pdf(rpt)
            return Response(
                pdf,
                mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={rpt['id']}.pdf"}
            )
        except Exception as e:
            return jsonify({"error": f"PDF failed: {e}"}), 500

    # HTML
    return Response(_render_html(rpt), mimetype="text/html",
                    headers={"Content-Disposition": f"inline; filename={rpt['id']}.html"})


@reports_bp.route("/delete/<rid>", methods=["POST"])
def delete_report(rid):
    """Delete an in-memory report. Requires dashboard password."""
    d = request.get_json(silent=True) or {}
    pw = (d.get("password") or "").strip()
    if not pw:
        return jsonify({"ok": False, "error": "Password required."}), 400
    if not _verify_admin_pw(pw):
        return jsonify({"ok": False, "error": "Incorrect password. Deletion denied."}), 403
    try:
        global _report_store
        before = len(_report_store)
        _report_store = [r for r in _report_store if r.get("id") != rid]
        deleted = before - len(_report_store)
        return jsonify({"ok": True, "deleted": deleted})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── HTML renderer ─────────────────────────────────────────────────────────────

def _render_compliance_section(comp: dict) -> str:
    """
    FR08-03 — Render the full NIST/CIS compliance section for the HTML report.
    Called by _render_html() only when report_type == "compliance".
    """
    score       = comp.get("score", 0)
    grade       = comp.get("grade", "?")
    grade_color = comp.get("grade_color", "#94a3b8")
    passed      = comp.get("passed", 0)
    warned      = comp.get("warned", 0)
    failed      = comp.get("failed", 0)
    unknown     = comp.get("unknown", 0)
    framework   = comp.get("framework", "NIST SP 800-53 / CIS Controls v8")
    families    = comp.get("families", {})

    status_colors = {
        "PASS":    "#10b981",
        "WARN":    "#f59e0b",
        "FAIL":    "#ef4444",
        "UNKNOWN": "#64748b",
    }
    status_icons = {
        "PASS":    "✅",
        "WARN":    "⚠️",
        "FAIL":    "❌",
        "UNKNOWN": "❓",
    }

    # Score banner
    score_bar = f'<div style="flex:1;height:12px;background:rgba(255,255,255,.08);border-radius:6px;overflow:hidden"><div style="width:{score}%;height:100%;background:linear-gradient(90deg,{grade_color}88,{grade_color});border-radius:6px"></div></div>'

    banner = f"""
    <div style="display:flex;align-items:center;gap:22px;padding:20px 24px;
                border-radius:14px;background:rgba(255,255,255,.04);
                border:1px solid rgba(255,255,255,.08);margin-bottom:20px">
      <div style="width:80px;height:80px;border-radius:50%;border:3px solid {grade_color};
                  display:flex;flex-direction:column;align-items:center;justify-content:center;
                  flex-shrink:0;box-shadow:0 0 24px {grade_color}44">
        <div style="font-size:28px;font-weight:900;color:{grade_color};font-family:monospace">{grade}</div>
        <div style="font-size:11px;color:{grade_color}99">{score}%</div>
      </div>
      <div style="flex:1">
        <div style="font-size:13px;color:#94a3b8;margin-bottom:3px">Compliance Score</div>
        <div style="font-size:20px;font-weight:800;color:{grade_color};margin-bottom:8px">
          {score}% — Grade {grade}
        </div>
        {score_bar}
        <div style="font-size:11px;color:#475569;margin-top:6px">{framework}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;flex-shrink:0">
        <div style="text-align:center;padding:10px 14px;background:rgba(16,185,129,.1);
                    border-radius:8px;border:1px solid rgba(16,185,129,.25)">
          <div style="font-size:22px;font-weight:900;color:#10b981;font-family:monospace">{passed}</div>
          <div style="font-size:10px;color:#10b981;text-transform:uppercase;letter-spacing:.06em">Pass</div>
        </div>
        <div style="text-align:center;padding:10px 14px;background:rgba(245,158,11,.1);
                    border-radius:8px;border:1px solid rgba(245,158,11,.25)">
          <div style="font-size:22px;font-weight:900;color:#f59e0b;font-family:monospace">{warned}</div>
          <div style="font-size:10px;color:#f59e0b;text-transform:uppercase;letter-spacing:.06em">Warn</div>
        </div>
        <div style="text-align:center;padding:10px 14px;background:rgba(239,68,68,.1);
                    border-radius:8px;border:1px solid rgba(239,68,68,.25)">
          <div style="font-size:22px;font-weight:900;color:#ef4444;font-family:monospace">{failed}</div>
          <div style="font-size:10px;color:#ef4444;text-transform:uppercase;letter-spacing:.06em">Fail</div>
        </div>
        <div style="text-align:center;padding:10px 14px;background:rgba(100,116,139,.1);
                    border-radius:8px;border:1px solid rgba(100,116,139,.25)">
          <div style="font-size:22px;font-weight:900;color:#64748b;font-family:monospace">{unknown}</div>
          <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em">Unknown</div>
        </div>
      </div>
    </div>"""

    # Per-family control tables
    family_html = ""
    for fam_name, ctrls in families.items():
        rows_html = ""
        for ctrl in ctrls:
            st      = ctrl["status"]
            st_col  = status_colors.get(st, "#64748b")
            st_icon = status_icons.get(st, "❓")
            remediation_html = (
                f'<div style="margin-top:6px;padding:8px 10px;background:rgba(239,68,68,.06);'
                f'border-left:3px solid {st_col};border-radius:4px;font-size:11px;color:#94a3b8">'
                f'<strong style="color:#f87171">Remediation:</strong> {ctrl["remediation"]}</div>'
            ) if ctrl.get("remediation") else ""

            rows_html += f"""
            <tr>
              <td style="white-space:nowrap;vertical-align:top;padding-top:12px">
                <div style="font-family:monospace;font-size:11px;font-weight:700;
                            color:{st_col};background:rgba(0,0,0,.3);
                            padding:3px 8px;border-radius:4px;display:inline-block">{ctrl['id']}</div>
                <div style="font-size:10px;color:#475569;margin-top:3px">{ctrl['cis']}</div>
              </td>
              <td style="vertical-align:top;padding-top:12px">
                <div style="font-size:12px;font-weight:700;color:#e2e8f0;margin-bottom:2px">{ctrl['title']}</div>
                <div style="font-size:11px;color:#64748b">{ctrl['description']}</div>
              </td>
              <td style="vertical-align:top;padding-top:12px;min-width:220px">
                <span style="font-size:10px;font-weight:700;padding:3px 10px;border-radius:12px;
                             background:rgba(0,0,0,.3);color:{st_col};
                             border:1px solid {st_col}44">{st_icon} {st}</span>
                <div style="font-size:11px;color:#94a3b8;margin-top:6px">{ctrl['finding']}</div>
                <div style="font-size:10px;color:#334155;margin-top:3px;font-family:monospace">{ctrl['evidence']}</div>
                {remediation_html}
              </td>
            </tr>"""

        family_html += f"""
        <div style="margin-bottom:18px">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
                      color:#64748b;margin-bottom:10px;display:flex;align-items:center;gap:8px">
            {fam_name}
            <span style="flex:1;height:1px;background:rgba(255,255,255,.06)"></span>
          </div>
          <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
                      border-radius:12px;overflow:hidden">
            <table style="width:100%;border-collapse:collapse;font-size:12px">
              <thead>
                <tr style="background:rgba(255,255,255,.04)">
                  <th style="padding:9px 14px;color:#64748b;font-size:10px;text-transform:uppercase;
                             letter-spacing:.08em;text-align:left;border-bottom:1px solid rgba(255,255,255,.06);
                             width:90px">Control</th>
                  <th style="padding:9px 14px;color:#64748b;font-size:10px;text-transform:uppercase;
                             letter-spacing:.08em;text-align:left;border-bottom:1px solid rgba(255,255,255,.06)">Description</th>
                  <th style="padding:9px 14px;color:#64748b;font-size:10px;text-transform:uppercase;
                             letter-spacing:.08em;text-align:left;border-bottom:1px solid rgba(255,255,255,.06)">Result &amp; Evidence</th>
                </tr>
              </thead>
              <tbody>{rows_html}</tbody>
            </table>
          </div>
        </div>"""

    return f"""
    <div class="rpt-section">
      <div class="rpt-section-title">📋 NIST SP 800-53 / CIS Controls v8 — Compliance Results</div>
      {banner}
      {family_html}
    </div>"""


def _render_html(r):
    logs   = r["logs"]
    sys    = r.get("system", {})
    sec    = r.get("security", {})
    net    = r.get("network", {})
    summ   = r["summary"]
    errors = r.get("recent_errors", [])

    # Log rows
    log_rows = ""
    for cat, s in logs.items():
        rate = round(s["errors"] / max(s["total"], 1) * 100, 1)
        bar_color = "#ef4444" if rate > 10 else "#f59e0b" if rate > 3 else "#10b981"
        log_rows += f"""
        <tr>
          <td style="font-weight:600;text-transform:capitalize">{cat.replace('_',' ')}</td>
          <td style="font-family:monospace">{s['total']:,}</td>
          <td style="font-family:monospace;color:#f87171">{s['errors']:,}</td>
          <td style="font-family:monospace;color:#fcd34d">{s['warnings']:,}</td>
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="flex:1;background:rgba(255,255,255,.08);border-radius:4px;height:6px;overflow:hidden">
                <div style="width:{min(rate*5,100)}%;height:100%;background:{bar_color};border-radius:4px"></div>
              </div>
              <span style="font-family:monospace;font-size:11px;color:{bar_color}">{rate}%</span>
            </div>
          </td>
        </tr>"""

    # Error rows
    err_rows = ""
    for e in errors[:20]:
        lv = e.get("level","INFO")
        lv_col = {"CRITICAL":"#f87171","ERROR":"#f87171","WARNING":"#fcd34d","FAILURE":"#f87171"}.get(lv,"#94a3b8")
        err_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:11px;white-space:nowrap">{e.get('timestamp','')[:16]}</td>
          <td><span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;background:rgba(0,0,0,.3);color:{lv_col}">{lv}</span></td>
          <td style="font-size:11px;color:#94a3b8">{e.get('category','')}</td>
          <td style="font-family:monospace;font-size:11px">{(e.get('source') or '')[:35]}</td>
          <td style="font-size:12px;color:#cbd5e1">{(e.get('message') or '')[:80]}</td>
        </tr>"""

    risk_col = r["risk_color"]
    risk_lbl = r["risk_label"]
    risk_pct = r["risk_score"]

    sys_html = ""
    if sys:
        def bar(pct):
            col = "#ef4444" if pct>90 else "#f59e0b" if pct>75 else "#10b981"
            return f'<div style="background:rgba(255,255,255,.08);border-radius:4px;height:8px;overflow:hidden;margin-top:4px"><div style="width:{pct}%;height:100%;background:{col};border-radius:4px"></div></div>'
        sys_html = f"""
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px">
          <div style="background:rgba(255,255,255,.04);border-radius:10px;padding:16px;border:1px solid rgba(255,255,255,.08)">
            <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em">CPU Usage</div>
            <div style="font-size:28px;font-weight:800;color:#4ade80;font-family:monospace;margin:4px 0">{sys.get('cpu_percent',0)}%</div>
            {bar(sys.get('cpu_percent',0))}
          </div>
          <div style="background:rgba(255,255,255,.04);border-radius:10px;padding:16px;border:1px solid rgba(255,255,255,.08)">
            <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em">RAM Usage</div>
            <div style="font-size:28px;font-weight:800;color:#22d3ee;font-family:monospace;margin:4px 0">{sys.get('ram_percent',0)}%</div>
            {bar(sys.get('ram_percent',0))}
            <div style="font-size:11px;color:#64748b;margin-top:5px">{sys.get('ram_used_gb',0)} / {sys.get('ram_total_gb',0)} GB</div>
          </div>
          <div style="background:rgba(255,255,255,.04);border-radius:10px;padding:16px;border:1px solid rgba(255,255,255,.08)">
            <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.08em">Disk Usage</div>
            <div style="font-size:28px;font-weight:800;color:#fcd34d;font-family:monospace;margin:4px 0">{sys.get('disk_percent',0)}%</div>
            {bar(sys.get('disk_percent',0))}
            <div style="font-size:11px;color:#64748b;margin-top:5px">Free: {sys.get('disk_free_gb',0)} GB</div>
          </div>
        </div>"""

    sec_events_html = ""
    for ev in sec.get("top_events", [])[:8]:
        lv_col = "#f87171" if ev.get("level") in ("CRITICAL","ERROR","FAILURE") else "#fcd34d"
        sec_events_html += f"<tr><td style='font-family:monospace;color:#4ade80'>{ev['event_id']}</td><td style='font-family:monospace'>{ev['count']:,}</td><td style='color:{lv_col}'>{ev.get('level','—')}</td></tr>"

    # FR08-03 — Compliance section (rendered only for compliance report type)
    compliance_html = ""
    if r.get("type") == "compliance" and r.get("compliance"):
        compliance_html = _render_compliance_section(r["compliance"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{r['name']}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,#060c1a,#0a1428);color:#e2e8f0;min-height:100vh;padding:28px}}
  .rpt-shell{{max-width:960px;margin:0 auto}}
  /* Header */
  .rpt-head{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid rgba(255,255,255,.08)}}
  .rpt-logo{{display:flex;align-items:center;gap:12px}}
  .rpt-logo-shield{{width:44px;height:44px;background:linear-gradient(135deg,#1547a0,#1a8cff);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 0 20px rgba(26,140,255,.4)}}
  .rpt-brand{{font-size:18px;font-weight:800;color:#fff}}
  .rpt-brand span{{color:#4da6ff}}
  .rpt-brand-sub{{font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.1em}}
  .rpt-type-badge{{padding:5px 14px;border-radius:20px;font-size:11px;font-weight:700;background:rgba(26,140,255,.15);color:#4da6ff;border:1px solid rgba(26,140,255,.3)}}
  /* Title block */
  .rpt-title-block{{margin-bottom:24px}}
  .rpt-title{{font-size:26px;font-weight:900;color:#fff;letter-spacing:-.02em;margin-bottom:5px}}
  .rpt-meta{{font-size:12px;color:#475569}}
  /* Risk banner */
  .rpt-risk{{display:flex;align-items:center;gap:20px;padding:18px 22px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);margin-bottom:22px}}
  .rpt-risk-ring{{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:22px;font-weight:900;border:3px solid {risk_col};box-shadow:0 0 20px {risk_col}44;color:{risk_col}}}
  .rpt-risk-label{{font-size:13px;color:#94a3b8;margin-bottom:4px}}
  .rpt-risk-title{{font-size:22px;font-weight:800;color:{risk_col}}}
  .rpt-risk-bar{{flex:1;height:10px;background:rgba(255,255,255,.08);border-radius:5px;overflow:hidden}}
  .rpt-risk-fill{{height:100%;border-radius:5px;background:linear-gradient(90deg,{risk_col}88,{risk_col});width:{risk_pct}%}}
  /* Summary pills */
  .rpt-pills{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .rpt-pill{{flex:1;min-width:140px;padding:16px 18px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08)}}
  .rpt-pill-label{{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:5px}}
  .rpt-pill-val{{font-size:26px;font-weight:900;font-family:monospace}}
  /* Section */
  .rpt-section{{margin-bottom:22px}}
  .rpt-section-title{{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
  .rpt-section-title::after{{content:'';flex:1;height:1px;background:rgba(255,255,255,.06)}}
  /* Card */
  .rpt-card{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:12px;overflow:hidden}}
  /* Table */
  .rpt-table{{width:100%;border-collapse:collapse;font-size:12px}}
  .rpt-table th{{padding:10px 14px;background:rgba(255,255,255,.04);color:#64748b;font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.08em;text-align:left;border-bottom:1px solid rgba(255,255,255,.06)}}
  .rpt-table td{{padding:9px 14px;border-bottom:1px solid rgba(255,255,255,.04);color:#cbd5e1;vertical-align:middle}}
  .rpt-table tr:last-child td{{border-bottom:none}}
  .rpt-table tr:hover td{{background:rgba(255,255,255,.02)}}
  /* Security box */
  .sec-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:18px}}
  .sec-box{{text-align:center;padding:14px;background:rgba(0,0,0,.2);border-radius:8px;border:1px solid rgba(255,255,255,.06)}}
  .sec-box-val{{font-size:30px;font-weight:900;font-family:monospace}}
  .sec-box-lbl{{font-size:11px;color:#64748b;margin-top:4px}}
  /* Footer */
  .rpt-footer{{margin-top:32px;padding-top:16px;border-top:1px solid rgba(255,255,255,.06);display:flex;justify-content:space-between;font-size:11px;color:#334155}}
  @media print{{body{{background:#fff;color:#000}}.rpt-shell{{max-width:100%}}}}
</style>
</head>
<body>
<div class="rpt-shell">

  <!-- Header -->
  <div class="rpt-head">
    <div class="rpt-logo">
      <div class="rpt-logo-shield">🛡</div>
      <div>
        <div class="rpt-brand">Secure Eye <span>Trust</span>+</div>
        <div class="rpt-brand-sub">Desktop Security Monitoring</div>
      </div>
    </div>
    <div>
      <div class="rpt-type-badge">{r['type'].upper()} REPORT</div>
      <div style="font-size:11px;color:#475569;margin-top:6px;text-align:right">{r['generated_at']}</div>
    </div>
  </div>

  <!-- Title -->
  <div class="rpt-title-block">
    <div class="rpt-title">{r['name']}</div>
    <div class="rpt-meta">Generated by {r['generated_by']} &nbsp;·&nbsp; {r['generated_at']}</div>
  </div>

  <!-- Risk Banner -->
  <div class="rpt-risk">
    <div class="rpt-risk-ring">{risk_pct}</div>
    <div style="flex:1">
      <div class="rpt-risk-label">Overall Risk Score</div>
      <div class="rpt-risk-title">{risk_lbl} Risk</div>
      <div style="margin-top:10px">
        <div class="rpt-risk-bar"><div class="rpt-risk-fill"></div></div>
      </div>
    </div>
    <div style="font-size:12px;color:#475569;text-align:right;max-width:200px">
      Based on log errors, security events, and system resource utilization
    </div>
  </div>

  <!-- Summary Pills -->
  <div class="rpt-pills">
    <div class="rpt-pill">
      <div class="rpt-pill-label">Total Logs</div>
      <div class="rpt-pill-val" style="color:#4da6ff">{summ['total_logs']:,}</div>
    </div>
    <div class="rpt-pill">
      <div class="rpt-pill-label">Errors</div>
      <div class="rpt-pill-val" style="color:#f87171">{summ['total_errors']:,}</div>
    </div>
    <div class="rpt-pill">
      <div class="rpt-pill-label">Warnings</div>
      <div class="rpt-pill-val" style="color:#fcd34d">{summ['total_warnings']:,}</div>
    </div>
    <div class="rpt-pill">
      <div class="rpt-pill-label">Error Rate</div>
      <div class="rpt-pill-val" style="color:#fb923c">{summ['error_rate']}%</div>
    </div>
    <div class="rpt-pill">
      <div class="rpt-pill-label">Connections</div>
      <div class="rpt-pill-val" style="color:#4ade80">{net.get('connection_count',0)}</div>
    </div>
  </div>

  {compliance_html}

  <!-- Log Category Breakdown -->
  <div class="rpt-section">
    <div class="rpt-section-title">📋 Log Category Breakdown</div>
    <div class="rpt-card">
      <table class="rpt-table">
        <thead><tr><th>Category</th><th>Total</th><th>Errors</th><th>Warnings</th><th>Error Rate</th></tr></thead>
        <tbody>{log_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- System Resources -->
  <div class="rpt-section">
    <div class="rpt-section-title">🖥 System Resources</div>
    <div class="rpt-card" style="padding:18px">{sys_html or '<p style="color:#475569;padding:14px">psutil not installed — run: pip install psutil</p>'}</div>
  </div>

  <!-- Security Events -->
  <div class="rpt-section">
    <div class="rpt-section-title">🔒 Security Events</div>
    <div class="rpt-card">
      <div class="sec-grid">
        <div class="sec-box">
          <div class="sec-box-val" style="color:#f87171">{sec.get('failed_logons',0)}</div>
          <div class="sec-box-lbl">Failed Logons (EID 4625)</div>
        </div>
        <div class="sec-box">
          <div class="sec-box-val" style="color:#fb923c">{sec.get('lockouts',0)}</div>
          <div class="sec-box-lbl">Account Lockouts (EID 4740)</div>
        </div>
        <div class="sec-box">
          <div class="sec-box-val" style="color:#fcd34d">{sec.get('priv_events',0)}</div>
          <div class="sec-box-lbl">Privilege Events (EID 4672)</div>
        </div>
      </div>
      {'<table class="rpt-table"><thead><tr><th>Event ID</th><th>Count</th><th>Level</th></tr></thead><tbody>' + sec_events_html + '</tbody></table>' if sec_events_html else '<div style="padding:14px;color:#475569">No security log data — fetch logs as Administrator</div>'}
    </div>
  </div>

  <!-- Recent Errors -->
  {'<div class="rpt-section"><div class="rpt-section-title">⚠ Recent Errors & Failures</div><div class="rpt-card"><table class="rpt-table"><thead><tr><th>Timestamp</th><th>Level</th><th>Category</th><th>Source</th><th>Message</th></tr></thead><tbody>' + err_rows + '</tbody></table></div></div>' if err_rows else ''}

  <!-- Footer -->
  <div class="rpt-footer">
    <span>Secure Eye Trust+ v2.0 — Report ID: {r['id']}</span>
    <span>Generated: {r['generated_at']}</span>
  </div>
</div>
</body>
</html>"""


def _build_report_pdf(rpt):
    """Build a simple PDF representation for general reports."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    import re

    def clean_text(value, maxlen=None):
        if value is None:
            return ""
        text = str(value)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
        if maxlen:
            text = text[:maxlen]
        return text

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=18, leading=22)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=11, leading=14)
    normal_style = ParagraphStyle("Normal", parent=styles["Normal"], fontSize=9, leading=12)
    mono_style = ParagraphStyle("Mono", parent=styles["Code"], fontSize=8, leading=10)

    story = []
    story.append(Paragraph(clean_text(rpt.get("name")), title_style))
    story.append(Spacer(1, 4 * mm))

    meta = [
        [Paragraph("Generated", heading_style), Paragraph(clean_text(rpt.get("generated_at")), normal_style),
         Paragraph("Type", heading_style), Paragraph(clean_text(str(rpt.get("type","")).upper()), normal_style)],
        [Paragraph("Report ID", heading_style), Paragraph(clean_text(rpt.get("id")), mono_style),
         Paragraph("Risk", heading_style), Paragraph(clean_text(f"{rpt.get('risk_label','')} / {rpt.get('risk_score',0)}"), normal_style)],
    ]
    meta_table = Table(meta, colWidths=[35*mm, 65*mm, 25*mm, 55*mm])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 4 * mm))

    summary = rpt.get("summary", {})
    summary_rows = [
        [Paragraph("Metric", heading_style), Paragraph("Value", heading_style)],
        [Paragraph("Total Logs", normal_style), Paragraph(clean_text(summary.get("total_logs", 0)), normal_style)],
        [Paragraph("Errors", normal_style), Paragraph(clean_text(summary.get("total_errors", 0)), normal_style)],
        [Paragraph("Warnings", normal_style), Paragraph(clean_text(summary.get("total_warnings", 0)), normal_style)],
        [Paragraph("Error Rate", normal_style), Paragraph(clean_text(f"{summary.get('error_rate',0)}%"), normal_style)],
    ]
    story.append(Paragraph("Report Summary", heading_style))
    story.append(Spacer(1, 2 * mm))
    summary_table = Table(summary_rows, colWidths=[45*mm, 90*mm])
    summary_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 4 * mm))

    logs = rpt.get("logs", {})
    if logs:
        log_rows = [[Paragraph("Category", heading_style), Paragraph("Total", heading_style),
                     Paragraph("Errors", heading_style), Paragraph("Warnings", heading_style)]]
        for cat, stats in logs.items():
            log_rows.append([
                Paragraph(clean_text(cat.replace("_", " ").title()), normal_style),
                Paragraph(clean_text(stats.get("total", 0)), normal_style),
                Paragraph(clean_text(stats.get("errors", 0)), normal_style),
                Paragraph(clean_text(stats.get("warnings", 0)), normal_style),
            ])
        story.append(Paragraph("Log Category Summary", heading_style))
        story.append(Spacer(1, 2 * mm))
        log_table = Table(log_rows, colWidths=[55*mm, 30*mm, 30*mm, 30*mm])
        log_table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f8fafc")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(log_table)
        story.append(Spacer(1, 4 * mm))

    if rpt.get("compliance"):
        comp = rpt["compliance"]
        story.append(Paragraph("Compliance Summary", heading_style))
        story.append(Spacer(1, 2 * mm))
        comp_text = f"Framework: {clean_text(comp.get('framework',''))} | Score: {clean_text(str(comp.get('score',0)))}% | Grade: {clean_text(comp.get('grade','?'))}"
        story.append(Paragraph(comp_text, normal_style))
        story.append(Spacer(1, 4 * mm))

    errors = rpt.get("recent_errors", [])
    if errors:
        story.append(Paragraph("Recent Errors", heading_style))
        story.append(Spacer(1, 2 * mm))
        for err in errors[:12]:
            story.append(Paragraph(
                f"{clean_text(err.get('timestamp',''))} — {clean_text(err.get('level',''))} — {clean_text(err.get('category',''))} — {clean_text(err.get('source',''))}",
                mono_style))
            story.append(Paragraph(clean_text(err.get('message','')), normal_style))
            story.append(Spacer(1, 1.5 * mm))

    doc.build(story)
    return buf.getvalue()
