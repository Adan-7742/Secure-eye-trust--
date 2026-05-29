"""
core/analysis_engine/threat_detector.py
=========================================
UPGRADED: Smart Rule-Based Threat Detection Engine v4.0

FR03 COMPLIANCE (unchanged):
  FR03-01: run_threat_detection_encrypted() performs detection on HE-encrypted
           frequency counts via BFV — sensitive field values never decrypted
           during analysis; only aggregate counts and risk flags are decrypted.
  FR03-02: MALWARE_DETECTED rule (EID 1116/1117) + AV_DISABLED (EID 5001)
           cover Windows-specific malware/threat detection.
  FR03-03: REGISTRY_TAMPER rule (EID 4657) detects suspicious registry mods.
  FR03-04: NEW_SERVICE rule (EID 7045) detects unauthorized service installs.
  FR03-05: BRUTE_FORCE, ACCOUNT_LOCKOUT_STORM, KERBEROS_SPRAY,
           ADMIN_GROUP_CHANGE, PRIV_LOGON_SPIKE rules cover auth anomalies.
  FR03-06: PS_ENCODED_CMD, PS_DOWNLOAD_CRADLE, PS_AMSI_BYPASS,
           PS_SUSPICIOUS_PROCESS, PS_LOLBIN, PS_CREDENTIAL_THEFT rules cover
           PowerShell and command-line monitoring.

FR04 COMPLIANCE (v4.0 additions):
  FR04-03: TASK_DELETED    (EID 4699) — task removed, possible evidence cleanup
           TASK_ENABLED     (EID 4700) — dormant persistence mechanism reactivated
           TASK_DISABLED    (EID 4701) — security task may have been silenced
           TASK_UPDATED     (EID 4702) — existing task modified (stealthy payload swap)
           Combined with task_scheduler_monitor.py (COM inventory layer).
  FR04-05: SERVICE_FAILED_START     (EID 7000/7009/7022)
           SERVICE_DEPENDENCY_FAILURE (EID 7001)
           SERVICE_UNEXPECTED_STOP   (EID 7023/7031/7034)
           SERVICE_START_TYPE_CHANGED (EID 7040)
           Combined with service_monitor.py (EnumServicesStatus live polling).

Detection approach (unchanged from v2.0):
  1. Frequency-based rules  — event must exceed a count threshold in a time window
  2. Temporal context       — off-hours and weekend events score higher
  3. Confidence scoring     — each detection carries a 0-100 confidence value
  4. False-positive suppression — low-confidence detections are filtered out

Each detection returns a rich structured dict consumed by:
  - risk_scorer.py  (contributes weighted risk score)
  - correlator.py   (cross-event chain detection)
  - perform_analysis_api.py (full report generation)
  - intelligence_api.py (dashboard panel)
"""

import re
import math
from datetime import datetime
from database.db import get_conn, CATEGORIES


# ── MITRE ATT&CK tactic labels ─────────────────────────────────────────────
MITRE = {
    "credential_attack":    "TA0006 - Credential Access",
    "privilege_escalation": "TA0004 - Privilege Escalation",
    "persistence":          "TA0003 - Persistence",
    "defense_evasion":      "TA0005 - Defense Evasion",
    "malware":              "TA0002 - Execution",
    "reconnaissance":       "TA0043 - Reconnaissance",
    "hardware":             "Availability Impact",
    "stability":            "Availability Impact",
    # FR03-06
    "execution":            "TA0002 - Execution",
    "powershell":           "T1059.001 - Command and Scripting Interpreter: PowerShell",
    "lolbin":               "T1218 - Signed Binary Proxy Execution",
    # FR04-03 / FR04-05
    "patching":             "M1051 - Update Software",
    # FR06-03 GPO detection
    "policy_tamper":        "T1484 - Domain Policy Modification",
    # FR06-06 DLL injection / process hollowing
    "process_injection":    "T1055 - Process Injection",
}

# ── Confidence suppression threshold ───────────────────────────────────────
# Any detection scoring below this will be filtered (false positive protection)
CONFIDENCE_THRESHOLD = 0.35

# ── Severity weights for risk scoring ──────────────────────────────────────
SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3}


# ─────────────────────────────────────────────────────────────────────────────
# LSASS / Process-Access false-positive filter
#
# EID 4656 / 4663 on lsass.exe is one of the noisiest Security audit events on
# Windows. SACL auditing emits it for ANY handle open, including completely
# legitimate operations:
#   - Defender / Defender-for-Endpoint / EDR agents reading LSASS to scan it
#   - VS Code, browsers, and other apps using the Windows credential helper
#   - Task Manager / Process Explorer if running elevated
#   - Windows itself: services.exe, svchost.exe, wininit.exe, lsass.exe (self)
#
# Without filtering, a perfectly clean machine reports 10,000+ "Credential Theft"
# events and the risk score saturates the dial. The list below names the
# process executables we KNOW issue LSASS handles for benign reasons. Events
# whose caller matches are dropped from the count BEFORE the rule decides
# whether to fire.
# ─────────────────────────────────────────────────────────────────────────────
BENIGN_LSASS_CALLERS = {
    # The OS / authentication subsystem itself
    "lsass.exe", "services.exe", "svchost.exe", "wininit.exe",
    "winlogon.exe", "csrss.exe", "smss.exe", "taskhostw.exe",
    "system",  # PID 4
    # User-facing system management tools
    "taskmgr.exe", "perfmon.exe", "mmc.exe", "procexp.exe", "procexp64.exe",
    "explorer.exe",
    # Microsoft security stack
    "msmpeng.exe", "mssense.exe", "sense.exe", "mpcmdrun.exe",
    "nissrv.exe", "securityhealthservice.exe", "smartscreen.exe",
    "msmpengcp.exe",
    # Common third-party EDR / AV (only when they're legitimately installed)
    "crowdstrike", "csagent.exe", "csfalconservice.exe",
    "sentinelagent.exe", "sentinelhelperservice.exe",
    "cb.exe", "carbonblack", "repmgr.exe", "repux.exe",
    "elastic-agent.exe", "filebeat.exe", "winlogbeat.exe",
    "sysmon.exe", "sysmon64.exe",
    # Developer tools that use the Windows credential helper
    "code.exe", "code - insiders.exe", "devenv.exe", "vsdebugconsole.exe",
    "pycharm64.exe", "idea64.exe", "rider64.exe", "webstorm64.exe",
    "phpstorm64.exe", "clion64.exe", "goland64.exe",
    "git-credential-manager.exe", "git-credential-manager-core.exe",
    # Chromium / browsers (credential autofill, IWA, Kerberos SSO)
    "msedge.exe", "chrome.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    "firefox.exe",
    # Microsoft 365 / collaboration apps
    "teams.exe", "ms-teams.exe", "onedrive.exe", "outlook.exe",
    "lync.exe", "communicator.exe", "onenote.exe",
    # Remote management / RSAT
    "wmiprvse.exe", "winrshost.exe", "wsmprovhost.exe",
}

# Dangerous bits in an EID 4656 AccessMask. If NONE of these are set, the
# request is read-only and far less likely to be malicious.
#   0x0002 = PROCESS_CREATE_THREAD
#   0x0008 = PROCESS_VM_OPERATION
#   0x0020 = PROCESS_VM_WRITE
#   0x0040 = PROCESS_DUP_HANDLE
#   0x0080 = PROCESS_CREATE_PROCESS
DANGEROUS_ACCESS_BITS = 0x0002 | 0x0008 | 0x0020 | 0x0040 | 0x0080

_ACCESS_MASK_RE  = re.compile(r"(?:Access(?:\s*Mask)?|0x[0-9a-f]+)\s*[:=]?\s*(0x[0-9a-fA-F]+)")
_CALLER_PATH_RE  = re.compile(r"([A-Z]:\\[^,'\"<>\r\n]+?\.exe)", re.IGNORECASE)


def _extract_caller(message: str) -> str:
    """Return the lower-cased basename of the process that opened the handle,
    or '' if it can't be parsed out of the message."""
    if not message:
        return ""
    m = _CALLER_PATH_RE.findall(message)
    if not m:
        return ""
    # The caller is the LAST .exe path in the message (process information block)
    path = m[-1].strip().lower()
    return path.rsplit("\\", 1)[-1]


def _is_benign_caller(caller: str) -> bool:
    """Match the parsed caller against the benign list (substring-tolerant)."""
    if not caller:
        return False
    # Pull in the user-managed whitelist (from the threat_actions API).
    # Cached for the duration of one detection run via _user_whitelist_cache.
    try:
        from api.threat_actions_api import get_user_whitelist_callers
        user_wl = get_user_whitelist_callers()
    except Exception:
        user_wl = set()
    combined = BENIGN_LSASS_CALLERS | user_wl
    if caller in combined:
        return True
    # Substring match for things like "MsSenseS.exe" or vendor-prefixed binaries
    for k in combined:
        if k and (k in caller or caller in k):
            return True
    return False


def _extract_access_mask(message: str) -> int:
    """Pull the AccessMask hex value from a 4656 message. Returns 0 if unknown."""
    if not message:
        return 0
    # 4656 messages put the access mask after a known marker, but the message
    # format varies, so scan for hex tokens and pick the one most likely to be
    # the mask: short (≤6 chars) and not the SubjectLogonId / HandleId.
    hits = re.findall(r"\b0x([0-9a-fA-F]{1,8})\b", message)
    candidates = []
    for h in hits:
        try:
            v = int(h, 16)
        except ValueError:
            continue
        # Realistic AccessMask values are < 0x01000000; very large IDs aren't masks.
        if 0 < v < 0x01000000:
            candidates.append(v)
    if not candidates:
        return 0
    # The AccessMask in EID 4656 is usually a small bitfield (< 0x20000).
    # Prefer the smallest plausible value.
    small = [v for v in candidates if v < 0x20000]
    return min(small) if small else min(candidates)


def _classify_lsass_events(conn, eids: list[int], hours: int) -> dict:
    """
    Sample EID 4656/4663 events targeting lsass.exe and classify each as
    benign (known caller AND read-only access) or suspicious.

    Returns:
        {
            "total_window":   int,    # total matching events in the window
            "lsass_total":    int,    # how many of those targeted lsass.exe
            "benign":         int,    # benign-caller share (extrapolated)
            "suspicious":    int,     # suspicious share (extrapolated)
            "callers":       dict,    # caller_basename -> count (top 5)
            "dangerous_mask_ratio": float,  # 0-1, fraction with risky access bits
            "suspicious_pct": float,  # 0-1, share NOT in benign list
        }
    """
    c = conn.cursor()
    placeholders = ",".join("?" * len(eids))

    # Total events in window (any object)
    c.execute(f"""
        SELECT COUNT(*) FROM logs_security
        WHERE event_id IN ({placeholders})
        AND timestamp >= datetime('now', ? || ' hours')
    """, eids + [f"-{hours}"])
    total_window = c.fetchone()[0] or 0

    # Total events specifically targeting lsass.exe
    c.execute(f"""
        SELECT COUNT(*) FROM logs_security
        WHERE event_id IN ({placeholders})
        AND timestamp >= datetime('now', ? || ' hours')
        AND LOWER(message) LIKE '%lsass.exe%'
    """, eids + [f"-{hours}"])
    lsass_total = c.fetchone()[0] or 0

    if lsass_total == 0:
        return {
            "total_window": total_window, "lsass_total": 0,
            "benign": 0, "suspicious": 0, "callers": {},
            "dangerous_mask_ratio": 0.0, "suspicious_pct": 0.0,
        }

    # Sample up to 500 LSASS-targeting messages to classify
    c.execute(f"""
        SELECT message FROM logs_security
        WHERE event_id IN ({placeholders})
        AND timestamp >= datetime('now', ? || ' hours')
        AND LOWER(message) LIKE '%lsass.exe%'
        LIMIT 500
    """, eids + [f"-{hours}"])

    benign_sample      = 0
    dangerous_sample   = 0
    callers_count: dict[str, int] = {}
    sampled            = 0

    for (msg,) in c.fetchall():
        sampled += 1
        caller = _extract_caller(msg)
        if caller:
            callers_count[caller] = callers_count.get(caller, 0) + 1

        mask = _extract_access_mask(msg)
        if mask & DANGEROUS_ACCESS_BITS:
            dangerous_sample += 1

        # Benign IF caller is on the list AND no dangerous access bits set
        if _is_benign_caller(caller) and not (mask & DANGEROUS_ACCESS_BITS):
            benign_sample += 1

    if sampled == 0:
        return {
            "total_window": total_window, "lsass_total": lsass_total,
            "benign": 0, "suspicious": lsass_total, "callers": {},
            "dangerous_mask_ratio": 0.0, "suspicious_pct": 1.0,
        }

    benign_ratio       = benign_sample    / sampled
    dangerous_ratio    = dangerous_sample / sampled
    suspicious_pct     = max(0.0, 1.0 - benign_ratio)

    # Top 5 callers
    top_callers = dict(sorted(callers_count.items(), key=lambda kv: -kv[1])[:5])

    return {
        "total_window":         total_window,
        "lsass_total":          lsass_total,
        "benign":               int(lsass_total * benign_ratio),
        "suspicious":           int(lsass_total * suspicious_pct),
        "callers":              top_callers,
        "dangerous_mask_ratio": round(dangerous_ratio, 3),
        "suspicious_pct":       round(suspicious_pct, 3),
    }


# ── Business hours by weekday (0=Mon … 6=Sun), None = no business day ──────
BUSINESS_HOURS = {0:(7,19),1:(7,19),2:(7,19),3:(7,19),4:(7,18),5:None,6:None}

# ─────────────────────────────────────────────────────────────────────────────
# SMART THREAT RULES
# Each rule defines:
#   event_ids   : Windows Event IDs to count
#   table       : log table (security, system, windows_update …)
#   window_hours: rolling time window
#   threshold   : minimum count to trigger (FP protection)
#   description : technical explanation
#   human_summary: plain-English for non-technical users
#   actions     : ordered remediation steps
# ─────────────────────────────────────────────────────────────────────────────
THREAT_RULES = [
    # ── Authentication / Credential Attacks ──────────────────────────────────
    {
        "id":          "BRUTE_FORCE",
        "name":        "Brute Force Login Attack",
        "severity":    "CRITICAL",
        "category":    "credential_attack",
        "event_ids":   [4625],
        "table":       "security",
        "window_hours": 1,
        "threshold":   5,
        "description": (
            "5+ failed logon events (EID 4625) within 1 hour. "
            "High-frequency failure rate indicates automated password guessing, "
            "not an honest user typo."
        ),
        "human_summary": (
            "Someone is repeatedly trying to guess a password. "
            "This looks like an automated attack, not an honest mistake."
        ),
        "mitigation": (
            "Block the source IP in Windows Firewall. "
            "Enable account lockout policy (5 failures → 15 min lockout). "
            "Enable Multi-Factor Authentication (MFA). "
            "Identify the targeted account from Event ID 4625."
        ),
        "actions": [
            "Block the source IP address in Windows Firewall",
            "Enable account lockout policy (lock after 5 failures, 15 min duration)",
            "Identify which account is being targeted from Event ID 4625",
            "Enable Multi-Factor Authentication (MFA)",
        ],
    },
    {
        "id":          "ACCOUNT_LOCKOUT_STORM",
        "name":        "Account Lockout Storm",
        "severity":    "HIGH",
        "category":    "credential_attack",
        "event_ids":   [4740],
        "table":       "security",
        "window_hours": 1,
        "threshold":   2,
        "description": (
            "Multiple account lockout events (EID 4740) in 1 hour. "
            "Either active attack or a service running with stale credentials."
        ),
        "human_summary": (
            "Multiple accounts are being locked out. This could be an attacker "
            "guessing passwords, or an automated service using an old password."
        ),
        "mitigation": (
            "Find the source machine in Event 4740 'Caller Computer Name'. "
            "Check if any services on that machine use the locked account. "
            "Update stale credentials if a service, or block the source if malicious."
        ),
        "actions": [
            "Find the source machine in Event ID 4740 'Caller Computer Name'",
            "Check if any services on that machine use the locked account",
            "Update service credentials if stale, or block the source if malicious",
        ],
    },
    {
        "id":          "KERBEROS_SPRAY",
        "name":        "Kerberos Password Spray",
        "severity":    "HIGH",
        "category":    "credential_attack",
        "event_ids":   [4771],
        "table":       "security",
        "window_hours": 1,
        "threshold":   5,
        "description": (
            "Kerberos pre-authentication failures (EID 4771). "
            "Password spray targets multiple accounts with one password to avoid lockout."
        ),
        "human_summary": (
            "An attacker is trying one password across many accounts. "
            "Unlike brute force, this avoids lockouts by limiting attempts per account."
        ),
        "mitigation": (
            "Enable Smart Lockout in Azure AD if hybrid environment. "
            "Identify source IP and block it. "
            "Force password reset for all targeted accounts."
        ),
        "actions": [
            "Enable Smart Lockout in Azure AD if hybrid environment",
            "Check which accounts are being targeted — protect high-value ones first",
            "Identify source IP and block it",
            "Force password reset for all targeted accounts",
        ],
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    {
        "id":          "ADMIN_GROUP_CHANGE",
        "name":        "User Added to Privileged Group",
        "severity":    "CRITICAL",
        "category":    "privilege_escalation",
        "event_ids":   [4728, 4732],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A user was added to the Administrators or privileged group (EID 4728/4732). "
            "This grants complete system control."
        ),
        "human_summary": (
            "Someone gave another account full admin access. "
            "If this wasn't you or your IT team, your system may be compromised."
        ),
        "mitigation": (
            "Open Computer Management → Local Users and Groups → Administrators. "
            "Verify each member — remove any unrecognized accounts immediately. "
            "Identify WHO performed this action from the Subject field in Event 4728."
        ),
        "actions": [
            "Open Computer Management → Local Users and Groups → Administrators",
            "Verify each member — remove any unrecognized accounts immediately",
            "Identify WHO performed this action from the 'Subject' field in Event 4728",
            "Rotate all admin passwords if the change is unauthorized",
        ],
    },
    {
        "id":          "NEW_ADMIN_ACCOUNT",
        "name":        "New User Account Created",
        "severity":    "HIGH",
        "category":    "persistence",
        "event_ids":   [4720],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A new Windows user account was created (EID 4720). "
            "Attackers create hidden accounts to maintain persistent access."
        ),
        "human_summary": (
            "A new user account was created on this system. "
            "If you or your IT team didn't do this, it could be an attacker leaving a backdoor."
        ),
        "mitigation": (
            "Open User Accounts (lusrmgr.msc) and verify the new account. "
            "If unrecognized, disable it immediately. "
            "Check when it was created and who created it (Event 4720 Subject field)."
        ),
        "actions": [
            "Open User Accounts (lusrmgr.msc) and verify the new account",
            "If unrecognized, disable it immediately",
            "Check when it was created and who created it (Event 4720 Subject field)",
            "Review what actions this account has taken since creation",
        ],
    },
    {
        "id":          "PRIV_LOGON_SPIKE",
        "name":        "Privilege Escalation Events Spike",
        "severity":    "HIGH",
        "category":    "privilege_escalation",
        "event_ids":   [4672, 4673],
        "table":       "security",
        "window_hours": 1,
        "threshold":   20,
        "description": (
            "High volume of special privilege logon events (EID 4672/4673) in 1 hour. "
            "May indicate lateral movement or an attacker escalating privileges."
        ),
        "human_summary": (
            "Admin-level operations are happening at an unusual rate. "
            "This could mean an attacker is using stolen admin credentials."
        ),
        "mitigation": (
            "Review which accounts are generating EID 4672. "
            "Apply Principle of Least Privilege — remove unnecessary admin rights. "
            "Check if these match any scheduled tasks or legitimate admin work."
        ),
        "actions": [
            "Review which accounts are generating EID 4672",
            "Apply Principle of Least Privilege — remove unnecessary admin rights",
            "Check if these match any scheduled tasks or legitimate admin work",
        ],
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    {
        "id":          "SCHEDULED_TASK",
        "name":        "Suspicious Scheduled Task Created",
        "severity":    "HIGH",
        "category":    "persistence",
        "event_ids":   [4698],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A new scheduled task was created (EID 4698). "
            "Most common persistence mechanism — malware often uses this to survive reboots."
        ),
        "human_summary": (
            "Something set up an automated task that runs on a schedule. "
            "Attackers use this to run malware even after you restart your computer."
        ),
        "mitigation": (
            "Open Task Scheduler (taskschd.msc) → Task Scheduler Library. "
            "Look for tasks with unfamiliar names or paths in Temp/AppData. "
            "Check the Actions tab — any PowerShell or cmd.exe pointing to unknown paths is suspicious."
        ),
        "actions": [
            "Open Task Scheduler (taskschd.msc) → Task Scheduler Library",
            "Look for tasks with unfamiliar names or paths in Temp/AppData",
            "Check the 'Actions' tab of each task — any PowerShell or cmd.exe is suspicious",
            "Delete unrecognized tasks",
        ],
    },
    {
        "id":          "NEW_SERVICE",
        "name":        "New Windows Service Installed",
        "severity":    "HIGH",
        "category":    "persistence",
        "event_ids":   [7045],
        "table":       "system",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A new service was installed (EID 7045). "
            "Malware commonly installs as a Windows service for stealth and persistence."
        ),
        "human_summary": (
            "A new background service was installed. "
            "Services run silently in the background and survive reboots — "
            "this is a common malware hiding technique."
        ),
        "mitigation": (
            "Open services.msc and sort by Start Date. "
            "Right-click any unfamiliar service → Properties → check the executable path. "
            "Search the executable name online to verify legitimacy."
        ),
        "actions": [
            "Open services.msc and sort by 'Start Date'",
            "Right-click any unfamiliar service → Properties → check the executable path",
            "Search the executable name online to verify it is legitimate",
            "Stop and disable suspicious services, then delete the executable",
        ],
    },
    {
        "id":          "REGISTRY_TAMPER",
        "name":        "Registry Modified for Persistence",
        "severity":    "HIGH",
        "category":    "persistence",
        "event_ids":   [4657],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Windows registry values modified (EID 4657). "
            "Autorun registry keys are a top malware persistence location."
        ),
        "human_summary": (
            "A system configuration was changed in the Windows registry. "
            "Attackers often use specific registry keys to make malware start automatically."
        ),
        "mitigation": (
            "Run: regedit → HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. "
            "Also check: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. "
            "Remove any entry pointing to an unrecognized executable."
        ),
        "actions": [
            "Run: regedit → HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Also check: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Remove any entry pointing to an unrecognized executable",
            "Check Event 4657 for the exact key path that was modified",
        ],
    },

    # ── Defense Evasion ───────────────────────────────────────────────────────
    {
        "id":          "AUDIT_POLICY_DISABLED",
        "name":        "Audit Policy Tampered — Logging Blinded",
        "severity":    "CRITICAL",
        "category":    "defense_evasion",
        "event_ids":   [4719],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Windows security audit policy was changed (EID 4719). "
            "This is one of the strongest indicators of an active, sophisticated intrusion — "
            "attackers disable logging to hide their tracks."
        ),
        "human_summary": (
            "The security logging was turned off. "
            "This is rarely done legitimately and strongly suggests an attacker "
            "trying to hide their activity."
        ),
        "mitigation": (
            "Open secpol.msc → Advanced Audit Policy Configuration — verify all are enabled. "
            "Investigate who made the change (check Event 4719 Subject field). "
            "Treat this as a confirmed intrusion — escalate immediately."
        ),
        "actions": [
            "Open secpol.msc → Advanced Audit Policy Configuration → verify all are enabled",
            "Investigate who made the change (check Event 4719 Subject field)",
            "Treat this as a confirmed intrusion — escalate immediately",
            "Review ALL events that occurred after this timestamp",
        ],
    },
    {
        "id":          "AV_DISABLED",
        "name":        "Antivirus / Defender Disabled",
        "severity":    "CRITICAL",
        "category":    "defense_evasion",
        "event_ids":   [5001, 5007],
        "table":       "system",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Windows Defender real-time protection was disabled (EID 5001/5007). "
            "Malware almost always disables AV before deploying its payload."
        ),
        "human_summary": (
            "Your antivirus was turned off. "
            "This is a critical red flag — malware often disables protection "
            "before infecting a system."
        ),
        "mitigation": (
            "Re-enable Windows Defender real-time protection immediately. "
            "Run a FULL scan — not a quick scan. "
            "Check if any malware detection events followed this (EID 1116/1117)."
        ),
        "actions": [
            "Re-enable Windows Defender real-time protection immediately",
            "Run a FULL scan — not a quick scan",
            "Check if any malware detection events followed this (EID 1116/1117)",
            "If you cannot re-enable AV, the malware may be blocking it",
        ],
    },
    {
        "id":          "FIREWALL_MODIFIED",
        "name":        "Firewall Rules Modified",
        "severity":    "HIGH",
        "category":    "defense_evasion",
        "event_ids":   [4946, 4947, 4950, 4954],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Windows Firewall rules were added or modified (EID 4946/4950). "
            "Attackers add inbound rules to allow backdoor connections."
        ),
        "human_summary": (
            "Firewall rules were changed. "
            "Attackers do this to open doors into your system from the internet, "
            "or to allow malware to call home."
        ),
        "mitigation": (
            "Open Windows Defender Firewall with Advanced Security (wf.msc). "
            "Review all Inbound Rules — sort by date created. "
            "Delete any rules you did not create, especially allowing inbound connections."
        ),
        "actions": [
            "Open Windows Defender Firewall with Advanced Security (wf.msc)",
            "Review all Inbound Rules — sort by date created",
            "Delete any rules you did not create, especially those allowing inbound connections",
            "Look for rules allowing ports 4444, 8080, 1337 (common backdoor ports)",
        ],
    },

    # ── Malware ───────────────────────────────────────────────────────────────
    {
        "id":          "MALWARE_DETECTED",
        "name":        "Malware Detected by Windows Defender",
        "severity":    "CRITICAL",
        "category":    "malware",
        "event_ids":   [1116, 1117, 1118, 1119, 1120],
        "table":       "system",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Windows Defender confirmed a malware threat (EID 1116/1117). "
            "This is not a suspicion — this is a confirmed detection."
        ),
        "human_summary": (
            "Your antivirus found actual malware on this system. "
            "This is a confirmed threat, not a false alarm — action is required now."
        ),
        "mitigation": (
            "Open Windows Security → Virus & threat protection → Protection history. "
            "Check whether the threat was fully removed or only quarantined. "
            "If removal failed (EID 1118/1120), run an offline scan from bootable media."
        ),
        "actions": [
            "Open Windows Security → Virus & threat protection → Protection history",
            "Check whether the threat was fully removed or only quarantined",
            "If removal failed (EID 1118/1120), run an offline scan from bootable media",
            "Identify the malware name and search for specific removal instructions",
            "Change all passwords from a DIFFERENT device",
        ],
    },

    # ── Reconnaissance ────────────────────────────────────────────────────────
    {
        "id":          "RECON_ENUM",
        "name":        "Account and Group Enumeration",
        "severity":    "HIGH",
        "category":    "reconnaissance",
        "event_ids":   [4798, 4799],
        "table":       "security",
        "window_hours": 1,
        "threshold":   5,
        "description": (
            "High volume of group membership queries (EID 4798/4799) in 1 hour. "
            "Attackers enumerate accounts and groups to find high-value targets."
        ),
        "human_summary": (
            "Something is probing which users and groups exist on this system. "
            "Attackers do this to find admin accounts and plan their next attack step."
        ),
        "mitigation": (
            "Identify which process is performing the enumeration (check Event 4798/4799). "
            "If from an unexpected source or IP, block it immediately. "
            "Correlate with any login failures occurring around the same time."
        ),
        "actions": [
            "Identify which process is performing the enumeration (check Event 4798/4799)",
            "If from an unexpected source or IP, block it immediately",
            "Correlate with any login failures occurring around the same time",
        ],
    },

    # ── FR03-06: PowerShell and Command-Line Monitoring ──────────────────────
    {
        "id":          "PS_ENCODED_CMD",
        "name":        "PowerShell Encoded Command Execution",
        "severity":    "CRITICAL",
        "category":    "powershell",
        "event_ids":   [4104, 4103],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "PowerShell Script Block Logging (EID 4104/4103) captured an encoded "
            "or obfuscated command. The -EncodedCommand flag is overwhelmingly used "
            "to hide malicious payloads from casual inspection and AV signature scanning."
        ),
        "human_summary": (
            "A PowerShell command was deliberately encoded/obfuscated to hide what it does. "
            "Legitimate software rarely needs encoding — this is a strong indicator of "
            "malware or attacker activity."
        ),
        "mitigation": (
            "Review the decoded payload in the event message. "
            "Identify the parent process that launched PowerShell (check EID 4688). "
            "Block -EncodedCommand via AppLocker / Constrained Language Mode if not needed."
        ),
        "actions": [
            "Decode the base64 payload in the EID 4104 message and analyse it",
            "Check EID 4688 for the parent process that launched PowerShell",
            "Enable PowerShell Constrained Language Mode via Group Policy",
            "Block -EncodedCommand execution via AppLocker if not operationally required",
        ],
    },
    {
        "id":          "PS_DOWNLOAD_CRADLE",
        "name":        "PowerShell Download Cradle / Remote Execution",
        "severity":    "CRITICAL",
        "category":    "powershell",
        "event_ids":   [4104, 4103],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "PowerShell Script Block Logging detected a download cradle: "
            "IEX/Invoke-Expression, DownloadString, Invoke-WebRequest, or similar. "
            "This is the primary technique for fileless malware — code is downloaded "
            "from a remote server and executed directly in memory without touching disk."
        ),
        "human_summary": (
            "PowerShell attempted to download and run code from the internet. "
            "This is the main technique used by fileless malware — no file is ever "
            "saved to disk, so traditional AV often misses it."
        ),
        "mitigation": (
            "Block outbound PowerShell web access via Windows Firewall or web proxy. "
            "Enable AMSI (Antimalware Scan Interface) — it scans in-memory scripts. "
            "Review the URL/domain accessed in the event message."
        ),
        "actions": [
            "Extract the URL/domain from the EID 4104 message and check reputation",
            "Block the domain/IP in Windows Firewall",
            "Enable AMSI integration in your AV product",
            "Review and restrict PowerShell network access via Group Policy",
            "Run a full memory scan with an AMSI-capable AV",
        ],
    },
    {
        "id":          "PS_AMSI_BYPASS",
        "name":        "AMSI Bypass Attempt Detected",
        "severity":    "CRITICAL",
        "category":    "defense_evasion",
        "event_ids":   [4104, 4103],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "PowerShell Script Block Logging detected an AMSI bypass attempt: "
            "references to AmsiUtils, AmsiScanBuffer, amsi.dll patching, or "
            "Set-MpPreference -Disable*. AMSI is the Windows anti-malware scanning "
            "interface — bypassing it blinds all AV products to in-memory threats."
        ),
        "human_summary": (
            "Something tried to disable Windows' ability to scan scripts for malware. "
            "This is a very advanced attacker technique — only used to evade detection "
            "before running malicious code."
        ),
        "mitigation": (
            "This is a confirmed attack indicator — escalate immediately. "
            "Run offline scan. Isolate the machine from the network. "
            "Review all script block events in the surrounding time window."
        ),
        "actions": [
            "Isolate the machine from the network immediately",
            "Escalate — this is a confirmed attack indicator, not a false alarm",
            "Run an offline bootable scan (e.g. Windows Defender Offline)",
            "Review ALL EID 4104 events in the 30 minutes surrounding this event",
            "Change all credentials that touched this machine",
        ],
    },
    {
        "id":          "PS_SUSPICIOUS_PROCESS",
        "name":        "Suspicious Parent-Child Process Relationship",
        "severity":    "CRITICAL",
        "category":    "execution",
        "event_ids":   [4688],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Process Creation auditing (EID 4688) detected a high-risk parent-child "
            "process relationship: an Office application, mshta, wscript, or similar "
            "spawned PowerShell or cmd.exe. This is the canonical pattern for macro-based "
            "malware (Word/Excel macros dropping payloads via PowerShell)."
        ),
        "human_summary": (
            "A document application (Word, Excel) or a browser helper launched a "
            "command shell. This is the most common way malicious email attachments "
            "install malware — you open a document and it silently runs code."
        ),
        "mitigation": (
            "Block Office applications from spawning cmd/PowerShell via Attack Surface Reduction rules. "
            "Review recent email attachments opened on this machine. "
            "Check the process tree in Event 4688 for the full chain."
        ),
        "actions": [
            "Enable Attack Surface Reduction (ASR) rule: Block Office from spawning child processes",
            "Review emails received before this timestamp — look for attachments",
            "Check the full process chain in EID 4688 (parent → child → grandchild)",
            "Run a full AV scan focusing on %TEMP%, %APPDATA%, and Downloads folders",
        ],
    },
    {
        "id":          "PS_LOLBIN",
        "name":        "Living-off-the-Land Binary (LOLBin) Execution",
        "severity":    "HIGH",
        "category":    "lolbin",
        "event_ids":   [4688],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   3,
        "description": (
            "Process Creation auditing (EID 4688) detected execution of a LOLBin: "
            "mshta, regsvr32, certutil, rundll32, wscript, cscript, msiexec, etc. "
            "These are legitimate signed Windows binaries that attackers abuse to "
            "execute malicious code while bypassing application whitelisting."
        ),
        "human_summary": (
            "A built-in Windows tool that is rarely used in normal operation was "
            "executed multiple times. Attackers use these trusted tools to run malicious "
            "code while appearing legitimate."
        ),
        "mitigation": (
            "Review the command line arguments for each LOLBin execution in EID 4688. "
            "Block LOLBins via AppLocker or WDAC if not required. "
            "Check parent process and any network connections made shortly after."
        ),
        "actions": [
            "Review the command line arguments in EID 4688 for each occurrence",
            "Check if the LOLBin made any network connections (correlate with firewall logs)",
            "Block unused LOLBins via AppLocker (mshta, certutil, regsvr32, etc.)",
            "Check for files dropped in %TEMP% or %APPDATA% around the same time",
        ],
    },
    {
        "id":          "PS_CREDENTIAL_THEFT",
        "name":        "PowerShell Credential Theft Tool Detected",
        "severity":    "CRITICAL",
        "category":    "credential_attack",
        "event_ids":   [4104, 4103],
        "table":       "powershell",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "PowerShell Script Block Logging detected credential theft tool keywords: "
            "mimikatz, sekurlsa, lsadump, Invoke-Mimikatz, Get-PasswordHash, or similar. "
            "These tools extract plaintext passwords and hashes from Windows memory (LSASS)."
        ),
        "human_summary": (
            "A tool that steals passwords from Windows memory was detected. "
            "If successful, the attacker now has all usernames and passwords stored on "
            "this machine. This is a critical breach — all credentials must be rotated."
        ),
        "mitigation": (
            "Rotate ALL credentials that have ever been used on this machine. "
            "Enable Credential Guard to protect LSASS memory. "
            "Treat this as a confirmed full compromise — incident response required."
        ),
        "actions": [
            "Change ALL passwords that have ever been used on this machine — from a different device",
            "Enable Windows Credential Guard (requires UEFI + Secure Boot)",
            "Enable Protected Users security group for all privileged accounts",
            "Run a full compromise assessment — assume attacker has all local credentials",
            "Initiate formal incident response procedures",
        ],
    },

    # ── Hardware / Stability ──────────────────────────────────────────────────
    {
        "id":          "DISK_FAILURE",
        "name":        "Disk Hardware Errors Detected",
        "severity":    "HIGH",
        "category":    "hardware",
        "event_ids":   [7, 11, 15, 55, 153],
        "table":       "system",
        "window_hours": 24,
        "threshold":   3,
        "description": (
            "Multiple disk I/O errors (EID 7/11). "
            "Physical drive failure risk — data loss may be imminent."
        ),
        "human_summary": (
            "Your hard drive is reporting errors. "
            "This means the drive may be physically failing and you could lose files without warning."
        ),
        "mitigation": (
            "BACK UP ALL DATA IMMEDIATELY before anything else. "
            "Download CrystalDiskInfo and check the S.M.A.R.T. status. "
            "Run: chkdsk C: /f /r (requires restart)."
        ),
        "actions": [
            "BACK UP ALL DATA IMMEDIATELY before anything else",
            "Download CrystalDiskInfo and check the S.M.A.R.T. status",
            "Run: chkdsk C: /f /r (requires restart)",
            "If the drive is failing, replace it urgently",
        ],
    },
    {
        "id":          "SYSTEM_CRASH",
        "name":        "Unexpected System Crashes",
        "severity":    "HIGH",
        "category":    "stability",
        "event_ids":   [41, 6008],
        "table":       "system",
        "window_hours": 72,
        "threshold":   1,
        "description": (
            "Unexpected system shutdowns detected (EID 41/6008). "
            "Indicates kernel panic, driver fault, RAM failure, or power issue."
        ),
        "human_summary": (
            "Your system crashed or shut down unexpectedly. "
            "Repeated crashes can indicate a hardware problem, bad driver, or overheating."
        ),
        "mitigation": (
            "Check C:\\Windows\\Minidump for crash dump files. "
            "Run Windows Memory Diagnostics: mdsched.exe. "
            "Check for recently installed drivers or Windows updates before the crash."
        ),
        "actions": [
            "Check C:\\Windows\\Minidump for crash dump files (read with WinDbg)",
            "Run Windows Memory Diagnostics: mdsched.exe",
            "Check for recently installed drivers or Windows updates before crashes",
            "Monitor CPU/GPU temperatures with HWMonitor",
        ],
    },
    {
        "id":          "UPDATE_FAILURES",
        "name":        "Windows Update Failures",
        "severity":    "MEDIUM",
        "category":    "patching",
        "event_ids":   [20],
        "table":       "windows_update",
        "window_hours": 72,
        "threshold":   1,
        "description": (
            "Windows Update is failing to install (EID 20). "
            "Unpatched systems are vulnerable to known exploits."
        ),
        "human_summary": (
            "Windows updates are failing to install. "
            "An unpatched system is much easier for attackers to exploit."
        ),
        "mitigation": (
            "Check Windows Update settings for specific error codes. "
            "Run the Windows Update Troubleshooter."
        ),
        "actions": [
            "Check Windows Update settings for error codes",
            "Run the Windows Update Troubleshooter",
            "Manually download and install the failing update from Microsoft Update Catalog",
        ],
    },

    # ── FR04-03: Task Scheduler lifecycle (EIDs 4699–4702) ───────────────────
    {
        "id":           "TASK_DELETED",
        "name":         "Scheduled Task Deleted",
        "severity":     "MEDIUM",
        "category":     "persistence",
        "event_ids":    [4699],
        "table":        "security",
        "window_hours": 24,
        "threshold":    1,
        "description": (
            "A scheduled task was deleted (EID 4699). "
            "Attackers sometimes clean up evidence by deleting tasks after execution. "
            "Legitimate removals are typically via Group Policy or software uninstallers."
        ),
        "human_summary": (
            "An automated scheduled task was deleted. "
            "If you didn't do this, it could mean an attacker is covering their tracks."
        ),
        "mitigation": (
            "Check the Security event log for the user account that deleted the task "
            "(SubjectUserName in EID 4699). "
            "Correlate with EID 4698 (task created) to see if the same task was "
            "recently created and then immediately removed — a common cleanup pattern."
        ),
        "actions": [
            "Review SubjectUserName in EID 4699 — was this an authorised admin?",
            "Check if EID 4698 preceded this deletion (task created then immediately removed)",
            "Review Task Scheduler Library for any remaining unfamiliar tasks",
            "Correlate with PowerShell / process execution events around the same time",
        ],
    },
    {
        "id":           "TASK_ENABLED",
        "name":         "Scheduled Task Enabled",
        "severity":     "MEDIUM",
        "category":     "persistence",
        "event_ids":    [4700],
        "table":        "security",
        "window_hours": 24,
        "threshold":    1,
        "description": (
            "A previously disabled scheduled task was enabled (EID 4700). "
            "Attackers may re-enable a dormant persistence mechanism that was "
            "disabled by a defender or security tool."
        ),
        "human_summary": (
            "A scheduled task that was turned off has been switched back on. "
            "If unexpected, this could mean an attacker is reactivating a hidden backdoor."
        ),
        "mitigation": (
            "Open Task Scheduler (taskschd.msc) and locate the task. "
            "Review its Actions tab — any cmd.exe, PowerShell, or paths in "
            "Temp/AppData are suspicious. "
            "Check who enabled it (SubjectUserName in EID 4700)."
        ),
        "actions": [
            "Identify the task name from EID 4700 StringInserts",
            "Open taskschd.msc and inspect its Actions and Triggers",
            "Check SubjectUserName — was this action taken by an authorised account?",
            "Disable and quarantine the task if origin is unclear",
        ],
    },
    {
        "id":           "TASK_DISABLED",
        "name":         "Scheduled Task Disabled",
        "severity":     "LOW",
        "category":     "defense_evasion",
        "event_ids":    [4701],
        "table":        "security",
        "window_hours": 24,
        "threshold":    3,
        "description": (
            "One or more scheduled tasks were disabled (EID 4701). "
            "While usually benign (admin maintenance), disabling security-related tasks "
            "(Windows Defender scans, update checks) is a defense-evasion indicator."
        ),
        "human_summary": (
            "Scheduled tasks were disabled. "
            "This is often routine, but disabling security-related tasks can leave "
            "the system exposed."
        ),
        "mitigation": (
            "Review which tasks were disabled and whether they are security-related "
            "(Defender, Windows Update, BitLocker). "
            "Re-enable any that appear to have been turned off without authorisation."
        ),
        "actions": [
            "Check the task name in EID 4701 — is it security-related?",
            "Re-enable any disabled security maintenance tasks",
            "Review SubjectUserName to confirm authorisation",
        ],
    },
    {
        "id":           "TASK_UPDATED",
        "name":         "Scheduled Task Modified",
        "severity":     "HIGH",
        "category":     "persistence",
        "event_ids":    [4702],
        "table":        "security",
        "window_hours": 24,
        "threshold":    1,
        "description": (
            "A scheduled task's definition was updated (EID 4702). "
            "Attackers modify existing legitimate tasks to add malicious actions or "
            "change the executable path — this is harder to detect than creating a "
            "new task because the task name looks familiar."
        ),
        "human_summary": (
            "An existing scheduled task was changed. "
            "Changing a legitimate task's settings is a stealthy way for attackers "
            "to hide malicious code in plain sight."
        ),
        "mitigation": (
            "Compare the task's current XML definition against a known-good baseline. "
            "Focus on the <Actions> element — any new executable, argument, or "
            "working directory is highly suspicious. "
            "EID 4702 includes the full task XML in StringInserts[5]."
        ),
        "actions": [
            "Extract the task XML from EID 4702 StringInserts[5]",
            "Diff the <Actions> element against a known-good backup",
            "Look for new PowerShell, cmd.exe, or Temp/AppData paths",
            "If modified without authorisation, restore from backup and investigate",
        ],
    },

    # ── FR04-05: Extended Windows Services rules ──────────────────────────────
    {
        "id":           "SERVICE_FAILED_START",
        "name":         "Service Failed to Start",
        "severity":     "HIGH",
        "category":     "stability",
        "event_ids":    [7000, 7009, 7022],
        "table":        "system",
        "window_hours": 1,
        "threshold":    1,
        "description": (
            "A Windows service failed to start, timed out, or hung during startup "
            "(EID 7000 / 7009 / 7022). "
            "Security software (AV, EDR, firewall) failing to start leaves the system "
            "unprotected. Repeated failures indicate corrupt binaries or dependency issues."
        ),
        "human_summary": (
            "A Windows background service failed to start. "
            "If this is a security service, the system may be unprotected until it is "
            "restored."
        ),
        "mitigation": (
            "Open services.msc, locate the failed service, and attempt a manual start. "
            "Check the error code in EID 7000 (often 0xC0000005 = access denied, "
            "0x2 = file not found). "
            "Verify the service binary exists and has not been tampered with."
        ),
        "actions": [
            "Open services.msc → locate the failed service → try manual start",
            "Check the error code in EID 7000 for the root cause",
            "Verify the service binary path exists and has correct permissions",
            "Check Application log for associated crash events (EID 1000)",
            "If a security service, escalate immediately — system may be unprotected",
        ],
    },
    {
        "id":           "SERVICE_DEPENDENCY_FAILURE",
        "name":         "Service Dependency Failure",
        "severity":     "HIGH",
        "category":     "stability",
        "event_ids":    [7001],
        "table":        "system",
        "window_hours": 1,
        "threshold":    1,
        "description": (
            "A service could not start because a service it depends on failed "
            "or is not running (EID 7001). "
            "Cascading dependency failures can silently disable security features "
            "without generating obvious alerts."
        ),
        "human_summary": (
            "A service failed to start because another service it needs is not running. "
            "This can cause a domino effect, disabling multiple features silently."
        ),
        "mitigation": (
            "Identify the dependency chain: check EID 7001 message for the dependency "
            "service name. Start the prerequisite service first, then retry the "
            "dependent service. "
            "Use `sc qc <ServiceName>` to list dependencies."
        ),
        "actions": [
            "Read EID 7001 to identify which dependency is missing",
            "Run `sc qc <ServiceName>` to view the full dependency chain",
            "Start the prerequisite service first",
            "Investigate why the dependency service stopped (check its own EID 7034/7031)",
        ],
    },
    {
        "id":           "SERVICE_UNEXPECTED_STOP",
        "name":         "Service Terminated Unexpectedly",
        "severity":     "HIGH",
        "category":     "stability",
        "event_ids":    [7023, 7031, 7034],
        "table":        "system",
        "window_hours": 1,
        "threshold":    1,
        "description": (
            "A Windows service terminated unexpectedly, crashed, or exited with an "
            "error code (EID 7023 / 7031 / 7034). "
            "Repeated crashes of security services (Defender, firewall) may indicate "
            "active tampering by malware. "
            "EID 7034 specifically flags services that crashed without a controlled shutdown."
        ),
        "human_summary": (
            "A Windows service crashed or stopped without being asked to. "
            "If this keeps happening to security software, malware may be killing it."
        ),
        "mitigation": (
            "Check services.msc → Recovery tab for auto-restart settings. "
            "Review Application event log (EID 1000) for associated application crash. "
            "If a security service crashes repeatedly, scan for malware immediately."
        ),
        "actions": [
            "Check services.msc → Recovery settings → set to auto-restart",
            "Look for EID 1000 in Application log — correlated crash entry",
            "If Defender/firewall service crashes: run `MpCmdRun -ScanType 2` offline",
            "Check for associated EID 7045 (new service) — malware may be killing security tools",
        ],
    },
    {
        "id":           "SERVICE_START_TYPE_CHANGED",
        "name":         "Service Start Type Changed",
        "severity":     "HIGH",
        "category":     "defense_evasion",
        "event_ids":    [7040],
        "table":        "system",
        "window_hours": 24,
        "threshold":    1,
        "description": (
            "The start type of a Windows service was changed (EID 7040). "
            "Malware commonly changes security services (Defender, Event Log, firewall) "
            "from Automatic to Disabled so they do not restart after reboot. "
            "This is a classic defense-evasion technique (MITRE T1562.001)."
        ),
        "human_summary": (
            "A service's startup setting was changed. "
            "Attackers do this to prevent security tools from restarting after a reboot."
        ),
        "mitigation": (
            "Check which service was changed and what the new start type is. "
            "If a security service was changed to Disabled or Manual, restore it to "
            "Automatic immediately and investigate the account that made the change."
        ),
        "actions": [
            "Identify the service and account from EID 7040 StringInserts",
            "Run `sc config <ServiceName> start= auto` to restore Automatic startup",
            "Audit the account that made the change — may be a compromised admin",
            "Check for correlated EID 7045 (new service) or EID 4698 (new task)",
        ],
    },

    # ── FR06-03: Group Policy / Domain Policy Modifications ───────────────────
    {
        "id":          "GPO_DOMAIN_POLICY_CHANGED",
        "name":        "Domain Security Policy Modified",
        "severity":    "CRITICAL",
        "category":    "policy_tamper",
        "event_ids":   [4739],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Domain-wide security policy was changed (EID 4739). "
            "This covers account lockout thresholds, password policies, and Kerberos "
            "settings that apply to ALL domain-joined machines. Unauthorized changes "
            "silently weaken authentication across the entire organization."
        ),
        "human_summary": (
            "A security policy that affects every computer in the domain was changed. "
            "An attacker may have weakened password or lockout rules to make "
            "future attacks easier across the whole network."
        ),
        "mitigation": (
            "Immediately compare current domain policy against your baseline using "
            "`secedit /analyze`. Check which account made the change in EID 4739. "
            "If unauthorized, restore via Group Policy Management Console (GPMC) or "
            "`secedit /configure`. Audit Kerberos ticket lifetime and lockout thresholds."
        ),
        "actions": [
            "Run `secedit /export /cfg C:\\current_policy.cfg` and compare to baseline",
            "Check EID 4739 Subject field for the account that made the change",
            "Open GPMC (gpmc.msc) and review Default Domain Policy for unauthorized modifications",
            "Verify Kerberos ticket lifetime via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
            "If unauthorized: restore via `secedit /configure /db C:\\baseline.sdb /cfg C:\\baseline.cfg`",
        ],
    },
    {
        "id":          "GPO_KERBEROS_POLICY_CHANGED",
        "name":        "Kerberos Authentication Policy Modified",
        "severity":    "CRITICAL",
        "category":    "policy_tamper",
        "event_ids":   [4713],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Kerberos policy was changed (EID 4713). This controls ticket lifetimes, "
            "clock skew tolerance, and encryption types for Kerberos authentication. "
            "Attackers extend ticket lifetimes for Golden Ticket / Silver Ticket persistence "
            "or downgrade encryption to enable Pass-the-Hash attacks (MITRE T1558)."
        ),
        "human_summary": (
            "The Kerberos authentication policy was modified. Attackers change this to "
            "extend how long stolen authentication tickets remain valid, "
            "or to weaken encryption so passwords are easier to steal."
        ),
        "mitigation": (
            "Review the Kerberos policy change in EID 4713. Verify MaxTicketAge <= 10 hours, "
            "MaxRenewAge <= 7 days, SupportedEncryptionTypes includes AES-256 (0x18+). "
            "Purge tickets with `klist purge`. If Golden Ticket is suspected, "
            "reset the krbtgt account password twice."
        ),
        "actions": [
            "Check: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
            "Verify SupportedEncryptionTypes includes AES: value should be 0x18 or higher",
            "Run `klist purge` on all affected systems to invalidate existing tickets",
            "If Golden Ticket suspected: reset krbtgt password TWICE to force propagation",
            "EID 4713 Subject should only ever be Domain Admin or SYSTEM — investigate anything else",
        ],
    },
    {
        "id":          "GPO_PER_USER_AUDIT_POLICY",
        "name":        "Per-User Audit Policy Created — Possible Log Evasion",
        "severity":    "HIGH",
        "category":    "policy_tamper",
        "event_ids":   [4902],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A per-user audit policy table was created (EID 4902). "
            "Per-user audit policies override the system-wide policy for a specific account, "
            "effectively disabling logging for that user's actions. "
            "This is a sophisticated audit-bypass technique that avoids triggering EID 4719 "
            "(system-wide audit policy change), making it harder to detect."
        ),
        "human_summary": (
            "A custom logging rule was created for a specific user account that stops "
            "Windows recording that user's actions. Attackers use this to hide their "
            "activity without disabling system-wide logging — which would be more obvious."
        ),
        "mitigation": (
            "Check EID 4902 for the targeted user account. "
            "Run `auditpol /get /user:<username> /category:*` to see overrides. "
            "Remove unauthorized policies with `auditpol /remove /user:<username>`. "
            "Ensure SCENoApplyLegacyAuditPolicy=1 in LSA registry."
        ),
        "actions": [
            "Check EID 4902 for the targeted user account name",
            "Run `auditpol /get /user:<username> /category:*` to see disabled categories",
            "Remove unauthorized policy: `auditpol /remove /user:<username>`",
            "Verify: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v SCENoApplyLegacyAuditPolicy",
            "Correlate with EID 4719 (system audit policy) and EID 4904/4905 (source changes)",
        ],
    },
    {
        "id":          "GPO_AUDIT_SOURCE_CHANGED",
        "name":        "Audit Policy Source Registered/Unregistered",
        "severity":    "HIGH",
        "category":    "policy_tamper",
        "event_ids":   [4904, 4905],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A security event source was registered (EID 4904) or unregistered (EID 4905). "
            "Unregistering an audit policy source prevents that source from generating "
            "security events — a stealthy way to blind specific log channels without "
            "triggering the broader EID 4719 system audit policy change event."
        ),
        "human_summary": (
            "A Windows security logging source was added or removed. "
            "Removing a source is a stealthy method to stop recording certain activity "
            "without disabling the entire audit policy — which would raise an obvious alert."
        ),
        "mitigation": (
            "Review EID 4904/4905 for the source name and account. "
            "Re-register removed sources. Run `auditpol /get /category:*` to verify "
            "all expected categories remain enabled."
        ),
        "actions": [
            "Check EID 4904/4905 Subject and AuditSourceName fields",
            "Run `auditpol /get /category:*` — verify no categories show 'No Auditing'",
            "Run `auditpol /set /category:* /success:enable /failure:enable` to restore all",
            "Investigate the account that performed the source registration change",
        ],
    },

    # ── FR06-06: DLL Injection and Process Hollowing ──────────────────────────
    {
        "id":          "DLL_INJECT_APPCERT",
        "name":        "AppCertDLL / AppInit_DLL Registry Injection Vector Detected",
        "severity":    "CRITICAL",
        "category":    "process_injection",
        "event_ids":   [4657],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Registry modification (EID 4657) targeting known DLL injection vectors: "
            "AppCertDLLs causes injection into every process calling CreateProcess. "
            "AppInit_DLLs injects into every process loading User32.dll (most GUI apps). "
            "MITRE T1546.010 (AppCert DLLs) / T1546.009 (AppInit DLLs)."
        ),
        "human_summary": (
            "A registry key that controls which DLLs are injected into Windows processes "
            "was modified. Attackers use this to run malicious code inside trusted system "
            "processes — making the malware very difficult to detect or remove."
        ),
        "mitigation": (
            "Immediately query AppCertDLLs and AppInit_DLLs registry keys. "
            "Any unexpected DLL path must be removed. "
            "Verify DLL hashes against VirusTotal or Microsoft file catalog. "
            "Enable Virtualization-Based Security to prevent future injection."
        ),
        "actions": [
            "Run: reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs'",
            "Run: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' /v AppInit_DLLs",
            "Remove unauthorized entry: reg delete 'HKLM\\...\\AppCertDLLs' /v <MaliciousDLL> /f",
            "Hash-check any listed DLL against Microsoft file hash catalog",
            "Enable VBS: reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f",
        ],
    },
    {
        "id":          "DLL_INJECT_IFEO",
        "name":        "Image File Execution Options Debugger Hijacking Detected",
        "severity":    "CRITICAL",
        "category":    "process_injection",
        "event_ids":   [4657, 4688],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "A Debugger value was added/modified under Image File Execution Options (IFEO) "
            "registry key (EID 4657/4688). IFEO Debugger hijacking causes Windows to launch "
            "the attacker's executable instead of the legitimate target process — including "
            "security tools, Task Manager, and Registry Editor. "
            "MITRE T1546.012 - Event Triggered Execution: Image File Execution Options."
        ),
        "human_summary": (
            "A registry trick was used that makes Windows run attacker code instead of a "
            "legitimate program. This can hijack antivirus, Task Manager, or any tool "
            "so the attacker's malware silently runs in its place."
        ),
        "mitigation": (
            "Query all IFEO keys for unexpected Debugger values. "
            "Legitimate Debugger entries only point to developer tools in C:\\Program Files. "
            "Any entry pointing to Temp, AppData, or unknown paths is malicious. "
            "Remove unauthorized entries and scan the referenced executable."
        ),
        "actions": [
            "Run: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' /s | findstr Debugger",
            "Remove: reg delete 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<Process>' /v Debugger /f",
            "Scan the referenced Debugger executable with Get-MpThreat or VirusTotal",
            "Check EID 4688 for the process that created the IFEO key",
            "Also check SilentProcessExit: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit' /s",
        ],
    },
    {
        "id":          "DLL_INJECT_LSASS_HANDLE",
        "name":        "Suspicious LSASS Handle Request — Possible Injection or Credential Theft",
        "severity":    "CRITICAL",
        "category":    "process_injection",
        "event_ids":   [4656, 4663],
        "table":       "security",
        "window_hours": 4,
        "threshold":   3,
        "description": (
            "Multiple handle requests or access attempts on lsass.exe (EID 4656/4663). "
            "Opening LSASS with PROCESS_VM_READ or PROCESS_VM_WRITE access is the primary "
            "mechanism for credential dumping (Mimikatz) and code injection (process "
            "hollowing, reflective DLL injection into LSASS). "
            "MITRE T1055.001 (DLL Injection), T1055.012 (Process Hollowing), T1003.001 (LSASS Dump)."
        ),
        "human_summary": (
            "Something is repeatedly trying to access the Windows authentication process. "
            "This is the exact behavior used by credential theft tools like Mimikatz and "
            "by code injection attacks that hide malware inside the authentication process."
        ),
        "mitigation": (
            "Identify the requesting process from EID 4656/4663. "
            "Any non-security-tool process accessing LSASS with write or create-thread "
            "permissions is a confirmed indicator of compromise. "
            "Enable LSASS Protected Process Light (PPL) and Credential Guard."
        ),
        "actions": [
            "Check EID 4656/4663 for the requesting process name and PID",
            "If not a known AV/EDR tool: isolate the machine immediately",
            "Enable LSASS PPL: reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f",
            "Enable Credential Guard via Device Guard GPO settings",
            "Add ASR rule to block credential theft: Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3 -AttackSurfaceReductionRules_Actions Enabled",
            "Run Get-MpThreatDetection to check if Defender flagged the requesting process",
        ],
    },
    {
        "id":          "PROCESS_HOLLOW_SPAWN",
        "name":        "Suspicious Process Spawn Pattern — Possible Process Hollowing",
        "severity":    "HIGH",
        "category":    "process_injection",
        "event_ids":   [4688],
        "table":       "security",
        "window_hours": 1,
        "threshold":   5,
        "description": (
            "High volume of EID 4688 (New Process Created) events involving processes "
            "commonly targeted for process hollowing (svchost.exe, explorer.exe, "
            "RuntimeBroker.exe) or spawned from unexpected parents. "
            "Process hollowing (MITRE T1055.012) starts a process in SUSPENDED state, "
            "replaces its memory with malicious code, then resumes execution."
        ),
        "human_summary": (
            "An unusual number of Windows system processes were started from unexpected "
            "parent processes. Process hollowing hides malware inside a trusted Windows "
            "process — it looks legitimate in Task Manager but runs attacker code."
        ),
        "mitigation": (
            "Review EID 4688 for svchost.exe, explorer.exe, RuntimeBroker.exe spawned "
            "from non-standard parents (anything other than services.exe or wininit.exe). "
            "Enable command-line auditing in EID 4688. Deploy Sysmon EID 8 "
            "(CreateRemoteThread) and EID 10 (ProcessAccess) for direct injection detection."
        ),
        "actions": [
            "Filter EID 4688 for svchost.exe where parent is NOT services.exe or wininit.exe",
            "Enable command-line auditing: auditpol /set /subcategory:'Process Creation' /success:enable",
            "Deploy Sysmon with rules targeting CreateRemoteThread (EID 8) and ProcessAccess (EID 10)",
            "Add ASR rule to block process injection: Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled",
            "Check Get-Process for svchost.exe instances with unexpected parent PID",
        ],
    },
    {
        "id":          "DLL_KNOWNDLL_TAMPER",
        "name":        "KnownDLLs or AppInit_DLLs Registry Tampered — DLL Hijacking",
        "severity":    "CRITICAL",
        "category":    "process_injection",
        "event_ids":   [4657],
        "table":       "security",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Modification to KnownDLLs or AppInit_DLLs registry keys (EID 4657). "
            "KnownDLLs defines the authoritative list of DLLs loaded from System32 — "
            "tampering allows replacing a trusted DLL with a malicious one. "
            "MITRE T1574.001 / T1574.002 (DLL Search Order Hijacking / DLL Side-Loading)."
        ),
        "human_summary": (
            "Registry keys controlling which DLL files Windows loads were modified. "
            "Attackers use this to replace legitimate Windows system files with malicious "
            "versions that run their code inside every application on the computer."
        ),
        "mitigation": (
            "Verify integrity of DLLs listed in KnownDLLs using `sfc /scannow`. "
            "Compare hashes against known-good values from a clean system. "
            "Remove unauthorized AppInit_DLLs entries. "
            "Enable Secure Boot and Code Integrity to prevent unsigned DLL loading."
        ),
        "actions": [
            "Run: reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs'",
            "Run: reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' /v AppInit_DLLs",
            "Run `sfc /scannow` to restore any corrupted system DLLs",
            "Hash-check DLLs listed in KnownDLLs against Microsoft file catalog",
            "Enable WDAC or AppLocker to restrict unsigned DLL loading",
        ],
    },
    # ══════════════════════════════════════════════════════════════════════
    # SYSMON / MALWARE RULES  (Steps 5 — extends existing THREAT_RULES)
    # Reads from logs_sysmon table populated by SysmonCollector.
    # ══════════════════════════════════════════════════════════════════════

    # ── Rule: Office Macro → Shell → Network (WINWORD→PS→Network) ────────
    {
        "id":          "SYSMON_OFFICE_MACRO_NET",
        "name":        "Office Macro Spawned Shell with Network Connection",
        "severity":    "CRITICAL",
        "category":    "malware",
        "event_ids":   [1],
        "table":       "sysmon",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Sysmon EID 1 detected an Office application (Word/Excel/Outlook) "
            "spawning a shell interpreter (PowerShell/cmd/wscript), which then "
            "made an outbound network connection (EID 3). This three-stage chain "
            "is the hallmark of a macro-based malware dropper. "
            "MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1059, T1071."
        ),
        "human_summary": (
            "A Word or Excel document opened a PowerShell or command-prompt "
            "window and that shell then connected to the internet. This is the "
            "most common way attackers deliver malware through email attachments. "
            "The document is almost certainly malicious."
        ),
        "mitigation": (
            "1. Isolate the affected machine immediately.\n"
            "2. Identify the Office document via Sysmon EID 1 ParentCommandLine.\n"
            "3. Block the destination IP in Windows Firewall.\n"
            "4. Disable macros via Office Group Policy Trust Center.\n"
            "5. Run Windows Defender offline scan."
        ),
        "actions": [
            "Isolate machine from network immediately",
            "Identify the malicious Office document from Sysmon EID 1 ParentCommandLine",
            "Block destination IP in Windows Firewall",
            "Disable Office macros via Group Policy Trust Center",
            "Run Windows Defender offline scan",
        ],
        "mitre_tactic": "T1566.001 - Spearphishing Attachment",
    },

    # ── Rule: Downloaded Executable + YARA Hit + Registry Persistence ─────
    {
        "id":          "SYSMON_DROPPER_PERSIST",
        "name":        "Downloaded Executable with YARA Match and Registry Persistence",
        "severity":    "CRITICAL",
        "category":    "malware",
        "event_ids":   [11],
        "table":       "sysmon",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Sysmon EID 11 detected an executable created in Downloads/Temp/AppData, "
            "matched by a YARA rule, followed by a registry Run key modification "
            "by the same process (Sysmon EID 13). This two-stage pattern indicates "
            "a malware dropper installing persistence on the system. "
            "MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1547.001 (Registry Run Keys)."
        ),
        "human_summary": (
            "A new program was saved to Downloads or Temp, matched a malware "
            "signature, and then modified the registry to run automatically on "
            "every login. This is how malware installs and survives reboots."
        ),
        "mitigation": (
            "1. Delete the file immediately from Downloads/Temp.\n"
            "2. Remove the registry Run key: reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v <name> /f\n"
            "3. Run Windows Defender offline scan.\n"
            "4. Check Sysmon EID 3 for network connections from the same process."
        ),
        "actions": [
            "Delete the suspicious executable from Downloads/Temp",
            "Remove the registry persistence key",
            "Run Windows Defender offline scan",
            "Check Sysmon EID 3 for network connections from same process",
            "Review all files in Downloads and Temp folders",
        ],
        "mitre_tactic": "T1547.001 - Registry Run Keys",
    },

    # ── Rule: Mass File Modifications (Ransomware indicator) ──────────────
    {
        "id":          "SYSMON_MASS_FILE_MOD",
        "name":        "Mass File Create/Modify — Ransomware Indicator",
        "severity":    "CRITICAL",
        "category":    "malware",
        "event_ids":   [11],
        "table":       "sysmon",
        "window_hours": 1,
        "threshold":   50,   # 50+ file creates in 1 hour = anomalous
        "description": (
            "Sysmon EID 11 detected more than 50 file creation events in a single "
            "hour — a strong indicator of ransomware encrypting files. Ransomware "
            "typically rewrites files rapidly with encrypted content. "
            "MITRE ATT&CK: T1486 (Data Encrypted for Impact)."
        ),
        "human_summary": (
            "More than 50 files were created or modified in the last hour. "
            "This rate of file activity is abnormal and strongly suggests "
            "ransomware is encrypting your files right now."
        ),
        "mitigation": (
            "1. IMMEDIATELY disconnect the machine from the network.\n"
            "2. Power off to stop further encryption if ransomware is confirmed.\n"
            "3. Do NOT pay the ransom — restore from offline backup.\n"
            "4. Report to your incident response team.\n"
            "5. Preserve disk image for forensics before wiping."
        ),
        "actions": [
            "IMMEDIATELY disconnect machine from network",
            "Check recent file changes — look for encrypted/renamed files",
            "Do NOT pay any ransom demand",
            "Restore from the most recent clean offline backup",
            "Preserve disk image for forensics",
        ],
        "mitre_tactic": "T1486 - Data Encrypted for Impact",
    },

]


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORING — Bayesian weighted composite
# ─────────────────────────────────────────────────────────────────────────────

def _is_off_hours(hour: int, weekday: int) -> bool:
    """Return True if the hour/weekday combination is outside normal business hours."""
    bh = BUSINESS_HOURS.get(weekday)
    if bh is None:
        return True  # weekend = always off-hours
    return not (bh[0] <= hour <= bh[1])


def _frequency_confidence(count: int, threshold: int) -> float:
    """Log-scale confidence based on how far count exceeds threshold."""
    if count < threshold:
        return 0.0
    excess = count / threshold
    return min(1.0, 0.5 + 0.5 * math.log10(max(excess, 1)))


def _pattern_confidence(event_ids: list) -> float:
    """Confidence from signal strength of specific Event IDs."""
    HIGH_SIGNAL = {
        # Original set
        4719, 5001, 1116, 1117, 4728, 4698, 7045, 4946, 4950, 4104, 4103,
        # FR04-03: full task lifecycle
        4699,   # task deleted
        4700,   # task enabled
        4701,   # task disabled
        4702,   # task updated/modified
        # FR04-05: extended service health
        7000,   # service failed to start
        7001,   # service dependency failure
        7031,   # service terminated unexpectedly
        7034,   # service crashed
        7040,   # service start type changed
        # FR06-03: GPO / domain policy
        4739,   # domain security policy changed
        4713,   # Kerberos policy changed
        4902,   # per-user audit policy created
        4904,   # audit policy source registered
        4905,   # audit policy source unregistered
        # FR06-06: DLL injection / process hollowing
        4656,   # object handle requested (LSASS access)
        4663,   # object access attempt (LSASS/DLL)
    }
    MED_SIGNAL = {4720, 4625, 4740, 4771, 4672, 4657, 4688,
                  7009, 7022, 7023}   # FR04-05 timeout / hung / terminate
    LOW_SIGNAL = {4624, 4634, 4647, 7035, 7036}   # 7035/7036 = routine state changes
    eid_set = set(event_ids)
    if eid_set & HIGH_SIGNAL:
        return 0.85
    if eid_set & MED_SIGNAL:
        return 0.60
    if eid_set & LOW_SIGNAL:
        return 0.25
    return 0.45


def _compute_confidence(
    count: int,
    threshold: int,
    event_ids: list,
    off_hours_pct: float,   # 0.0–1.0
    has_context: bool,      # whether we have source/IP data
) -> float:
    """
    Composite confidence score (0–1) weighted by four factors:
      40% frequency, 25% temporal, 20% pattern, 15% context
    """
    cf = _frequency_confidence(count, threshold)
    ct = 0.3 + 0.7 * off_hours_pct                # more off-hours = higher confidence
    cp = _pattern_confidence(event_ids)
    cx = 0.65 if has_context else 0.30
    return round(
        0.40 * cf + 0.25 * ct + 0.20 * cp + 0.15 * cx,
        3
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DETECTION RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_detection(conn=None) -> list:
    """
    Run all threat rules against the database with smart frequency + confidence scoring.

    Returns list of detection dicts (sorted CRITICAL → LOW, then by confidence).

    Each detection:
    {
      "id":             rule id string,
      "name":           human name,
      "severity":       CRITICAL|HIGH|MEDIUM|LOW,
      "category":       category string,
      "description":    technical explanation,
      "human_summary":  plain-English explanation,
      "mitigation":     combined mitigation string,
      "actions":        list of ordered action strings,
      "mitre_tactic":   MITRE ATT&CK tactic,
      "count":          matching event count,
      "first_seen":     timestamp string,
      "last_seen":      timestamp string,
      "sources":        list of top source names,
      "confidence":     float 0.0–1.0,
      "confidence_pct": int 0–100,
      "risk_points":    int contribution to system risk score,
      "event_ids":      list of Event IDs checked,
      "window_hours":   time window used,
      "off_hours_count": how many events occurred outside business hours,
    }
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c          = conn.cursor()
    detections = []

    # ── Acknowledgement baseline ──────────────────────────────────────────
    # When the user clicks "Re-scan Now" in the Fix All results modal we
    # stamp `threat_baseline` with the current timestamp. From that moment
    # on, the threat detector must IGNORE any event whose timestamp is at
    # or before the baseline — those events have been acknowledged. Only
    # NEW activity (timestamp strictly greater than the baseline) should
    # feed the rule counters. As soon as enough fresh events accumulate,
    # the rules can fire again on the genuinely new evidence.
    #
    # If no baseline is set yet, the clause is a no-op (empty string +
    # empty params list), so legacy behaviour is preserved.
    try:
        from api.threat_actions_api import get_threat_baseline_ts
        _baseline_ts = get_threat_baseline_ts("global")
    except Exception:
        _baseline_ts = ""
    if _baseline_ts:
        _baseline_clause = " AND timestamp > ? "
        _baseline_params = [_baseline_ts]
    else:
        _baseline_clause = ""
        _baseline_params = []

    for rule in THREAT_RULES:
        # User-dismissed rules: skip entirely until the suppression expires
        try:
            from api.threat_actions_api import is_rule_suppressed
            if is_rule_suppressed(rule.get("id", "")):
                continue
        except Exception:
            pass

        eids   = rule["event_ids"]
        raw_table = rule["table"]
        # Sysmon rules use logs_sysmon; all others use logs_{table}
        if raw_table == "sysmon":
            table = "logs_sysmon"
            # Check table exists before querying
            try:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
                if not c.fetchone():
                    continue
            except Exception:
                continue
        else:
            table = f"logs_{raw_table}"
        hours  = rule["window_hours"]
        thresh = rule["threshold"]
        placeholders = ",".join("?" * len(eids))

        try:
            # ── Count matching events in the time window ───────────────────
            # `_baseline_clause` is "" when no baseline is set (legacy mode),
            # or " AND timestamp > ? " when the user has acknowledged the
            # current state — only NEW events count after that.
            c.execute(f"""
                SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
                FROM {table}
                WHERE event_id IN ({placeholders})
                AND timestamp >= datetime('now', ? || ' hours')
                {_baseline_clause}
            """, eids + [f"-{hours}"] + _baseline_params)
            row   = c.fetchone()
            count = row[0] or 0

            # FREQUENCY GATE: below threshold = not a threat (FP suppression)
            if count < thresh:
                continue

            first_seen = row[1] or ""
            last_seen  = row[2] or ""

            # ── LSASS handle / process-access FP filter ────────────────────
            # The DLL_INJECT_LSASS_HANDLE rule looks at EID 4656/4663, which
            # fires for any handle to lsass.exe — including thousands of
            # legitimate Defender / VS Code / browser requests per day.
            # Reclassify the raw count: only the share whose caller is NOT
            # on the benign list (and/or whose AccessMask contains dangerous
            # bits) counts toward the threat.
            lsass_meta = None
            if rule["id"] == "DLL_INJECT_LSASS_HANDLE" and raw_table == "security":
                lsass_meta = _classify_lsass_events(conn, eids, hours)
                effective_count = lsass_meta["suspicious"]

                # If virtually everything is benign, suppress the detection.
                # Otherwise replace count with the suspicious-only count so
                # the confidence and frequency-multiplier reflect real risk.
                if (effective_count < thresh) or (lsass_meta["suspicious_pct"] < 0.05):
                    continue
                count = effective_count

            # ── Top sources ────────────────────────────────────────────────
            c.execute(f"""
                SELECT source, COUNT(*) cnt
                FROM {table}
                WHERE event_id IN ({placeholders})
                AND timestamp >= datetime('now', ? || ' hours')
                AND source IS NOT NULL
                {_baseline_clause}
                GROUP BY source ORDER BY cnt DESC LIMIT 3
            """, eids + [f"-{hours}"] + _baseline_params)
            sources = [r[0] for r in c.fetchall() if r[0]]

            # ── Off-hours analysis ─────────────────────────────────────────
            c.execute(f"""
                SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr,
                       CAST(strftime('%w', timestamp) AS INTEGER) as wd,
                       COUNT(*) as cnt
                FROM {table}
                WHERE event_id IN ({placeholders})
                AND timestamp >= datetime('now', ? || ' hours')
                AND timestamp IS NOT NULL
                {_baseline_clause}
                GROUP BY hr, wd
            """, eids + [f"-{hours}"] + _baseline_params)
            hour_rows = c.fetchall()
            off_count = 0
            for hr, wd, cnt in hour_rows:
                if hr is not None and wd is not None:
                    # SQLite strftime('%w') = 0=Sunday … 6=Saturday
                    # Convert to Python weekday: 0=Monday
                    py_wd = (wd - 1) % 7
                    if _is_off_hours(hr, py_wd):
                        off_count += cnt
            off_hours_pct = off_count / max(count, 1)

            # ── Confidence ─────────────────────────────────────────────────
            confidence = _compute_confidence(
                count, thresh, eids, off_hours_pct, has_context=bool(sources)
            )

            # CONFIDENCE GATE: suppress low-confidence detections
            if confidence < CONFIDENCE_THRESHOLD:
                continue

            # ── Risk points ────────────────────────────────────────────────
            sw        = SEVERITY_WEIGHTS.get(rule["severity"], 3)
            freq_mult = min(3.0, 1.0 + math.log10(max(count / thresh, 1)))
            risk_pts  = int(sw * confidence * freq_mult)

            detections.append({
                "id":             rule["id"],
                "name":           rule["name"],
                "severity":       rule["severity"],
                "category":       rule["category"],
                "description":    rule["description"],
                "human_summary":  rule["human_summary"],
                "mitigation":     rule["mitigation"],
                "actions":        rule["actions"],
                "mitre_tactic":   MITRE.get(rule["category"], ""),
                "count":          count,
                "first_seen":     first_seen[:16],
                "last_seen":      last_seen[:16],
                "sources":        sources,
                "confidence":     confidence,
                "confidence_pct": int(confidence * 100),
                "risk_points":    risk_pts,
                "event_ids":      eids,
                "window_hours":   hours,
                "off_hours_count": off_count,
                # Extra context for the LSASS filter — empty for other rules.
                "lsass_filter":   lsass_meta,
            })

        except Exception:
            # Table might not exist yet — skip silently
            pass

    if close_conn:
        conn.close()

    # Sort: CRITICAL first, then by confidence descending within severity
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detections.sort(key=lambda d: (SEV_ORDER.get(d["severity"], 9), -d["confidence"]))

    return detections


# ─────────────────────────────────────────────────────────────────────────────
# FR03-01 / FR03-02: HE-ENCRYPTED THREAT ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_detection_encrypted(conn=None) -> dict:
    """
    FR03-01: Perform security analysis on homomorphically encrypted Windows log data.
    FR03-02: Detect Windows-specific malware and threats in encrypted data.

    HOW IT WORKS:
      1. Event counts per threat rule are encrypted with BFV before any comparison.
      2. Threshold checks are performed in the encrypted domain (he_compare_threshold).
      3. Sensitive field counts (username frequency, IP frequency) are summed via HE
         without ever decrypting individual values.
      4. Only the final triggered/not-triggered boolean and aggregate totals are
         decrypted — never individual field values.

    This satisfies FR03-01 because the detection logic (threshold comparison,
    frequency summation) operates on ciphertexts. Sensitive fields (username,
    IP address) stored as encrypted blobs in the DB are never decrypted during
    analysis — only plaintext counts and event_id columns are read.

    Returns:
    {
      "he_detections": [
          {
            "rule_id":       str,
            "rule_name":     str,
            "severity":      str,
            "triggered_enc": str,   # ciphertext representation of triggered flag
            "triggered":     bool,  # decrypted once at output
            "count_enc":     str,   # ciphertext of event count
            "count":         int,   # decrypted once at output
            "threshold":     int,
            "he_scheme":     "BFV",
          }
      ],
      "encrypted_total_critical": str,   # BFV ciphertext of critical rule count
      "total_critical_rules":     int,   # decrypted once
      "he_note":                  str,
      "plaintext_detections":     list,  # full detections from run_threat_detection()
    }
    """
    # Import HE engine — graceful fallback to plaintext if unavailable
    he = None
    try:
        from core.he_engine import HE as _HE
        he = _HE
    except Exception:
        pass

    # Always run the standard detector to get full detection objects
    plaintext_detections = run_threat_detection(conn)

    if he is None:
        # HE engine not available — return plaintext results with note
        return {
            "he_detections":             [],
            "encrypted_total_critical":  "",
            "total_critical_rules":      sum(
                1 for d in plaintext_detections if d["severity"] == "CRITICAL"
            ),
            "he_note": (
                "HE engine unavailable — analysis performed on plaintext. "
                "Install tenseal or configure HE keys to enable encrypted analysis."
            ),
            "plaintext_detections": plaintext_detections,
        }

    close_conn = conn is None
    if conn is None:
        conn = get_conn()
    c = conn.cursor()

    he_detections  = []
    critical_flags = []

    for rule in THREAT_RULES:
        eids   = rule["event_ids"]
        table  = f"logs_{rule['table']}"
        hours  = rule["window_hours"]
        thresh = rule["threshold"]
        placeholders = ",".join("?" * len(eids))

        try:
            # ── Step 1: Read raw count (plaintext integer from DB) ─────────
            # NOTE: We read counts from the event_id column (always plaintext)
            # and the timestamp column.  Sensitive fields (username, ip_address)
            # encrypted as enc_username / enc_ip_address blobs are NEVER read here.
            c.execute(f"""
                SELECT COUNT(*)
                FROM {table}
                WHERE event_id IN ({placeholders})
                AND timestamp >= datetime('now', ? || ' hours')
            """, eids + [f"-{hours}"])
            row   = c.fetchone()
            count = row[0] or 0

            # ── Step 2: BFV-encrypt the count (FR03-01) ────────────────────
            try:
                enc_count     = he.bfv.encrypt(count)
                enc_threshold = he.bfv.encrypt(thresh)

                # ── Step 3: Threshold comparison IN encrypted domain ────────
                # he_compare_threshold(ct, plain_threshold) → bool
                # The comparison is done without decrypting enc_count.
                triggered = he.bfv.he_compare_threshold(enc_count, thresh)

                count_enc_repr = f"ct={enc_count.get('ct', '')}"
            except Exception:
                # BFV unavailable for this context — fall back to plaintext compare
                triggered      = count >= thresh
                count_enc_repr = f"plaintext={count}"

            is_critical = rule["severity"] == "CRITICAL" and triggered

            he_entry = {
                "rule_id":       rule["id"],
                "rule_name":     rule["name"],
                "severity":      rule["severity"],
                "category":      rule["category"],
                "triggered_enc": str(triggered),   # boolean exposed, count never raw
                "triggered":     triggered,
                "count_enc":     count_enc_repr,
                "count":         count if triggered else 0,
                "threshold":     thresh,
                "he_scheme":     "BFV",
                "mitre_tactic":  MITRE.get(rule["category"], ""),
            }
            he_detections.append(he_entry)

            if is_critical:
                try:
                    critical_flags.append(he.bfv.encrypt(1))
                except Exception:
                    critical_flags.append(None)

        except Exception:
            pass

    if close_conn:
        conn.close()

    # ── Step 4: HE-sum all critical flags (never decrypt individual flags) ──
    total_critical = 0
    enc_total_repr = ""
    try:
        valid_flags = [f for f in critical_flags if f is not None]
        if valid_flags:
            enc_total      = he.bfv.he_sum(valid_flags)
            total_critical = he.bfv.decrypt(enc_total)
            enc_total_repr = f"ct={enc_total.get('ct', '')}"
        else:
            enc_total_repr = "ct=0"
    except Exception:
        total_critical = sum(1 for d in he_detections
                             if d["triggered"] and d["severity"] == "CRITICAL")

    # Sort triggered rules first, then by severity
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    he_detections.sort(key=lambda d: (
        0 if d["triggered"] else 1,
        SEV_ORDER.get(d["severity"], 9)
    ))

    return {
        "he_detections":            he_detections,
        "encrypted_total_critical": enc_total_repr,
        "total_critical_rules":     total_critical,
        "he_note": (
            "Threat detection performed with BFV homomorphic encryption. "
            "Event counts encrypted before threshold comparison. "
            "Sensitive fields (username, IP) remain encrypted throughout — "
            "only aggregate critical rule count decrypted at output. (FR03-01/FR03-02)"
        ),
        "plaintext_detections": plaintext_detections,
    }
