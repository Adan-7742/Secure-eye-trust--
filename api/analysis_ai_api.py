"""
api/analysis_ai_api.py
======================
Blueprint: POST /api/analyze/ai-describe

Takes the raw full-analysis results (patterns, zero-day, security threats,
offenders) and calls Groq/Llama to generate plain-English AI descriptions
for each finding.

Falls back to a rich static knowledge base if no Groq key is configured.

Response shape:
{
  "ai_available": bool,
  "model": "llama-3.3-70b-versatile" | "static",
  "pattern_descriptions": {
      "Brute Force Login": { "plain_english": "...", "severity_context": "...", "action": "..." },
      ...
  },
  "security_threat_descriptions": {
      4625: { "plain_english": "...", "action": "..." },
      ...
  },
  "zeroday_summary": "...",
  "overall_summary": "...",
  "error": null | "reason string"
}
"""

import os
import json
import re
from pathlib import Path
from flask import Blueprint, request, jsonify

analysis_ai_bp = Blueprint("analysis_ai", __name__)

_ENV_FILE  = Path(__file__).resolve().parent.parent / ".env"
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_groq_key() -> str:
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_ENV_FILE, override=False)
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY", "").strip()


def _call_groq(prompt: str, api_key: str, max_tokens: int = 2000) -> dict:
    payload = {
        "model":       GROQ_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "max_tokens":  max_tokens,
        "temperature": 0.25,
    }
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    try:
        import requests as _requests
        resp = _requests.post(GROQ_URL, json=payload, headers=headers, timeout=40)
        resp.raise_for_status()
        raw = resp.json()["choices"][0]["message"]["content"].strip()
    except ImportError:
        import json as _json
        from urllib.request import urlopen, Request as _UReq
        req = _UReq(
            GROQ_URL,
            data=_json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=40) as r:
            data = _json.loads(r.read().decode("utf-8"))
        raw = data["choices"][0]["message"]["content"].strip()

    # Strip markdown fences
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
    return json.loads(raw.strip())


def _build_prompt(patterns: list, security_threats: dict, zero_day: list, offenders: dict) -> str:
    # Summarise patterns
    p_lines = []
    for p in patterns[:12]:
        p_lines.append(
            f"  - [{p.get('severity','?')}] {p.get('pattern','?')}: "
            f"{p.get('hit_count',0)} hits — {p.get('description','')[:80]}"
            + (f'\n    Sample: "{p.get("sample","")[:80]}"' if p.get("sample") else "")
        )

    # Security threats
    st_lines = []
    for t in (security_threats.get("threats") or [])[:15]:
        st_lines.append(f"  - Event ID {t.get('event_id','?')} ({t.get('severity','?')}): "
                        f"{t.get('count',0)} times — {t.get('description','')[:80]}")

    # Zero-day suspects
    zd_lines = []
    for z in zero_day[:8]:
        zd_lines.append(f"  - Source: {z.get('source','?')}, Event ID: {z.get('event_id','?')}, "
                        f"Category: {z.get('category','?')}, Occurrences: {z.get('occurrences',0)}")

    # Top offenders (flatten all categories)
    off_lines = []
    for cat, items in (offenders or {}).items():
        for o in (items or [])[:3]:
            off_lines.append(f"  - [{cat}] {o.get('source','?')}: "
                             f"{o.get('total',0)} events, {o.get('error_rate',0)}% error rate")

    prompt = f"""You are a senior Windows security analyst. Analyse the following log analysis results and generate plain-English explanations for a non-technical IT manager.

THREAT PATTERNS DETECTED:
{chr(10).join(p_lines) or '  None'}

SECURITY EVENT ID THREATS:
{chr(10).join(st_lines) or '  None'}

ZERO-DAY / RARE EVENTS:
{chr(10).join(zd_lines) or '  None'}

TOP OFFENDING SOURCES:
{chr(10).join(off_lines) or '  None'}

Respond ONLY with a valid JSON object in exactly this structure (no text outside the JSON, no markdown fences):

{{
  "overall_summary": "3-5 sentence summary of all findings. What is the most important thing the user needs to know? State the overall threat level and what immediate action is needed.",

  "pattern_descriptions": {{
    "EXACT_PATTERN_NAME": {{
      "plain_english": "2-3 sentences explaining what this threat pattern means in simple language. What is happening? Why is it dangerous?",
      "severity_context": "1 sentence explaining why this severity rating was assigned and how serious this is.",
      "action": "The single most important step this user should take RIGHT NOW. Be specific (e.g. 'Open Event Viewer, filter Security log for Event ID 4625, look for repeated failures from a single IP address')."
    }}
  }},

  "security_threat_descriptions": {{
    "EVENT_ID_AS_STRING": {{
      "name": "Short human-readable name (e.g. 'Failed Logon', 'Account Created')",
      "plain_english": "2 sentences: what does Windows log this event for, and why is the count on this system significant?",
      "action": "One concrete step to investigate or resolve this."
    }}
  }},

  "zeroday_summary": "2-3 sentences explaining what rare/unusual events mean in general. Are these concerning on this system? What should the user look for?",

  "offender_insights": "2-3 sentences explaining what the top offending sources mean. Which source is most concerning and why?"
}}

Rules:
- Use plain English. Explain technical terms if you must use them.
- Be specific and actionable — not vague advice like 'review the logs'.
- pattern_descriptions keys must exactly match the pattern names from the input data.
- security_threat_descriptions keys must be the Event ID numbers as strings (e.g. "4625").
- If a section has no data, use empty object {{}} or an appropriate message.
- Output ONLY the JSON object. No intro text, no explanation, no markdown."""

    return prompt


# ── Static knowledge base (fallback) ─────────────────────────────────────────

PATTERN_KB = {
    "Brute Force Login": {
        "plain_english": "Someone or an automated bot is repeatedly trying to guess passwords on this system. Each failed attempt is logged as Event ID 4625. Five or more failures in a short window is the classic signature of a brute-force attack.",
        "severity_context": "CRITICAL — a successful brute force gives an attacker full access to the compromised account.",
        "action": "Open Event Viewer → Windows Logs → Security, filter for Event ID 4625. Find the source IP of repeated failures and block it in Windows Firewall (wf.msc → Inbound Rules → New Rule → Block this IP).",
    },
    "Account Lockout": {
        "plain_english": "User accounts are being automatically locked out after too many failed login attempts. This can be caused by a brute-force attack, a service using an old password, or a user who forgot their credentials.",
        "severity_context": "HIGH — repeated lockouts are a strong indicator of an active attack or misconfigured service causing system disruption.",
        "action": "Filter Security log for Event ID 4740 to find which account is locking out and which machine is the source of the failures.",
    },
    "Privilege Escalation": {
        "plain_english": "A user or process gained elevated administrator-level permissions. While this can be legitimate (e.g. an admin running a task), it can also indicate an attacker exploiting a vulnerability to take full control of the system.",
        "severity_context": "HIGH — privilege escalation is a core step in most attacks; once an attacker has admin rights, they can install malware, steal data, and cover their tracks.",
        "action": "Filter Security log for Event IDs 4672 and 4673. Identify the account that received elevated privileges and verify it was expected and authorised.",
    },
    "Windows Defender Alert": {
        "plain_english": "Windows Defender has detected and flagged a threat — malware, ransomware, or a potentially unwanted program. This is the most serious alert your system can generate.",
        "severity_context": "CRITICAL — confirmed malware presence requires immediate isolation and remediation before data loss or further infection spreads.",
        "action": "Open Windows Security → Protection History immediately. If a threat is listed, run a full offline scan (Windows Security → Virus & Threat Protection → Scan Options → Microsoft Defender Offline Scan).",
    },
    "Unexpected Shutdown": {
        "plain_english": "The computer shut down without going through the normal shutdown sequence — usually caused by a power failure, Blue Screen of Death (BSOD) crash, or a critical hardware failure.",
        "severity_context": "HIGH — unexpected shutdowns cause data loss and can indicate hardware failure or OS instability that will worsen over time.",
        "action": "Check C:\\Windows\\Minidump for crash dump files and upload to an online BSOD analyser. Run Windows Memory Diagnostic (mdsched.exe) and check system temperatures with HWMonitor.",
    },
    "Disk Hardware Error": {
        "plain_english": "The hard drive is reporting read or write errors — an early warning sign that the drive may be physically failing. If ignored, this leads to data loss with no recovery possible.",
        "severity_context": "HIGH — disk failures are irreversible once they progress. Every day of delay increases the risk of total data loss.",
        "action": "BACK UP ALL IMPORTANT DATA IMMEDIATELY. Then run: chkdsk C: /f /r from an elevated Command Prompt. Install CrystalDiskInfo (free) to check S.M.A.R.T. health status.",
    },
    "Memory Corruption": {
        "plain_english": "Windows detected hardware memory errors — the RAM modules may be faulty, causing data corruption and system crashes. This is a serious hardware issue.",
        "severity_context": "HIGH — faulty RAM corrupts data silently before causing obvious crashes, and can lead to irreversible file system damage.",
        "action": "Run Windows Memory Diagnostic: press Win+R, type mdsched.exe, choose 'Restart now and check for problems'. If errors are found, replace the RAM modules.",
    },
    "Application Crash": {
        "plain_english": "One or more applications crashed unexpectedly. While occasional crashes are normal, repeated crashes from the same application indicate a software bug, incompatibility, or corrupted files.",
        "severity_context": "MEDIUM — application crashes affect productivity and may indicate deeper system instability if they recur frequently.",
        "action": "Filter the Application log for Event ID 1000. Note the 'Faulting application name' — update or reinstall that specific application.",
    },
    "New Admin Account": {
        "plain_english": "A new Windows user account was created or a user was added to the Administrators group. If this was not authorised by your IT team, it is a serious sign that an attacker has created a backdoor account.",
        "severity_context": "HIGH — unauthorised admin accounts give attackers persistent access that survives password changes and reboots.",
        "action": "Check Event ID 4720 (account created) and 4728 (added to admin group) in Security log immediately. If the account is unknown, disable it now: Control Panel → User Accounts → Manage Accounts.",
    },
    "Scheduled Task Created": {
        "plain_english": "A new scheduled task was registered on this system. Attackers use scheduled tasks as a 'persistence mechanism' — a way to ensure their malicious code runs automatically every time the computer starts or at regular intervals.",
        "severity_context": "MEDIUM — scheduled tasks for persistence are one of the top 10 attack techniques used by real-world threat actors.",
        "action": "Open Task Scheduler (taskschd.msc), review all tasks in 'Task Scheduler Library'. Right-click any unrecognised task → Properties — check what program it runs and delete if unknown.",
    },
    "Audit Policy Change": {
        "plain_english": "The Windows security audit policy was modified. Attackers commonly disable audit logging as one of their first actions after gaining access — so their subsequent activity leaves no trace in the logs.",
        "severity_context": "CRITICAL — disabling audit logs is a classic anti-forensic technique used in targeted attacks.",
        "action": "Run secpol.msc (Local Security Policy), go to Security Settings → Local Policies → Audit Policy and verify all categories are enabled for both Success and Failure.",
    },
    "Service Failure": {
        "plain_english": "One or more Windows background services crashed or stopped unexpectedly. Services run critical system functions — a failing service can disable security features, network connectivity, or application functionality.",
        "severity_context": "MEDIUM — if the failing service is a security product (like Windows Defender or a firewall service), the severity is effectively CRITICAL.",
        "action": "Open Event Viewer → Windows Logs → System, filter for Event IDs 7034 and 7023 to identify the specific service that crashed and the error code.",
    },
    "New Service Installed": {
        "plain_english": "A new Windows service was installed on this system. Legitimate software installs services as part of setup — but attackers also install malicious services as a way to run code persistently in the background.",
        "severity_context": "HIGH — malicious services run with SYSTEM-level privileges and are difficult to detect without specifically monitoring for them.",
        "action": "Check Event ID 7045 in the System log to see the service name and binary path. Search the service executable path online to verify it is from a trusted vendor.",
    },
    "Registry Tampering": {
        "plain_english": "Windows registry keys were modified. The registry controls how Windows starts up and behaves — attackers frequently modify registry keys to run malware automatically at startup or to disable security features.",
        "severity_context": "HIGH — registry-based persistence is nearly invisible to casual inspection and survives reboots and many cleanup attempts.",
        "action": "Filter Security log for Event ID 4657. Note which registry key was modified. Pay special attention to keys under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run which control startup programs.",
    },
    "TLS/SSL Error": {
        "plain_english": "Encrypted network connections are failing with TLS/SSL errors. This can mean outdated security protocols, expired certificates, or in some cases, a network interception (man-in-the-middle) attempt.",
        "severity_context": "MEDIUM — TLS errors can expose data that should be encrypted, or indicate that an attacker is trying to intercept your network traffic.",
        "action": "Check the Schannel event source in the System log. Verify that all SSL certificates are valid and not expired. Ensure Windows is configured to use TLS 1.2 or higher.",
    },
    "Network Error": {
        "plain_english": "Network connectivity errors were detected — connections being refused, DNS resolution failures, or network interfaces becoming unreachable. This can affect system updates, remote access, and internet connectivity.",
        "severity_context": "LOW — usually caused by misconfiguration or infrastructure issues rather than attacks, but can mask more serious connectivity problems.",
        "action": "Run ipconfig /all and ping 8.8.8.8 from Command Prompt to diagnose basic connectivity. Check Event ID details for the specific network component that is failing.",
    },
}

SECURITY_EID_KB = {
    "4624": {"name": "Successful Logon",         "plain_english": "A user successfully logged into this computer. High frequency from unexpected accounts or at unusual hours can indicate unauthorised access.", "action": "Review logon type — type 3 (network) or 10 (remote interactive) from unfamiliar IPs at odd hours warrants investigation."},
    "4625": {"name": "Failed Logon",              "plain_english": "A login attempt failed. Repeated failures in rapid succession from the same source are the signature of a password-guessing (brute force) attack.", "action": "Filter for Event ID 4625, group by source IP address. Any IP with 10+ failures in a short window should be blocked in Windows Firewall."},
    "4648": {"name": "Explicit Credential Logon", "plain_english": "A process or program logged in using explicitly provided credentials (like using 'Run as'). Can indicate credential reuse or an attacker moving laterally through the network.", "action": "Identify which process used explicit credentials and verify it was an expected administrative action."},
    "4657": {"name": "Registry Key Modified",     "plain_english": "A Windows registry value was changed. Malware frequently modifies registry keys to run automatically at startup or to disable security tools.", "action": "Check which registry key changed and by which process. Investigate any changes to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."},
    "4672": {"name": "Special Privileges Assigned","plain_english": "A user was granted administrator-equivalent privileges at logon. Normal for admin accounts, but if a regular user account appears here, it may indicate privilege escalation.", "action": "Review which account received special privileges and verify this matches expected administrator accounts only."},
    "4698": {"name": "Scheduled Task Created",    "plain_english": "A new automated task was added to the Windows Task Scheduler. Attackers use this as a persistence mechanism — their malicious program runs automatically on schedule or at startup.", "action": "Open taskschd.msc and review all tasks. Delete any task whose executable path you do not recognise."},
    "4719": {"name": "Audit Policy Changed",      "plain_english": "The Windows security audit policy was modified. Disabling audit logging is a primary anti-forensics technique — attackers do this so their subsequent actions leave no evidence.", "action": "Immediately open secpol.msc and verify audit policies are fully enabled. Investigate who made the change."},
    "4720": {"name": "User Account Created",      "plain_english": "A new Windows user account was created. Attackers create backdoor accounts to maintain access even after their initial entry point is closed.", "action": "Verify this account was authorised. If unknown, disable it immediately in User Accounts and change all admin passwords."},
    "4728": {"name": "Added to Admin Group",      "plain_english": "A user was added to a privileged group (Administrators or similar). This grants complete control over the computer. Unauthorised changes here indicate a serious compromise.", "action": "Verify this group membership change was authorised by IT. If not, remove the user from the group and audit all recent administrator activity."},
    "4740": {"name": "Account Locked Out",        "plain_english": "A user account was automatically locked out after too many failed password attempts. Often caused by a brute-force attack or a service running with stale credentials.", "action": "Find the source of the failed attempts using Event ID 4625. If it is a service, update the service account password in services.msc."},
    "4776": {"name": "NTLM Auth Attempt",         "plain_english": "The system attempted to validate credentials using the NTLM protocol. Multiple failures may indicate a password spray attack — trying one password across many accounts.", "action": "Check for a pattern of failures across multiple account names from the same source IP, which indicates a spray attack rather than targeted brute force."},
}


def _static_fallback(patterns, security_threats, zero_day, offenders, reason="") -> dict:
    pat_descs = {}
    for p in (patterns or []):
        name = p.get("pattern", "")
        kb   = PATTERN_KB.get(name, {})
        if kb:
            pat_descs[name] = kb
        else:
            sev = p.get("severity", "MEDIUM")
            pat_descs[name] = {
                "plain_english": f"This pattern ({name}) matched {p.get('hit_count', 0)} times in your logs. "
                                 f"Severity is {sev}. Review the matched log entries for more context.",
                "severity_context": f"{sev} severity — review the matched log samples in Event Viewer.",
                "action": f"Open Event Viewer and search for log entries matching '{name}' to investigate further.",
            }

    st_descs = {}
    for t in (security_threats.get("threats") or []):
        eid = str(t.get("event_id", ""))
        kb  = SECURITY_EID_KB.get(eid, {})
        if kb:
            st_descs[eid] = {
                "name":          kb["name"],
                "plain_english": kb["plain_english"],
                "action":        kb["action"],
            }
        else:
            st_descs[eid] = {
                "name":          f"Windows Event {eid}",
                "plain_english": f"Event ID {eid} was recorded {t.get('count', 0)} times. "
                                 f"Severity: {t.get('severity', 'INFO')}. Search Microsoft docs for this Event ID for full details.",
                "action":        f"Search 'Windows Event ID {eid}' on Microsoft Learn for the official explanation and recommended action.",
            }

    # Summary
    crit_patterns = [p for p in (patterns or []) if p.get("severity") == "CRITICAL"]
    high_patterns = [p for p in (patterns or []) if p.get("severity") == "HIGH"]

    if crit_patterns:
        overall = (f"CRITICAL threats require immediate attention: {', '.join(p.get('pattern','?') for p in crit_patterns[:2])}. "
                   f"These are active security risks that should be investigated before anything else. "
                   f"{len(patterns or [])} total threat patterns were detected across all log categories. "
                   "Use the action steps for each threat below to begin your investigation.")
    elif high_patterns:
        overall = (f"{len(high_patterns)} high-severity threat pattern(s) were detected including: "
                   f"{', '.join(p.get('pattern','?') for p in high_patterns[:2])}. "
                   "These should be reviewed within 24 hours. Use the action steps below to prioritise your response.")
    elif patterns:
        overall = (f"{len(patterns)} threat pattern(s) were detected at medium or low severity. "
                   "No critical or high-priority threats require immediate action, but the patterns below should be reviewed this week.")
    else:
        overall = ("No threat patterns were matched in the current analysis. "
                   "The system appears to be operating within normal security parameters. "
                   "Continue monitoring regularly and re-run analysis after any significant system changes.")

    zd_summary = "No unusual rare event combinations were detected." if not zero_day else (
        f"{len(zero_day)} rare event source-and-ID combination(s) were found. "
        "These are events that appear very infrequently — which can indicate new software, one-off system changes, "
        "or early-stage attack activity that has not yet triggered the main pattern detectors. "
        "Review each entry and verify the source is a trusted application."
    )

    return {
        "ai_available":                False,
        "model":                       "static",
        "overall_summary":             overall,
        "pattern_descriptions":        pat_descs,
        "security_threat_descriptions": st_descs,
        "zeroday_summary":             zd_summary,
        "offender_insights":           (
            "The top offending sources are the applications or drivers generating the most errors. "
            "A high error rate (above 20%) from a single source usually indicates a specific service or driver that needs updating or reinstalling. "
            "Focus on sources with the highest error rate rather than the highest raw count."
        ),
        "error": f"AI descriptions unavailable ({reason}) — using static knowledge base." if reason else None,
    }


# ── Route ─────────────────────────────────────────────────────────────────────

@analysis_ai_bp.route("/analyze/ai-describe", methods=["POST"])
def ai_describe():
    """
    POST /api/analyze/ai-describe
    Body: { "patterns": [...], "security_threats": {...}, "zero_day": [...], "top_offenders": {...} }
    Returns AI-generated descriptions for each finding.
    """
    try:
        body    = request.get_json(force=True) or {}
        patterns          = body.get("patterns", [])
        security_threats  = body.get("security_threats", {})
        zero_day          = body.get("zero_day", [])
        offenders         = body.get("top_offenders", {})

        api_key = _get_groq_key()
        if not api_key:
            return jsonify(_static_fallback(patterns, security_threats, zero_day, offenders, reason="no_key"))

        # Only call AI if there's actually something to describe
        if not patterns and not (security_threats.get("threats")) and not zero_day:
            return jsonify(_static_fallback(patterns, security_threats, zero_day, offenders, reason="no_data"))

        prompt = _build_prompt(patterns, security_threats, zero_day, offenders)
        result = _call_groq(prompt, api_key, max_tokens=2400)
        result["ai_available"] = True
        result["model"]        = GROQ_MODEL
        result["error"]        = None
        return jsonify(result)

    except json.JSONDecodeError as e:
        print(f"[analysis_ai] JSON parse error: {e}")
        body = request.get_json(force=True) or {}
        return jsonify(_static_fallback(
            body.get("patterns", []), body.get("security_threats", {}),
            body.get("zero_day", []), body.get("top_offenders", {}),
            reason="json_parse_error"
        ))
    except Exception as e:
        import traceback
        traceback.print_exc()
        body = request.get_json(force=True) or {}
        return jsonify(_static_fallback(
            body.get("patterns", []), body.get("security_threats", {}),
            body.get("zero_day", []), body.get("top_offenders", {}),
            reason=str(e)
        ))
