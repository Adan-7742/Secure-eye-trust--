"""
api/ai_narrative.py
===================
Groq/Llama-powered narrative generator for perform_analysis_api.py

Replaces the static _generate_narrative() with a rich AI-generated report
that includes:
  - Plain-English executive summary
  - Per-threat explanation (what it is, where from, how to fix)
  - Anomaly day context
  - Prioritised action plan
  - Protection recommendations

Falls back to the existing static narrative if Groq is unavailable.
"""

import os
import json
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_ENV_FILE  = Path(__file__).resolve().parent.parent / ".env"
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"


def _get_groq_key() -> str:
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_ENV_FILE, override=False)
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY", "").strip()


def _build_prompt(r: dict) -> str:
    cats         = r.get("categories", {})
    threats      = r.get("threat_hits", [])
    anomalies    = r.get("anomaly_days", [])
    recs         = r.get("recommendations", [])
    error_details= r.get("error_details", [])
    hostname  = r.get("hostname", "this system")
    period    = r.get("period_days", 30)
    total_ev  = r.get("total_events", 0)
    total_err = r.get("total_errors", 0)
    risk      = r.get("risk_summary", {}).get("label", "Low")
    score     = r.get("risk_summary", {}).get("score", 0)
    peak_hour = r.get("peak_hour", "unknown")
    top_srcs  = r.get("top_sources", [])[:5]

    cat_summary = []
    for cat, cv in cats.items():
        total = cv.get("total", 0)
        if total > 0:
            err = cv.get("errors", 0) + cv.get("critical", 0)
            pct = round(err / total * 100, 1) if total > 0 else 0
            cat_summary.append(
                f"  - {cat.replace('_',' ').title()}: {total:,} events, "
                f"{err:,} errors ({pct}%), {cv.get('warnings',0):,} warnings"
            )

    threat_summary = []
    for h in threats:
        exs = h.get("examples", [])
        ex  = exs[0].get("message", "")[:120] if exs else ""
        threat_summary.append(
            f"  - [{h['severity']}] {h['name']}: {h['count']} occurrences, "
            f"last seen {h.get('latest','unknown')[:16]}"
            + (f'\n    Example: "{ex}"' if ex else "")
        )

    # Top 30 error event IDs for the prompt (rest handled by static KB)
    eid_summary = []
    for e in error_details[:30]:
        eid_summary.append(
            f"  - Event ID {e['event_id']} ({e['level']}): {e['count']}x, "
            f"source: {e['sources'][0] if e['sources'] else 'unknown'}, "
            f"category: {', '.join(e['categories'])}"
            + (f', example: "{e["example"][:80]}"' if e.get("example") else "")
        )

    anom_summary = []
    for a in anomalies[:5]:
        anom_summary.append(
            f"  - {a['date']}: {a['count']:,} events (Z-score {a['zscore']})"
        )

    src_summary = []
    for s in top_srcs:
        src_summary.append(f"  - {s['source']}: {s['count']} events")

    data_block = f"""
SYSTEM: {hostname}
RISK LEVEL: {risk} (score {score}/100)
PERIOD ANALYSED: Last {period} days
TOTAL EVENTS: {total_ev:,}
TOTAL ERRORS/FAILURES: {total_err:,}
PEAK ACTIVITY HOUR: {peak_hour}

CATEGORY BREAKDOWN:
{chr(10).join(cat_summary) or '  (no data)'}

DETECTED THREATS:
{chr(10).join(threat_summary) or '  None detected'}

ANOMALOUS DAYS (statistical spikes):
{chr(10).join(anom_summary) or '  None detected'}

TOP EVENT SOURCES:
{chr(10).join(src_summary) or '  (no data)'}

TOP ERROR EVENT IDs (most frequent errors/failures by Windows Event ID):
{chr(10).join(eid_summary) or '  (no event ID data)'}

EXISTING RECOMMENDATIONS:
{chr(10).join('  - [' + rec['priority'] + '] ' + rec['text'] for rec in recs) or '  None'}
"""

    prompt = f"""You are a senior Windows security analyst writing an executive-level system health report for a non-technical IT manager. Analyse the following log data and write a clear, professional, structured report.

{data_block}

Write the report in the following exact JSON structure (no extra text, no markdown fences):

{{
  "executive_summary": "3-4 sentence plain English summary of the overall system health. State the risk level, what is happening, and what needs attention. Write as if explaining to a manager who doesn't know technical terms.",

  "what_is_happening": "A detailed paragraph (5-8 sentences) explaining exactly what is happening on this system right now. Explain each active threat in simple language. What do these errors mean? Are they signs of attack, hardware failure, software bugs, or misconfiguration?",

  "threat_explanations": [
    {{
      "name": "threat name from data",
      "plain_english": "What this threat means in simple language (2-3 sentences)",
      "where_from": "Where is this coming from / what causes it (2 sentences)",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "how_to_fix": "Specific step-by-step action the user should take (3-5 concrete steps)",
      "protection": "How to prevent this in future (2-3 sentences)"
    }}
  ],

  "anomaly_explanation": "If there are anomalous days, explain what statistical spikes mean in plain English. What might have caused them? What should the user look for? (3-4 sentences, or 'No anomalous activity detected — event volume has been consistent.' if none)",

  "top_sources_analysis": "Explain what the top event sources mean and whether they are concerning (3-4 sentences)",

  "event_id_explanations": [
    {{
      "event_id": "the Windows Event ID number as string",
      "name": "short human-readable name for this event (e.g. 'Failed Logon', 'Service Crash')",
      "level": "ERROR|WARNING|CRITICAL|FAILURE",
      "count": 0,
      "what_it_means": "Plain English explanation of what this Event ID means. What does Windows log this for? (2 sentences)",
      "why_occurring": "Why is this happening on this specific system based on the context? (1-2 sentences)",
      "severity_note": "Is this count normal, concerning, or critical? (1 sentence)",
      "fix": "One concrete action to resolve or investigate this (1-2 sentences)"
    }}
  ],

  "action_plan": [
    {{
      "priority": "IMMEDIATE|24_HOURS|THIS_WEEK|ONGOING",
      "action": "Specific thing to do",
      "reason": "Why this matters in plain English",
      "how": "Brief instructions on how to do this"
    }}
  ],

  "protection_summary": "Overall protection advice — what should this user do going forward to keep their system safe? Write 4-6 practical sentences covering passwords, monitoring, updates, backups, and access control.",

  "verdict": "One clear, confident sentence verdict about the overall state of this system."
}}

Rules:
- Use plain English throughout — no jargon without explanation
- Be specific and actionable, not vague
- If no threats were detected, say so clearly and explain what healthy looks like
- Keep threat_explanations only for threats that actually appeared in the data (empty array if none)
- Keep action_plan items between 3 and 6
- For event_id_explanations: include ALL event IDs from the TOP ERROR EVENT IDs list provided, explain each one
- Do NOT include any text outside the JSON object"""

    return prompt


def _call_groq(prompt: str, api_key: str) -> dict:
    payload = {
        "model":       GROQ_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "max_tokens":  2500,
        "temperature": 0.3,
    }
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept":        "application/json",
    }

    if _HAS_REQUESTS:
        resp = _requests.post(GROQ_URL, json=payload, headers=headers, timeout=45)
        resp.raise_for_status()
        raw = resp.json()["choices"][0]["message"]["content"].strip()
    else:
        import json as _json
        from urllib.request import urlopen, Request as _UReq
        req = _UReq(
            GROQ_URL,
            data=_json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=45) as r:
            data = _json.loads(r.read().decode("utf-8"))
        raw = data["choices"][0]["message"]["content"].strip()

    # Strip markdown fences if model wrapped it
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    return json.loads(raw)


def generate_ai_narrative(r: dict) -> dict:
    """
    Main entry point.
    Returns a dict with rich AI content, or falls back gracefully.
    
    Return shape:
    {
        "ai_available": bool,
        "executive_summary": str,
        "what_is_happening": str,
        "threat_explanations": [...],
        "anomaly_explanation": str,
        "top_sources_analysis": str,
        "action_plan": [...],
        "protection_summary": str,
        "verdict": str,
        "error": str | None   # only on fallback
    }
    """
    api_key = _get_groq_key()

    if not api_key:
        return _static_fallback(r, reason="no_key")

    try:
        prompt = _build_prompt(r)
        result = _call_groq(prompt, api_key)
        result["ai_available"] = True
        result["error"] = None
        return result
    except json.JSONDecodeError as e:
        print(f"[ai_narrative] JSON parse error: {e}")
        return _static_fallback(r, reason="json_error")
    except Exception as e:
        print(f"[ai_narrative] Groq call failed: {e}")
        return _static_fallback(r, reason=str(e))


def _static_fallback(r: dict, reason: str = "") -> dict:
    """
    Build a structured narrative from static logic — used when Groq unavailable.
    Mirrors the shape of the AI response so the frontend works identically.
    """
    cats      = r.get("categories", {})
    threats   = r.get("threat_hits", [])
    anomalies = r.get("anomaly_days", [])
    hostname  = r.get("hostname", "this system")
    period    = r.get("period_days", 30)
    total_ev  = r.get("total_events", 0)
    total_err = r.get("total_errors", 0)
    risk      = r.get("risk_summary", {}).get("label", "Low")
    score     = r.get("risk_summary", {}).get("score", 0)
    err_rate  = r.get("risk_summary", {}).get("error_rate", 0.0)

    risk_desc = {
        "Critical": "in a CRITICAL security state requiring immediate action",
        "High":     "showing HIGH-RISK activity that needs prompt attention",
        "Medium":   "showing moderate activity with some areas of concern",
        "Low":      "operating normally with no major threats detected",
    }.get(risk, "under monitoring")

    exec_summary = (
        f"{hostname} is currently {risk_desc} (Risk Score: {score}/100). "
        f"Over the past {period} days, {total_ev:,} log events were recorded "
        f"with an error rate of {round(err_rate, 1)}%. "
    )
    if threats:
        critical = [h for h in threats if h["severity"] == "CRITICAL"]
        exec_summary += f"{len(threats)} threat pattern(s) were detected" + (
            f", including {len(critical)} CRITICAL issue(s)" if critical else ""
        ) + "."
    else:
        exec_summary += "No threat patterns were detected in this period."

    # Build threat explanations from static knowledge base
    THREAT_KB = {
        "Brute Force Login": {
            "plain_english": "Someone or something is repeatedly trying to guess passwords on this computer. This is one of the most common attack methods.",
            "where_from": "These attempts usually come from automated bots scanning the internet, or from a compromised device on your local network.",
            "how_to_fix": "1. Check Event ID 4625 in Security logs for source IPs.\n2. Block suspicious IPs in Windows Firewall.\n3. Enable account lockout policy (lock after 5 failed attempts).\n4. Force password reset for targeted accounts.\n5. Enable multi-factor authentication where possible.",
            "protection": "Use strong passwords (16+ characters), enable account lockout policies, and consider using a VPN instead of exposing RDP directly to the internet.",
        },
        "Account Lockout": {
            "plain_english": "User accounts are being locked out, either due to forgotten passwords, automated attacks, or a compromised script/service using old credentials.",
            "where_from": "Can be caused by brute-force attacks, a service running with an old password, or a user forgetting their credentials.",
            "how_to_fix": "1. Check Event ID 4740 to find the source machine.\n2. Identify which account is locking out.\n3. If it's a service, update the credentials in Services manager.\n4. If it's a user, verify they are not under attack.\n5. Review audit logs for the source workstation.",
            "protection": "Implement a proper account lockout policy and set up alerts for repeated lockouts. Regularly audit service accounts.",
        },
        "Privilege Escalation": {
            "plain_english": "A user or process gained elevated administrator permissions. While sometimes legitimate, this can indicate an attacker trying to take full control of your system.",
            "where_from": "Can be from a legitimate admin action, a software installer, or a malicious actor exploiting a vulnerability to gain admin rights.",
            "how_to_fix": "1. Review Event IDs 4672 and 4673 for which accounts gained privileges.\n2. Verify these elevations were expected and authorised.\n3. Revoke unnecessary admin privileges (Principle of Least Privilege).\n4. Check if any new scheduled tasks or services were created.\n5. Run a malware scan immediately.",
            "protection": "Implement the principle of least privilege — give users only the minimum access they need. Use separate admin accounts for administrative tasks.",
        },
        "Windows Defender Alert": {
            "plain_english": "Windows Defender detected malware or a suspicious threat on this system. This is a serious warning that should be investigated immediately.",
            "where_from": "Malware can arrive via email attachments, malicious downloads, infected USB drives, or compromised websites.",
            "how_to_fix": "1. Open Windows Security and review quarantined items.\n2. Run a full offline scan immediately.\n3. Isolate the machine from the network if infection is confirmed.\n4. Identify and delete the malicious file.\n5. Change all passwords from a clean machine.",
            "protection": "Keep Windows Defender updated with real-time protection enabled. Avoid downloading software from untrusted sources. Use email filtering.",
        },
        "Unexpected Shutdown": {
            "plain_english": "The computer shut down unexpectedly without going through the normal shutdown process. This typically indicates a crash, power failure, or critical system error.",
            "where_from": "Usually caused by hardware issues (overheating, failing PSU), driver crashes (Blue Screen of Death), or power outages.",
            "how_to_fix": "1. Check Windows Event Viewer for Event ID 41 (kernel power failure).\n2. Review BSOD minidump files in C:\\Windows\\Minidump.\n3. Check CPU and system temperatures.\n4. Update or roll back recently installed drivers.\n5. Run Windows Memory Diagnostic tool.",
            "protection": "Use a UPS (Uninterruptible Power Supply) for power protection. Keep drivers updated and monitor system temperatures.",
        },
        "Disk Hardware Error": {
            "plain_english": "The hard drive is reporting read/write errors. This is a warning sign that the disk may be failing, which could lead to data loss.",
            "where_from": "Caused by physical drive wear and tear, bad sectors developing on the disk, or I/O controller issues.",
            "how_to_fix": "1. Run chkdsk /f /r from an elevated command prompt immediately.\n2. Run S.M.A.R.T. diagnostic tool (CrystalDiskInfo is free).\n3. Back up all important data RIGHT NOW before the drive fails further.\n4. Check Event ID 11 (disk error) for the affected drive letter.\n5. Plan to replace the drive if S.M.A.R.T. shows warnings.",
            "protection": "Implement regular backups (3-2-1 rule: 3 copies, 2 media types, 1 offsite). Monitor disk health monthly.",
        },
        "Application Crash": {
            "plain_english": "One or more applications crashed unexpectedly. While a single crash may be harmless, repeated crashes suggest a stability problem.",
            "where_from": "Usually caused by software bugs, incompatible updates, corrupted files, or insufficient memory.",
            "how_to_fix": "1. Check Event ID 1000 in Application log to identify the crashing application.\n2. Update or reinstall the affected application.\n3. Check for Windows updates that might fix the issue.\n4. Run sfc /scannow to check for corrupted system files.\n5. Check available RAM and disk space.",
            "protection": "Keep all applications updated. Monitor Event Viewer regularly for recurring crashes from the same source.",
        },
        "New Admin Account": {
            "plain_english": "A new administrator account was created or a user was added to the Administrators group. This is a major security event if it was not authorised.",
            "where_from": "Could be a legitimate IT action, or a sign that an attacker has established a persistent backdoor account on your system.",
            "how_to_fix": "1. Check Event ID 4720 (new account) and 4728 (added to admin group).\n2. Identify who created the account and when.\n3. If not authorised, disable and delete the account immediately.\n4. Change all admin passwords.\n5. Review all recent administrator-level activity.",
            "protection": "Restrict who can create admin accounts. Set up alerts for Event ID 4720 and 4728. Audit administrator accounts monthly.",
        },
        "Scheduled Task Created": {
            "plain_english": "A new scheduled task was created on this system. Attackers frequently use scheduled tasks to maintain persistent access or run malicious code automatically.",
            "where_from": "Can be legitimate software installation, or an attacker creating a task that runs malware at startup or at regular intervals.",
            "how_to_fix": "1. Open Task Scheduler and review all tasks in Task Scheduler Library.\n2. Check Event ID 4698 to see who created which tasks.\n3. Delete any suspicious tasks you don't recognise.\n4. Check the task's action — what program does it run?\n5. Scan the file the task runs with Windows Defender.",
            "protection": "Regularly audit scheduled tasks. Restrict who can create tasks via Group Policy. Monitor Event ID 4698 alerts.",
        },
        "Service Failure": {
            "plain_english": "One or more Windows services crashed or stopped unexpectedly. Services are background processes essential to system operation.",
            "where_from": "Usually caused by software bugs, corrupted files, resource conflicts, or dependency failures.",
            "how_to_fix": "1. Check Event ID 7034 and 7035 to identify the failing service.\n2. Open Services (services.msc) and check the service status.\n3. Right-click the service → Properties → Recovery to set auto-restart.\n4. Update or reinstall the software associated with the service.\n5. Check Application event log for related crash errors.",
            "protection": "Configure critical services to restart automatically on failure. Monitor services with a tool like Windows Admin Center.",
        },
    }

    threat_explanations = []
    for h in threats:
        kb = THREAT_KB.get(h["name"], {})
        threat_explanations.append({
            "name":          h["name"],
            "plain_english": kb.get("plain_english", f"This pattern ({h['name']}) was detected {h['count']} time(s). Review logs for details."),
            "where_from":    kb.get("where_from", "Review the event log for source machines and user accounts involved."),
            "severity":      h["severity"],
            "how_to_fix":    kb.get("how_to_fix", "1. Review Event Viewer for details.\n2. Investigate the source.\n3. Follow security best practices."),
            "protection":    kb.get("protection", "Maintain updated security policies and monitor logs regularly."),
        })

    # Anomaly explanation
    if anomalies:
        worst = max(anomalies, key=lambda a: a.get("zscore", 0))
        anom_explanation = (
            f"Statistical anomalies were detected on {len(anomalies)} day(s). "
            f"The worst spike was on {worst.get('date','unknown')} with {worst.get('count',0):,} events "
            f"(Z-score: {worst.get('zscore',0)} — meaning it was {worst.get('zscore',0)}x the standard deviation above normal). "
            "Event spikes like this can indicate a security incident, a batch process running amok, "
            "or a period of system instability. You should review logs from these dates in detail."
        )
    else:
        anom_explanation = (
            "No anomalous activity detected — event volume has been consistent throughout the monitoring period. "
            "This is a positive sign that no sudden incidents caused a flood of events."
        )

    # Action plan from existing recommendations
    PRIORITY_MAP = {"CRITICAL": "IMMEDIATE", "HIGH": "24_HOURS", "MEDIUM": "THIS_WEEK", "LOW": "ONGOING"}
    HOW_MAP = {
        "Enable multi-factor": "Go to your Microsoft account or Azure AD settings and enable MFA for all users.",
        "Investigate": "Open Event Viewer (eventvwr.msc) and filter for the relevant Event IDs.",
        "Run chkdsk": "Open Command Prompt as Administrator and run: chkdsk C: /f /r",
        "Monitor": "Set up Windows Event Log alerts or use a SIEM tool.",
        "rotate": "Go to user account settings and change passwords immediately.",
        "forensic": "Preserve logs, isolate the system, and contact your security team.",
    }

    action_plan = []
    for rec in r.get("recommendations", []):
        priority = PRIORITY_MAP.get(rec["priority"], "THIS_WEEK")
        how = "Review Event Viewer and follow security best practices for this area."
        for key, val in HOW_MAP.items():
            if key.lower() in rec["text"].lower():
                how = val
                break
        action_plan.append({
            "priority": priority,
            "action":   rec["text"],
            "reason":   f"Risk level: {rec['priority']}",
            "how":      how,
        })

    if not action_plan:
        action_plan.append({
            "priority": "ONGOING",
            "action":   "Continue routine monitoring and re-run analysis in 24 hours",
            "reason":   "System appears healthy",
            "how":      "Schedule regular log reviews and keep Windows updated.",
        })

    # Build event_id_explanations from comprehensive static knowledge base
    EID_KB = {
        # ── SECURITY / AUTHENTICATION ─────────────────────────────────────
        "4624": {"name": "Successful Logon",            "severity": "INFO",   "category": "Authentication", "what": "A user successfully logged on to the system. This is a normal event but high frequency from unexpected accounts is worth investigating.", "fix": "Review the account name and logon type. Logon type 3 (network) or 10 (remote interactive) from unusual hours may indicate unauthorised access."},
        "4625": {"name": "Failed Logon",                "severity": "HIGH",   "category": "Authentication", "what": "A login attempt failed — wrong password, locked account, or invalid username. Repeated failures indicate brute-force activity.", "fix": "Filter Event ID 4625 in Security log. Look for repeated failures from the same user/IP. Block the source IP in Windows Firewall if automated."},
        "4634": {"name": "Account Logoff",              "severity": "INFO",   "category": "Authentication", "what": "A user or session logged off. Normal in routine operation but sudden mass logoffs can indicate session hijacking or forced termination.", "fix": "No action needed unless logoffs are unexpected or from service accounts."},
        "4647": {"name": "User Initiated Logoff",       "severity": "INFO",   "category": "Authentication", "what": "A user explicitly initiated a logoff from the system.", "fix": "No action needed. Monitor if this coincides with unusual activity."},
        "4648": {"name": "Logon with Explicit Creds",   "severity": "MEDIUM", "category": "Authentication", "what": "A process logged on using explicitly supplied credentials (e.g. runas). Can indicate credential reuse or lateral movement.", "fix": "Verify which process used explicit credentials and whether the target account is expected."},
        "4657": {"name": "Registry Value Modified",     "severity": "HIGH",   "category": "Tampering",      "what": "A Windows registry key value was modified. Malware commonly modifies registry keys for persistence and auto-start.", "fix": "Identify the modified key and the process that changed it. Run a full malware scan. Check startup registry keys: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."},
        "4663": {"name": "Object Access Attempt",       "severity": "MEDIUM", "category": "Audit",          "what": "An attempt was made to access a securable object (file, registry key, etc.). Part of normal system auditing.", "fix": "Review which object was accessed and by whom. Investigate if sensitive files are being accessed unexpectedly."},
        "4672": {"name": "Special Privileges Assigned", "severity": "HIGH",   "category": "Privilege",      "what": "A user was granted elevated administrator-level privileges during logon. Normal for admins but suspicious for regular users.", "fix": "Verify which account received special privileges. Investigate if a non-admin account gained admin rights unexpectedly."},
        "4673": {"name": "Privileged Service Called",   "severity": "HIGH",   "category": "Privilege",      "what": "A privileged system service was called — can indicate privilege escalation attempts by malware or exploits.", "fix": "Check which process called the service and whether it was expected. Cross-reference with other security events at the same time."},
        "4688": {"name": "New Process Created",         "severity": "MEDIUM", "category": "Process",        "what": "A new process was started on the system. High volume indicates automation or possible malware spawning child processes.", "fix": "Review the process name and parent process. Investigate cmd.exe or powershell.exe spawned by unusual parents."},
        "4698": {"name": "Scheduled Task Created",      "severity": "HIGH",   "category": "Persistence",    "what": "A new scheduled task was created. Attackers use scheduled tasks as a persistence mechanism to survive reboots.", "fix": "Open Task Scheduler (taskschd.msc) and review all tasks. Delete unrecognised tasks. Check Event ID 4702 for task modifications."},
        "4699": {"name": "Scheduled Task Deleted",      "severity": "MEDIUM", "category": "Persistence",    "what": "A scheduled task was deleted. Could indicate an attacker cleaning up after an operation.", "fix": "Identify which task was deleted and by whom. Restore if a legitimate task was removed."},
        "4702": {"name": "Scheduled Task Updated",      "severity": "HIGH",   "category": "Persistence",    "what": "An existing scheduled task was modified. Attackers may update tasks to change what they execute.", "fix": "Review the modified task in Task Scheduler. Compare with known-good configuration."},
        "4719": {"name": "Audit Policy Changed",        "severity": "CRITICAL","category": "Policy",        "what": "The system security audit policy was changed. This could mean someone is trying to disable logging to hide their activities.", "fix": "Verify who changed the policy and restore the correct audit settings via secpol.msc or Group Policy Editor."},
        "4720": {"name": "User Account Created",        "severity": "HIGH",   "category": "Account",        "what": "A new Windows user account was created. Attackers create backdoor accounts for persistent access.", "fix": "Confirm this was authorised. If not, immediately disable and delete the account, rotate all admin passwords."},
        "4722": {"name": "User Account Enabled",        "severity": "MEDIUM", "category": "Account",        "what": "A previously disabled user account was re-enabled. Attackers may re-enable dormant accounts.", "fix": "Verify who enabled the account and whether this was authorised."},
        "4723": {"name": "Password Change Attempt",     "severity": "MEDIUM", "category": "Account",        "what": "A user attempted to change their own password. Unusual if from a service account or at odd hours.", "fix": "Verify this was intentional. Monitor service accounts for unexpected password change attempts."},
        "4724": {"name": "Password Reset by Admin",     "severity": "HIGH",   "category": "Account",        "what": "An administrator reset another user's password. Could be legitimate IT activity or an attacker taking control of accounts.", "fix": "Confirm this was an authorised IT action. If unexpected, treat as a potential account takeover."},
        "4725": {"name": "User Account Disabled",       "severity": "MEDIUM", "category": "Account",        "what": "A user account was disabled. Normal in HR offboarding but suspicious if an admin account is disabled.", "fix": "Verify the account that was disabled and whether this was planned."},
        "4726": {"name": "User Account Deleted",        "severity": "HIGH",   "category": "Account",        "what": "A user account was permanently deleted from the system.", "fix": "Confirm this was authorised. An attacker may delete accounts to cover their tracks after creating backdoors."},
        "4728": {"name": "User Added to Admin Group",   "severity": "CRITICAL","category": "Privilege",     "what": "A user was added to a privileged security group such as Administrators or Domain Admins. This grants full system control.", "fix": "Immediately verify whether this was authorised. If not, remove the user from the group and investigate how it happened."},
        "4732": {"name": "User Added to Local Group",   "severity": "MEDIUM", "category": "Account",        "what": "A user was added to a local security group. Depending on the group, this may expand their access rights.", "fix": "Review which group the user was added to and verify this was expected."},
        "4740": {"name": "Account Lockout",             "severity": "HIGH",   "category": "Authentication", "what": "A user account was locked out after too many failed login attempts. Can indicate brute-force attack or stale credentials in a service.", "fix": "Check Event ID 4625 for the source. Find which machine is generating the failed attempts. Update stale credentials in services if applicable."},
        "4756": {"name": "Member Added to Universal Group", "severity": "MEDIUM","category": "Account",     "what": "A member was added to a universal group (used in Active Directory environments).", "fix": "Verify this group membership change was authorised by IT."},
        "4767": {"name": "Account Unlocked",            "severity": "INFO",   "category": "Authentication", "what": "A locked-out user account was unlocked by an administrator.", "fix": "Monitor for repeated lockout-unlock cycles which may indicate a password attack."},
        "4771": {"name": "Kerberos Pre-Auth Failed",    "severity": "HIGH",   "category": "Authentication", "what": "Kerberos pre-authentication failed — often indicates a password spray or brute-force attack against domain accounts.", "fix": "Identify the source IP from the event. Block if automated. Force password reset for targeted accounts."},
        "4776": {"name": "NTLM Auth Attempt",           "severity": "MEDIUM", "category": "Authentication", "what": "The domain controller attempted to validate credentials using NTLM. Repeated failures indicate password attacks.", "fix": "Consider disabling NTLMv1 if present. Monitor for repeated failures from the same source."},
        "4798": {"name": "User Local Group Enumerated", "severity": "HIGH",   "category": "Reconnaissance", "what": "A process enumerated the local groups of a user account — common during reconnaissance by attackers mapping the network.", "fix": "Check which process performed the enumeration. Investigate if this was a security scanner or malicious activity."},
        "4799": {"name": "Local Group Membership Queried","severity": "HIGH", "category": "Reconnaissance", "what": "A process queried the membership of a local group — an attacker technique to find privileged accounts.", "fix": "Identify the querying process. Correlate with other suspicious events at the same timestamp."},

        # ── PROCESS / EXECUTION ───────────────────────────────────────────
        "4103": {"name": "PowerShell Module Logging",   "severity": "MEDIUM", "category": "Execution",      "what": "PowerShell executed a command and module logging captured it. Can indicate administrative work or malicious scripts.", "fix": "Review the PowerShell commands logged. Encoded or obfuscated commands are a red flag for malicious activity."},
        "4104": {"name": "PowerShell Script Block",     "severity": "HIGH",   "category": "Execution",      "what": "PowerShell script block logging captured a script execution. Attackers often use PowerShell for fileless malware attacks.", "fix": "Review the script content. Look for Base64-encoded commands, downloading executables, or disabling security tools."},

        # ── SYSTEM / KERNEL ───────────────────────────────────────────────
        "41":   {"name": "Kernel Power Failure",        "severity": "HIGH",   "category": "Stability",      "what": "The system shut down unexpectedly without going through the normal shutdown process — usually caused by a BSOD crash or sudden power loss.", "fix": "Check C:\\Windows\\Minidump for crash dump files. Update or roll back drivers. Verify power supply stability. Run memory diagnostics (mdsched.exe)."},
        "6008": {"name": "Unexpected Shutdown",         "severity": "HIGH",   "category": "Stability",      "what": "Windows detected that it was not shut down cleanly during the previous session — indicates a crash, power failure, or forced power off.", "fix": "Review Event ID 41 for the crash details. Check BSOD minidumps, update drivers, and monitor system temperatures."},
        "6013": {"name": "System Uptime",               "severity": "INFO",   "category": "System",         "what": "Windows logs the system uptime daily. Unusually low uptime values may indicate frequent crashes or restarts.", "fix": "No action needed unless uptime is very low, which would indicate instability."},

        # ── DISK / STORAGE ────────────────────────────────────────────────
        "11":   {"name": "Disk I/O Error",              "severity": "CRITICAL","category": "Hardware",      "what": "The disk controller reported a read or write error on the drive. This is a serious early warning sign of potential disk failure and data loss.", "fix": "Run chkdsk C: /f /r from an elevated Command Prompt immediately. Check S.M.A.R.T. status with CrystalDiskInfo. Back up all data NOW before the drive fails."},
        "7":    {"name": "Disk Bad Block",              "severity": "CRITICAL","category": "Hardware",      "what": "The disk has bad sectors that could not be read — a sign of physical drive degradation.", "fix": "Back up data immediately. Run chkdsk to mark bad sectors. Plan drive replacement."},
        "15":   {"name": "Disk Not Ready",              "severity": "HIGH",   "category": "Hardware",       "what": "A disk was not ready to respond to a request — could indicate connection issues or drive failure.", "fix": "Check physical disk connections. Run diagnostics. Consider replacing the drive."},
        "55":   {"name": "NTFS File System Error",      "severity": "HIGH",   "category": "Hardware",       "what": "The NTFS file system detected corruption or structural errors on the volume.", "fix": "Run chkdsk /f /r on the affected volume. If errors persist, back up data and reformat or replace the drive."},
        "153":  {"name": "Disk Reset (Timeout)",        "severity": "HIGH",   "category": "Hardware",       "what": "The operating system timed out waiting for the disk to respond — indicates a slow or failing drive.", "fix": "Run S.M.A.R.T. diagnostic. Check SATA/NVMe cables. Replace the drive if timeouts are frequent."},

        # ── MEMORY ────────────────────────────────────────────────────────
        "1001": {"name": "Windows Error Reporting",     "severity": "MEDIUM", "category": "Stability",      "what": "Windows Error Reporting captured a crash or hang event and prepared a report. Indicates application or system instability.", "fix": "Identify the crashing component from the event details. Update or reinstall the affected software."},
        "5":    {"name": "Memory Paging Error",         "severity": "HIGH",   "category": "Hardware",       "what": "A paging error occurred in memory — can indicate failing RAM or corrupted virtual memory.", "fix": "Run Windows Memory Diagnostic (mdsched.exe). Check pagefile settings. Consider replacing RAM if errors persist."},

        # ── SERVICES ──────────────────────────────────────────────────────
        "7000": {"name": "Service Failed to Start",     "severity": "HIGH",   "category": "Services",       "what": "A Windows service failed to start during system startup or on demand. This can prevent features or security software from running.", "fix": "Open Event Viewer and check the full error. Try starting the service manually in services.msc. Check for missing dependencies or corrupted service binaries."},
        "7001": {"name": "Service Dependency Failure",  "severity": "HIGH",   "category": "Services",       "what": "A service could not start because another service it depends on failed or was not running.", "fix": "Identify the dependency chain. Start the prerequisite service first, then retry the dependent service."},
        "7009": {"name": "Service Timeout",             "severity": "HIGH",   "category": "Services",       "what": "A service did not respond within the expected timeout period during startup — usually indicates the service is hung or overloaded.", "fix": "Restart the service. Check system resources (CPU, memory). Review application logs for the service."},
        "7011": {"name": "Service Response Timeout",    "severity": "HIGH",   "category": "Services",       "what": "The Service Control Manager timed out waiting for a service to respond to a control request.", "fix": "Restart the service. Increase timeout in registry if needed: HKLM\\SYSTEM\\CurrentControlSet\\Control\\ServicesPipeTimeout."},
        "7023": {"name": "Service Terminated with Error","severity": "HIGH",  "category": "Services",       "what": "A service terminated with an error code — indicates the service crashed or encountered a fatal error.", "fix": "Note the error code from the event. Search for the specific error code to diagnose the root cause."},
        "7031": {"name": "Service Terminated Unexpectedly","severity": "HIGH","category": "Services",       "what": "A service terminated unexpectedly. Windows will take the recovery actions specified for the service.", "fix": "Check the service recovery settings in services.msc. Review application event log for related errors."},
        "7034": {"name": "Service Crashed",             "severity": "HIGH",   "category": "Services",       "what": "A Windows service terminated unexpectedly without a controlled shutdown. This can be caused by bugs, resource exhaustion, or corrupted files.", "fix": "Right-click the service in services.msc → Properties → Recovery. Set it to auto-restart. Check Event Viewer Application log for crash details."},
        "7035": {"name": "Service Control Signal",      "severity": "INFO",   "category": "Services",       "what": "A start or stop control signal was sent to a service. Normal for routine service management but suspicious if unexpected.", "fix": "Verify the action was expected. Investigate if a critical service was stopped without authorisation."},
        "7036": {"name": "Service State Changed",       "severity": "INFO",   "category": "Services",       "what": "A service entered a running or stopped state. Informational — high frequency may indicate service instability.", "fix": "Monitor if a critical service is repeatedly starting and stopping, which indicates a crash loop."},
        "7040": {"name": "Service Start Type Changed",  "severity": "MEDIUM", "category": "Services",       "what": "The start type of a service was changed (e.g. from Automatic to Disabled). Malware may disable security services.", "fix": "Verify which service was changed and whether the change was authorised. Restore original start type if needed."},
        "7045": {"name": "New Service Installed",       "severity": "HIGH",   "category": "Persistence",    "what": "A new service was installed on the system. Attackers install malicious services for persistence.", "fix": "Review the service name, binary path, and who installed it. Delete and investigate if unrecognised."},

        # ── APPLICATIONS ─────────────────────────────────────────────────
        "1000": {"name": "Application Crash",           "severity": "MEDIUM", "category": "Application",    "what": "An application crashed unexpectedly. Windows logs the faulting application name and the crash module. Repeated crashes suggest software bugs, incompatibility, or malware.", "fix": "Note the faulting application name. Update or reinstall it. Check for pending Windows Updates. Run sfc /scannow to check for corrupted system files."},
        "1001": {"name": "Application Fault Report",    "severity": "MEDIUM", "category": "Application",    "what": "Windows Error Reporting created a crash report for a faulting application or process.", "fix": "Review the faulting module. If it's a system DLL, run sfc /scannow. If it's a third-party app, update or reinstall."},
        "1002": {"name": "Application Hang",            "severity": "MEDIUM", "category": "Application",    "what": "An application stopped responding (hung) and had to be terminated or recovered. Can indicate resource contention or bugs.", "fix": "Update the application. Check available RAM and CPU. Investigate if the hang is reproducible."},
        "1003": {"name": ".NET Runtime Error",          "severity": "MEDIUM", "category": "Application",    "what": "The .NET runtime encountered an unhandled exception and the application had to terminate.", "fix": "Update .NET Framework/Runtime. Review the exception type in the event for more details. Reinstall the affected application."},

        # ── WINDOWS UPDATE ────────────────────────────────────────────────
        "20":   {"name": "Update Installation Failed",  "severity": "HIGH",   "category": "Updates",        "what": "A Windows Update failed to install. Missing security patches leave the system vulnerable to known exploits.", "fix": "Open Windows Update settings and view the error code. Run Windows Update Troubleshooter. Try manually downloading the update from Microsoft Update Catalog."},
        "43":   {"name": "Update Download Started",     "severity": "INFO",   "category": "Updates",        "what": "Windows Update began downloading an update package. Normal operation.", "fix": "No action required. Ensure the download completes and the update installs successfully."},
        "19":   {"name": "Update Installed Successfully","severity": "INFO",  "category": "Updates",        "what": "A Windows Update was successfully installed. This is a positive event.", "fix": "No action required. Restart the system if prompted to complete the update."},

        # ── NETWORK ───────────────────────────────────────────────────────
        "4776": {"name": "NTLM Credential Validation",  "severity": "MEDIUM", "category": "Network",        "what": "The domain controller attempted to validate NTLM credentials. Repeated failures from a single source may indicate a password spray attack.", "fix": "Monitor for patterns of repeated failures. Disable NTLMv1 if in use. Consider blocking suspicious source IPs."},
        "5140": {"name": "Network Share Accessed",      "severity": "MEDIUM", "category": "Network",        "what": "A network share was accessed. Can be normal in file server environments but suspicious if from unexpected accounts or times.", "fix": "Review which share was accessed and by whom. Investigate access to sensitive shares like C$ or ADMIN$."},
        "5145": {"name": "Network Share Check",         "severity": "MEDIUM", "category": "Network",        "what": "A network object (file or folder on a share) was checked to see if client has desired access.", "fix": "Monitor for unusual access patterns to sensitive shares, especially from service accounts."},
        "5156": {"name": "Network Connection Allowed",  "severity": "INFO",   "category": "Network",        "what": "Windows Firewall allowed a network connection. High volume from unexpected processes may indicate malware calling home.", "fix": "Monitor for unusual process names making outbound connections, especially to external IPs."},
        "5157": {"name": "Network Connection Blocked",  "severity": "MEDIUM", "category": "Network",        "what": "Windows Firewall blocked a network connection attempt. High frequency may indicate malware or a misconfigured application.", "fix": "Identify the blocked process and destination. If legitimate, add a firewall rule. If unexpected, investigate the process."},
        "5158": {"name": "Port Bound",                  "severity": "MEDIUM", "category": "Network",        "what": "An application bound to a local port to listen for connections. Unexpected port bindings can indicate backdoors.", "fix": "Use netstat -ano to check what is listening on each port. Investigate unrecognised processes."},

        # ── WINDOWS DEFENDER / SECURITY ───────────────────────────────────
        "1116": {"name": "Malware Detected",            "severity": "CRITICAL","category": "Malware",       "what": "Windows Defender detected malware or a potentially unwanted application on this system. This requires immediate action.", "fix": "Open Windows Security → Protection History to see the threat. Ensure it was quarantined or removed. Run a full offline scan. If confirmed infection, isolate the machine and change all passwords."},
        "1117": {"name": "Malware Action Taken",        "severity": "CRITICAL","category": "Malware",       "what": "Windows Defender took action against detected malware (quarantine, removal, or block). The threat may still need investigation.", "fix": "Review the action taken in Windows Security. Verify the threat was fully removed. Run a second scan with a different tool (Malwarebytes) to confirm clean."},
        "1118": {"name": "Malware Remediation Started", "severity": "CRITICAL","category": "Malware",       "what": "Windows Defender started remediation of a detected malware threat.", "fix": "Allow remediation to complete. Review the threat details and verify full removal."},
        "1119": {"name": "Malware Remediation Succeeded","severity": "HIGH",  "category": "Malware",        "what": "Windows Defender successfully remediated a malware threat. The immediate threat is resolved but root cause investigation is still needed.", "fix": "Check how the malware entered the system (email, download, USB). Change passwords and review recent activity."},
        "1120": {"name": "Malware Remediation Failed",  "severity": "CRITICAL","category": "Malware",       "what": "Windows Defender failed to remove a detected malware threat. The system may still be infected.", "fix": "Immediately isolate the machine from the network. Boot into Windows Recovery Environment and run an offline scan. Consider OS reinstallation."},
        "5001": {"name": "Real-Time Protection Disabled","severity": "CRITICAL","category": "Malware",      "what": "Windows Defender real-time protection was disabled. This leaves the system completely exposed to malware threats.", "fix": "Re-enable real-time protection immediately in Windows Security. Investigate why it was disabled — malware often disables AV as a first step."},
        "5004": {"name": "Antivirus Config Changed",    "severity": "HIGH",   "category": "Malware",        "what": "A Windows Defender configuration setting was changed. Could be legitimate update or malware weakening defences.", "fix": "Verify the configuration change was expected. Restore default settings if changed without authorisation."},
        "5007": {"name": "Defender Policy Changed",     "severity": "HIGH",   "category": "Malware",        "what": "A Windows Defender policy was modified. Attackers disable AV policies to avoid detection.", "fix": "Check which policy was changed and restore it. Re-enable any disabled scanning features."},

        # ── REMOTE DESKTOP / REMOTE ACCESS ───────────────────────────────
        "4778": {"name": "RDP Session Reconnected",     "severity": "MEDIUM", "category": "Remote Access",  "what": "A remote desktop session was reconnected to the system. Unexpected reconnections outside business hours are suspicious.", "fix": "Verify the user and source IP. Consider restricting RDP access to a VPN only."},
        "4779": {"name": "RDP Session Disconnected",    "severity": "INFO",   "category": "Remote Access",  "what": "A remote desktop session was disconnected. Normal in RDP usage.", "fix": "Monitor for unusual disconnect patterns that might indicate session hijacking attempts."},
        "1149": {"name": "RDP Auth Succeeded (Pre-Login)","severity": "HIGH", "category": "Remote Access",  "what": "A remote desktop connection was accepted before full authentication. Relevant for Network Level Authentication monitoring.", "fix": "Ensure NLA (Network Level Authentication) is enabled for RDP. Limit RDP to specific IPs via firewall."},

        # ── FIREWALL / AUDIT ─────────────────────────────────────────────
        "4946": {"name": "Firewall Rule Added",         "severity": "HIGH",   "category": "Firewall",       "what": "A new Windows Firewall rule was added. Attackers add rules to allow inbound connections for backdoors or C2 traffic.", "fix": "Review the newly added rule in Windows Defender Firewall. Remove any rules that allow unexpected inbound connections."},
        "4947": {"name": "Firewall Rule Modified",      "severity": "HIGH",   "category": "Firewall",       "what": "An existing Windows Firewall rule was modified. Could indicate someone weakening firewall protections.", "fix": "Verify the rule change was expected. Restore the original rule configuration if unauthorised."},
        "4950": {"name": "Firewall Setting Changed",    "severity": "HIGH",   "category": "Firewall",       "what": "A Windows Firewall setting was changed. Attackers may disable the firewall entirely to allow unrestricted network access.", "fix": "Check if the firewall is still enabled. Re-enable if disabled and investigate who made the change."},
        "4954": {"name": "Firewall Policy Changed",     "severity": "HIGH",   "category": "Firewall",       "what": "The Windows Firewall Group Policy settings were changed. Could disable protection for all users on the machine.", "fix": "Review current firewall policy settings. Restore defaults if security settings were weakened."},

        # ── CERTIFICATE / CRYPTO ──────────────────────────────────────────
        "36871": {"name": "TLS/SSL Fatal Error",        "severity": "MEDIUM", "category": "Cryptography",   "what": "A fatal error occurred during a TLS/SSL handshake. Can indicate misconfiguration, certificate issues, or an interception attempt.", "fix": "Review certificate validity. Update TLS settings to require TLS 1.2 or higher. Check for expired or self-signed certificates."},
        "36888": {"name": "Fatal Alert Sent",           "severity": "MEDIUM", "category": "Cryptography",   "what": "Windows Schannel sent a fatal TLS alert to a remote system. Often seen with protocol mismatches or certificate problems.", "fix": "Update SSL/TLS configuration. Ensure both client and server support compatible protocol versions."},
        "36887": {"name": "Fatal Alert Received",       "severity": "MEDIUM", "category": "Cryptography",   "what": "Windows Schannel received a fatal TLS alert from a remote system — the remote end aborted the secure connection.", "fix": "Check certificate configuration on both endpoints. Update to TLS 1.2/1.3 and disable older protocols."},
    }

    error_details = r.get("error_details", [])
    event_id_explanations = []
    for e in error_details[:60]:   # show ALL up to 60
        eid = str(e.get("event_id", ""))
        kb  = EID_KB.get(eid, {})
        lvl = e.get("level", "ERROR")
        cnt = e.get("count", 0)
        srcs = e.get("sources", [])
        cats_list = e.get("categories", [])
        example = e.get("example", "")

        # Determine severity note based on count
        if cnt >= 1000:
            sev_note = f"Count of {cnt:,} is VERY HIGH — requires immediate investigation."
        elif cnt >= 100:
            sev_note = f"Count of {cnt:,} is elevated and worth investigating promptly."
        elif cnt >= 20:
            sev_note = f"Count of {cnt:,} is above normal — monitor closely."
        else:
            sev_note = f"Count of {cnt:,} is relatively low — low priority unless increasing."

        event_id_explanations.append({
            "event_id":      eid,
            "name":          kb.get("name", f"Windows Event {eid}"),
            "level":         lvl,
            "count":         cnt,
            "severity":      kb.get("severity", lvl),
            "category":      kb.get("category", "System"),
            "sources":       srcs[:3],
            "log_categories": cats_list,
            "latest":        e.get("latest", "")[:16],
            "example":       example[:120] if example else "",
            "what_it_means": kb.get("what", f"Windows recorded Event ID {eid} ({lvl}) {cnt:,} time(s). Review Event Viewer for full details."),
            "why_occurring":  f"Occurring {cnt:,} time(s) from: {', '.join(srcs[:2]) or 'unknown source'} in log category: {', '.join(cats_list) or 'unknown'}.",
            "severity_note":  sev_note,
            "fix":            kb.get("fix", f"Open Event Viewer, filter for Event ID {eid}, and investigate the source and details of each occurrence."),
        })

    return {
        "ai_available":          False,
        "executive_summary":     exec_summary,
        "what_is_happening": (
            f"{hostname} has been analysed over the past {period} days. "
            f"A total of {total_ev:,} events were recorded with {total_err:,} errors. "
            + (f"The system is at {risk} risk. " if risk != "Low" else "The system appears healthy. ")
            + ("The following threats require attention: " + ", ".join(h["name"] for h in threats[:3]) + ". " if threats else "No active threats were detected. ")
            + ("Statistical anomalies were found on certain days which warrant investigation." if anomalies else "Event volume has been consistent.")
        ),
        "threat_explanations":   threat_explanations,
        "anomaly_explanation":   anom_explanation,
        "top_sources_analysis": (
            "The top event sources show which applications and services are generating the most log activity. "
            "High error counts from a single source often indicate a specific service or driver that needs attention. "
            "Review the top sources and cross-reference with the threat patterns to prioritise your investigation."
        ),
        "event_id_explanations": event_id_explanations,
        "action_plan":           action_plan,
        "protection_summary": (
            "To protect this system going forward: keep Windows and all software updated regularly to patch security vulnerabilities. "
            "Enable and maintain Windows Defender with real-time protection. "
            "Use strong, unique passwords and enable multi-factor authentication for all accounts, especially administrator accounts. "
            "Regularly back up important data following the 3-2-1 rule (3 copies, 2 different media, 1 offsite). "
            "Review these analysis reports regularly and act on recommendations promptly. "
            "Restrict administrator privileges to only those users who absolutely need them."
        ),
        "verdict": (
            f"{hostname} requires IMMEDIATE security action — critical threats were detected." if risk == "Critical"
            else f"{hostname} is at elevated risk and should be reviewed within 24 hours." if risk == "High"
            else f"{hostname} shows moderate risk activity — schedule a review this week." if risk == "Medium"
            else f"{hostname} appears healthy — continue routine monitoring."
        ),
        "error": f"AI narrative unavailable ({reason}) — using static analysis.",
    }
