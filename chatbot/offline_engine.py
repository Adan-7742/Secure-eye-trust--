"""
chatbot/offline_engine.py
=========================
Rule-based AI fallback when Groq API is unavailable or no key is set.
Provides meaningful responses using pattern matching + knowledge base.

FR05-05 UPDATE:
  - Added POLICY_PATTERNS covering 8 policy topic areas
  - Added offline_policy_recommendations(signals) function — builds
    structured policy recommendations from live DB signals without AI
  - Added POLICY_KB — comprehensive knowledge base of Windows security
    policies with exact GPO paths, PowerShell commands, and MITRE mappings
"""

import re

EVENT_IDS = {
    41:   ("CRITICAL", "Kernel-Power — system shut down unexpectedly (crash/power loss)"),
    1000: ("HIGH",     "Application Error — app crashed, check faulting module"),
    1001: ("HIGH",     "Windows Error Reporting — crash dump recorded"),
    1002: ("MEDIUM",   "Application Hang — process stopped responding"),
    4624: ("INFO",     "Successful account logon"),
    4625: ("CRITICAL", "Failed account logon — possible brute force"),
    4634: ("INFO",     "Account logoff"),
    4648: ("HIGH",     "Logon with explicit credentials"),
    4672: ("HIGH",     "Special privileges assigned to new logon"),
    4688: ("MEDIUM",   "New process created"),
    4698: ("HIGH",     "Scheduled task created — common persistence technique"),
    4699: ("MEDIUM",   "Scheduled task deleted"),
    4700: ("MEDIUM",   "Scheduled task enabled"),
    4701: ("LOW",      "Scheduled task disabled"),
    4702: ("HIGH",     "Scheduled task updated — check for payload change"),
    4719: ("HIGH",     "System audit policy changed"),
    4720: ("HIGH",     "User account created"),
    4725: ("MEDIUM",   "User account disabled"),
    4740: ("HIGH",     "User account locked out"),
    5001: ("CRITICAL", "Windows Defender real-time protection disabled"),
    5007: ("HIGH",     "Windows Defender policy changed"),
    6005: ("INFO",     "Event Log service started = system boot"),
    6006: ("INFO",     "Event Log service stopped = system shutdown"),
    6008: ("HIGH",     "Unexpected shutdown recorded"),
    7000: ("HIGH",     "Service failed to start"),
    7001: ("HIGH",     "Service dependency failure"),
    7034: ("HIGH",     "Service crashed unexpectedly"),
    7036: ("INFO",     "Service state changed (running/stopped)"),
    7040: ("HIGH",     "Service start type changed — possible defense evasion"),
    7045: ("HIGH",     "New service installed — verify if authorized"),
}


# ── FR05-05: Policy knowledge base ────────────────────────────────────────────
POLICY_KB = {
    "account_lockout": {
        "title":    "Enable Account Lockout Policy",
        "priority": "CRITICAL",
        "steps": [
            "Open Group Policy Editor: `gpedit.msc`",
            "Navigate to: Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy",
            "Set 'Account lockout threshold' to 5 invalid attempts",
            "Set 'Account lockout duration' to 15 minutes",
            "Set 'Reset account lockout counter after' to 15 minutes",
            "Apply and run `gpupdate /force`",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy",
        "command":  "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
        "mitre":    "T1110 - Brute Force",
        "effort":   "Low",
    },
    "mfa": {
        "title":    "Enable Multi-Factor Authentication (MFA)",
        "priority": "CRITICAL",
        "steps": [
            "For Azure AD / Microsoft 365: go to Azure Portal → Azure Active Directory → Security → MFA",
            "Enable Security Defaults or configure Conditional Access policies",
            "For local Windows: install Windows Hello for Business via GPO",
            "GPO path: Computer Configuration → Administrative Templates → Windows Components → Windows Hello for Business",
            "Enforce MFA for all admin accounts first, then all users",
        ],
        "gpo_path": "Computer Configuration → Administrative Templates → Windows Components → Windows Hello for Business",
        "command":  "Set-MsolUser -UserPrincipalName <user@domain> -StrongAuthenticationRequirements $req",
        "mitre":    "T1078 - Valid Accounts",
        "effort":   "Medium",
    },
    "audit_policy": {
        "title":    "Enable Comprehensive Windows Audit Policy",
        "priority": "HIGH",
        "steps": [
            "Open `secpol.msc` → Advanced Audit Policy Configuration",
            "Enable 'Audit Logon Events' (Success and Failure) — covers EID 4624/4625",
            "Enable 'Audit Account Lockout' (Failure) — covers EID 4740",
            "Enable 'Audit Privilege Use' (Success and Failure) — covers EID 4672/4673",
            "Enable 'Audit Process Creation' (Success) — covers EID 4688",
            "Enable 'Audit Policy Change' (Success and Failure) — covers EID 4719",
            "Enable 'Audit Object Access' for registry monitoring — covers EID 4657",
            "Run `auditpol /get /category:*` to verify current settings",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration",
        "command":  "auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
        "mitre":    "T1562.002 - Impair Defenses: Disable Windows Event Logging",
        "effort":   "Low",
    },
    "password_policy": {
        "title":    "Enforce Strong Password Policy",
        "priority": "HIGH",
        "steps": [
            "Open `gpedit.msc` → Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy",
            "Set 'Minimum password length' to 14 characters",
            "Enable 'Password must meet complexity requirements'",
            "Set 'Maximum password age' to 90 days",
            "Set 'Minimum password age' to 1 day",
            "Set 'Enforce password history' to 24 passwords",
            "Consider enabling Windows Fine-Grained Password Policies for admin accounts (stricter)",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy",
        "command":  "net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24",
        "mitre":    "T1110.001 - Password Guessing",
        "effort":   "Low",
    },
    "defender": {
        "title":    "Harden Windows Defender Configuration",
        "priority": "CRITICAL",
        "steps": [
            "Ensure real-time protection is enabled: `Set-MpPreference -DisableRealtimeMonitoring $false`",
            "Enable cloud-based protection: `Set-MpPreference -MAPSReporting Advanced`",
            "Enable Attack Surface Reduction (ASR) rules via PowerShell or GPO",
            "GPO path: Computer Configuration → Administrative Templates → Windows Defender Antivirus",
            "Enable 'Block credential stealing from LSASS': `Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f... -AttackSurfaceReductionRules_Actions Enabled`",
            "Enable tamper protection in Windows Security app → Virus & threat protection settings",
        ],
        "gpo_path": "Computer Configuration → Administrative Templates → Windows Defender Antivirus",
        "command":  "Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent 2",
        "mitre":    "T1562.001 - Impair Defenses: Disable or Modify Tools",
        "effort":   "Low",
    },
    "powershell": {
        "title":    "Restrict PowerShell Execution Policy",
        "priority": "HIGH",
        "steps": [
            "Set execution policy to RemoteSigned or AllSigned for all users",
            "GPO: Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on Script Execution → set to 'Allow only signed scripts'",
            "Enable PowerShell Script Block Logging (EID 4104): GPO → Administrative Templates → Windows PowerShell → Turn on PowerShell Script Block Logging",
            "Enable Constrained Language Mode for non-admin users: `[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')`",
            "Block -EncodedCommand via AppLocker or WDAC policy",
        ],
        "gpo_path": "Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell",
        "command":  "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force",
        "mitre":    "T1059.001 - PowerShell",
        "effort":   "Medium",
    },
    "applocker": {
        "title":    "Implement AppLocker Application Whitelisting",
        "priority": "HIGH",
        "steps": [
            "Open `gpedit.msc` → Computer Configuration → Windows Settings → Security Settings → Application Control Policies → AppLocker",
            "Create default rules for Executable Rules, Windows Installer Rules, and Script Rules",
            "Block execution from %TEMP%, %APPDATA%, %USERPROFILE%\\Downloads",
            "Start the Application Identity service: `sc config AppIDSvc start= auto && net start AppIDSvc`",
            "Test in Audit mode first before enforcing: set all rule collections to 'Audit only'",
            "Review AppLocker event logs (EIDs 8003/8004) for 30 days before switching to Enforce",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Application Control Policies → AppLocker",
        "command":  "sc config AppIDSvc start= auto && net start AppIDSvc",
        "mitre":    "T1218 - Signed Binary Proxy Execution",
        "effort":   "High",
    },
    "firewall": {
        "title":    "Harden Windows Firewall Rules",
        "priority": "HIGH",
        "steps": [
            "Open `wf.msc` → Windows Defender Firewall with Advanced Security",
            "Set inbound default action to 'Block' for all profiles (Domain, Private, Public)",
            "Review all inbound rules — disable any rules not explicitly required",
            "Block common attacker ports inbound: 4444, 1337, 8080 (if not used)",
            "Enable firewall logging: right-click each profile → Properties → Logging → Log dropped packets",
            "GPO: Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall",
            "Enable EID 5152/5157 auditing to log blocked connections",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall with Advanced Security",
        "command":  "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
        "mitre":    "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
        "effort":   "Medium",
    },
    "windows_update": {
        "title":    "Enforce Automatic Windows Update Policy",
        "priority": "HIGH",
        "steps": [
            "GPO: Computer Configuration → Administrative Templates → Windows Components → Windows Update",
            "Set 'Configure Automatic Updates' to '4 - Auto download and schedule the install'",
            "Set 'Specify intranet Microsoft update service location' if using WSUS",
            "Set maximum update deferral to 0 days for security updates",
            "Enable 'Remove access to use all Windows Update features' to prevent users disabling updates",
            "Run `wuauclt /detectnow` to force immediate update check",
        ],
        "gpo_path": "Computer Configuration → Administrative Templates → Windows Components → Windows Update",
        "command":  "wuauclt /detectnow /updatenow",
        "mitre":    "M1051 - Update Software",
        "effort":   "Low",
    },
    "least_privilege": {
        "title":    "Enforce Principle of Least Privilege",
        "priority": "HIGH",
        "steps": [
            "Audit all local Administrator group members: `net localgroup Administrators`",
            "Remove any non-essential accounts from the Administrators group",
            "Create separate standard user accounts and admin accounts for all privileged users",
            "Enable User Account Control (UAC) at the highest level",
            "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → 'User Account Control: Run all administrators in Admin Approval Mode' → Enabled",
            "Review EID 4728 (user added to privileged group) alerts regularly",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options",
        "command":  "net localgroup Administrators",
        "mitre":    "T1078.003 - Valid Accounts: Local Accounts",
        "effort":   "Medium",
    },
    "scheduled_tasks": {
        "title":    "Restrict Scheduled Task Creation",
        "priority": "MEDIUM",
        "steps": [
            "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment",
            "Remove standard users from 'Create symbolic links' and review task permissions",
            "Audit Task Scheduler library regularly via `schtasks /query /fo LIST /v`",
            "Enable EID 4698 auditing and set up alerts for new task creation",
            "Restrict task creation to administrators only via DCOM permissions on Task Scheduler service",
            "Delete any unrecognised tasks from Task Scheduler Library",
        ],
        "gpo_path": "Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment",
        "command":  "schtasks /query /fo LIST /v | findstr /i 'task name status'",
        "mitre":    "T1053.005 - Scheduled Task/Job: Scheduled Task",
        "effort":   "Medium",
    },
    "credential_guard": {
        "title":    "Enable Windows Credential Guard",
        "priority": "HIGH",
        "steps": [
            "Requirements: UEFI 2.3.1 or later, Secure Boot, 64-bit CPU with virtualisation extensions",
            "GPO: Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security",
            "Set 'Credential Guard Configuration' to 'Enabled with UEFI lock'",
            "Alternatively use Device Guard and Credential Guard Hardware Readiness Tool",
            "Verify after reboot: `msinfo32.exe` → System Summary → check 'Virtualization-based security' is Running",
        ],
        "gpo_path": "Computer Configuration → Administrative Templates → System → Device Guard",
        "command":  "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f",
        "mitre":    "T1003.001 - OS Credential Dumping: LSASS Memory",
        "effort":   "High",
    },
}


def offline_policy_recommendations(signals: dict) -> dict:
    """
    FR05-05: Build structured policy recommendations from live DB signals
    without requiring an AI API key.

    Uses the POLICY_KB and compares against signal thresholds to produce
    a prioritised, data-driven recommendation list.

    Args:
        signals: dict from get_policy_context()["policy_signals"]

    Returns:
        {
          "recommendations": [...],
          "summary": "..."
        }
    """
    recs = []

    # Account lockout — triggered by failed logons
    failed_logons = signals.get("failed_logons_total", 0)
    if failed_logons > 0:
        r = dict(POLICY_KB["account_lockout"])
        r["reason"] = (
            f"{failed_logons} failed logon attempts (EID 4625) detected. "
            "Without an account lockout policy, brute-force attacks can run indefinitely."
        )
        if failed_logons > 50:
            r["priority"] = "CRITICAL"
        recs.append(r)

    # MFA — triggered by failed logons or lockouts
    lockouts = signals.get("account_lockouts", 0)
    if failed_logons > 10 or lockouts > 0:
        r = dict(POLICY_KB["mfa"])
        r["reason"] = (
            f"{failed_logons} failed logons and {lockouts} account lockouts detected. "
            "MFA prevents credential-based attacks even when passwords are compromised."
        )
        recs.append(r)

    # Audit policy — triggered by audit policy change events
    audit_changes = signals.get("audit_policy_changes", 0)
    r = dict(POLICY_KB["audit_policy"])
    if audit_changes > 0:
        r["reason"] = (
            f"{audit_changes} audit policy change event(s) (EID 4719) detected. "
            "Ensure comprehensive audit logging is enabled and cannot be silently disabled."
        )
        r["priority"] = "CRITICAL"
    else:
        r["reason"] = (
            "Comprehensive audit policy ensures all critical security Event IDs "
            "(4624/4625/4672/4688/4698/4719) are captured."
        )
    recs.append(r)

    # Defender hardening — triggered by Defender disabled events
    defender_events = signals.get("defender_disabled_events", 0)
    if defender_events > 0:
        r = dict(POLICY_KB["defender"])
        r["priority"] = "CRITICAL"
        r["reason"] = (
            f"{defender_events} Windows Defender disabled event(s) (EID 5001/5007) detected. "
            "Defender was turned off — immediate hardening and tamper protection required."
        )
        recs.append(r)
    else:
        r = dict(POLICY_KB["defender"])
        r["reason"] = (
            "Proactive Defender hardening prevents attackers from disabling protection. "
            "Enable tamper protection and ASR rules now."
        )
        recs.append(r)

    # Windows Update — triggered by update failures
    update_failures = signals.get("update_failures", 0)
    if update_failures > 0:
        r = dict(POLICY_KB["windows_update"])
        r["priority"] = "HIGH"
        r["reason"] = (
            f"{update_failures} Windows Update failure(s) detected. "
            "Unpatched systems are vulnerable to known CVEs. Enforce automatic update policy."
        )
        recs.append(r)

    # PowerShell restrictions — triggered by suspicious PS commands
    ps_cmds = signals.get("ps_suspicious_commands", 0)
    if ps_cmds > 0:
        r = dict(POLICY_KB["powershell"])
        r["priority"] = "HIGH"
        r["reason"] = (
            f"{ps_cmds} suspicious PowerShell command(s) detected (encoded or download cradle). "
            "Restrict execution policy and enable Script Block Logging."
        )
        recs.append(r)

    # Scheduled task restrictions — triggered by task creation events
    tasks_created = signals.get("scheduled_tasks_created", 0)
    if tasks_created > 0:
        r = dict(POLICY_KB["scheduled_tasks"])
        r["reason"] = (
            f"{tasks_created} new scheduled task(s) created (EID 4698). "
            "Review and restrict task creation to administrators only."
        )
        recs.append(r)

    # New services — triggered by 7045
    new_services = signals.get("new_services_installed", 0)
    if new_services > 0:
        r = dict(POLICY_KB["applocker"])
        r["reason"] = (
            f"{new_services} new service(s) installed (EID 7045). "
            "AppLocker prevents unauthorised executables from running as services."
        )
        recs.append(r)

    # Privilege escalation — triggers least privilege recommendation
    priv_events = signals.get("priv_escalation_events", 0)
    if priv_events > 50:
        r = dict(POLICY_KB["least_privilege"])
        r["priority"] = "HIGH"
        r["reason"] = (
            f"{priv_events} privilege escalation events (EID 4672/4673) detected. "
            "High frequency suggests too many accounts with admin rights."
        )
        recs.append(r)

    # Firewall changes — triggers firewall hardening
    fw_changes = signals.get("firewall_rule_changes", 0)
    if fw_changes > 0:
        r = dict(POLICY_KB["firewall"])
        r["reason"] = (
            f"{fw_changes} firewall rule change(s) (EID 4946/4947/4950) detected. "
            "Audit and harden all firewall rules to prevent backdoor access."
        )
        recs.append(r)

    # Always include password policy and credential guard as baseline
    r = dict(POLICY_KB["password_policy"])
    r["reason"] = "Strong password policy is a baseline requirement for all Windows environments."
    r["priority"] = "MEDIUM"
    recs.append(r)

    r = dict(POLICY_KB["credential_guard"])
    r["reason"] = (
        "Credential Guard prevents LSASS memory dumping attacks (Mimikatz). "
        "Recommended on all Windows 10/11 Enterprise and Server 2016+ systems."
    )
    recs.append(r)

    # Sort by priority
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs.sort(key=lambda x: _order.get(x.get("priority", "LOW"), 9))

    # Build summary
    critical_count = sum(1 for r in recs if r.get("priority") == "CRITICAL")
    high_count     = sum(1 for r in recs if r.get("priority") == "HIGH")
    summary_parts  = []
    if critical_count:
        summary_parts.append(f"{critical_count} CRITICAL policy gap(s) require immediate action")
    if high_count:
        summary_parts.append(f"{high_count} HIGH priority improvement(s) recommended")
    if failed_logons > 50:
        summary_parts.append(f"the {failed_logons} failed logon attempts suggest an active credential attack")
    if not summary_parts:
        summary = "No critical policy gaps detected from current log data. Review the recommended improvements to maintain a strong security baseline."
    else:
        summary = (
            "Based on live log analysis: "
            + ", ".join(summary_parts)
            + ". Prioritise account lockout and MFA policies first."
        )

    return {"recommendations": recs, "summary": summary}


# ── General conversation patterns ─────────────────────────────────────────────
PATTERNS = [
    (r"event.?id[:\s]+(\d{3,5})",      "_eid_lookup"),
    (r"\b(4625|brute.?force|login.*fail|failed.*logon)",
     "🔐 **Brute Force / Failed Logon**\n\n`Event ID 4625` indicates failed authentication.\n\n**Actions:**\n- Enable Account Lockout Policy\n- Check source IP in event details\n- Review `Event ID 4740` for locked accounts\n- Look for patterns: same account, many IPs = spray attack"),
    (r"kernel.power|event.?id.?41|unexpected.*shut|6008",
     "⚡ **Unexpected Shutdown (Event ID 41)**\n\nSystem was not cleanly shut down — power loss, BSOD, or overheating.\n\n**Actions:**\n1. Check `C:\\Windows\\Minidump` for crash dumps\n2. Run `sfc /scannow` in admin CMD\n3. Check Event Viewer → System → `Event ID 6008`\n4. Monitor temps with HWMonitor"),
    (r"\bdisk\b|ntfs|bad.?sector|chkdsk|i/o.*error",
     "💾 **Disk Error Detected**\n\nDisk hardware issues risk data loss.\n\n**Actions:**\n1. `chkdsk C: /f /r` (requires restart)\n2. `wmic diskdrive get status` — check S.M.A.R.T.\n3. Consider backup immediately\n4. Event ID 7 (disk) in System log = hardware failure"),
    (r"memory|whea|bad.?pool|pool.?corrupt",
     "🧠 **Memory/Hardware Error**\n\nRAM or hardware issue causing instability.\n\n**Actions:**\n1. Run `mdsched.exe` (Windows Memory Diagnostic)\n2. Check for `Event ID 1001` (BugCheck) in System log\n3. Test RAM sticks one at a time\n4. Update BIOS firmware"),
    (r"service.*fail|7034|7035",
     "⚙️ **Service Crash (Event ID 7034)**\n\nA Windows service terminated unexpectedly.\n\n**Actions:**\n1. `services.msc` → find the service → set Recovery to auto-restart\n2. Check Application log for corresponding `Event ID 1000`\n3. `Event ID 7045` = new service installed — verify it's legitimate"),
    (r"health|status|overview|summary|how is",
     "_health_report"),

    # ── FR05-05: Policy improvement patterns ──────────────────────────────────
    (r"policy|policies|improve.*security|security.*improve|hardening|harden|recommendations?",
     "_policy_overview"),
    (r"lockout|lock.?out.?policy|account.?policy|password.?policy|brute.?force.?prevent",
     "_policy_account"),
    (r"mfa|multi.?factor|two.?factor|2fa|authenticat",
     "_policy_mfa"),
    (r"audit.?policy|audit.?log|event.*logging|logging.?policy",
     "_policy_audit"),
    (r"defender.*policy|defender.*setting|antivirus.*policy|av.?policy|tamper.?protect",
     "_policy_defender"),
    (r"powershell.*policy|ps.*execut|script.*policy|execution.?policy|applocker|whitelist",
     "_policy_powershell"),
    (r"firewall.*policy|firewall.*rule|firewall.*hardening|wf.msc",
     "_policy_firewall"),
    (r"update.*policy|patch.*policy|windows.*update.*setting|wsus",
     "_policy_update"),
    (r"least.*privilege|admin.*rights|uac.*policy|privilege.*policy|credential.?guard",
     "_policy_privilege"),

    (r"hello|hi\b|hey\b|help\b|what can",
     "👋 **LogVault AI — Offline Mode**\n\nI'm running without an internet connection but can still help with:\n\n- 🔍 **Event ID lookup** — *\"What is Event ID 4625?\"*\n- 💾 **Error diagnosis** — *\"Any disk errors?\"*\n- 🔒 **Security events** — *\"Explain failed logons\"*\n- 🏥 **Health report** — *\"System health report\"*\n- 🛠️ **Fixes** — *\"How to fix service crash?\"*\n- 🔐 **Security policies** — *\"Improve security policies\"*\n\n---\n*💡 For full AI: set `GROQ_API_KEY` (free at console.groq.com)*"),
]


# ── Offline response handlers ──────────────────────────────────────────────────

def _eid_lookup(msg: str, _ctx: dict) -> str:
    m = re.search(r"(\d{3,5})", msg)
    if not m:
        return "Please include the Event ID number, e.g. *\"What is Event ID 4625?\"*"
    eid = int(m.group(1))
    if eid in EVENT_IDS:
        sev, desc = EVENT_IDS[eid]
        return f"📋 **Event ID {eid}** — Severity: `{sev}`\n\n{desc}\n\n---\n*🔌 Offline mode*"
    return f"📋 Event ID **{eid}** is not in my offline database.\n\n*Connect Groq API for full lookup.*"


def _health_report(msg: str, ctx: dict) -> str:
    stats = ctx.get("stats", {})
    if not stats:
        return ("📊 **System Health Report**\n\nNo logs loaded yet.\n\n"
                "Click **🪟 Fetch Real Windows Logs** first.\n\n---\n*🔌 Offline mode*")

    lines = ["## 🏥 System Health Report\n"]
    total_errors = 0
    for cat, data in stats.items():
        if not isinstance(data, dict):
            continue
        e = data.get("errors", 0)
        w = data.get("warnings", 0)
        t = data.get("total", 0)
        total_errors += e
        icon = "🔴" if e > 50 else "🟠" if e > 10 else "🟡" if e > 0 else "🟢"
        lines.append(f"{icon} **{cat.title()}**: {t} events | {e} errors | {w} warnings")

    score = max(0, 100 - total_errors * 2)
    grade = "Excellent" if score > 85 else "Good" if score > 70 else "Fair" if score > 50 else "Poor"
    lines.insert(1, f"**Score: {score}/100 — {grade}**\n")
    lines.append("\n---\n*🔌 Offline mode — Groq API gives deeper AI recommendations*")
    return "\n".join(lines)


def _format_policy_rec(kb_key: str) -> str:
    """Format a single POLICY_KB entry as a readable offline response."""
    rec = POLICY_KB.get(kb_key, {})
    if not rec:
        return "Policy information not available offline."
    lines = [
        f"🔐 **{rec['title']}**",
        f"Priority: `{rec['priority']}` | Effort: `{rec.get('effort', '?')}`",
        f"MITRE: `{rec.get('mitre', 'N/A')}`\n",
        "**Configuration steps:**",
    ]
    for i, step in enumerate(rec.get("steps", []), 1):
        lines.append(f"{i}. {step}")
    lines.append(f"\n**GPO Path:** `{rec.get('gpo_path', 'N/A')}`")
    cmd = rec.get("command", "N/A")
    if cmd and cmd != "N/A":
        lines.append(f"\n**Quick command:**\n```\n{cmd}\n```")
    lines.append("\n---\n*🔌 Offline mode — Groq API provides data-driven recommendations*")
    return "\n".join(lines)


def _policy_overview(msg: str, ctx: dict) -> str:
    signals = ctx.get("policy_signals", {})
    result  = offline_policy_recommendations(signals)
    recs    = result.get("recommendations", [])
    summary = result.get("summary", "")

    lines = ["## 🔐 Windows Security Policy Recommendations\n", summary, ""]
    critical = [r for r in recs if r.get("priority") == "CRITICAL"]
    high     = [r for r in recs if r.get("priority") == "HIGH"]

    if critical:
        lines.append("### 🔴 Critical — Act Immediately")
        for r in critical:
            lines.append(f"- **{r['title']}**: {r.get('reason', '')}")
        lines.append("")
    if high:
        lines.append("### 🟠 High Priority")
        for r in high[:4]:
            lines.append(f"- **{r['title']}**: {r.get('reason', '')}")
        lines.append("")

    lines.append("Ask me about a specific area: *\"account lockout policy\"*, *\"MFA policy\"*, *\"audit policy\"*, *\"Defender policy\"*, *\"PowerShell policy\"*, *\"firewall policy\"*")
    lines.append("\n---\n*🔌 Offline mode — Groq API provides full structured JSON recommendations*")
    return "\n".join(lines)


def _policy_account(msg: str, ctx: dict) -> str:
    return _format_policy_rec("account_lockout") + "\n\n" + "**Also consider:** " + POLICY_KB["password_policy"]["title"] + "\n" + " → " + POLICY_KB["password_policy"]["gpo_path"]


def _policy_mfa(msg: str, ctx: dict) -> str:
    return _format_policy_rec("mfa")


def _policy_audit(msg: str, ctx: dict) -> str:
    return _format_policy_rec("audit_policy")


def _policy_defender(msg: str, ctx: dict) -> str:
    return _format_policy_rec("defender")


def _policy_powershell(msg: str, ctx: dict) -> str:
    return _format_policy_rec("powershell") + "\n\n**Also consider:** " + POLICY_KB["applocker"]["title"] + " — blocks execution from Temp/AppData."


def _policy_firewall(msg: str, ctx: dict) -> str:
    return _format_policy_rec("firewall")


def _policy_update(msg: str, ctx: dict) -> str:
    return _format_policy_rec("windows_update")


def _policy_privilege(msg: str, ctx: dict) -> str:
    return _format_policy_rec("least_privilege") + "\n\n**Also consider:** " + POLICY_KB["credential_guard"]["title"] + " to protect LSASS from credential dumping."


# Map pattern dispatch strings to handler functions
_POLICY_HANDLERS = {
    "_policy_overview":    _policy_overview,
    "_policy_account":     _policy_account,
    "_policy_mfa":         _policy_mfa,
    "_policy_audit":       _policy_audit,
    "_policy_defender":    _policy_defender,
    "_policy_powershell":  _policy_powershell,
    "_policy_firewall":    _policy_firewall,
    "_policy_update":      _policy_update,
    "_policy_privilege":   _policy_privilege,
}


def match_offline(msg: str, ctx: dict) -> str:
    """Main dispatcher for offline responses."""
    low = msg.lower()
    for pattern, response in PATTERNS:
        if re.search(pattern, low, re.I):
            if response == "_eid_lookup":
                return _eid_lookup(msg, ctx)
            if response == "_health_report":
                return _health_report(msg, ctx)
            if response in _POLICY_HANDLERS:
                return _POLICY_HANDLERS[response](msg, ctx)
            return response + "\n\n---\n*🔌 Offline mode — connect Groq for deeper AI analysis*"

    return (
        "🔌 **Offline Mode**\n\nCouldn't match your query to a known pattern.\n\n"
        "Try: *\"health report\"*, *\"Event ID 41\"*, *\"disk errors\"*, *\"failed logon\"*, *\"security policies\"*\n\n"
        "**For full AI:** get a free key at [console.groq.com](https://console.groq.com) and enter it in ⚙ Settings."
    )
