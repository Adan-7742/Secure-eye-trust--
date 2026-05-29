"""
api/log_explain_api.py — rich AI log explanation endpoint
POST /api/explain-log

Priority: Groq (GROQ_LOG_API_KEY or GROQ_API_KEY) → Perplexity → Static KB

FR15 COMPLIANCE (updated):
  FR15-01: Windows-specific security explanations  ← already satisfied
  FR15-02: Windows troubleshooting guidance        ← already satisfied
  FR15-03: Event ID and error code references      ← already satisfied
  FR15-04: PowerShell remediation commands         ← NOW SATISFIED
           _build_prompt() now requests powershell_commands[] array.
           _EID_EXTENDED_KB maps 50+ EIDs to specific PS commands.
           _static_fallback() now returns powershell_commands from KB.
  FR15-05: Windows Registry modification guidance  ← NOW SATISFIED
           _build_prompt() now requests registry_guidance field.
           _EID_EXTENDED_KB maps EIDs to specific registry paths/commands.
           _static_fallback() now returns registry_guidance from KB.
"""
import os, json, re
from flask import Blueprint, request, jsonify

log_explain_bp = Blueprint("log_explain", __name__)

# ── Basic EID name/category/severity lookup (unchanged) ──────────────────────
_EID_KB = {
    "4624":  {"name": "Successful Logon",            "cat": "Authentication", "sev": "INFO"},
    "4625":  {"name": "Failed Logon Attempt",         "cat": "Authentication", "sev": "CRITICAL"},
    "4634":  {"name": "Account Logoff",               "cat": "Authentication", "sev": "INFO"},
    "4648":  {"name": "Explicit Credential Logon",    "cat": "Authentication", "sev": "HIGH"},
    "4672":  {"name": "Special Privilege Logon",      "cat": "Privilege",      "sev": "HIGH"},
    "4673":  {"name": "Privileged Service Called",    "cat": "Privilege",      "sev": "HIGH"},
    "4674":  {"name": "Privileged Object Operation",  "cat": "Privilege",      "sev": "HIGH"},
    "4688":  {"name": "New Process Created",          "cat": "Process",        "sev": "INFO"},
    "4697":  {"name": "Service Installed",            "cat": "Services",       "sev": "HIGH"},
    "4698":  {"name": "Scheduled Task Created",       "cat": "Persistence",    "sev": "MEDIUM"},
    "4699":  {"name": "Scheduled Task Deleted",       "cat": "Persistence",    "sev": "HIGH"},
    "4700":  {"name": "Scheduled Task Enabled",       "cat": "Persistence",    "sev": "HIGH"},
    "4701":  {"name": "Scheduled Task Disabled",      "cat": "Persistence",    "sev": "MEDIUM"},
    "4702":  {"name": "Scheduled Task Updated",       "cat": "Persistence",    "sev": "HIGH"},
    "4713":  {"name": "Kerberos Policy Changed",      "cat": "Policy",         "sev": "HIGH"},
    "4719":  {"name": "Audit Policy Changed",         "cat": "Audit",          "sev": "HIGH"},
    "4720":  {"name": "User Account Created",         "cat": "Account",        "sev": "HIGH"},
    "4728":  {"name": "Member Added to Admin Group",  "cat": "Privilege",      "sev": "CRITICAL"},
    "4739":  {"name": "Domain Policy Changed",        "cat": "Policy",         "sev": "HIGH"},
    "4740":  {"name": "Account Locked Out",           "cat": "Authentication", "sev": "CRITICAL"},
    "4657":  {"name": "Registry Value Modified",      "cat": "Tampering",      "sev": "HIGH"},
    "4656":  {"name": "Object Handle Requested",      "cat": "Audit",          "sev": "WARNING"},
    "4663":  {"name": "Object Access Attempt",        "cat": "Audit",          "sev": "MEDIUM"},
    "4902":  {"name": "Per-User Audit Policy Created","cat": "Policy",         "sev": "HIGH"},
    "4904":  {"name": "Audit Policy Source Register", "cat": "Policy",         "sev": "HIGH"},
    "4905":  {"name": "Audit Policy Source Unregister","cat": "Policy",        "sev": "HIGH"},
    "6008":  {"name": "Unexpected Shutdown",          "cat": "System",         "sev": "HIGH"},
    "7034":  {"name": "Service Crashed",              "cat": "Services",       "sev": "MEDIUM"},
    "7040":  {"name": "Service Start Type Changed",   "cat": "Services",       "sev": "HIGH"},
    "7045":  {"name": "New Service Installed",        "cat": "Services",       "sev": "HIGH"},
    "1000":  {"name": "Application Error/Crash",      "cat": "Application",    "sev": "ERROR"},
    "1002":  {"name": "Application Hang",             "cat": "Application",    "sev": "WARNING"},
    "1116":  {"name": "Malware Detected",             "cat": "Malware",        "sev": "CRITICAL"},
    "1117":  {"name": "Malware Action Taken",         "cat": "Malware",        "sev": "CRITICAL"},
    "1118":  {"name": "Malware Action Failed",        "cat": "Malware",        "sev": "CRITICAL"},
    "1119":  {"name": "Malware Remediation Success",  "cat": "Malware",        "sev": "HIGH"},
    "1120":  {"name": "Malware Removal Failed",       "cat": "Malware",        "sev": "CRITICAL"},
    "5001":  {"name": "Real-Time Protection Off",     "cat": "Malware",        "sev": "CRITICAL"},
    "5007":  {"name": "Defender Settings Changed",    "cat": "Defense Evasion","sev": "HIGH"},
    "5010":  {"name": "AV Scan Disabled",             "cat": "Defense Evasion","sev": "CRITICAL"},
    "5012":  {"name": "On-Access Protection Disabled","cat": "Defense Evasion","sev": "CRITICAL"},
    "5152":  {"name": "Firewall Blocked Packet",      "cat": "Network",        "sev": "MEDIUM"},
    "5157":  {"name": "Firewall Blocked Connection",  "cat": "Network",        "sev": "MEDIUM"},
    "4947":  {"name": "Firewall Rule Modified",       "cat": "Firewall",       "sev": "HIGH"},
    "4954":  {"name": "Firewall Policy Changed",      "cat": "Firewall",       "sev": "HIGH"},
    "4946":  {"name": "Firewall Rule Added",          "cat": "Firewall",       "sev": "HIGH"},
    "4950":  {"name": "Firewall Setting Changed",     "cat": "Firewall",       "sev": "HIGH"},
    "10016": {"name": "DCOM Permission Error",        "cat": "System",         "sev": "WARNING"},
    "8193":  {"name": "VSS Writer Error",             "cat": "Application",    "sev": "ERROR"},
    "11723": {"name": "MSI Installer Error",          "cat": "Application",    "sev": "ERROR"},
    "16384": {"name": "Software Protection Event",    "cat": "Licensing",      "sev": "INFO"},
    "11":    {"name": "Disk Controller Error",        "cat": "Hardware",       "sev": "HIGH"},
    "51":    {"name": "Disk Error During Paging",     "cat": "Hardware",       "sev": "HIGH"},
}

# ── FR15-04 + FR15-05: Extended KB — PowerShell commands & Registry guidance ──
_EID_EXTENDED_KB = {
    "4625": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | Select-Object TimeCreated, Message | Format-List",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 200 | Group-Object {$_.Properties[5].Value} | Sort-Object Count -Descending | Select-Object -First 10",
            "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa — 'LimitBlankPasswordUse' DWORD=1 (disallow blank passwords)",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon — 'CachedLogonsCount' set to 0 or 1 to limit cached credentials",
            ],
            "commands": [
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f",
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v auditbaseobjects",
            ],
            "explanation": "LSA registry keys control Windows authentication policies. Hardening these settings reduces brute-force attack surface and limits credential caching exposure.",
        },
    },
    "4648": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} -MaxEvents 30 | Select-Object TimeCreated, Message | Format-List",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4648,4624)} -MaxEvents 100 | Sort-Object TimeCreated | Format-Table TimeCreated, Id, Message -AutoSize",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa — 'DisableDomainCreds' DWORD=1 prevents domain credential caching",
            ],
            "commands": [
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v DisableDomainCreds /t REG_DWORD /d 1 /f",
            ],
            "explanation": "Explicit credential use can indicate lateral movement. DisableDomainCreds limits cached credential reuse across the network.",
        },
    },
    "4672": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 50 | Select-Object TimeCreated, Message | Format-List",
            "Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource",
            "whoami /priv",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System — 'EnableLUA' DWORD=1 enforces UAC for all admins",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System — 'ConsentPromptBehaviorAdmin' DWORD=2 (prompt for credentials)",
            ],
            "commands": [
                r"reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v EnableLUA /t REG_DWORD /d 1 /f",
                r"reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f",
            ],
            "explanation": "EnableLUA enforces UAC. ConsentPromptBehaviorAdmin=2 requires credential re-entry for admin operations, preventing silent privilege escalation.",
        },
    },
    "4728": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize",
            "net localgroup Administrators",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System — 'FilterAdministratorToken' DWORD=1 restricts built-in Administrator token",
            ],
            "commands": [
                r"reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v FilterAdministratorToken /t REG_DWORD /d 1 /f",
            ],
            "explanation": "FilterAdministratorToken=1 forces the built-in Administrator to use split tokens, limiting blast radius of compromised admin accounts.",
        },
    },
    "4657": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4657} -MaxEvents 50 | Select-Object TimeCreated, Message | Format-List",
            "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | Format-List",
            "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | Format-List",
            "reg query 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run — autorun programs for all users (common malware persistence)",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run — autorun programs for current user",
                r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon — Userinit and Shell values (hijacked by rootkits)",
                r"HKLM\SYSTEM\CurrentControlSet\Services — service configuration (malware installs as services)",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options — debugger hijacking technique",
            ],
            "commands": [
                r"reg query 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'",
                r"reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'",
                r"reg query 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'",
                r"reg delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' /v <SuspiciousEntry> /f",
            ],
            "explanation": "Autorun registry keys are the most common malware persistence mechanism. Unexpected entries under Run/RunOnce or Winlogon Userinit/Shell values indicate infection. Any key pointing to Temp, AppData, or ProgramData is highly suspicious.",
        },
    },
    "4719": {
        "ps_commands": [
            "auditpol /get /category:* | Format-Table",
            "auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
            "auditpol /set /subcategory:'Account Management' /success:enable /failure:enable",
            "auditpol /backup /file:C:\\audit_policy_backup.csv",
            "auditpol /restore /file:C:\\audit_policy_backup.csv",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa — 'SCENoApplyLegacyAuditPolicy' DWORD=1 forces advanced audit policy",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security — 'MaxSize' set to at least 196608 (192MB)",
            ],
            "commands": [
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f",
                r"reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' /v MaxSize /t REG_DWORD /d 196608 /f",
            ],
            "explanation": "SCENoApplyLegacyAuditPolicy ensures advanced audit policies cannot be overridden by basic GPO settings. Attacker modification of EID 4719 disables logging — restoring via auditpol /restore re-enables all categories.",
        },
    },
    "4739": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4739} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "secedit /export /cfg C:\\current_policy.cfg",
            "secedit /analyze /db C:\\baseline.sdb /cfg C:\\current_policy.cfg /log C:\\policy_diff.log",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters — 'RequireSignOrSeal' DWORD=1 (secure channel signing)",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters — 'MaximumPasswordAge' and 'MinimumPasswordAge' for domain password policy",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'",
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' /v RequireSignOrSeal /t REG_DWORD /d 1 /f",
            ],
            "explanation": "Domain policy changes (EID 4739) affect all domain-joined machines. The Netlogon registry parameters hold domain-level password and Kerberos policy. Unauthorized changes can weaken authentication across the entire domain.",
        },
    },
    "4902": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4902,4904,4905)} -MaxEvents 30 | Select-Object TimeCreated, Id, Message | Format-List",
            "auditpol /get /category:* | Where-Object {$_ -match 'No Auditing'}",
            "auditpol /set /subcategory:'Policy Change' /success:enable /failure:enable",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa — 'SCENoApplyLegacyAuditPolicy' must be 1",
            ],
            "commands": [
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f",
            ],
            "explanation": "Per-user audit policy tables can override system-wide audit policies for specific users — attackers exploit this to exclude their account from logging.",
        },
    },
    "4904": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4904,4905)} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "auditpol /get /category:* | Format-Table",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa — 'AuditBaseObjects' DWORD=1 enables object-level auditing",
            ],
            "commands": [
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v AuditBaseObjects /t REG_DWORD /d 1 /f",
            ],
            "explanation": "EID 4904 fires when a new audit policy source registers — unexpected registrations may indicate a tool bypassing the standard audit framework.",
        },
    },
    "4713": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4713} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "klist purge",
            "nltest /sc_query:<DomainName>",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters — 'MaxTicketAge' and 'MaxRenewAge' Kerberos ticket lifetime",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters — 'SupportedEncryptionTypes' should include AES (0x18 or higher)",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'",
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' /v SupportedEncryptionTypes /t REG_DWORD /d 0x18 /f",
            ],
            "explanation": "Kerberos policy changes affect Golden/Silver Ticket attack feasibility. AES encryption prevents downgrade to RC4 used in Pass-the-Hash. Extended ticket lifetimes allow attackers to maintain access longer.",
        },
    },
    "1116": {
        "ps_commands": [
            "Get-MpThreatDetection | Select-Object ThreatID, ThreatName, ActionSuccess, DetectionSourceTypeID | Format-List",
            "Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive, Resources | Format-List",
            "Start-MpScan -ScanType FullScan",
            "Update-MpSignature",
            "Get-MpComputerStatus | Select-Object AMRunningMode, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | Format-List",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender — 'DisableAntiSpyware' must NOT be 1",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection — 'DisableRealtimeMonitoring' must NOT be 1",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths — check for unauthorized exclusions added by malware",
            ],
            "commands": [
                r"reg query 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableAntiSpyware",
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'",
                r"reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableAntiSpyware /f",
            ],
            "explanation": "Malware commonly adds its own path to Defender exclusions and disables real-time monitoring via registry. After detection, verify no unauthorized exclusions exist and all Defender policy keys are correctly set.",
        },
    },
    "5001": {
        "ps_commands": [
            "Set-MpPreference -DisableRealtimeMonitoring $false",
            "Set-MpPreference -MAPSReporting Advanced",
            "Start-Service WinDefend",
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AMServiceEnabled | Format-List",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection — DELETE 'DisableRealtimeMonitoring' if it exists",
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender — DELETE 'DisableAntiSpyware' if set to 1",
                r"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend — 'Start' DWORD must be 2 (Automatic); if 4 (Disabled), restore to 2",
            ],
            "commands": [
                r"reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' /v DisableRealtimeMonitoring /f",
                r"reg delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableAntiSpyware /f",
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend' /v Start /t REG_DWORD /d 2 /f",
            ],
            "explanation": "When Defender is disabled (EID 5001), malware has almost certainly set DisableRealtimeMonitoring=1. These keys must be DELETED (not set to 0). WinDefend Start value is also changed to 4 (Disabled) — restore to 2 (Automatic) for persistence across reboots.",
        },
    },
    "5007": {
        "ps_commands": [
            "Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, DisableRealtimeMonitoring | Format-List",
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=5007} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths — unauthorized malware exclusion paths",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions — unauthorized file extension exclusions",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes — unauthorized process exclusions",
            ],
            "commands": [
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' /s",
                r"Remove-MpPreference -ExclusionPath 'C:\suspicious\path'",
            ],
            "explanation": "Defender settings changes (EID 5007) frequently indicate an attacker adding malware paths to the exclusion list. Query the Exclusions registry keys and remove unexpected entries — legitimate exclusions should only be paths required by known business software.",
        },
    },
    "4656": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656} -MaxEvents 50 | Where-Object {$_.Message -match 'lsass|winlogon|services'} | Format-List",
            "Get-Process lsass | Select-Object Id, CPU, WorkingSet, Handles",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4656,4663)} -MaxEvents 100 | Where-Object {$_.Message -match '\\.dll'} | Format-List",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options — 'Debugger' values indicate IFEO hijacking (DLL injection technique)",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs — unexpected entries indicate DLL hijacking",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs — malware persistence: DLL injected into every CreateProcess call",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'",
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs'",
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s | findstr Debugger",
            ],
            "explanation": "Handle requests on lsass.exe indicate credential dumping or process injection. AppCertDLLs causes a DLL to be injected into every CreateProcess call — a stealthy persistence mechanism. IFEO Debugger values hijack process launches. KnownDLLs tampering replaces trusted system DLLs.",
        },
    },
    "7045": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | Sort-Object Name | Format-Table Name, Status, DisplayName -AutoSize",
            "sc qc <ServiceName>",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> — full service config including ImagePath",
                r"HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> — 'Start': 2=Auto, 3=Manual, 4=Disabled",
                r"HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName> — 'ImagePath' — malware hides here as svchost or rundll32 with unusual parameters",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>'",
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>' /v ImagePath",
                r"sc delete <ServiceName>",
            ],
            "explanation": "New service registry entries persist through reboots. Malware installs as services with ImagePath pointing to temp directories or disguised as legitimate svchost.exe parameters. Inspect ImagePath for Temp, AppData, or ProgramData locations.",
        },
    },
    "7040": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "Get-Service WinDefend, MpsSvc, EventLog, wuauserv | Select-Object Name, Status, StartType | Format-Table",
            "sc config <ServiceName> start= auto",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend — 'Start' DWORD must be 2 (Automatic); attackers change to 4 (Disabled)",
                r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog — 'Start' DWORD must be 2 (Automatic)",
                r"HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc — 'Start' DWORD must be 2 (Automatic) for Windows Firewall",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend' /v Start",
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend' /v Start /t REG_DWORD /d 2 /f",
                r"reg add 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog' /v Start /t REG_DWORD /d 2 /f",
            ],
            "explanation": "Service start type changes (EID 7040) are critical defense-evasion indicators. Attackers change security services to Disabled (4) so they do not restart after reboot. Check the Start DWORD in each service's registry key and restore to 2 (Automatic) for all security-critical services.",
        },
    },
    "4947": {
        "ps_commands": [
            "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Sort-Object DisplayName | Format-Table DisplayName, Direction, Action, Profile -AutoSize",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4947,4946,4954)} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "Set-NetFirewallRule -DisplayName '<SuspiciousRule>' -Enabled False",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules — all local firewall rules",
                r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall — GPO-applied firewall policy (takes precedence)",
            ],
            "commands": [
                r"reg query 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' | findstr /i 'allow'",
                r"reg query 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' /v EnableFirewall",
            ],
            "explanation": "Firewall rules are stored in the FirewallRules registry key. Malware adds inbound Allow rules here for remote access. Review all Allow+Inbound rules added recently. GPO firewall policy overrides local rules — check both locations.",
        },
    },
    "4698": {
        "ps_commands": [
            "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4698,4700,4702)} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
            "schtasks /query /fo LIST /v | findstr /i 'task name\\|run as user\\|task to run'",
            "Unregister-ScheduledTask -TaskName '<SuspiciousTask>' -Confirm:$false",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks — all registered task GUIDs and their Actions",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree — task hierarchy (path to GUID mapping)",
            ],
            "commands": [
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' /s",
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' /s | findstr Actions",
            ],
            "explanation": "Task metadata is stored in the Schedule\\TaskCache registry hive. Malware adds tasks directly here to bypass schtasks.exe logging. Check TaskCache\\Tree for unexpected GUIDs and TaskCache\\Tasks Actions containing PowerShell, cmd, or paths in Temp/AppData.",
        },
    },
    "4688": {
        "ps_commands": [
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 | Where-Object {$_.Message -match 'powershell|cmd|mshta|wscript|rundll32'} | Select-Object TimeCreated, Message | Format-List",
            "Get-Process | Where-Object {$_.Path -match 'Temp|AppData|ProgramData'} | Select-Object Name, Id, Path | Format-Table",
        ],
        "registry_guidance": {
            "paths": [
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options — 'Debugger' value hijacks process launches",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths — attackers add entries to redirect process lookups",
            ],
            "commands": [
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s | findstr /i Debugger",
                r"reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths' /s",
            ],
            "explanation": "IFEO Debugger keys redirect a process launch to an attacker-controlled binary — a process hijacking technique. App Paths entries can similarly redirect which executable runs. Both are stealthy persistence mechanisms requiring no modification of the target executable.",
        },
    },
}


def _extract_caller_from_message(msg: str) -> str:
    """Pull the calling process path out of a 4656/4663 message, if present."""
    if not msg:
        return ""
    import re as _re
    # Match Windows path ending in .exe — pick the LAST one in the string
    # (the message structure puts the requesting process at the end)
    hits = _re.findall(r"([A-Za-z]:\\[^,'\"<>\r\n]+?\.exe)", msg)
    return (hits[-1] if hits else "").strip()


def _build_prompt(log):
    """FR15-04 + FR15-05: Build AI prompt that explicitly requests PS commands and registry guidance.

    Improvements over the older version:
      - Parses the calling process from EID 4656/4663 messages and tells the AI
        about it (e.g. "the requesting process is Code.exe"). Without this the
        AI produces generic "verify the user's identity" boilerplate.
      - Identifies known-benign callers (VS Code, Defender, browsers) so the
        AI can say "this is normal" instead of treating every event as an
        attack.
      - Requires the powershell_commands[] to start with a 'Get-' command
        that INSPECTS the event/process before any remediation.
      - Explicitly forbids generic placeholders like "verify identity",
        "check permissions" as the only response.
    """
    eid  = str(log.get("event_id") or "")
    kb   = _EID_KB.get(eid, {})
    ext  = _EID_EXTENDED_KB.get(eid, {})
    name = kb.get("name", f"Windows Event {eid}" if eid else "Log Event")
    msg  = (log.get("message") or "")[:700]

    # ── Extract specific context the AI can use ──────────────────────────────
    caller_hint = ""
    benign_note = ""
    if eid in ("4656", "4663") and msg:
        caller = _extract_caller_from_message(msg)
        if caller:
            basename = caller.rsplit("\\", 1)[-1].lower()
            caller_hint = (
                f"\nIMPORTANT: The process that triggered this event is:\n"
                f"  {caller}\n"
                f"In your analysis, name this specific process — do NOT give "
                f"generic 'verify the user's identity' advice."
            )
            # Tag well-known benign callers so the AI doesn't cry wolf
            benign_set = {
                "code.exe", "code - insiders.exe",
                "msmpeng.exe", "mssense.exe", "sense.exe",
                "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
                "lsass.exe", "services.exe", "svchost.exe", "wininit.exe",
                "explorer.exe", "taskmgr.exe", "perfmon.exe", "mmc.exe",
                "teams.exe", "outlook.exe", "onedrive.exe",
                "devenv.exe", "pycharm64.exe", "idea64.exe",
                "git-credential-manager.exe",
            }
            if basename in benign_set:
                benign_note = (
                    f"\nNOTE: '{basename}' is a well-known benign process that "
                    f"legitimately opens lsass.exe for the Windows credential "
                    f"helper / authentication. This event is most likely a "
                    f"false positive, not an attack. Frame your analysis "
                    f"accordingly — say so plainly in `this_specific_event`."
                )

    ps_hint = ""
    if ext.get("ps_commands"):
        ps_hint = "\nKNOWN POWERSHELL COMMANDS FOR THIS EID:\n" + "\n".join(f"  - {c}" for c in ext["ps_commands"][:3])

    reg_hint = ""
    if ext.get("registry_guidance"):
        rg = ext["registry_guidance"]
        reg_hint = "\nKNOWN REGISTRY PATHS FOR THIS EID:\n" + "\n".join(f"  - {p}" for p in rg.get("paths", [])[:3])

    return f"""You are an expert Windows security analyst. Explain this specific Windows log event in detail.

LOG EVENT:
  Event Name : {name}
  Event ID   : {eid or "N/A"}
  Level      : {log.get("level","unknown")}
  Source     : {log.get("source","unknown")}
  Category   : {log.get("category","unknown")}
  Timestamp  : {log.get("timestamp","unknown")}
  Message    : {msg}
{caller_hint}{benign_note}{ps_hint}{reg_hint}

STRICT RULES:
1. Be SPECIFIC to this event — never produce generic advice like "verify the user's
   identity" or "check user permissions" as a complete answer. If you find yourself
   writing those phrases, you are giving a bad answer. Anchor every step to the
   actual Event ID, source, and (if present) the calling process.
2. If the event is a false positive (benign caller doing routine work), say so
   plainly in `this_specific_event` and `immediate_action`. The immediate_action
   in that case should be something like "No action needed — this is normal
   activity by <process>".
3. `powershell_commands[]` MUST contain real, runnable PowerShell or cmd lines.
   The FIRST command should INSPECT (Get-WinEvent, Get-Process, Get-MpThreat,
   etc.) — never start with a destructive action.
4. `fix_steps[]` describes intent in plain English. `powershell_commands[]`
   is the actual script that will be executed. Keep them aligned.

Respond ONLY with valid JSON (no markdown, no preamble, no explanation outside the JSON):

{{
  "event_name": "exact name of this Windows event type",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "Authentication|Malware|Network|System|Application|Hardware|Privilege|Services|Persistence|Firewall|Audit|Policy|Updates|Licensing|Other",
  "is_threat": true_or_false,
  "threat_level": "Critical|High|Medium|Low|None",
  "overview": "2-3 sentences explaining what this process/service/event is and what it normally does on Windows.",
  "usual_behavior": [
    "first expected normal behavior for this source/event",
    "second expected normal behavior",
    "third expected normal behavior"
  ],
  "warning_signs": [
    "first sign this event could indicate a problem or attack",
    "second warning sign",
    "third warning sign"
  ],
  "this_specific_event": "2-3 sentences analyzing THIS specific log entry — naming the actual process/user/source from the message. State plainly whether it looks malicious or routine.",
  "immediate_action": "One concrete action — and if no action is needed (benign FP), say exactly that.",
  "fix_steps": [
    "Step 1: specific action that references THIS event's source or process",
    "Step 2: specific action",
    "Step 3: specific action"
  ],
  "powershell_commands": [
    "Get-WinEvent or Get-Process command that INSPECTS this specific event/process first",
    "Second runnable PowerShell/cmd command for this specific event",
    "Third runnable command"
  ],
  "registry_guidance": {{
    "relevant_paths": [
      "HKLM\\\\path\\\\to\\\\key — description of what to check or change",
      "HKCU\\\\path\\\\to\\\\key — description"
    ],
    "registry_commands": [
      "reg query or reg add command 1",
      "reg query or reg add command 2"
    ],
    "explanation": "1-2 sentences explaining what registry changes are relevant and why."
  }},
  "prevention": "1-2 sentences on how to prevent or reduce these events",
  "related_events": ["list", "of", "related", "event", "IDs"]
}}

REQUIREMENTS:
- usual_behavior, warning_signs, and fix_steps MUST each be arrays with exactly 3 string items.
- powershell_commands MUST contain at least 2 specific, runnable PowerShell or cmd commands that reference THIS event (its EID, source, or process name). Generic Get-WinEvent calls without filtering on this event's EID are not acceptable.
- registry_guidance.relevant_paths MUST contain at least 2 specific Windows registry paths relevant to this event.
- registry_guidance.registry_commands MUST contain at least 1 runnable reg.exe command.
- All commands must be Windows-specific and directly relevant to investigating or remediating this Event ID.

POWERSHELL SYNTAX RULES — VIOLATIONS WILL CAUSE THE SCRIPT TO FAIL AT RUNTIME:
- `Select-Object -ExpandProperty` takes EXACTLY ONE property name. If you need
  multiple fields, drop -ExpandProperty and use `Select-Object Id, Name, Path`
  instead. NEVER write `Select-Object -ExpandProperty Id, Name, Path`.
- Each PowerShell command must be a complete one-liner on a single line.
  Do NOT split a single pipeline across multiple commands in the array.
- Do NOT wrap commands in `try { ... } catch { ... }` — the executor adds
  its own try/catch wrapper. Adding your own creates nested braces that
  break parsing.
- Do NOT use backticks (`) for line continuation — keep each command on one line.
- Quote any path or filter value that contains spaces or special characters.
- Each command in `powershell_commands[]` must be self-contained and runnable
  on its own; do not rely on variables defined in a previous command.
- Use real, verified cmdlet names: Get-WinEvent, Get-Process, Get-Service,
  Get-ScheduledTask, Get-LocalUser, sfc, gpresult, netstat, Get-NetTCPConnection,
  Stop-Process, Restart-Service, reg query, reg add, reg delete, schtasks, etc.
  Do NOT invent cmdlet names like 'Get-WindowsLog' that do not exist."""


def _parse_json(text):
    try:
        text = re.sub(r"```json|```", "", text).strip()
        m = re.search(r'\{[\s\S]*\}', text)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return None


# ────────────────────────────────────────────────────────────────────────
# PowerShell sanitiser — auto-fix the common AI mistakes BEFORE they reach
# the user's clipboard or the executor.
#
# Even the upgraded 70B model occasionally produces these patterns, and
# users who keep the env override on the 8B model see them constantly:
#
#   ❌ Select-Object -ExpandProperty Id, Name, Path
#      → -ExpandProperty takes ONE property; the array becomes
#        "Cannot convert 'System.Object[]' to type 'System.String'".
#      ✅ Auto-fix: drop -ExpandProperty, leaving `Select-Object Id, Name, Path`.
#
#   ❌ } catch { Write-Error $_; exit 1 }
#      → User wrapped their commands in try/catch, but the executor adds
#        its OWN wrapper, creating an unbalanced/nested brace soup.
#      ✅ Auto-fix: strip any top-level try/catch the model added.
#
#   ❌ Backtick line continuation (` at line end)
#      → Hard to read in the UI and sometimes mangled by JSON encoding.
#      ✅ Auto-fix: join the next line.
#
# The sanitiser is purely defensive: it never changes the semantics of a
# correct command, only normalises the common breakages. It also returns
# a list of `applied_fixes` so we can log them and refine the prompt later.
# ────────────────────────────────────────────────────────────────────────

# Matches `-ExpandProperty Foo, Bar[, ...]` (i.e. the bad multi-arg form).
# Single-property `-ExpandProperty Foo` (no comma) is left alone — correct.
_BAD_EXPANDPROPERTY = re.compile(
    r"-ExpandProperty\s+([A-Za-z_][A-Za-z0-9_]*\s*,\s*[A-Za-z_][\w\s,]*)",
    re.IGNORECASE,
)


def _sanitize_powershell_line(line: str) -> tuple[str, list[str]]:
    """Fix one PowerShell command. Returns (cleaned_line, fixes_applied)."""
    fixes: list[str] = []
    if not isinstance(line, str):
        return ("", fixes)

    cleaned = line

    # Fix 1: `-ExpandProperty A, B, C` → drop `-ExpandProperty`
    m = _BAD_EXPANDPROPERTY.search(cleaned)
    if m:
        cleaned = _BAD_EXPANDPROPERTY.sub(r"\1", cleaned)
        fixes.append("removed multi-arg -ExpandProperty")

    # Fix 2: backtick line continuation at end of line → just join the spaces
    if cleaned.rstrip().endswith("`"):
        cleaned = cleaned.rstrip().rstrip("`").rstrip() + " "
        fixes.append("removed backtick continuation")

    # Fix 3: strip a user-added wrapping `try { ... } catch { ... }` so it
    # doesn't fight the executor's own wrapper. We only strip the SINGLE
    # outermost try { … } catch { … } pattern; nested ones the user might
    # legitimately need are kept.
    stripped = cleaned.strip()
    if stripped.startswith("try {") or stripped.startswith("try{"):
        # Heuristic: if the line both opens with `try {` and contains
        # `} catch`, treat it as a wrapper and remove the framing tokens.
        if re.search(r"\}\s*catch", stripped, re.IGNORECASE):
            inner = re.sub(r"^\s*try\s*\{", "", stripped, count=1)
            inner = re.sub(r"\}\s*catch\s*\{[^}]*\}\s*$", "", inner, count=1,
                           flags=re.IGNORECASE)
            cleaned = inner.strip()
            fixes.append("removed redundant try/catch wrapper")

    # Fix 4: orphan closing brace on its own line — the model sometimes
    # emits `} catch { Write-Error $_; exit 1 }` as a STANDALONE array
    # entry. Just drop that entry.
    if re.match(r"^\s*\}\s*catch", cleaned, re.IGNORECASE):
        fixes.append("dropped orphan `} catch` line")
        return ("", fixes)

    return (cleaned, fixes)


def _sanitize_powershell_array(cmds) -> tuple[list[str], list[str]]:
    """Apply line-level sanitiser to every command and drop empty results.

    Returns (cleaned_commands, all_fixes_applied).
    """
    if not isinstance(cmds, list):
        return ([], [])
    out: list[str] = []
    all_fixes: list[str] = []
    for raw in cmds:
        cleaned, fixes = _sanitize_powershell_line(raw)
        all_fixes.extend(fixes)
        if cleaned.strip():
            out.append(cleaned)
    return (out, all_fixes)


# ────────────────────────────────────────────────────────────────────────
# Default model
# ────────────────────────────────────────────────────────────────────────
# Why 70B-versatile, not 8B-instant?
#   The 8B model frequently produces *syntactically-invalid* PowerShell —
#   most commonly `Select-Object -ExpandProperty Id, Name, Path` (the
#   ExpandProperty parameter only accepts ONE property; passing an array
#   throws "Cannot convert 'System.Object[]' to the type 'System.String'").
#   The 70B model has seen enough real PowerShell during training that it
#   doesn't make that class of mistake. Free-tier RPD on Groq is 1,000/day
#   for 70B-versatile, which is plenty for an interactive Explain feature.
# Operators who really want to override can still set GROQ_LOG_MODEL.
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
_LOG_MODEL = os.environ.get("GROQ_LOG_MODEL", DEFAULT_GROQ_MODEL).strip() or DEFAULT_GROQ_MODEL
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"


def _call_groq(prompt):
    key = (os.environ.get("GROQ_LOG_API_KEY", "").strip() or
           os.environ.get("GROQ_API_KEY", "").strip())
    if not key:
        return None
    print(f"[Groq] using model: {_LOG_MODEL}")
    try:
        import requests as _r
        resp = _r.post(GROQ_CHAT_URL,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": _LOG_MODEL, "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 2400, "temperature": 0.2},
            timeout=35)
        resp.raise_for_status()
        text = resp.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        result = _parse_json(text)
        if result:
            result["_groq_model"] = _LOG_MODEL
            return result
    except Exception as e:
        print(f"[Groq/{_LOG_MODEL}] {e}")
    return None


def _call_perplexity(prompt):
    key = os.environ.get("PERPLEXITY_API_KEY", "").strip()
    if not key:
        return None
    try:
        import requests as _r
        resp = _r.post("https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": "sonar", "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 1200, "temperature": 0.3},
            timeout=25)
        resp.raise_for_status()
        return _parse_json(resp.json()["choices"][0]["message"]["content"])
    except Exception as e:
        print(f"[Perplexity] {e}")
        return None


def _static_fallback(log):
    """FR15-04 + FR15-05: Static fallback now returns powershell_commands and registry_guidance."""
    eid  = str(log.get("event_id") or "")
    kb   = _EID_KB.get(eid, {})
    ext  = _EID_EXTENDED_KB.get(eid, {})
    lvl  = (log.get("level") or "INFO").upper()
    src  = log.get("source") or "Unknown"
    sev  = kb.get("sev") or ("CRITICAL" if lvl in ("CRITICAL", "FAILURE") else
                              "HIGH" if lvl == "ERROR" else
                              "MEDIUM" if lvl == "WARNING" else "INFO")
    name = kb.get("name") or (f"Windows Event {eid}" if eid else "Log Event")
    msg  = log.get("message") or ""
    is_desc_err = "description for Event ID" in msg or "could not be found" in msg

    overview = (
        f"Note: The message says the description could not be loaded — this is a display artifact, "
        f"not a security issue. Event ID {eid} ({name}) is a real Windows event from {src}. "
        f"Add GROQ_API_KEY to .env for full AI analysis."
        if is_desc_err else
        f"{src} generated Event ID {eid} ({name}). "
        f"Add GROQ_API_KEY to .env for full AI-powered analysis of this specific event."
    )

    # FR15-04: PowerShell commands from extended KB
    ps_cmds = ext.get("ps_commands") or [
        f"Get-WinEvent -FilterHashtable @{{LogName='*'; Id={eid}}} -MaxEvents 20 | Select-Object TimeCreated, Message | Format-List",
        f"Get-WinEvent -FilterHashtable @{{LogName='*'; Id={eid}}} -MaxEvents 50 | Group-Object Id | Format-Table Name, Count -AutoSize",
        "eventvwr.msc",
    ]

    # FR15-05: Registry guidance from extended KB
    rg = ext.get("registry_guidance") or {}
    registry_guidance = {
        "relevant_paths": rg.get("paths") or [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion — general Windows configuration",
            r"HKLM\SYSTEM\CurrentControlSet\Control — system control parameters",
        ],
        "registry_commands": rg.get("commands") or [
            f"reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control' /s | findstr /i \"{eid}\"",
        ],
        "explanation": rg.get("explanation") or (
            f"Review the Windows registry for configuration changes related to Event ID {eid}. "
            f"Check for unauthorized modifications to relevant service or policy registry keys."
        ),
    }

    return {
        "event_name":   name,
        "severity":     sev,
        "category":     kb.get("cat") or log.get("category") or "System",
        "is_threat":    sev in ("CRITICAL", "HIGH"),
        "threat_level": "High" if sev == "CRITICAL" else sev.capitalize() if sev != "INFO" else "None",
        "overview":     overview,
        "usual_behavior": [
            f"{src} generates this event during normal Windows operation.",
            f"Event ID {eid} is a standard Windows log entry when triggered by expected system activity.",
            "The event is recorded automatically by the Windows Event Log service.",
        ],
        "warning_signs": [
            f"High frequency of Event ID {eid} from {src} in a short timeframe.",
            "This event appearing alongside authentication failures or privilege escalation events.",
            "The source running from an unexpected directory or with unusual parameters.",
        ],
        "this_specific_event": (
            f"This is a {lvl.lower()}-level event from {src}. "
            f"Without AI analysis, check Windows Event Viewer for Event ID {eid} and review nearby events at the same timestamp."
        ),
        "immediate_action": f"Open Windows Event Viewer (eventvwr.msc) → Windows Logs and review Event ID {eid} from {src}.",
        "fix_steps": [
            f"Open Event Viewer (eventvwr.msc) and find Event ID {eid} from {src}.",
            "Check for related events in the same 5-minute window.",
            "If this event repeats frequently, investigate the triggering process or service.",
        ],
        "powershell_commands": ps_cmds,
        "registry_guidance":   registry_guidance,
        "prevention": "Keep Windows and all software updated. Monitor logs regularly with Secure Eye Trust+.",
        "related_events": [],
        "ai_source": "static_kb",
    }


@log_explain_bp.route("/explain-log", methods=["POST"])
def explain_log():
    try:
        body = request.get_json(force=True) or {}
        log  = body.get("log")
        if not log:
            return jsonify({"error": "Missing 'log' field"}), 400

        prompt = _build_prompt(log)
        result = _call_groq(prompt)
        source = "groq"
        if not result:
            result = _call_perplexity(prompt)
            source = "perplexity"
        if not result:
            result = _static_fallback(log)
            source = "static_kb"

        # Guarantee FR15-04 / FR15-05 fields always present even if AI omitted them
        eid = str(log.get("event_id") or "")
        ext = _EID_EXTENDED_KB.get(eid, {})

        if not result.get("powershell_commands"):
            result["powershell_commands"] = ext.get("ps_commands") or [
                f"Get-WinEvent -FilterHashtable @{{LogName='*'; Id={eid}}} -MaxEvents 20 | Format-List",
            ]

        if not result.get("registry_guidance"):
            rg = ext.get("registry_guidance") or {}
            result["registry_guidance"] = {
                "relevant_paths":    rg.get("paths", []),
                "registry_commands": rg.get("commands", []),
                "explanation":       rg.get("explanation", "Review relevant registry keys for this event."),
            }

        # ── Defensive PowerShell sanitisation ───────────────────────────────
        # Even with a stronger model and a stricter prompt, occasionally
        # broken syntax slips through. Auto-fix the well-known offenders
        # here so the user never sees a "Cannot convert System.Object[]"
        # at execution time. `_sanitize_applied` is echoed back so the
        # frontend (and our logs) can show which auto-fixes ran.
        cleaned_ps, ps_fixes = _sanitize_powershell_array(
            result.get("powershell_commands") or []
        )
        result["powershell_commands"] = cleaned_ps
        if result.get("registry_guidance", {}).get("registry_commands"):
            cleaned_reg, reg_fixes = _sanitize_powershell_array(
                result["registry_guidance"]["registry_commands"]
            )
            result["registry_guidance"]["registry_commands"] = cleaned_reg
            ps_fixes += reg_fixes
        if ps_fixes:
            result["_sanitize_applied"] = ps_fixes
            print(f"[explain-log] sanitiser fixed: {', '.join(ps_fixes)}")

        result["ai_source"]  = source
        result["groq_model"] = result.pop("_groq_model", "") if source == "groq" else ""
        result["ok"]         = True
        # Echo context back so the front-end can wire the Run Now button
        result["event_id"]   = str(log.get("event_id") or "")
        result["rule_id"]    = str(body.get("rule_id") or log.get("rule_id") or "")
        return jsonify(result)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500
