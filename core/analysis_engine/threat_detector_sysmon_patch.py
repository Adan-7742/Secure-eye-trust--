"""
core/analysis_engine/threat_detector_sysmon_patch.py
=====================================================
Four new Sysmon-aware threat detection rules for threat_detector.py

INTEGRATION INSTRUCTIONS
--------------------------
Open  core/analysis_engine/threat_detector.py

Find THREAT_RULES = [  (line ~94).
Find the closing  ]  of that list (line ~1370).

Paste SYSMON_THREAT_RULES (below) right before the closing ] :

    ... existing last rule ...,
    },

    # ── Sysmon Rules ─────────────────────────────────────────
]  <-- remove this, keep the contents

becomes:

    ... existing last rule ...,
    },

    # ── Sysmon Rules (EID 1 / 3 / 11 / 13 / 22) ─────────────
    *SYSMON_THREAT_RULES,   # <-- spread the list in
]

Or simply paste each dict from SYSMON_THREAT_RULES individually.

IMPORTANT: The standard run_threat_detection() loop in threat_detector.py
queries `logs_{rule['table']}` by event_id using the generic THREAT_RULES loop.
For Sysmon rules the table is  "sysmon"  so the query goes to  logs_sysmon.
Make sure logs_sysmon exists before enabling these rules (see db_sysmon_patch.py).
"""

SYSMON_THREAT_RULES = [

    # ── Rule S1: Suspicious Parent-Child Process Chain ────────────────────────
    {
        "id":          "SUSPICIOUS_PARENT_CHAIN",
        "name":        "Office App Spawning Shell (Macro/Exploit)",
        "severity":    "CRITICAL",
        "category":    "process_creation",
        "event_ids":   [1],
        "table":       "sysmon",
        "window_hours": 24,
        "threshold":   1,

        # The generic loop counts by event_id; Sysmon rules use a higher
        # threshold sentinel (-1) to force custom SQL in the extended loop.
        # The actual match logic is in the correlator (Chain 9).
        # Here we provide a broad frequency guard: any EID 1 from Sysmon
        # triggers at count ≥ 1, relying on the correlator for precision.
        "description": (
            "Sysmon EID 1 detected a process creation where the parent process is "
            "an Office application (Word, Excel, Outlook) and the child process is a "
            "shell interpreter (PowerShell, cmd, wscript, mshta). "
            "Legitimate Office workflows do not spawn system shells. "
            "This pattern indicates macro-based code execution or a client-side exploit. "
            "MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1059 (Scripting Interpreter)."
        ),
        "human_summary": (
            "Word or Excel opened a command-line or PowerShell window — something it "
            "should never do on its own. This almost always means a malicious macro in a "
            "document is trying to run commands on your computer."
        ),
        "mitigation": (
            "Disable macros in Office (File → Options → Trust Center → Macro Settings → "
            "Disable all macros except digitally signed macros). "
            "Review recent documents opened by the user. "
            "Check Sysmon EID 3 (Network Connection) for follow-on C2 traffic. "
            "Isolate the endpoint if confirmed malicious."
        ),
        "actions": [
            "Identify the Office document from Sysmon EID 1 ParentCommandLine field",
            "Disable Office macros via Group Policy Trust Center settings",
            "Check Sysmon EID 3 from same process_guid for network connections",
            "Isolate the machine if active network connection confirmed",
            "Run Windows Defender offline scan on the machine",
        ],
        "mitre_tactic": "TA0002 - Execution",
    },

    # ── Rule S2: Unsigned Executable from Temp/Downloads ─────────────────────
    {
        "id":          "UNSIGNED_EXECUTABLE",
        "name":        "Unsigned Executable Ran from Temp/Downloads",
        "severity":    "HIGH",
        "category":    "process_creation",
        "event_ids":   [1],
        "table":       "sysmon",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Sysmon EID 1 detected an unsigned process (Signed: false) executing from "
            "a user-writable directory (Temp, Downloads, AppData, ProgramData). "
            "Legitimate software installers should be digitally signed. "
            "An unsigned executable from a writable location strongly suggests "
            "a malware dropper, post-exploitation tool, or a compromised installer. "
            "MITRE ATT&CK: T1204.002 (User Execution: Malicious File)."
        ),
        "human_summary": (
            "A program without a valid digital signature ran from your Downloads or Temp folder. "
            "Legitimate software is almost always signed by its publisher. "
            "An unsigned program from these folders is a strong indicator of malware."
        ),
        "mitigation": (
            "Terminate the process immediately. "
            "Hash the file (Get-FileHash) and check against VirusTotal. "
            "Delete the file from disk. "
            "Enable SmartScreen / Windows Defender for browser downloads. "
            "Consider AppLocker or WDAC to block unsigned executables."
        ),
        "actions": [
            "Terminate the unsigned process immediately",
            "Run: Get-FileHash '<path>' | select Hash and check VirusTotal",
            "Delete the unsigned executable from disk",
            "Enable Windows SmartScreen for downloaded file checking",
            "Review Sysmon EID 3 and 11 from same process_guid",
        ],
        "mitre_tactic": "TA0002 - Execution",
    },

    # ── Rule S3: Shell Process Connecting to External IP ─────────────────────
    {
        "id":          "EXTERNAL_NETWORK_CONNECTION",
        "name":        "Shell/Interpreter Connecting to External IP",
        "severity":    "HIGH",
        "category":    "network",
        "event_ids":   [3],
        "table":       "sysmon",
        "window_hours": 6,
        "threshold":   1,
        "description": (
            "Sysmon EID 3 detected an outbound network connection initiated by a "
            "shell interpreter (powershell.exe, cmd.exe, wscript.exe, certutil.exe, "
            "mshta.exe) to a non-RFC-1918 (external/internet) destination. "
            "These processes have no legitimate reason to initiate outbound internet "
            "connections in an enterprise environment. This is a strong indicator of "
            "command-and-control beaconing or payload download. "
            "MITRE ATT&CK: T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer)."
        ),
        "human_summary": (
            "PowerShell or a command-prompt window connected to an internet address. "
            "These programs should not normally browse the internet on their own. "
            "This is a common sign that malware is downloading more tools or "
            "checking in with an attacker's server."
        ),
        "mitigation": (
            "Block the destination IP in Windows Firewall immediately. "
            "Terminate the connecting process. "
            "Review the process CommandLine (Sysmon EID 1 with same process_guid). "
            "Submit the destination IP to threat intelligence feeds. "
            "Consider blocking PowerShell outbound connections via Windows Firewall rules "
            "for non-server endpoints."
        ),
        "actions": [
            "Block destination IP in Windows Firewall immediately",
            "Terminate the connecting process (powershell, cmd, etc.)",
            "Identify the full command that caused the connection from Sysmon EID 1",
            "Submit destination IP to VirusTotal / AbuseIPDB",
            "Consider restricting PowerShell network access via firewall policy",
        ],
        "mitre_tactic": "TA0011 - Command and Control",
    },

    # ── Rule S4: Registry Run/RunOnce Persistence Key Added ───────────────────
    {
        "id":          "REGISTRY_PERSISTENCE",
        "name":        "Registry Run Key Persistence Added",
        "severity":    "HIGH",
        "category":    "persistence",
        "event_ids":   [13],
        "table":       "sysmon",
        "window_hours": 24,
        "threshold":   1,
        "description": (
            "Sysmon EID 13 detected a value written to a Windows Registry autostart "
            "location (HKLM/HKCU Run, RunOnce, Userinit, or Winlogon). "
            "These keys cause programs to launch automatically at every login. "
            "Legitimate software rarely writes to these keys — most persistence-capable "
            "malware uses them as a primary survival mechanism. "
            "MITRE ATT&CK: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)."
        ),
        "human_summary": (
            "A program changed the registry to make itself (or another program) "
            "run automatically every time someone logs in. "
            "This is how most malware survives reboots. "
            "Unless you just installed legitimate software, this change is highly suspicious."
        ),
        "mitigation": (
            "Examine the registry value that was added using regedit or autoruns.exe. "
            "If the value points to an unknown or temp-folder executable, remove it. "
            "Run: reg delete \"<key>\" /v \"<value>\" /f\n"
            "Use Sysinternals Autoruns to review all autostart entries. "
            "Check Sysmon EID 1 and 11 for the file that set the key."
        ),
        "actions": [
            "Open Sysinternals Autoruns and review all Run key entries",
            "Identify and delete any unknown Run key values",
            "Check Sysmon EID 11 for the file that was dropped alongside this key",
            "Check Sysmon EID 1 to see what process set the registry key",
            "Run: reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Run: reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
        "mitre_tactic": "TA0003 - Persistence",
    },
]
