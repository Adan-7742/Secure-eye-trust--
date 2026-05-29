"""
core/analysis_engine/correlator_sysmon_patch.py
================================================
Two new Sysmon-aware attack chain correlation rules for correlator.py

INTEGRATION INSTRUCTIONS
--------------------------
Open  core/analysis_engine/correlator.py.

Find the line:
    if close_conn:
        conn.close()

Paste _CHAIN_9_OFFICE_MACRO_NETWORK() and _CHAIN_10_DOWNLOADED_EXE_REGISTRY()
calls immediately BEFORE that line, inside run_correlation().

Then add these two helper functions to the module (outside run_correlation).

The complete insertion looks like this inside run_correlation():

    # ── Chain 9: Office Macro → Network (Sysmon) ─────────────────────────
    try:
        _chain_office_macro_network(c, alerts)
    except Exception:
        pass

    # ── Chain 10: Downloaded EXE → Registry Persistence (Sysmon) ─────────
    try:
        _chain_downloaded_exe_registry(c, alerts)
    except Exception:
        pass

    if close_conn:
        conn.close()
    ...

Copy the two functions below into correlator.py as module-level functions.
"""

# ── Helper: safe timestamp comparison ─────────────────────────────────────────

def _ts_after(ts_a: str, ts_b: str) -> bool:
    """
    Return True if ts_a > ts_b (both ISO-like strings, first 19 chars used).
    Gracefully handles empty/None.
    """
    if not ts_a or not ts_b:
        return False
    try:
        return ts_a[:19] > ts_b[:19]
    except Exception:
        return False


# ── Helper: private IP check ──────────────────────────────────────────────────

import re as _re

_PRIVATE_RE = _re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|fd)"
)

def _is_external(ip: str) -> bool:
    if not ip:
        return False
    return not bool(_PRIVATE_RE.match(ip))


# ── Chain 9: Office Macro → PowerShell → Network ──────────────────────────────

def _chain_office_macro_network(c, alerts: list) -> None:
    """
    Chain 9: OFFICE_MACRO_NETWORK  (risk 90)

    Stage 1: Office app (WINWORD/EXCEL/etc.) spawns powershell.exe or cmd.exe
             Detected via Sysmon EID 1 — parent_image contains Office app,
             message/command_line contains shell process name.

    Stage 2: That shell process makes an outbound network connection
             Detected via Sysmon EID 3 — dest_ip is external, timestamp
             is AFTER the process creation timestamp.

    Temporal ordering enforced: network connection ts > process creation ts.

    Confidence:
        base  0.60
        +0.10 if PowerShell CommandLine contains -enc / -EncodedCommand
        +0.10 if destination IP is external (non-RFC1918)
        capped at 1.0
    """
    OFFICE_APPS = (
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "mspub.exe", "onenote.exe", "msaccess.exe", "visio.exe",
    )
    SHELL_PROCS = (
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
    )

    CONFIDENCE_BASE = 0.60

    try:
        # Stage 1: Office → shell spawn in last 24h
        # Look for rows where parent_image matches Office AND
        # the image (or message) matches a shell process
        office_filter  = " OR ".join(["LOWER(parent_image) LIKE ?" for _ in OFFICE_APPS])
        shell_filter   = " OR ".join(["LOWER(message) LIKE ?" for _ in SHELL_PROCS])

        c.execute(f"""
            SELECT process_guid, command_line, timestamp, dest_ip
            FROM logs_sysmon
            WHERE event_id = 1
              AND timestamp >= datetime('now', '-24 hours')
              AND ({office_filter})
              AND ({shell_filter})
            ORDER BY timestamp DESC
            LIMIT 20
        """, (
            [f"%{a}%" for a in OFFICE_APPS] +
            [f"%{s}%" for s in SHELL_PROCS]
        ))
        spawns = c.fetchall()

    except Exception:
        # Flatten params if named substitution failed
        try:
            c.execute("""
                SELECT process_guid, command_line, timestamp, dest_ip
                FROM logs_sysmon
                WHERE event_id = 1
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                      LOWER(parent_image) LIKE '%winword.exe%'
                      OR LOWER(parent_image) LIKE '%excel.exe%'
                      OR LOWER(parent_image) LIKE '%powerpnt.exe%'
                      OR LOWER(parent_image) LIKE '%outlook.exe%'
                  )
                  AND (
                      LOWER(message) LIKE '%powershell%'
                      OR LOWER(message) LIKE '%cmd.exe%'
                      OR LOWER(message) LIKE '%wscript%'
                      OR LOWER(message) LIKE '%mshta%'
                  )
                ORDER BY timestamp DESC
                LIMIT 20
            """)
            spawns = c.fetchall()
        except Exception:
            return

    if not spawns:
        return

    # Stage 2: Network connection from same process_guid, AFTER spawn timestamp
    confirmed = []
    for spawn in spawns:
        proc_guid  = spawn[0]
        cmd_line   = (spawn[1] or "").lower()
        spawn_ts   = spawn[2] or ""

        if not proc_guid:
            continue

        try:
            c.execute("""
                SELECT dest_ip, dest_port, timestamp
                FROM logs_sysmon
                WHERE event_id = 3
                  AND process_guid = ?
                  AND timestamp > ?
                ORDER BY timestamp ASC
                LIMIT 5
            """, (proc_guid, spawn_ts))
            net_rows = c.fetchall()
        except Exception:
            continue

        for nr in net_rows:
            dest_ip   = nr[0] or ""
            dest_port = nr[1]
            net_ts    = nr[2] or ""

            if not _ts_after(net_ts, spawn_ts):
                continue  # temporal ordering not satisfied

            # Calculate confidence
            conf = CONFIDENCE_BASE
            if "-enc" in cmd_line or "encodedcommand" in cmd_line:
                conf += 0.10
            if _is_external(dest_ip):
                conf += 0.10
            conf = min(conf, 1.0)

            confirmed.append({
                "spawn_ts":   spawn_ts,
                "net_ts":     net_ts,
                "proc_guid":  proc_guid,
                "cmd_line":   (spawn[1] or "")[:200],
                "dest_ip":    dest_ip,
                "dest_port":  dest_port,
                "conf":       conf,
                "encoded":    ("-enc" in cmd_line or "encodedcommand" in cmd_line),
                "external":   _is_external(dest_ip),
            })
            break  # one network hit per spawn is enough

    if not confirmed:
        return

    # Use the highest-confidence instance for the alert
    best = max(confirmed, key=lambda x: x["conf"])
    conf = best["conf"]

    from database.db import CORRELATION_CONFIDENCE_THRESHOLD  # noqa
    if conf < 0.40:  # use module-level threshold if imported; fallback 0.40
        return

    evidence = [
        f"Office application spawned shell process (Sysmon EID 1)",
        f"Shell CommandLine: {best['cmd_line'][:150]}",
        f"Process GUID: {best['proc_guid']}",
        f"Network connection to {best['dest_ip']}:{best['dest_port']} (Sysmon EID 3)",
        f"Connection occurred {best['net_ts']} — AFTER spawn at {best['spawn_ts']}",
    ]
    if best["encoded"]:
        evidence.append("PowerShell used -EncodedCommand (obfuscation indicator)")
    if best["external"]:
        evidence.append(f"Destination {best['dest_ip']} is a routable (external) IP")
    if len(confirmed) > 1:
        evidence.append(f"Total matching spawn-then-network sequences: {len(confirmed)}")

    alerts.append({
        "id":          "OFFICE_MACRO_NETWORK",
        "name":        "Office Macro → Shell → Network Connection",
        "severity":    "CRITICAL",
        "description": (
            "An Office application (Word/Excel/Outlook) spawned a shell process "
            "(PowerShell/cmd) which then established an outbound network connection. "
            "This three-stage pattern is the hallmark of a malicious macro dropper: "
            "the document runs VBA that launches PowerShell to download a second-stage payload. "
            "MITRE ATT&CK: T1566.001 (Phishing: Spearphishing Attachment), "
            "T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol)."
        ),
        "human_summary": (
            "A Word or Excel document opened a PowerShell or command-prompt window "
            "and that shell immediately connected to the internet. "
            "This is the most common way attackers take over computers through email attachments. "
            "The document is almost certainly malicious."
        ),
        "evidence":       evidence,
        "mitigation": (
            "1. Isolate the affected machine from the network immediately.\n"
            "2. Identify the Office document that triggered the macro via Sysmon EID 1 parent.\n"
            "3. Block the destination IP in Windows Firewall and report to threat intel.\n"
            "4. Disable macros in Office Group Policy (File → Options → Trust Center).\n"
            "5. Scan with Windows Defender offline and a second-opinion scanner.\n"
            "6. Check Sysmon EID 11 for any files dropped to disk during this sequence."
        ),
        "actions": [
            "Disconnect the machine from the network now",
            "Identify the malicious Office document from Sysmon EID 1 parent_image field",
            f"Block destination IP {best['dest_ip']} in Windows Firewall",
            "Disable macros via Office Group Policy Trust Center settings",
            "Run Windows Defender offline scan + second-opinion AV scan",
            "Check Sysmon EID 11 (File Create) for payloads dropped to disk",
        ],
        "risk_score":        90,
        "confidence":        round(conf, 3),
        "confidence_pct":    int(conf * 100),
        "is_chain":          True,
        "stages_confirmed":  2,
        "mitre_tactics":     ["TA0001 - Initial Access", "TA0002 - Execution", "TA0011 - Command and Control"],
        "sysmon_eids":       [1, 3],
    })


# ── Chain 10: Downloaded EXE → Registry Persistence ───────────────────────────

def _chain_downloaded_exe_registry(c, alerts: list) -> None:
    """
    Chain 10: DOWNLOADED_EXE_REGISTRY  (risk 85)

    Stage 1: Executable/script file created in Downloads/Temp/AppData
             Detected via Sysmon EID 11 — target_filename matches
             suspicious path AND suspicious extension.

    Stage 2: Registry Run/RunOnce/Userinit key modified by same or nearby process
             Detected via Sysmon EID 13 — target_object contains persistence keys,
             timestamp is AFTER the file creation timestamp.

    Temporal ordering enforced: registry modification ts > file creation ts.

    Confidence:
        base  0.65
        +0.10 if process is unsigned (Signed = false in EID 11 message)
        +0.10 if file path is in Downloads (indicates internet-sourced file)
        capped at 1.0
    """
    SUSPICIOUS_PATHS = (
        "%downloads%", "%\\temp\\%", "%\\tmp\\%",
        "%appdata\\local\\temp%", "%appdata\\roaming%",
        "%\\public\\%", "%\\programdata\\%",
    )
    SUSPICIOUS_EXTS = (".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".scr", ".hta")
    REGISTRY_KEYS   = (
        "%\\currentversion\\run%",
        "%\\currentversion\\runonce%",
        "%userinit%",
        "%\\environment%",
        "%winlogon%",
    )
    CONFIDENCE_BASE = 0.65

    # Build dynamic SQL for file drops
    path_clauses = " OR ".join(
        ["LOWER(target_filename) LIKE ?" for _ in SUSPICIOUS_PATHS]
    )
    ext_clauses  = " OR ".join(
        ["LOWER(target_filename) LIKE ?" for _ in SUSPICIOUS_EXTS]
    )

    try:
        c.execute(f"""
            SELECT process_guid, target_filename, timestamp, message
            FROM logs_sysmon
            WHERE event_id = 11
              AND timestamp >= datetime('now', '-24 hours')
              AND ({path_clauses})
              AND ({ext_clauses})
            ORDER BY timestamp DESC
            LIMIT 30
        """, (
            list(SUSPICIOUS_PATHS) + [f"%{e}" for e in SUSPICIOUS_EXTS]
        ))
        file_drops = c.fetchall()
    except Exception:
        # Fallback: simpler query without dynamic params
        try:
            c.execute("""
                SELECT process_guid, target_filename, timestamp, message
                FROM logs_sysmon
                WHERE event_id = 11
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                      LOWER(target_filename) LIKE '%\\downloads\\%'
                      OR LOWER(target_filename) LIKE '%\\temp\\%'
                      OR LOWER(target_filename) LIKE '%appdata%'
                  )
                  AND (
                      LOWER(target_filename) LIKE '%.exe'
                      OR LOWER(target_filename) LIKE '%.dll'
                      OR LOWER(target_filename) LIKE '%.ps1'
                      OR LOWER(target_filename) LIKE '%.vbs'
                      OR LOWER(target_filename) LIKE '%.bat'
                  )
                ORDER BY timestamp DESC
                LIMIT 30
            """)
            file_drops = c.fetchall()
        except Exception:
            return

    if not file_drops:
        return

    # Registry key persistence filter
    reg_key_clauses = " OR ".join(
        ["LOWER(target_object) LIKE ?" for _ in REGISTRY_KEYS]
    )

    confirmed = []
    for drop in file_drops:
        proc_guid   = drop[0]
        filename    = drop[1] or ""
        drop_ts     = drop[2] or ""
        drop_msg    = (drop[3] or "").lower()

        # Check for unsigned indicator in the message
        unsigned   = "signed: false" in drop_msg or "false" in drop_msg
        from_dl    = "\\downloads\\" in filename.lower()

        # Stage 2: Registry write after file creation
        # Try matching by process_guid first, then fall back to any registry write after file drop
        try:
            if proc_guid:
                c.execute(f"""
                    SELECT target_object, details, timestamp
                    FROM logs_sysmon
                    WHERE event_id = 13
                      AND timestamp > ?
                      AND ({reg_key_clauses})
                    ORDER BY timestamp ASC
                    LIMIT 5
                """, [drop_ts] + list(REGISTRY_KEYS))
            else:
                c.execute(f"""
                    SELECT target_object, details, timestamp
                    FROM logs_sysmon
                    WHERE event_id = 13
                      AND timestamp > ?
                      AND ({reg_key_clauses})
                    ORDER BY timestamp ASC
                    LIMIT 5
                """, [drop_ts] + list(REGISTRY_KEYS))
            reg_rows = c.fetchall()
        except Exception:
            try:
                c.execute("""
                    SELECT target_object, details, timestamp
                    FROM logs_sysmon
                    WHERE event_id = 13
                      AND timestamp > ?
                      AND (
                          LOWER(target_object) LIKE '%\\currentversion\\run%'
                          OR LOWER(target_object) LIKE '%userinit%'
                          OR LOWER(target_object) LIKE '%winlogon%'
                      )
                    ORDER BY timestamp ASC
                    LIMIT 5
                """, (drop_ts,))
                reg_rows = c.fetchall()
            except Exception:
                continue

        for rr in reg_rows:
            reg_key  = rr[0] or ""
            reg_val  = rr[1] or ""
            reg_ts   = rr[2] or ""

            if not _ts_after(reg_ts, drop_ts):
                continue  # temporal ordering not satisfied

            conf = CONFIDENCE_BASE
            if unsigned:
                conf += 0.10
            if from_dl:
                conf += 0.10
            conf = min(conf, 1.0)

            confirmed.append({
                "filename":  filename[:300],
                "drop_ts":   drop_ts,
                "reg_key":   reg_key[:200],
                "reg_val":   reg_val[:200],
                "reg_ts":    reg_ts,
                "conf":      conf,
                "unsigned":  unsigned,
                "from_dl":   from_dl,
            })
            break  # one registry hit per file drop is enough

    if not confirmed:
        return

    best = max(confirmed, key=lambda x: x["conf"])
    conf = best["conf"]
    if conf < 0.40:
        return

    evidence = [
        f"Suspicious file created: {best['filename'][-100:]} (Sysmon EID 11)",
        f"File creation time: {best['drop_ts']}",
        f"Registry persistence key set: {best['reg_key'][-100:]} (Sysmon EID 13)",
        f"Registry write time: {best['reg_ts']} — AFTER file creation",
        f"Registry value: {best['reg_val'][:100]}",
    ]
    if best["unsigned"]:
        evidence.append("File appears unsigned (no valid signature)")
    if best["from_dl"]:
        evidence.append("File created in Downloads folder (likely internet-sourced)")
    if len(confirmed) > 1:
        evidence.append(f"Total matching drop-then-persist sequences: {len(confirmed)}")

    alerts.append({
        "id":          "DOWNLOADED_EXE_REGISTRY",
        "name":        "Downloaded Executable → Registry Persistence",
        "severity":    "CRITICAL",
        "description": (
            "An executable or script was created in a user-writable directory "
            "(Downloads/Temp/AppData), and a Windows Registry Run or RunOnce key "
            "was subsequently modified — ensuring the file executes on every login. "
            "This two-stage pattern matches the persistence phase of a malware infection: "
            "the payload lands on disk, then anchors itself for survival across reboots. "
            "MITRE ATT&CK: T1105 (Ingress Tool Transfer), T1547.001 (Registry Run Keys)."
        ),
        "human_summary": (
            "A new program was saved to your Downloads or Temp folder, and immediately "
            "after that, the registry was changed to make it run automatically every time "
            "you log in. This is how malware installs itself. The program will keep running "
            "even after a restart unless removed."
        ),
        "evidence":      evidence,
        "mitigation": (
            "1. Delete the file immediately: " + best["filename"][-80:] + "\n"
            "2. Remove the registry persistence key:\n"
            "   reg delete \"" + best["reg_key"][-80:] + "\" /f\n"
            "3. Run Windows Defender offline scan to check for additional payloads.\n"
            "4. Review Sysmon EID 3 (Network Connection) from the same process_guid "
            "   to identify any C2 communications.\n"
            "5. Check Sysmon EID 1 (Process Create) to see if the file was already executed."
        ),
        "actions": [
            f"Delete the suspicious file: {best['filename'][-80:]}",
            f"Remove registry key: reg delete \"{best['reg_key'][-80:]}\" /f",
            "Run Windows Defender offline scan",
            "Check Sysmon EID 3 for network connections from this process",
            "Check Sysmon EID 1 for process execution from this file",
            "Review all files in Downloads and Temp folders",
        ],
        "risk_score":        85,
        "confidence":        round(conf, 3),
        "confidence_pct":    int(conf * 100),
        "is_chain":          True,
        "stages_confirmed":  2,
        "mitre_tactics":     ["TA0003 - Persistence", "TA0005 - Defense Evasion"],
        "sysmon_eids":       [11, 13],
    })
