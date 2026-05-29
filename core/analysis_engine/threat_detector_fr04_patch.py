"""
core/analysis_engine/threat_detector_fr04_patch.py
====================================================
FR04-03 / FR04-05 — Additional detection rules for threat_detector.py.

HOW TO APPLY:
  In threat_detector.py, find the closing bracket of THREAT_RULES (the `]`
  after the UPDATE_FAILURES rule on line ~780) and insert the contents of
  FR04_EXTRA_RULES just before it.

  Then update HIGH_SIGNAL (line ~807) to include the new EIDs:
      HIGH_SIGNAL = {4719, 5001, 1116, 1117, 4728, 4698, 7045, 4946, 4950,
                     4104, 4103,
                     # FR04-03 task lifecycle
                     4699, 4700, 4701, 4702,
                     # FR04-05 extended service events
                     7000, 7001, 7031, 7034, 7040}

This file can also be used standalone for testing — the rules list is
self-contained and importable.
"""

# ── New rules to append to THREAT_RULES ──────────────────────────────────────

FR04_EXTRA_RULES = [

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

    # ── FR04-05: Extended service event rules ─────────────────────────────────

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
]


# ── Patch helper ──────────────────────────────────────────────────────────────

def apply_patch_to_threat_rules(existing_rules: list) -> list:
    """
    Merge FR04_EXTRA_RULES into an existing THREAT_RULES list.
    Skips rules whose 'id' already exists so it is idempotent.

    Usage in threat_detector.py:
        from core.analysis_engine.threat_detector_fr04_patch import apply_patch_to_threat_rules
        THREAT_RULES = apply_patch_to_threat_rules(THREAT_RULES)
    """
    existing_ids = {r["id"] for r in existing_rules}
    added = 0
    for rule in FR04_EXTRA_RULES:
        if rule["id"] not in existing_ids:
            existing_rules.append(rule)
            existing_ids.add(rule["id"])
            added += 1
    if added:
        import logging
        logging.getLogger("threat_detector").info(
            f"FR04 patch applied — {added} new rules added"
        )
    return existing_rules


# ── Updated HIGH_SIGNAL set (replace the existing one in threat_detector.py) ──

UPDATED_HIGH_SIGNAL = {
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
}
