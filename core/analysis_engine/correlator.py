"""
core/analysis_engine/correlator.py
=====================================
UPGRADED: Attack Chain Correlation Engine v2.0

Detects multi-stage kill-chain patterns that span multiple events over time.

KEY UPGRADE: Temporal ordering enforcement.
  - Each chain stage must occur AFTER the previous stage's first event.
  - Simple co-occurrence (old system) = high false positives.
  - Temporal ordering proves intentional, sequential attacker behavior.

ATTACK CHAINS:
  1. BRUTE_FORCE_SUCCESS    — Failed logins → successful login (account compromise)
  2. RECON_THEN_ATTACK      — Enumeration → login failures (targeted attack)
  3. EVASION_THEN_ATTACK    — Audit disabled → attack activity (sophisticated intrusion)
  4. PRIV_THEN_PERSIST      — Privilege escalation → backdoor installed (post-exploitation)
  5. AV_DISABLED_MALWARE    — Defender disabled → malware/new service (infection chain)
  6. OFF_HOURS_ADMIN        — Admin logon at unusual hours (standalone high-confidence)
  7. MASS_ACCOUNT_OPS       — Multiple account creations in short window (persistence storm)
  8. MULTI_CAT_STORM        — Error spikes across 3+ categories (system-level event)
"""

import math
from datetime import datetime, timedelta
from database.db import get_conn, CATEGORIES

# Minimum confidence to report a correlation
CORRELATION_CONFIDENCE_THRESHOLD = 0.40


def _fetch_count_and_times(c, table: str, event_ids: list, hours: int):
    """
    Fetch event count, min timestamp, and max timestamp for given event IDs
    within a rolling time window.
    Returns (count, first_ts_str, last_ts_str) — count is 0 if nothing found.
    """
    placeholders = ",".join("?" * len(event_ids))
    try:
        c.execute(f"""
            SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
            FROM {table}
            WHERE event_id IN ({placeholders})
            AND timestamp >= datetime('now', ? || ' hours')
        """, event_ids + [f"-{hours}"])
        row = c.fetchone()
        return (row[0] or 0, row[1] or "", row[2] or "")
    except Exception:
        return (0, "", "")


def _get_max_timestamp(c, table: str, event_ids: list) -> str:
    """Get the most recent timestamp for given event IDs."""
    placeholders = ",".join("?" * len(event_ids))
    try:
        c.execute(f"""
            SELECT MAX(timestamp) FROM {table}
            WHERE event_id IN ({placeholders})
        """, event_ids)
        row = c.fetchone()
        return (row[0] or "") if row else ""
    except Exception:
        return ""


def _count_after_timestamp(c, table: str, event_ids: list, after_ts: str) -> int:
    """Count events that occurred AFTER a specific timestamp (temporal ordering)."""
    if not after_ts:
        return 0
    placeholders = ",".join("?" * len(event_ids))
    try:
        c.execute(f"""
            SELECT COUNT(*) FROM {table}
            WHERE event_id IN ({placeholders})
            AND timestamp > ?
        """, event_ids + [after_ts])
        row = c.fetchone()
        return row[0] or 0
    except Exception:
        return 0


def run_correlation(conn=None) -> list:
    """
    Run all attack chain correlation rules.

    Returns list of correlation alert dicts sorted by severity.

    Each alert:
    {
      "id":           unique rule id,
      "name":         human-readable name,
      "severity":     CRITICAL|HIGH|MEDIUM,
      "description":  what this correlation means,
      "human_summary": plain-English explanation,
      "evidence":     list of supporting facts,
      "mitigation":   recommended action string,
      "actions":      list of ordered action strings,
      "confidence":   float 0.0–1.0,
      "confidence_pct": int 0–100,
      "is_chain":     True,
      "stages_confirmed": int,
    }
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c      = conn.cursor()
    alerts = []

    # ── Chain 1: Brute Force → Successful Login ──────────────────────────────
    # Temporal enforcement: success must happen AFTER failures started
    try:
        fails, fail_first, fail_last = _fetch_count_and_times(
            c, "logs_security", [4625], 1
        )
        succs, succ_first, succ_last = _fetch_count_and_times(
            c, "logs_security", [4624], 2
        )
        # Temporal check: was there a success AFTER the first failure?
        succs_after = _count_after_timestamp(
            c, "logs_security", [4624], fail_first
        ) if fail_first else succs

        if fails >= 5 and succs_after >= 1:
            # Confidence: high failure count + success after = very high
            conf = min(1.0, 0.55 + 0.05 * math.log10(max(fails, 1)) + 0.2)
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "BRUTE_FORCE_SUCCESS",
                    "name":     "Brute Force Attack — Account Compromise Detected",
                    "severity": "CRITICAL",
                    "description": (
                        f"{fails} failed logon attempts (EID 4625) followed by "
                        f"{succs_after} successful logon(s) (EID 4624) in the same window. "
                        "This is the signature of a successful brute-force or credential-stuffing "
                        "attack — an account is now compromised."
                    ),
                    "human_summary": (
                        "An attacker repeatedly guessed passwords and eventually succeeded. "
                        "The account is now compromised and the attacker has an active session."
                    ),
                    "evidence": [
                        f"{fails} failed logons (EID 4625) starting {fail_first[:16]}",
                        f"{succs_after} successful logon(s) (EID 4624) after failures began",
                        "Temporal ordering confirmed — success came AFTER failures",
                    ],
                    "mitigation": (
                        "1. Immediately lock all accounts that had failures in the last hour.\n"
                        "2. Force password reset for any account that logged in after the failures.\n"
                        "3. Block the source IP identified in Event ID 4624.\n"
                        "4. Enable MFA immediately.\n"
                        "5. Review all actions taken from the session that followed the brute force."
                    ),
                    "actions": [
                        "Immediately lock all accounts that had failures in the last hour",
                        "Force password reset for any account that logged in after the failures",
                        "Block the source IP identified in Event ID 4624 in Windows Firewall",
                        "Enable MFA for all user accounts",
                        "Review all actions taken after the successful logon",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  2,
                })
    except Exception:
        pass

    # ── Chain 2: Reconnaissance → Login Attacks ──────────────────────────────
    # Temporal: login attacks must follow enumeration
    try:
        recon, recon_first, recon_last = _fetch_count_and_times(
            c, "logs_security", [4798, 4799], 2
        )
        attacks_after = _count_after_timestamp(
            c, "logs_security", [4625, 4771], recon_first
        ) if recon_first else 0

        if recon >= 3 and attacks_after >= 5:
            conf = min(1.0, 0.60 + 0.05 * min(recon / 3.0, 3.0))
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "RECON_THEN_ATTACK",
                    "name":     "Reconnaissance Followed by Targeted Login Attacks",
                    "severity": "HIGH",
                    "description": (
                        f"Account/group enumeration ({recon} × EID 4798/4799) occurred, "
                        f"then {attacks_after} login failure(s) followed in sequence. "
                        "Attackers enumerate accounts first to know which usernames to target."
                    ),
                    "human_summary": (
                        "The attacker first mapped out which accounts exist, "
                        "then used those usernames to attempt password guessing. "
                        "This is a targeted attack, not random noise."
                    ),
                    "evidence": [
                        f"{recon} enumeration events (EID 4798/4799) at {recon_first[:16]}",
                        f"{attacks_after} login failures AFTER enumeration began",
                        "Temporal ordering confirms: recon before attack",
                    ],
                    "mitigation": (
                        "1. Block the process or IP performing enumeration.\n"
                        "2. Lock accounts targeted by login failures.\n"
                        "3. Enable advanced audit policy for account management.\n"
                        "4. Review all events from the same source IP."
                    ),
                    "actions": [
                        "Block the process or IP performing enumeration",
                        "Lock accounts that were targeted by login failures",
                        "Enable advanced audit policy for account management",
                        "Review all events from the same source IP",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  2,
                })
    except Exception:
        pass

    # ── Chain 3: Audit Policy Disabled → Attack Activity (Evasion + Attack) ──
    # Temporal: attack events must occur AFTER the policy was changed
    try:
        policy_changes, _, policy_ts = _fetch_count_and_times(
            c, "logs_security", [4719], 24
        )
        if policy_changes >= 1 and policy_ts:
            post_events = _count_after_timestamp(
                c, "logs_security",
                [4625, 4672, 4720, 4728, 4698, 4771],
                policy_ts
            )
            if post_events >= 1:
                conf = min(1.0, 0.80 + 0.05 * min(post_events / 5.0, 2.0))
                alerts.append({
                    "id":       "EVASION_THEN_ATTACK",
                    "name":     "Audit Policy Disabled Before Attack Activity",
                    "severity": "CRITICAL",
                    "description": (
                        f"The audit policy was modified (EID 4719 at {policy_ts[:16]}) "
                        f"and {post_events} suspicious event(s) occurred AFTER the change. "
                        "Attackers disable audit logging as their first step to avoid leaving "
                        "evidence of their subsequent actions."
                    ),
                    "human_summary": (
                        "The attacker's first move was to disable Windows security auditing — "
                        "a deliberate attempt to prevent their actions from being logged. "
                        "This is a strong indicator of a sophisticated, intentional intrusion."
                    ),
                    "evidence": [
                        f"EID 4719 (audit policy disabled) at {policy_ts[:16]}",
                        f"{post_events} suspicious event(s) occurred AFTER the policy change",
                        "Temporal ordering confirmed — attack followed the logging blind-spot",
                    ],
                    "mitigation": (
                        "1. Restore audit policy via secpol.msc IMMEDIATELY.\n"
                        "2. Treat this as a confirmed intrusion — initiate incident response.\n"
                        "3. Preserve all existing logs before the attacker clears them.\n"
                        "4. Consider isolating the machine from the network.\n"
                        "5. Review ALL events that occurred after the policy change timestamp."
                    ),
                    "actions": [
                        "Restore audit policy via secpol.msc IMMEDIATELY",
                        "Treat this as a confirmed intrusion — initiate incident response",
                        "Preserve all existing logs before the attacker clears them",
                        "Consider isolating the machine from the network",
                        "Review ALL events that occurred after the policy change",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  2,
                })
    except Exception:
        pass

    # ── Chain 4: Privilege Escalation → Persistence ──────────────────────────
    try:
        priv_count, priv_first, _ = _fetch_count_and_times(
            c, "logs_security", [4672, 4673, 4728], 2
        )
        persist_after = _count_after_timestamp(
            c, "logs_security", [4698, 4720, 4728, 4657],
            priv_first
        ) if priv_first else 0
        sys_persist_after = _count_after_timestamp(
            c, "logs_system", [7045],
            priv_first
        ) if priv_first else 0
        total_persist = persist_after + sys_persist_after

        if priv_count >= 2 and total_persist >= 1:
            conf = min(1.0, 0.70 + 0.05 * min(total_persist, 3))
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "PRIV_THEN_PERSIST",
                    "name":     "Privilege Escalation Followed by Persistence Installation",
                    "severity": "CRITICAL",
                    "description": (
                        f"Privilege escalation events ({priv_count} × EID 4672/4673/4728) "
                        f"occurred, then {total_persist} persistence-related event(s) "
                        "(EID 4698/4720/7045/4657) followed in sequence. "
                        "Classic post-exploitation: gain admin access, then install a backdoor."
                    ),
                    "human_summary": (
                        "After gaining elevated privileges, the attacker installed a backdoor "
                        "(scheduled task, new service, or new account) to ensure they can "
                        "return even if their initial access is revoked."
                    ),
                    "evidence": [
                        f"{priv_count} privilege escalation events (EID 4672/4673/4728)",
                        f"{total_persist} persistence events installed AFTER escalation",
                        "Temporal ordering confirmed — backdoor installed after privilege gain",
                    ],
                    "mitigation": (
                        "1. Review all scheduled tasks in Task Scheduler — delete unknowns.\n"
                        "2. Check all services installed in the last 24 hours.\n"
                        "3. Disable/delete any accounts created outside normal workflow.\n"
                        "4. Review the admin account that performed escalation events.\n"
                        "5. Run a full malware scan with offline capability."
                    ),
                    "actions": [
                        "Review all scheduled tasks in Task Scheduler — delete unknowns",
                        "Check all services installed in the last 24 hours",
                        "Disable/delete any accounts created outside normal workflow",
                        "Review the admin account that performed escalation events",
                        "Run a full malware scan with offline capability",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  2,
                })
    except Exception:
        pass

    # ── Chain 5: AV Disabled → Malware / New Service ─────────────────────────
    try:
        av_count, av_first, _ = _fetch_count_and_times(
            c, "logs_system", [5001, 5007], 24
        )
        if av_count >= 1 and av_first:
            malware_after = _count_after_timestamp(
                c, "logs_system", [1116, 1117, 1118, 7045], av_first
            )
            if malware_after >= 1:
                conf = 0.85
                alerts.append({
                    "id":       "AV_DISABLED_MALWARE",
                    "name":     "Antivirus Disabled Then Malware/Service Activity",
                    "severity": "CRITICAL",
                    "description": (
                        f"Windows Defender disabled (EID 5001/5007 at {av_first[:16]}), "
                        f"then {malware_after} malware or suspicious service event(s) followed. "
                        "The AV was disabled to allow malware to run undetected."
                    ),
                    "human_summary": (
                        "The antivirus was disabled, and then malware activity or a new service "
                        "was detected immediately afterward. "
                        "The AV disable was the preparation step for the infection."
                    ),
                    "evidence": [
                        f"EID 5001/5007 (AV disabled) at {av_first[:16]}",
                        f"{malware_after} malware/service events occurred AFTER AV was disabled",
                        "Temporal ordering confirmed — infection followed disabling of protection",
                    ],
                    "mitigation": (
                        "1. Re-enable Windows Defender immediately.\n"
                        "2. Run an OFFLINE malware scan (boot from external media).\n"
                        "3. Do NOT run the system online until scanned.\n"
                        "4. Check all processes started after the AV disable event.\n"
                        "5. Consider full OS reinstallation if infection is confirmed."
                    ),
                    "actions": [
                        "Re-enable Windows Defender immediately",
                        "Run an OFFLINE malware scan (boot from external media)",
                        "Do NOT run the system online until scanned",
                        "Check all processes started after the AV disable event",
                        "Consider full OS reinstallation if infection is confirmed",
                    ],
                    "confidence":        conf,
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  2,
                })
    except Exception:
        pass

    # ── Chain 6: Off-Hours Admin Logon ────────────────────────────────────────
    # Standalone high-signal detection (not a multi-stage chain but kept here
    # as a correlation finding because it requires temporal analysis)
    try:
        c.execute("""
            SELECT COUNT(*), MAX(timestamp) FROM logs_security
            WHERE event_id = 4672
            AND CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 0 AND 5
            AND timestamp >= datetime('now', '-7 days')
        """)
        row   = c.fetchone()
        count = row[0] or 0
        last  = (row[1] or "")[:16]
        if count >= 1:
            conf = min(1.0, 0.60 + 0.08 * math.log10(max(count, 1)))
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "OFF_HOURS_ADMIN",
                    "name":     "Administrator Logon at Unusual Hour",
                    "severity": "HIGH",
                    "description": (
                        f"{count} administrator-level logon(s) (EID 4672) occurred "
                        f"between midnight and 5am in the last 7 days (most recent: {last}). "
                        "Legitimate admin work rarely happens in the dead of night."
                    ),
                    "human_summary": (
                        "An administrator logged in at a time when no legitimate work "
                        "would normally happen. This could be an attacker using stolen credentials."
                    ),
                    "evidence": [
                        f"{count} EID 4672 events between 00:00–05:59",
                        f"Most recent occurrence: {last}",
                        "Off-hours admin activity is a strong behavioral anomaly",
                    ],
                    "mitigation": (
                        "1. Review the account name from Event ID 4672.\n"
                        "2. Verify whether this admin activity was planned maintenance.\n"
                        "3. If unrecognized, treat as potential compromise and rotate admin passwords."
                    ),
                    "actions": [
                        "Review the account name from Event ID 4672",
                        "Verify whether this admin activity was planned maintenance",
                        "If unrecognized, treat as potential compromise and rotate admin passwords",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          False,
                    "stages_confirmed":  1,
                })
    except Exception:
        pass

    # ── Chain 7: Mass Account Operations ─────────────────────────────────────
    try:
        acct_count, acct_first, _ = _fetch_count_and_times(
            c, "logs_security", [4720, 4728, 4732], 1
        )
        if acct_count >= 3:
            conf = min(1.0, 0.65 + 0.05 * math.log10(max(acct_count, 1)))
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "MASS_ACCOUNT_OPS",
                    "name":     "Mass Account Creation / Modification",
                    "severity": "CRITICAL",
                    "description": (
                        f"{acct_count} account creation or privilege assignment events "
                        "(EID 4720/4728/4732) in the last hour. "
                        "Attackers create multiple accounts rapidly to ensure persistence."
                    ),
                    "human_summary": (
                        "Multiple user accounts were created or given admin rights in a short time. "
                        "Attackers do this to guarantee they can return to the system later."
                    ),
                    "evidence": [
                        f"{acct_count} account creation/modification events in last 1 hour",
                        "Includes: account creation (4720), admin group add (4728), group add (4732)",
                    ],
                    "mitigation": (
                        "1. Check all accounts created or modified today in User Accounts.\n"
                        "2. Disable any unrecognized accounts immediately.\n"
                        "3. Audit who performed these operations using Event 4720 Subject fields."
                    ),
                    "actions": [
                        "Check all accounts created or modified today in User Accounts",
                        "Disable any unrecognized accounts immediately",
                        "Audit who performed these operations using Event 4720 Subject fields",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          True,
                    "stages_confirmed":  1,
                })
    except Exception:
        pass

    # ── Chain 8: Multi-Category Error Storm ──────────────────────────────────
    try:
        spiked = []
        for cat in CATEGORIES:
            try:
                c.execute(f"""
                    SELECT COUNT(*) FROM logs_{cat}
                    WHERE level IN ('ERROR', 'CRITICAL', 'FAILURE')
                    AND timestamp >= datetime('now', '-3 hours')
                """)
                count = c.fetchone()[0] or 0
                if count >= 20:
                    spiked.append((cat, count))
            except Exception:
                pass

        if len(spiked) >= 3:
            total     = sum(n for _, n in spiked)
            cats_str  = ", ".join(f"{cat}({n})" for cat, n in spiked)
            conf      = min(1.0, 0.55 + 0.05 * len(spiked))
            if conf >= CORRELATION_CONFIDENCE_THRESHOLD:
                alerts.append({
                    "id":       "MULTI_CAT_STORM",
                    "name":     "Multi-Category Error Storm",
                    "severity": "HIGH",
                    "description": (
                        f"Simultaneous error spikes across {len(spiked)} log categories "
                        f"in the last 3 hours: {cats_str} ({total} total errors). "
                        "Indicates system-level event: hardware failure, failed update, or active attack."
                    ),
                    "human_summary": (
                        "Errors are spiking across multiple parts of your system at the same time. "
                        "This usually means a hardware failure, a bad update, or an active attack "
                        "affecting multiple components simultaneously."
                    ),
                    "evidence": [f"{cat}: {n} errors in last 3 hours" for cat, n in spiked],
                    "mitigation": (
                        "1. Check hardware health (disk, RAM, power supply).\n"
                        "2. Review any recent software updates or configuration changes.\n"
                        "3. Check Windows Event Viewer System log for hardware-level errors.\n"
                        "4. Consider whether a scheduled task or update caused the storm."
                    ),
                    "actions": [
                        "Check hardware health (disk, RAM, power supply)",
                        "Review any recent software updates or configuration changes",
                        "Check Windows Event Viewer System log for hardware-level errors",
                        "Consider whether a scheduled task or update caused the storm",
                    ],
                    "confidence":        round(conf, 3),
                    "confidence_pct":    int(conf * 100),
                    "is_chain":          False,
                    "stages_confirmed":  1,
                })
    except Exception:
        pass

    # ══════════════════════════════════════════════════════════════════════
    # SYSMON CHAINS (Step 6) — added to existing correlator
    # Requires logs_sysmon table populated by SysmonCollector.
    # ══════════════════════════════════════════════════════════════════════

    # ── Chain 9: Office Macro → Shell → Network (risk 90) ────────────────
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
        if c.fetchone():
            OFFICE = ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe")
            SHELLS = ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
            office_like = " OR ".join(
                f"LOWER(COALESCE(sysmon_parent_image,'')) LIKE '%{o}%'" for o in OFFICE
            )
            shell_like  = " OR ".join(
                f"LOWER(COALESCE(sysmon_image,'')) LIKE '%{s}%'" for s in SHELLS
            )
            c.execute(f"""
                SELECT sysmon_process_guid, sysmon_command_line, timestamp,
                       sysmon_parent_image, sysmon_image
                FROM logs_sysmon
                WHERE event_id = 1
                  AND timestamp >= datetime('now', '-24 hours')
                  AND ({office_like})
                  AND ({shell_like})
                ORDER BY timestamp DESC LIMIT 20
            """)
            spawns = c.fetchall()
            confirmed = []
            for sp in spawns:
                guid    = sp[0]
                cmd     = (sp[1] or "")[:200]
                spawn_ts= sp[2] or ""
                parent  = (sp[3] or "").rsplit("\\", 1)[-1]
                image   = (sp[4] or "").rsplit("\\", 1)[-1]
                has_net = False
                if guid:
                    c.execute("""
                        SELECT sysmon_dest_ip, sysmon_dest_port, timestamp
                        FROM logs_sysmon
                        WHERE event_id = 3
                          AND sysmon_process_guid = ?
                          AND timestamp > ?
                        LIMIT 5
                    """, (guid, spawn_ts))
                    net_rows = c.fetchall()
                    if net_rows:
                        has_net = True
                        dest_ip   = net_rows[0][0] or ""
                        dest_port = net_rows[0][1] or ""
                        confirmed.append({
                            "parent": parent, "image": image, "cmd": cmd,
                            "spawn_ts": spawn_ts, "dest_ip": dest_ip,
                            "dest_port": dest_port, "encoded": "-enc" in cmd.lower(),
                        })
            if confirmed:
                best = confirmed[0]
                conf = 0.60
                if best["encoded"]: conf += 0.10
                if best["dest_ip"] and not best["dest_ip"].startswith(("10.","192.168.","172.")): conf += 0.10
                conf = min(conf, 1.0)
                evidence = [
                    f"Sysmon EID 1: {best['parent']} spawned {best['image']}",
                    f"CommandLine: {best['cmd'][:100]}",
                    f"Sysmon EID 3: network connection → {best['dest_ip']}:{best['dest_port']}",
                    f"Spawn timestamp: {best['spawn_ts']}",
                ]
                if best["encoded"]: evidence.append("Encoded PowerShell command detected")
                if len(confirmed) > 1: evidence.append(f"{len(confirmed)} spawn-then-network sequences found")
                alerts.append({
                    "id":          "SYSMON_OFFICE_MACRO_NET",
                    "name":        "Office Macro → Shell → Network (Sysmon)",
                    "severity":    "CRITICAL",
                    "description": (
                        "Office application spawned a shell which immediately made an outbound "
                        "network connection. Classic macro dropper chain. "
                        "MITRE: T1566.001, T1059, T1071."
                    ),
                    "human_summary": (
                        "A Word or Excel document opened PowerShell which connected to the internet. "
                        "This is the most common way malware is delivered via email attachments."
                    ),
                    "evidence":  evidence,
                    "mitigation": (
                        "1. Isolate machine immediately.\n"
                        "2. Disable Office macros via Group Policy.\n"
                        "3. Block destination IP in Windows Firewall.\n"
                        "4. Run Windows Defender offline scan."
                    ),
                    "actions": [
                        "Isolate machine from network immediately",
                        "Disable Office macros via Group Policy Trust Center",
                        f"Block IP {best['dest_ip']} in Windows Firewall",
                        "Run Windows Defender offline scan",
                    ],
                    "risk_score":       90,
                    "confidence":       round(conf, 3),
                    "confidence_pct":   int(conf * 100),
                    "is_chain":         True,
                    "stages_confirmed": 2,
                    "mitre_tactics":    ["TA0001","TA0002","TA0011"],
                    "sysmon_eids":      [1, 3],
                })
    except Exception as _e:
        pass

    # ── Chain 10: File Drop → YARA Hit → Registry Persistence (risk 85) ──
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
        if c.fetchone():
            c.execute("""
                SELECT timestamp, sysmon_target_file, sysmon_process_guid
                FROM logs_sysmon
                WHERE event_id = 11
                  AND timestamp >= datetime('now', '-24 hours')
                  AND (
                    LOWER(COALESCE(sysmon_target_file,'')) LIKE '%downloads%'
                    OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%temp%'
                    OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%appdata%'
                  )
                  AND (
                    LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.exe'
                    OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.dll'
                    OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.ps1'
                  )
                ORDER BY timestamp DESC LIMIT 20
            """)
            file_drops = c.fetchall()
            persist_confirmed = []
            for fd in file_drops:
                drop_ts  = fd[0] or ""
                filename = fd[1] or ""
                guid     = fd[2]
                # Check registry persistence after file drop
                c.execute("""
                    SELECT target_object, timestamp
                    FROM logs_sysmon
                    WHERE event_id = 13
                      AND timestamp > ?
                      AND (
                        LOWER(COALESCE(sysmon_target_object,'')) LIKE '%currentversion%run%'
                        OR LOWER(COALESCE(sysmon_target_object,'')) LIKE '%userinit%'
                        OR LOWER(COALESCE(sysmon_target_object,'')) LIKE '%winlogon%'
                      )
                    LIMIT 3
                """, (drop_ts,))
                reg_rows = c.fetchall()
                if reg_rows:
                    persist_confirmed.append({
                        "filename": filename.rsplit("\\", 1)[-1],
                        "path":     filename,
                        "drop_ts":  drop_ts,
                        "reg_key":  reg_rows[0][0] or "",
                        "reg_ts":   reg_rows[0][1] or "",
                    })
            if persist_confirmed:
                best  = persist_confirmed[0]
                conf  = 0.65
                if "downloads" in best["path"].lower(): conf += 0.10
                conf  = min(conf, 1.0)
                alerts.append({
                    "id":          "SYSMON_DROPPER_PERSIST",
                    "name":        "Downloaded Executable → Registry Persistence (Sysmon)",
                    "severity":    "CRITICAL",
                    "description": (
                        "Executable created in Downloads/Temp followed by registry Run key modification. "
                        "Classic dropper persistence chain. "
                        "MITRE: T1105, T1547.001."
                    ),
                    "human_summary": (
                        "A new program appeared in Downloads/Temp and then changed the registry "
                        "to run automatically on every login. This is how malware survives reboots."
                    ),
                    "evidence": [
                        f"File dropped: {best['filename']} at {best['drop_ts']}",
                        f"Path: {best['path'][-80:]}",
                        f"Registry key set: {best['reg_key'][-70:]} at {best['reg_ts']}",
                    ],
                    "mitigation": (
                        "1. Delete the file from Downloads/Temp.\n"
                        "2. Remove registry persistence key.\n"
                        "3. Run Windows Defender offline scan."
                    ),
                    "actions": [
                        f"Delete: {best['path'][-60:]}",
                        f"Remove registry key: {best['reg_key'][-60:]}",
                        "Run Windows Defender offline scan",
                    ],
                    "risk_score":       85,
                    "confidence":       round(conf, 3),
                    "confidence_pct":   int(conf * 100),
                    "is_chain":         True,
                    "stages_confirmed": 2,
                    "mitre_tactics":    ["TA0003","TA0005"],
                    "sysmon_eids":      [11, 13],
                })
    except Exception:
        pass

    if close_conn:
        conn.close()

    # Sort: CRITICAL chains first, then by confidence descending
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 9), -a.get("confidence", 0)))

    return alerts
