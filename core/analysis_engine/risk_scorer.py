"""
core/analysis_engine/risk_scorer.py
=====================================
UPGRADED: Smart Multi-Factor Risk Scoring Engine v2.0

SYSTEM RISK SCORE FORMULA (0-100):
  Score = threat_contribution(cap 70)
        + chain_bonus(+15 per confirmed attack chain, cap 20)
        + temporal_bonus(+5 per off-hours detection, cap 10)

Per-detection contribution:
  pts = severity_weight × confidence × log_frequency_multiplier

Where:
  severity_weight   = {CRITICAL:30, HIGH:18, MEDIUM:8, LOW:3}
  confidence        = 0.0–1.0 (from threat_detector confidence scoring)
  frequency_mult    = 1.0 + log10(count / threshold), capped at 3.0

RISK LEVEL THRESHOLDS:
  76–100 → CRITICAL   🚨  Immediate action required
  51–75  → HIGH       🔶  Investigate within 2 hours
  26–50  → SUSPICIOUS ⚠️  Review within 24 hours
  0–25   → NORMAL     ✅  No actionable threats
"""

import math

# ── Per-Event-ID base risk weights (for legacy score_event usage) ─────────────
EVENT_RISK = {
    # CRITICAL security events
    4719: {"score": 25, "label": "Audit Policy Disabled",    "category": "policy_tamper"},
    # FR06-03: GPO / domain policy modifications
    4739: {"score": 25, "label": "Domain Policy Changed",    "category": "policy_tamper"},
    4713: {"score": 25, "label": "Kerberos Policy Changed",  "category": "policy_tamper"},
    4902: {"score": 20, "label": "Per-User Audit Policy",    "category": "policy_tamper"},
    4904: {"score": 18, "label": "Audit Source Registered",  "category": "policy_tamper"},
    4905: {"score": 18, "label": "Audit Source Removed",     "category": "policy_tamper"},
    1116: {"score": 25, "label": "Malware Detected",         "category": "malware"},
    1117: {"score": 25, "label": "Malware Action Taken",     "category": "malware"},
    1120: {"score": 25, "label": "Malware Removal Failed",   "category": "malware"},
    5001: {"score": 25, "label": "AV Real-Time Disabled",    "category": "defense_evasion"},
    4946: {"score": 20, "label": "Firewall Rule Added",      "category": "defense_evasion"},
    4950: {"score": 20, "label": "Firewall Disabled",        "category": "defense_evasion"},
    # HIGH security events
    4728: {"score": 18, "label": "Added to Admin Group",     "category": "privilege_escalation"},
    4720: {"score": 15, "label": "New User Account Created", "category": "persistence"},
    4698: {"score": 14, "label": "Scheduled Task Created",   "category": "persistence"},
    4672: {"score": 12, "label": "Special Privileges Logon", "category": "privilege_escalation"},
    4673: {"score": 10, "label": "Privileged Service Called","category": "privilege_escalation"},
    4625: {"score":  8, "label": "Failed Logon",             "category": "brute_force"},
    4740: {"score": 12, "label": "Account Locked Out",       "category": "brute_force"},
    4657: {"score": 14, "label": "Registry Value Modified",  "category": "persistence"},
    7045: {"score": 14, "label": "New Service Installed",    "category": "persistence"},
    4104: {"score": 12, "label": "PowerShell Script Block",  "category": "execution"},
    4688: {"score":  4, "label": "New Process Created",      "category": "execution"},
    # FR06-06: DLL injection / process hollowing
    4656: {"score": 20, "label": "Suspicious Handle Request","category": "process_injection"},
    4663: {"score": 15, "label": "Suspicious Object Access", "category": "process_injection"},
    # MEDIUM events
    4648: {"score":  7, "label": "Explicit Credential Use",  "category": "lateral_movement"},
    4771: {"score":  7, "label": "Kerberos Pre-Auth Failed", "category": "brute_force"},
    4776: {"score":  5, "label": "NTLM Auth Attempt",        "category": "brute_force"},
    4798: {"score":  8, "label": "Local Group Enumerated",   "category": "reconnaissance"},
    4799: {"score":  8, "label": "Group Membership Queried", "category": "reconnaissance"},
    4947: {"score": 10, "label": "Firewall Rule Modified",   "category": "defense_evasion"},
    5007: {"score": 10, "label": "Defender Policy Changed",  "category": "defense_evasion"},
    4726: {"score":  8, "label": "User Account Deleted",     "category": "cleanup"},
    4699: {"score":  6, "label": "Scheduled Task Deleted",   "category": "cleanup"},
    # SYSTEM STABILITY events
    41:   {"score":  6, "label": "Kernel Power Failure",     "category": "stability"},
    6008: {"score":  5, "label": "Unexpected Shutdown",      "category": "stability"},
    11:   {"score":  8, "label": "Disk I/O Error",           "category": "hardware"},
    7:    {"score":  9, "label": "Disk Bad Block",           "category": "hardware"},
    7034: {"score":  5, "label": "Service Crashed",          "category": "stability"},
    20:   {"score":  4, "label": "Update Failed",            "category": "patching"},
    # LOW / INFORMATIONAL
    4624: {"score":  1, "label": "Successful Logon",         "category": "authentication"},
    4634: {"score":  0, "label": "Account Logoff",           "category": "authentication"},
    4647: {"score":  0, "label": "User Initiated Logoff",    "category": "authentication"},
    1000: {"score":  2, "label": "Application Crash",        "category": "stability"},
    1001: {"score":  2, "label": "Application Fault",        "category": "stability"},
}

# ── Sysmon EID weights (Step 7 — extends existing EVENT_RISK) ───────────────
EVENT_RISK.update({
    1:  {"score": 12, "label": "Sysmon: Process Create",     "category": "process_creation"},
    3:  {"score": 10, "label": "Sysmon: Network Connection",  "category": "network"},
    11: {"score": 10, "label": "Sysmon: File Create",         "category": "file_activity"},
    13: {"score": 14, "label": "Sysmon: Registry Value Set",  "category": "persistence"},
})

SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3}

# Per-detection severity base (used in compute_system_score)
# Lower than SEVERITY_WEIGHTS — the new scorer relies on confidence
# and diminishing accumulation rather than raw weight.
SEVERITY_BASE = {"CRITICAL": 22, "HIGH": 12, "MEDIUM": 5, "LOW": 2}

# Decay applied to each subsequent detection when accumulating (sorted desc by pts).
# First detection counts 100%, second 60%, third 36%, etc.
# This prevents "N noisy alerts == N× more dangerous".
DETECTION_DECAY = 0.6

# ── HARD EVIDENCE RULES ────────────────────────────────────────────────────
# These rule IDs represent confirmed, high-fidelity malicious activity (not
# heuristic patterns that could be benign admin work). A "Critical" overall
# verdict requires AT LEAST one of these to fire with confidence >= 0.7, OR
# at least one correlator attack chain. Without that, score is capped at 74.
HARD_EVIDENCE_RULES = {
    # Confirmed malware / AV signals
    "MALWARE_DETECTED",
    "AV_DISABLED",
    "AUDIT_POLICY_DISABLED",
    # Real attack patterns (high failure counts, etc.)
    "BRUTE_FORCE",
    "ACCOUNT_LOCKOUT_STORM",
    "KERBEROS_SPRAY",
    # PowerShell offensive tradecraft
    "PS_ENCODED_CMD",
    "PS_AMSI_BYPASS",
    "PS_CREDENTIAL_THEFT",
    # Credential theft / injection
    "DLL_INJECT_LSASS_HANDLE",
    "PROCESS_HOLLOW_SPAWN",
    # Macro & dropper behaviour (Sysmon-confirmed)
    "SYSMON_OFFICE_MACRO_NET",
    "SYSMON_DROPPER_PERSIST",
    "SYSMON_MASS_FILE_MOD",
    # Severe policy tampering
    "GPO_DOMAIN_POLICY_CHANGED",
}

CHAIN_BONUS      = 15   # per confirmed attack chain
OFF_HOURS_BONUS  = 5    # per detection with significant off-hours activity
MAX_SCORE        = 100

# Cap for the "Critical" verdict when no hard evidence is present.
# 74 = top of "High" band — still alarming, still actionable, but does
# not falsely claim the system is owned.
SOFT_CEILING     = 74


def score_event(event_id: int, normalized: dict, context: dict = None) -> dict:
    """
    Score a single event (used by pipeline/worker for per-event scoring).

    Args:
        event_id:   Windows Event ID
        normalized: normalized event dict with hour, weekday, logon_type etc.
        context:    optional aggregated context

    Returns: {score, label, category, multipliers}
    """
    context = context or {}
    base    = EVENT_RISK.get(event_id, {"score": 0, "label": f"Event {event_id}", "category": "other"})
    score   = base["score"]
    applied = []

    # ─── EID 4656 / 4663 LSASS-handle false-positive suppression ─────────────
    # Defender, VS Code, browsers, services.exe etc. routinely open lsass.exe
    # with read-only access. Firing a CRITICAL "Suspicious Handle Request"
    # alert for every one of those events floods the dashboard. If the caller
    # is on the benign list AND no dangerous access bits are set, downgrade
    # the score to 0 so no alert is generated.
    if event_id in (4656, 4663):
        msg = (normalized.get("message") or context.get("message") or "")
        if msg:
            try:
                from core.analysis_engine.threat_detector import (
                    _extract_caller, _is_benign_caller,
                    _extract_access_mask, DANGEROUS_ACCESS_BITS,
                )
                caller = _extract_caller(msg)
                mask   = _extract_access_mask(msg)
                # Only suppress for events explicitly targeting lsass.exe
                if "lsass.exe" in msg.lower():
                    benign_caller    = _is_benign_caller(caller)
                    dangerous_access = bool(mask & DANGEROUS_ACCESS_BITS)
                    if benign_caller and not dangerous_access:
                        return {
                            "score":       0,
                            "label":       base["label"],
                            "category":    base["category"],
                            "multipliers": [f"benign_caller:{caller}"],
                            "suppressed":  True,
                        }
            except Exception:
                # Best-effort filter only — never block scoring on import errors
                pass

    # Off-hours multiplier
    hour = normalized.get("hour")
    if hour is not None and 0 <= hour < 6 and base["category"] in (
        "authentication", "brute_force", "privilege_escalation", "lateral_movement"
    ):
        score = int(score * 1.5)
        applied.append("off_hours")

    # Weekend multiplier
    weekday = normalized.get("weekday")
    if weekday is not None and weekday >= 5 and base["category"] in (
        "authentication", "brute_force"
    ):
        score = int(score * 1.2)
        applied.append("weekend")

    # High failure count
    fail_count = context.get("failed_count_1h", 0)
    if event_id == 4625 and fail_count >= 10:
        score += 12
        applied.append(f"high_failure_count({fail_count})")
    elif event_id == 4625 and fail_count >= 5:
        score += 6
        applied.append(f"moderate_failure_count({fail_count})")

    # New IP bonus for successful logons following failures
    if context.get("is_new_ip") and event_id == 4624:
        score += 8
        applied.append("new_ip_logon")

    # Network logon type bonus
    logon_type = normalized.get("logon_type")
    if logon_type == 3 and event_id in (4624, 4625, 4648):
        score += 3
        applied.append("network_logon")
    elif logon_type == 10 and event_id in (4624, 4625):
        score += 4
        applied.append("remote_interactive_logon")

    return {
        "score":       min(score, 25),
        "label":       base["label"],
        "category":    base["category"],
        "multipliers": applied,
    }


def classify_score(total_score: int) -> dict:
    """Classify a total risk score into a human-readable risk level."""
    if total_score >= 76:
        return {
            "level":   "Critical",
            "color":   "#ef4444",
            "icon":    "🚨",
            "message": "Immediate action required — active threats detected",
        }
    elif total_score >= 51:
        return {
            "level":   "High",
            "color":   "#f97316",
            "icon":    "🔶",
            "message": "Investigate within 2 hours — significant risk detected",
        }
    elif total_score >= 26:
        return {
            "level":   "Suspicious",
            "color":   "#fbbf24",
            "icon":    "⚠️",
            "message": "Review within 24 hours — suspicious patterns detected",
        }
    else:
        return {
            "level":   "Normal",
            "color":   "#22c55e",
            "icon":    "✅",
            "message": "System operating within normal parameters",
        }


def compute_system_score(
    detections: list,
    anomaly_days: int = 0,
    sigma_hits: int = 0,
    yara_hits: int = 0,
    sysmon_chains: int = 0,
    attack_chains_count: int = 0,
) -> dict:
    """
    Compute the overall system risk score.

    REWRITE v3.0 — Evidence-weighted, false-positive-resistant.

    Real Windows systems produce hundreds of "errors" per day (driver
    retries, service hiccups, failed updates, DNS lookups, transient
    handle requests, etc.). The previous formula counted these as raw
    severity points and consistently saturated to 100/Critical on
    normal systems. This rewrite fixes that by:

      1. **Diminishing accumulation** — detections are sorted by per-event
         weight and each subsequent one contributes only 60% as much as
         the one before it. 20 noisy alerts are no longer treated as 20×
         the risk of 1 alert.

      2. **Confidence dampening** — detections with confidence < 0.5
         contribute only ~40% of their nominal weight. Confidence ≥ 0.7
         is required for full weight.

      3. **Sqrt-based frequency factor** (cap 1.5×, was log10 up to 3.0×).
         A spike of 100 events is alarming but not 3× more so than 10.

      4. **Lower bonus caps** for YARA / Sigma / Anomaly contributions —
         these have well-known false-positive rates and should never on
         their own push the score over the Critical threshold.

      5. **Hard-evidence gate** — to reach the Critical band (≥ 75) the
         system must observe at least one of:
             • A HARD_EVIDENCE_RULES detection at confidence ≥ 0.7
             • A correlator-confirmed attack chain
             • A Sysmon-correlated attack chain
         Without hard evidence the score is capped at SOFT_CEILING (74,
         top of "High"). The verdict is still actionable, but the system
         does not falsely report a confirmed compromise.

    Args:
        detections:           list of threat_detector dicts (id, severity,
                              confidence, count, window_hours, off_hours_count)
        anomaly_days:         days flagged by statistical anomaly detector
        sigma_hits:           Sigma rule hits
        yara_hits:            YARA matches
        sysmon_chains:        Sysmon-correlated attack chains
        attack_chains_count:  correlator multi-stage chains

    Returns: {score, classification, breakdown}
    """
    threat_score      = 0.0
    chain_bonus       = 0
    temporal_bonus    = 0
    det_breakdown     = []
    hard_evidence_hit = False
    weighted_pts      = []

    # ── (1) Per-detection points with confidence dampening ──────────────────
    significant_offhours_seen = False
    for d in detections:
        sev    = d.get("severity", "LOW")
        sw     = SEVERITY_BASE.get(sev, 2)
        cnt    = max(d.get("count", 1), 1)
        win    = max(d.get("window_hours", 1), 1)
        rid    = d.get("id", "")
        conf   = float(d.get("confidence", 0.5))

        # Confidence dampening — penalise low-confidence detections
        if conf < 0.5:
            conf_eff = conf * 0.4
        elif conf < 0.7:
            conf_eff = conf * 0.7
        else:
            conf_eff = conf

        # Sqrt-based frequency factor (capped at 1.5)
        # cnt/win → events per hour. 1=1.0, 4=1.2, 25=1.5, 100=1.5
        rate     = min(cnt / win, 100.0)
        freq_mult = min(1.5, 1.0 + math.sqrt(rate) / 10.0)

        pts = sw * conf_eff * freq_mult
        weighted_pts.append(pts)

        # ── Temporal bonus — gated to avoid inflating noise ─────────────────
        # The old version added +5 for ANY detection with off_hours_count>0,
        # even a single LOW-confidence pattern. That pushed score 17 → 29
        # on machines with zero real threats. New gating:
        #   • severity must be HIGH or CRITICAL
        #   • confidence must be ≥ 0.65
        #   • off-hours events must be ≥ 40% of the detection (not just 1
        #     stray weekend event)
        oh = int(d.get("off_hours_count", 0) or 0)
        if oh > 0 and sev in ("HIGH", "CRITICAL") and conf >= 0.65 and oh / max(cnt, 1) >= 0.40:
            significant_offhours_seen = True
            temporal_bonus = min(8, temporal_bonus + OFF_HOURS_BONUS)

        # Hard-evidence flag
        if rid in HARD_EVIDENCE_RULES and conf >= 0.7:
            hard_evidence_hit = True

        det_breakdown.append({
            "rule":       rid,
            "severity":   sev,
            "confidence": d.get("confidence", None),
            "points":     round(pts, 1),
            "hard":       (rid in HARD_EVIDENCE_RULES and conf >= 0.7),
        })

    # ── (2) Diminishing-returns accumulation ─────────────────────────────────
    # Sort highest-weight detections first, then add with geometric decay.
    weighted_pts.sort(reverse=True)
    factor = 1.0
    for pts in weighted_pts:
        threat_score += pts * factor
        factor *= DETECTION_DECAY

    # Threat-score cap lowered: 50 (was 70). Real attacks rarely need >50
    # base points before bonuses; this leaves room for evidence bonuses
    # without instantly saturating.
    threat_score = min(50, threat_score)

    # ── (3) Anomaly score — diminishing ──────────────────────────────────────
    # 1 anomaly day = 4, 2 = 7, 3 = 9, 4+ = 10 (cap)
    if anomaly_days <= 0:
        anom_score = 0
    elif anomaly_days == 1:
        anom_score = 4
    elif anomaly_days == 2:
        anom_score = 7
    elif anomaly_days == 3:
        anom_score = 9
    else:
        anom_score = 10

    # ── (4) Sigma / YARA / Sysmon-chain bonuses — sqrt scaling ───────────────
    # Sigma: 1 hit = 3, 3 = 5, 9 = 9, cap 10
    sigma_bonus  = min(10, int(math.sqrt(max(sigma_hits, 0)) * 3.2))
    # YARA: 1 hit = 4, 3 = 6, 9 = 11, cap 12
    yara_bonus   = min(12, int(math.sqrt(max(yara_hits,  0)) * 3.7))
    # Sysmon attack chains — high-fidelity, count toward hard evidence
    sysmon_bonus = min(15, sysmon_chains * 8)
    if sysmon_chains > 0:
        hard_evidence_hit = True

    # Correlator-confirmed multi-stage attack chains — strongest signal
    chain_bonus = min(20, attack_chains_count * 12)
    if attack_chains_count > 0:
        hard_evidence_hit = True

    # ── (5) Sum and apply hard-evidence gate ─────────────────────────────────
    raw = int(round(
        threat_score
        + chain_bonus
        + temporal_bonus
        + anom_score
        + sigma_bonus
        + yara_bonus
        + sysmon_bonus
    ))

    soft_gate_applied = False
    if not hard_evidence_hit and raw > SOFT_CEILING:
        raw = SOFT_CEILING
        soft_gate_applied = True

    raw = max(0, min(MAX_SCORE, raw))

    return {
        "score":          raw,
        "classification": classify_score(raw),
        "breakdown": {
            "threat_score":        round(threat_score, 1),
            "log_base":            round(threat_score, 1),  # UI alias
            "chain_bonus":         chain_bonus,
            "temporal_bonus":      temporal_bonus,
            "anomaly_score":       anom_score,
            "sigma_bonus":         sigma_bonus,
            "yara_bonus":          yara_bonus,
            "sysmon_chain_bonus":  sysmon_bonus,
            "hard_evidence":       hard_evidence_hit,
            "soft_gate_applied":   soft_gate_applied,
            "soft_ceiling":        SOFT_CEILING,
            "detection_count":     len(detections),
            "detail":              det_breakdown,
        },
    }
