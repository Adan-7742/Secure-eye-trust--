"""
core/pipeline/rule_engine.py
==============================
Per-event rule engine — fires on INDIVIDUAL events as they arrive.

This is NOT the same as threat_detector.py (which scans the DB for patterns).
This runs on each event IN REAL TIME as it passes through the pipeline,
before it is even stored. Results feed directly into the alert bus.

Rules here are stateless per-event checks:
  - Single event ID matches a known critical signature
  - IP/user in a known watchlist
  - Specific message keywords indicating immediate threat

For multi-event correlation (brute force over time), see correlator.py.
"""

from utils.logger import get_logger

log = get_logger("pipeline.rule_engine")

# ── Immediate-fire event ID rules ─────────────────────────────────────────────
# These event IDs are serious enough to fire an alert on ANY single occurrence.

IMMEDIATE_RULES = {
    # Audit policy disabled — top priority
    4719: {
        "name":        "Audit Policy Tampered",
        "severity":    "CRITICAL",
        "description": "Security audit policy was changed — attacker may be disabling logging.",
        "category":    "defense_evasion",
    },
    # Malware
    1116: {
        "name":        "Malware Detected",
        "severity":    "CRITICAL",
        "description": "Windows Defender detected malware. Immediate investigation required.",
        "category":    "malware",
    },
    1117: {
        "name":        "Malware Action Taken",
        "severity":    "CRITICAL",
        "description": "Windows Defender took action against a detected threat.",
        "category":    "malware",
    },
    1120: {
        "name":        "Malware Removal Failed",
        "severity":    "CRITICAL",
        "description": "Windows Defender could not remove the detected threat. System may be infected.",
        "category":    "malware",
    },
    5001: {
        "name":        "Antivirus Disabled",
        "severity":    "CRITICAL",
        "description": "Windows Defender real-time protection was disabled.",
        "category":    "defense_evasion",
    },
    # Admin group change
    4728: {
        "name":        "User Added to Admin Group",
        "severity":    "CRITICAL",
        "description": "A user was added to the Administrators group — full system access granted.",
        "category":    "privilege_escalation",
    },
    4732: {
        "name":        "User Added to Local Group",
        "severity":    "HIGH",
        "description": "A user was added to a privileged local group.",
        "category":    "privilege_escalation",
    },
    # New account
    4720: {
        "name":        "New User Account Created",
        "severity":    "HIGH",
        "description": "A new Windows user account was created — possible backdoor.",
        "category":    "persistence",
    },
    # Scheduled task / service persistence
    4698: {
        "name":        "Scheduled Task Created",
        "severity":    "HIGH",
        "description": "New scheduled task created — common persistence mechanism.",
        "category":    "persistence",
    },
    7045: {
        "name":        "New Service Installed",
        "severity":    "HIGH",
        "description": "New Windows service installed — possible malware persistence.",
        "category":    "persistence",
    },
    # Registry
    4657: {
        "name":        "Registry Modified",
        "severity":    "HIGH",
        "description": "Windows registry value modified — check for persistence keys.",
        "category":    "persistence",
    },
    # Firewall
    4946: {
        "name":        "Firewall Rule Added",
        "severity":    "HIGH",
        "description": "New inbound firewall rule — possible backdoor access.",
        "category":    "defense_evasion",
    },
    4950: {
        "name":        "Firewall Disabled",
        "severity":    "CRITICAL",
        "description": "Windows Firewall was disabled.",
        "category":    "defense_evasion",
    },
    # Disk failure
    11: {
        "name":        "Disk I/O Error",
        "severity":    "HIGH",
        "description": "Disk I/O error detected — potential drive failure. Back up data now.",
        "category":    "hardware",
    },
    7: {
        "name":        "Disk Bad Block",
        "severity":    "HIGH",
        "description": "Disk has bad sectors — imminent drive failure risk.",
        "category":    "hardware",
    },
}

# ── Threshold-based rules (count within a window, checked per-event) ──────────
# These maintain a rolling counter and fire when the threshold is crossed.

THRESHOLD_RULES = [
    {
        "id":        "BRUTE_FORCE_INSTANT",
        "event_ids": [4625],
        "window_s":  300,    # 5 minutes
        "threshold": 5,
        "name":      "Brute Force Detected",
        "severity":  "CRITICAL",
        "description": "5+ failed logon attempts in 5 minutes — active brute force attack.",
        "category":  "brute_force",
    },
    {
        "id":        "ACCOUNT_LOCKOUT_BURST",
        "event_ids": [4740],
        "window_s":  300,
        "threshold": 3,
        "name":      "Account Lockout Burst",
        "severity":  "HIGH",
        "description": "3+ account lockouts in 5 minutes.",
        "category":  "brute_force",
    },
    {
        "id":        "PRIVILEGE_SPIKE",
        "event_ids": [4672, 4673],
        "window_s":  300,
        "threshold": 10,
        "name":      "Privilege Escalation Spike",
        "severity":  "HIGH",
        "description": "10+ privilege assignment events in 5 minutes.",
        "category":  "privilege_escalation",
    },
    {
        "id":        "RECON_SPIKE",
        "event_ids": [4798, 4799],
        "window_s":  120,
        "threshold": 5,
        "name":      "Reconnaissance Activity",
        "severity":  "HIGH",
        "description": "Rapid group/account enumeration — possible attacker mapping the network.",
        "category":  "reconnaissance",
    },
]


class RuleEngine:
    """Per-event rule engine. Maintains rolling counters for threshold rules."""

    def __init__(self):
        import time
        # counter: rule_id → list of timestamps
        self._counters: dict[str, list] = {r["id"]: [] for r in THRESHOLD_RULES}
        self._lock = __import__("threading").Lock()

    def check_event(self, event: dict, norm: dict, category: str, risk_score: int) -> list:
        """
        Check a single event against all rules.
        Returns list of alert dicts (may be empty).
        """
        alerts = []
        eid    = int(event.get("event_id") or 0)
        now    = __import__("time").time()

        # Check immediate-fire rules
        if eid in IMMEDIATE_RULES:
            rule = IMMEDIATE_RULES[eid]
            alert = {
                "type":       "rule_match",
                "name":       rule["name"],
                "severity":   rule["severity"],
                "category":   rule["category"],
                "event_id":   eid,
                "description": rule["description"],
                "source":     event.get("source"),
                "user":       norm.get("user"),
                "ip":         norm.get("ip"),
                "timestamp":  event.get("timestamp"),
                "message":    (event.get("message") or "")[:200],
                "risk_score": risk_score,
            }
            alerts.append(alert)
            log.info(f"Immediate rule fired: {rule['name']} (EID {eid})")

        # Check threshold rules
        with self._lock:
            for rule in THRESHOLD_RULES:
                if eid not in rule["event_ids"]:
                    continue

                # Add current timestamp
                self._counters[rule["id"]].append(now)

                # Evict expired timestamps
                cutoff = now - rule["window_s"]
                self._counters[rule["id"]] = [
                    t for t in self._counters[rule["id"]] if t >= cutoff
                ]

                count = len(self._counters[rule["id"]])
                if count >= rule["threshold"]:
                    # Only fire once per threshold crossing (not on every event above threshold)
                    if count == rule["threshold"]:
                        alert = {
                            "type":        "threshold_rule",
                            "id":          rule["id"],
                            "name":        rule["name"],
                            "severity":    rule["severity"],
                            "category":    rule["category"],
                            "event_id":    eid,
                            "count":       count,
                            "window_s":    rule["window_s"],
                            "description": rule["description"],
                            "source":      event.get("source"),
                            "user":        norm.get("user"),
                            "ip":          norm.get("ip"),
                            "timestamp":   event.get("timestamp"),
                            "risk_score":  risk_score,
                        }
                        alerts.append(alert)
                        log.warning(f"Threshold rule fired: {rule['name']} ({count}/{rule['threshold']} in {rule['window_s']}s)")

        return alerts
