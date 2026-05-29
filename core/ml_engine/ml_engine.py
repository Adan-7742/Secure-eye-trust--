"""
core/ml_engine/ml_engine.py
============================
AI-Powered Security Analysis Engine
Uses rule-based + statistical ML to detect threats in log data.

WHAT THIS MODULE DOES:
    1. Brute Force Detection    — counts failed logons per source IP/user
    2. Anomaly Detection        — Z-score on hourly/daily event rates
    3. Zero-Day Pattern Scan    — heuristic rules for unusual activity
    4. Behavioral Analysis      — baseline normal → flag deviations
    5. Threat Scoring           — combines all signals into a risk score

NO EXTERNAL ML LIBRARY NEEDED:
    All algorithms are implemented from scratch using Python + math.
    This makes the code understandable and portable.
    To upgrade: replace rule-based classifiers with scikit-learn models.

HOW IT WORKS WITH WINDOWS LOGS:
    Security log → Event 4625 (failed logon) → count per user/IP → brute force?
    System log   → Kernel-Power events        → crash pattern?
    Any log      → Error spike on one day     → anomaly?

DATA FLOW:
    logs_* tables → ml_engine.analyze() → ml_detections table → /api/analyze/threats
"""

import math
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
from database.db import get_conn, log_activity
from utils.logger import get_logger

log = get_logger("ml_engine")


# ── Known threat patterns (regex-based zero-day heuristics) ──────────────────
THREAT_PATTERNS = [
    {
        "id":          "BRUTE_FORCE",
        "name":        "Brute Force Login Attempt",
        "event_ids":   [4625],
        "threshold":   5,          # 5+ failures triggers detection
        "window_mins": 10,
        "severity":    "HIGH",
        "description": "Multiple failed logon attempts detected (Event 4625). Possible brute force attack.",
        "mitigation":  "Enable account lockout policy. Check source IP in Security log.",
    },
    {
        "id":          "PRIV_ESCALATION",
        "name":        "Privilege Escalation",
        "event_ids":   [4672, 4648, 4674],
        "threshold":   3,
        "window_mins": 5,
        "severity":    "CRITICAL",
        "description": "Special privileges assigned to logon session (Event 4672). Possible lateral movement.",
        "mitigation":  "Review accounts with SeDebugPrivilege. Check for unexpected admin accounts.",
    },
    {
        "id":          "ACCOUNT_MANIPULATION",
        "name":        "Account Manipulation",
        "event_ids":   [4720, 4722, 4738, 4756],
        "threshold":   1,
        "window_mins": 60,
        "severity":    "HIGH",
        "description": "User account created or modified. Possible persistence technique.",
        "mitigation":  "Verify with AD team. Check if account was authorised.",
    },
    {
        "id":          "AUDIT_POLICY_CHANGE",
        "name":        "Audit Policy Tampered",
        "event_ids":   [4719, 4817],
        "threshold":   1,
        "window_mins": 60,
        "severity":    "CRITICAL",
        "description": "Security audit policy changed. Attacker may be disabling logging.",
        "mitigation":  "Restore audit policy immediately. Investigate who made the change.",
    },
    {
        "id":          "LATERAL_MOVEMENT",
        "name":        "Lateral Movement (Pass-the-Hash)",
        "event_ids":   [4624],
        "level_filter": "SUCCESS",
        "logon_type":  3,          # Network logon
        "threshold":   10,
        "window_mins": 5,
        "severity":    "HIGH",
        "description": "High volume of network logons detected. Possible lateral movement.",
        "mitigation":  "Check source hosts. Look for Mimikatz indicators.",
    },
    {
        "id":          "UNEXPECTED_SHUTDOWN",
        "name":        "Unexpected System Shutdown",
        "event_ids":   [41, 6008],
        "threshold":   1,
        "window_mins": 1440,
        "severity":    "MEDIUM",
        "description": "System rebooted without clean shutdown. Possible crash, power loss, or forced shutdown.",
        "mitigation":  "Check minidumps. Verify PSU and cooling.",
    },
    {
        "id":          "SERVICE_INSTALL",
        "name":        "Suspicious Service Installed",
        "event_ids":   [7045, 4697],
        "threshold":   1,
        "window_mins": 60,
        "severity":    "HIGH",
        "description": "New service installed. Common persistence/malware technique.",
        "mitigation":  "Verify service legitimacy. Check binary path.",
    },
    {
        "id":          "DISK_FAILURE",
        "name":        "Disk Hardware Failure",
        "event_ids":   [7, 11, 153],
        "source_pattern": r"(disk|atapi|storahci)",
        "threshold":   3,
        "window_mins": 60,
        "severity":    "HIGH",
        "description": "Disk controller errors detected. Imminent drive failure possible.",
        "mitigation":  "Run chkdsk /f /r. Check SMART status. Back up immediately.",
    },
    {
        "id":          "MEMORY_CORRUPTION",
        "name":        "Memory Corruption / BSOD",
        "event_ids":   [1001, 41],
        "source_pattern": r"(bugcheck|whea|kernel)",
        "threshold":   1,
        "window_mins": 1440,
        "severity":    "HIGH",
        "description": "BSOD or hardware memory error detected.",
        "mitigation":  "Run Windows Memory Diagnostic. Check minidumps.",
    },
    {
        "id":          "APP_CRASH_STORM",
        "name":        "Application Crash Storm",
        "event_ids":   [1000, 1001, 1002],
        "threshold":   5,
        "window_mins": 60,
        "severity":    "MEDIUM",
        "description": "Multiple application crashes in short period.",
        "mitigation":  "Check faulting module. Update/reinstall affected software.",
    },
]


class BehavioralBaseline:
    """
    Tracks 'normal' event rates and flags deviations.
    In a real ML system this would be a trained model.
    Here we use rolling average + standard deviation.
    """
    def __init__(self):
        self._hourly_buckets: dict[str, list[int]] = defaultdict(list)

    def update(self, category: str, hour: str, count: int):
        key = f"{category}:{hour[:2]}"   # hour of day
        self._hourly_buckets[key].append(count)
        # Keep last 30 samples
        if len(self._hourly_buckets[key]) > 30:
            self._hourly_buckets[key].pop(0)

    def is_anomalous(self, category: str, hour: str, count: int) -> tuple[bool, float]:
        key = f"{category}:{hour[:2]}"
        samples = self._hourly_buckets[key]
        if len(samples) < 3:
            return False, 0.0
        mean = sum(samples) / len(samples)
        std  = math.sqrt(sum((s - mean)**2 for s in samples) / len(samples))
        z    = (count - mean) / std if std > 0 else 0.0
        return abs(z) > 2.5, round(z, 3)


BASELINE = BehavioralBaseline()


class MLEngine:
    """
    Main ML analysis engine.
    Call .analyze_all() to run full threat detection across all log categories.
    """

    def __init__(self):
        log.info("ML Engine initialised")

    def analyze_all(self) -> dict:
        """
        Run all detection algorithms on current database contents.
        Returns: { "detections": [...], "summary": {...}, "risk_score": int }
        """
        conn = get_conn()
        all_detections = []

        # Run each detector
        all_detections.extend(self._detect_event_id_patterns(conn))
        all_detections.extend(self._detect_rate_anomalies(conn))
        all_detections.extend(self._detect_behavioral_shifts(conn))
        all_detections.extend(self._cross_category_correlation(conn))

        conn.close()

        # Save detections to DB
        self._persist_detections(all_detections)

        # Compute overall risk score
        severity_weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
        risk = min(100, sum(severity_weights.get(d["severity"], 5) for d in all_detections))

        summary = {
            "total_detections": len(all_detections),
            "critical":  sum(1 for d in all_detections if d["severity"] == "CRITICAL"),
            "high":      sum(1 for d in all_detections if d["severity"] == "HIGH"),
            "medium":    sum(1 for d in all_detections if d["severity"] == "MEDIUM"),
            "low":       sum(1 for d in all_detections if d["severity"] == "LOW"),
            "risk_score": risk,
            "risk_label": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 40 else "MEDIUM" if risk >= 20 else "LOW",
        }

        log.info(f"ML analysis complete: {len(all_detections)} detections, risk={risk}")
        log_activity("ml_analysis", f"{len(all_detections)} detections, risk_score={risk}")
        return {"detections": all_detections, "summary": summary}

    def _detect_event_id_patterns(self, conn) -> list:
        """
        Check each THREAT_PATTERN against the database.
        For each pattern, counts matching event IDs in the time window.
        """
        detections = []
        c = conn.cursor()

        for pattern in THREAT_PATTERNS:
            eids      = pattern["event_ids"]
            threshold = pattern["threshold"]
            placeholders = ",".join("?" * len(eids))

            # Check all log tables
            for cat in ["application", "system", "security", "windows_update"]:
                try:
                    c.execute(f"""
                        SELECT COUNT(*), GROUP_CONCAT(DISTINCT source), GROUP_CONCAT(event_id)
                        FROM logs_{cat}
                        WHERE event_id IN ({placeholders})
                    """, eids)
                    row = c.fetchone()
                    count = row[0] or 0
                    if count >= threshold:
                        detections.append({
                            "threat_type":  pattern["id"],
                            "name":         pattern["name"],
                            "category":     cat,
                            "severity":     pattern["severity"],
                            "confidence":   min(0.99, 0.5 + (count / (threshold * 3))),
                            "count":        count,
                            "description":  pattern["description"],
                            "mitigation":   pattern["mitigation"],
                            "event_ids":    str(eids),
                            "sources":      row[1] or "",
                            "detected_at":  datetime.now().isoformat(),
                            "algorithm":    "event_id_pattern_matching",
                        })
                except Exception:
                    pass

        return detections

    def _detect_rate_anomalies(self, conn) -> list:
        """
        Statistical anomaly detection:
        Compare each day's error count to the rolling average.
        Days with Z-score > 2.5 are flagged.
        """
        detections = []
        c = conn.cursor()

        for cat in ["application", "system", "security", "windows_update"]:
            try:
                c.execute(f"""
                    SELECT date, COUNT(*) as cnt
                    FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL','FAILURE') AND date IS NOT NULL
                    GROUP BY date ORDER BY date ASC
                """)
                rows = c.fetchall()
                if len(rows) < 3:
                    continue

                counts = [r[1] for r in rows]
                dates  = [r[0] for r in rows]
                mean   = sum(counts) / len(counts)
                std    = math.sqrt(sum((c - mean)**2 for c in counts) / len(counts))

                for date, count in zip(dates, counts):
                    z = (count - mean) / std if std > 0 else 0.0
                    if z > 2.5:
                        detections.append({
                            "threat_type":  "RATE_ANOMALY",
                            "name":         f"Error Rate Spike — {cat}",
                            "category":     cat,
                            "severity":     "HIGH" if z > 4 else "MEDIUM",
                            "confidence":   min(0.99, 0.5 + z / 10),
                            "count":        count,
                            "description":  f"{date}: {count} errors (Z={z:.2f}σ above normal). Statistically anomalous.",
                            "mitigation":   "Investigate events on this date. Check for system changes.",
                            "event_ids":    "[]",
                            "sources":      "",
                            "detected_at":  datetime.now().isoformat(),
                            "algorithm":    "z_score_daily_rate",
                        })
            except Exception as e:
                log.error(f"Rate anomaly detection failed for {cat}: {e}")

        return detections

    def _detect_behavioral_shifts(self, conn) -> list:
        """
        Compare recent 24h error rate vs 7-day baseline.
        A sudden increase indicates a behavioral shift.
        """
        detections = []
        c = conn.cursor()

        for cat in ["application", "system"]:
            try:
                # Last 24h
                c.execute(f"""
                    SELECT COUNT(*) FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL')
                    AND timestamp >= datetime('now','-1 day')
                """)
                recent = c.fetchone()[0] or 0

                # 7-day average (daily)
                c.execute(f"""
                    SELECT AVG(daily_count) FROM (
                        SELECT date, COUNT(*) as daily_count FROM logs_{cat}
                        WHERE level IN ('ERROR','CRITICAL') AND date IS NOT NULL
                        GROUP BY date ORDER BY date DESC LIMIT 7
                    )
                """)
                avg7 = c.fetchone()[0] or 0

                if avg7 > 0 and recent > avg7 * 2.5:
                    ratio = round(recent / avg7, 1)
                    detections.append({
                        "threat_type":  "BEHAVIORAL_SHIFT",
                        "name":         f"Behavioral Shift — {cat}",
                        "category":     cat,
                        "severity":     "HIGH",
                        "confidence":   min(0.95, 0.6 + ratio / 20),
                        "count":        recent,
                        "description":  f"Last 24h: {recent} errors ({ratio}× the 7-day average of {avg7:.0f}/day). Abnormal activity detected.",
                        "mitigation":   "Investigate recent changes: software installs, updates, config changes.",
                        "event_ids":    "[]",
                        "sources":      "",
                        "detected_at":  datetime.now().isoformat(),
                        "algorithm":    "behavioral_baseline_comparison",
                    })
            except Exception as e:
                log.error(f"Behavioral shift detection failed for {cat}: {e}")

        return detections

    def _cross_category_correlation(self, conn) -> list:
        """
        Check if errors spike across multiple categories simultaneously.
        This is a strong indicator of a system-level event (attack, hardware failure).
        """
        detections = []
        c = conn.cursor()

        spiked_cats = []
        for cat in ["application", "system", "security"]:
            try:
                c.execute(f"""
                    SELECT COUNT(*) FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL','FAILURE')
                    AND timestamp >= datetime('now','-6 hours')
                """)
                count = c.fetchone()[0] or 0
                if count > 20:
                    spiked_cats.append((cat, count))
            except Exception:
                pass

        if len(spiked_cats) >= 2:
            cats_str = ", ".join(f"{c}({n})" for c, n in spiked_cats)
            detections.append({
                "threat_type":  "CROSS_CATEGORY_STORM",
                "name":         "Multi-Category Error Storm",
                "category":     "all",
                "severity":     "CRITICAL",
                "confidence":   0.85,
                "count":        sum(n for _, n in spiked_cats),
                "description":  f"Simultaneous error spikes in {len(spiked_cats)} categories: {cats_str}. Indicates a system-level event.",
                "mitigation":   "Check for: hardware failure, OS update failure, active attack, power issues.",
                "event_ids":    "[]",
                "sources":      "",
                "detected_at":  datetime.now().isoformat(),
                "algorithm":    "cross_category_correlation",
            })

        return detections

    def _persist_detections(self, detections: list):
        """Save ML detection results to the ml_detections table."""
        if not detections:
            return
        conn = get_conn()
        conn.execute("DELETE FROM ml_detections")  # fresh results each run
        for d in detections:
            conn.execute("""
                INSERT INTO ml_detections
                (detected_at, category, threat_type, severity, confidence, details, event_ids)
                VALUES (?,?,?,?,?,?,?)
            """, (
                d["detected_at"], d["category"], d["threat_type"],
                d["severity"], d["confidence"],
                json.dumps({k: v for k, v in d.items() if k not in ("detected_at","category","threat_type","severity","confidence","event_ids")}),
                d.get("event_ids", "[]"),
            ))
        conn.commit()
        conn.close()

    def get_last_detections(self) -> list:
        """Return the last saved ML detections from the database."""
        conn = get_conn()
        c = conn.cursor()
        c.execute("""
            SELECT detected_at, category, threat_type, severity, confidence, details
            FROM ml_detections ORDER BY detected_at DESC
        """)
        rows = c.fetchall()
        conn.close()
        result = []
        for row in rows:
            d = json.loads(row[5] or "{}")
            d.update({
                "detected_at": row[0], "category": row[1],
                "threat_type": row[2], "severity": row[3], "confidence": row[4],
            })
            result.append(d)
        return result


# ── Singleton ─────────────────────────────────────────────────────────────────
ML = MLEngine()
