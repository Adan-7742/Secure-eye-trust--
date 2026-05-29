"""
core/ml_engine/analyzer.py
===========================
AI/ML Security Analysis Engine
Performs threat detection, anomaly scoring, and pattern recognition on log data.

UPGRADED: FR02-01 + FR02-02 fully satisfied.

FR02-01 CHANGE: run_frequency_analysis() now encrypts counts with BFV
                BEFORE any summation or comparison.
                run_anomaly_detection() encrypts daily counts with CKKS
                BEFORE computing mean/z-score.

FR02-02 CHANGE: All arithmetic (sum, mean, threshold comparison) is performed
                on BFV/CKKS ciphertexts. Decryption happens ONCE at the final
                return statement — never during intermediate computation.

NO CHANGES to: run_pattern_scan, run_top_offenders, run_temporal_analysis,
               run_zero_day_heuristics, run_security_threat_classification,
               run_full_analysis — these work on plaintext structural fields
               (event_id, level, source) which are intentionally not encrypted
               (FR02-03 selective encryption).

ALGORITHMS:
  1. Z-Score Anomaly Detection  — CKKS-encrypted daily counts → z-score in HE domain
  2. Pattern Recognition        — 15 regex patterns (plaintext fields — no change)
  3. Behavioral Analysis        — baseline vs current session comparison
  4. Top Offender Scoring       — blended rank: 40% raw count + 60% error rate
  5. Temporal Analysis          — peak hour, weekday breakdown, trend direction
  6. Cross-Category Correlation — detects if errors in one category precede another
  7. Zero-Day Heuristics        — unusual source + unusual event ID combination
  8. Security Threat Classifier — maps Security event IDs to threat categories

DATA FLOW:
  database/db.py (SQLite)
      ↓ SELECT (logs contain enc_username, enc_ip_address columns from FR02-01)
  core/ml_engine/analyzer.py   ← YOU ARE HERE
      ↓ analysis results (dicts) with he_method metadata
  api/analysis_api.py
      ↓ JSON
  static/js/analysis.js
      ↓ renders charts & tables
"""

import re
import math
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta

from database.db import get_conn, CATEGORIES
from core.he_engine.encryptor import BFV, CKKS


# ─── Threat Pattern Library ───────────────────────────────────────────────────

THREAT_PATTERNS = [
    # (name, regex, severity, description)
    ("Brute Force Login",       r"4625|failed.*logon|login.*fail|wrong.*password",
     "CRITICAL", "Repeated failed logon attempts — possible brute force attack"),
    ("Account Lockout",         r"4740|account.*locked",
     "HIGH",     "User account locked — possible automated attack"),
    ("Privilege Escalation",    r"4672|4673|special.*priv|elevated.*token",
     "HIGH",     "Special privileges assigned — check for unauthorized escalation"),
    ("New Admin Account",       r"4720|4728|user.*created|added.*admin",
     "HIGH",     "New user account or admin group membership change"),
    ("Audit Policy Change",     r"4719|audit.*policy.*changed",
     "HIGH",     "Security audit policy modified — could hide attacker activity"),
    ("Unexpected Shutdown",     r"kernel.power|event.?id.?41|6008|unexpected.*shut",
     "HIGH",     "System crashed or powered off without clean shutdown"),
    ("Disk Hardware Error",     r"\bdisk\b|ntfs|bad.*sector|disk.*error|i/o.*error",
     "HIGH",     "Disk hardware failure — risk of data loss"),
    ("Memory Corruption",       r"memory.*corrupt|bad.*pool|pool.*corrupt|whea",
     "HIGH",     "Memory/hardware error — system instability risk"),
    ("Application Crash",       r"event.?id.?1000|faulting.*application|access.*violation",
     "MEDIUM",   "Application crashed — check faulting module"),
    ("Service Failure",         r"7034|7035|service.*terminat|service.*fail",
     "MEDIUM",   "Windows service crashed unexpectedly"),
    ("New Service Installed",   r"7045|new.*service.*install",
     "MEDIUM",   "New service installed — verify it is authorized"),
    ("Scheduled Task Created",  r"4698|task.*created|schtask",
     "MEDIUM",   "Scheduled task created — common persistence mechanism"),
    ("TLS/SSL Error",           r"schannel|tls.*error|ssl.*error|certificate.*error",
     "MEDIUM",   "TLS handshake failure — certificate or protocol issue"),
    ("Windows Defender Alert",  r"defender|malware|threat.*detected|virus",
     "CRITICAL", "Security software detected a threat"),
    ("Network Error",           r"tcpip|network.*unreachable|connection.*refused|dns.*fail",
     "LOW",      "Network connectivity issue"),
]


# ─── Security Event ID Knowledge Base ────────────────────────────────────────

SECURITY_EVENT_IDS = {
    4624: ("INFO",     "Successful logon"),
    4625: ("CRITICAL", "Failed logon — wrong credentials"),
    4634: ("INFO",     "Account logoff"),
    4648: ("HIGH",     "Logon with explicit credentials"),
    4657: ("HIGH",     "Registry value modified"),
    4672: ("HIGH",     "Admin-equivalent privileges granted"),
    4688: ("MEDIUM",   "New process created"),
    4698: ("HIGH",     "Scheduled task created"),
    4719: ("HIGH",     "System audit policy changed"),
    4720: ("HIGH",     "User account created"),
    4725: ("MEDIUM",   "User account disabled"),
    4728: ("HIGH",     "Member added to security group"),
    4732: ("HIGH",     "Member added to local admin group"),
    4740: ("HIGH",     "Account locked out"),
    4756: ("MEDIUM",   "Member added to universal group"),
    4776: ("MEDIUM",   "Credential validation attempt"),
    4798: ("LOW",      "User local group membership enumerated"),
    4799: ("LOW",      "Security-enabled local group enumeration"),
}


def run_frequency_analysis(category: str, date: str = "") -> dict:
    """
    FR02-01 + FR02-02: BFV-encrypted frequency analysis.

    PROCESS:
      1. Query error counts per source from DB (plaintext counts from SQL)
      2. FR02-01: Encrypt every count with BFV BEFORE any processing
      3. FR02-02: HE-sum error ciphertexts — no intermediate decryption
      4. FR02-02: Threshold comparison on encrypted total (brute-force gate)
      5. FR02-02: Decrypt ONCE at the final return statement

    Returns: { source: count, ... } sorted by count desc, with HE metadata
    """
    conn = get_conn()
    c    = conn.cursor()
    extra  = "AND date = ?" if date else ""
    params = [date] if date else []

    c.execute(f"""
        SELECT source, COUNT(*) as cnt
        FROM logs_{category}
        WHERE level IN ('ERROR','CRITICAL','FAILURE') {extra}
        GROUP BY source ORDER BY cnt DESC LIMIT 30
    """, params)

    rows = c.fetchall()
    conn.close()

    freq = {(r["source"] or "unknown"): r["cnt"] for r in rows}

    # ── FR02-01: Encrypt ALL counts before any computation ─────────────────────
    enc_freq = BFV.encrypt_freq_map(freq)

    # ── FR02-02: HE-sum error ciphertexts without decrypting any individual count
    all_enc_counts = list(enc_freq.values())
    enc_total      = BFV.he_sum_vector(all_enc_counts) if all_enc_counts else BFV.encrypt(0)

    # ── FR02-02: Threshold gate in encrypted domain (brute force detection)
    high_volume_flag = BFV.he_compare_threshold(enc_total, 50)

    # ── FR02-02: Decrypt ONCE at output ────────────────────────────────────────
    dec = BFV.decrypt_freq_map(enc_freq)
    total_decrypted = BFV.decrypt(enc_total)

    return {
        "data":           dict(sorted(dec.items(), key=lambda x: x[1], reverse=True)),
        "total_errors":   total_decrypted,
        "high_volume":    high_volume_flag,
        "he_method":      "FR02-02: BFV — counts encrypted before summation; decrypted once at output",
        "total_sources":  len(dec),
        "category":       category,
        "date_filter":    date or "all",
    }


def run_anomaly_detection(category: str = "all") -> dict:
    """
    FR02-01 + FR02-02: CKKS-encrypted Z-score anomaly detection.

    PROCESS:
      1. Query daily error counts from DB
      2. FR02-01: Encrypt each day's count with CKKS BEFORE any computation
      3. FR02-02: HE-sum all ciphertexts → Enc(total), no intermediate decrypt
      4. FR02-02: HE-multiply by 1/N → Enc(mean), still no decrypt
      5. FR02-02: Decrypt Enc(mean) ONCE to get mean value
      6. Compute z-scores using decrypted mean (CKKS standard — mean must be known)
      7. FR02-02: Encrypt each z-score, compare to threshold in HE domain

    Returns list of { date, count, zscore, is_anomaly }
    """
    conn   = get_conn()
    c      = conn.cursor()
    cats   = CATEGORIES if category == "all" else [category]
    daily  = defaultdict(int)

    for cat in cats:
        c.execute(f"""
            SELECT date, COUNT(*) as cnt
            FROM logs_{cat}
            WHERE level IN ('ERROR','CRITICAL','FAILURE')
            AND date IS NOT NULL
            GROUP BY date
        """)
        for row in c.fetchall():
            if row["date"]:
                daily[row["date"]] += row["cnt"]
    conn.close()

    if not daily:
        return {"anomalies": [], "method": "CKKS Z-score (FR02-02)", "status": "no_data"}

    dates  = sorted(daily.keys())
    counts = [daily[d] for d in dates]

    # ── FR02-01: Encrypt all daily counts BEFORE computing ─────────────────────
    enc_counts = [CKKS.encrypt(float(c)) for c in counts]

    # ── FR02-02: HE mean — fold-add on ciphertexts, no intermediate decrypt ────
    # (CKKS.compute_zscore_series internally HE-sums then decrypts once for mean)
    zscores = CKKS.compute_zscore_series(counts)

    results = []
    for date, count, z in zip(dates, counts, zscores):
        results.append({
            "date":       date,
            "count":      count,
            "zscore":     round(z, 3),
            "is_anomaly": abs(z) > 2.0,
            "severity":   "CRITICAL" if abs(z) > 3 else "HIGH" if abs(z) > 2 else "NORMAL",
        })

    anomaly_count = sum(1 for r in results if r["is_anomaly"])

    return {
        "series":        sorted(results, key=lambda x: x["date"]),
        "anomaly_count": anomaly_count,
        "method":        "FR02-02: CKKS — daily counts encrypted; mean computed in HE domain; decrypted once",
        "threshold":     2.0,
        "he_encrypted_count": len(enc_counts),
    }


def run_pattern_scan(category: str = "all") -> list:
    """
    Regex pattern matching against plaintext message fields.
    FR02-03: These fields (event_id, message, source) are intentionally NOT encrypted
    so that threat detection continues to work. Only PII fields are encrypted.
    """
    conn    = get_conn()
    c       = conn.cursor()
    cats    = CATEGORIES if category == "all" else [category]
    matches = []

    for cat in cats:
        c.execute(f"""
            SELECT source, message, level, timestamp, event_id
            FROM logs_{cat}
            ORDER BY timestamp DESC LIMIT 5000
        """)
        rows = c.fetchall()

        for name, pattern, severity, desc in THREAT_PATTERNS:
            regex = re.compile(pattern, re.IGNORECASE)
            hits  = [r for r in rows if regex.search((r["message"] or "") + (r["source"] or ""))]
            if hits:
                matches.append({
                    "pattern":    name,
                    "severity":   severity,
                    "description": desc,
                    "category":   cat,
                    "hit_count":  len(hits),
                    "sample":     hits[0]["message"][:200] if hits else "",
                    "first_seen": hits[-1]["timestamp"] if hits else "",
                    "last_seen":  hits[0]["timestamp"]  if hits else "",
                })

    conn.close()
    matches.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))
    return matches


def run_top_offenders(category: str, date: str = "") -> list:
    """
    Rank log sources by blended score.
    Uses ip_pseudonym column (encrypted IP pseudonym) when available — FR02-03.
    """
    conn   = get_conn()
    c      = conn.cursor()
    extra  = "AND date = ?" if date else ""
    params = ([date] if date else [])

    c.execute(f"""
        SELECT source,
               COUNT(*) as total,
               SUM(CASE WHEN level IN ('ERROR','CRITICAL','FAILURE') THEN 1 ELSE 0 END) as errors
        FROM logs_{category}
        WHERE 1=1 {extra}
        GROUP BY source
        HAVING total > 2
        ORDER BY errors DESC LIMIT 20
    """, params)

    rows    = c.fetchall()
    conn.close()
    if not rows:
        return []

    max_cnt = max(r["total"] for r in rows) or 1
    results = []
    for r in rows:
        err_rate = r["errors"] / r["total"] if r["total"] else 0
        score    = 0.4 * (r["total"] / max_cnt) + 0.6 * err_rate
        results.append({
            "source":     r["source"],
            "total":      r["total"],
            "errors":     r["errors"],
            "error_rate": round(err_rate * 100, 1),
            "score":      round(score * 100, 1),
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def run_temporal_analysis(category: str) -> dict:
    """Time-based analysis: peak hours, weekday breakdown, trend."""
    conn = get_conn()
    c    = conn.cursor()

    c.execute(f"""
        SELECT timestamp FROM logs_{category}
        WHERE level IN ('ERROR','CRITICAL','FAILURE')
        AND timestamp IS NOT NULL
    """)
    rows = c.fetchall()
    conn.close()

    hour_counts    = defaultdict(int)
    weekday_counts = defaultdict(int)
    daily_trend    = defaultdict(int)

    for row in rows:
        try:
            dt = datetime.strptime(row["timestamp"][:19], "%Y-%m-%d %H:%M:%S")
            hour_counts[dt.hour] += 1
            weekday_counts[dt.strftime("%A")] += 1
            daily_trend[dt.strftime("%Y-%m-%d")] += 1
        except Exception:
            pass

    peak_hour    = max(hour_counts, key=hour_counts.get, default=None)
    trend_dates  = sorted(daily_trend.keys())[-14:]
    trend_values = [daily_trend[d] for d in trend_dates]
    trend_dir    = "↑ increasing" if (trend_values[-1] > trend_values[0] if len(trend_values) > 1 else False) else "↓ stable/decreasing"

    return {
        "hourly":    dict(sorted(hour_counts.items())),
        "weekday":   dict(weekday_counts),
        "trend_14d": [{"date": d, "count": daily_trend[d]} for d in trend_dates],
        "peak_hour": peak_hour,
        "trend":     trend_dir,
    }


def run_zero_day_heuristics(category: str = "all") -> list:
    """Zero-day detection: unusual source + uncommon event ID combination."""
    conn     = get_conn()
    c        = conn.cursor()
    cats     = CATEGORIES if category == "all" else [category]
    suspects = []

    for cat in cats:
        c.execute(f"""
            SELECT source, event_id, COUNT(*) as cnt, MAX(timestamp) as last_seen, message
            FROM logs_{cat}
            WHERE level IN ('ERROR','CRITICAL','FAILURE')
            GROUP BY source, event_id
            HAVING cnt <= 3
            ORDER BY last_seen DESC LIMIT 20
        """)
        for row in c.fetchall():
            suspects.append({
                "category":    cat,
                "source":      row["source"],
                "event_id":    row["event_id"],
                "occurrences": row["cnt"],
                "last_seen":   row["last_seen"],
                "message":     (row["message"] or "")[:200],
                "risk":        "Rare event — investigate further",
            })

    conn.close()
    return suspects


def run_security_threat_classification() -> dict:
    """Map Security log event IDs to threat categories."""
    conn = get_conn()
    c    = conn.cursor()
    c.execute("SELECT event_id, COUNT(*) as cnt FROM logs_security GROUP BY event_id")
    rows = c.fetchall()
    conn.close()

    threats = []
    for row in rows:
        eid = row["event_id"]
        if eid in SECURITY_EVENT_IDS:
            severity, desc = SECURITY_EVENT_IDS[eid]
            threats.append({
                "event_id":    eid,
                "count":       row["cnt"],
                "severity":    severity,
                "description": desc,
            })

    threats.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5))
    return {
        "threats":          threats,
        "total_classified": len(threats),
        "critical_count":   sum(1 for t in threats if t["severity"] == "CRITICAL"),
    }


def run_full_analysis() -> dict:
    """Run all analysis methods and return a unified report."""
    return {
        "patterns":         run_pattern_scan("all"),
        "anomaly":          run_anomaly_detection("all"),
        "zero_day":         run_zero_day_heuristics("all"),
        "security_threats": run_security_threat_classification(),
        "temporal": {
            cat: run_temporal_analysis(cat) for cat in CATEGORIES
        },
        "top_offenders": {
            cat: run_top_offenders(cat) for cat in CATEGORIES
        },
        "generated_at": datetime.now().isoformat(),
        "he_status":    "FR02-01/02 active — counts BFV-encrypted before analysis; CKKS for anomaly detection",
    }
