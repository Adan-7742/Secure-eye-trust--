"""
core/analysis_engine/anomaly_detector.py
==========================================
Statistical anomaly detection engine.

Uses Z-score analysis (no external ML libraries required) to detect:
  1. Daily event volume anomalies  — days with unusually high error counts
  2. Hourly pattern anomalies      — unusual activity at specific hours
  3. Per-source spike detection    — a single source suddenly generating many more events
  4. Authentication time anomalies — logins at statistically unusual hours

This is the "Isolation Forest equivalent" using pure math so it runs
on any system without scikit-learn.
"""

import math
from collections import defaultdict
from database.db import get_conn, CATEGORIES


def _zscore_series(values: list) -> list:
    """Compute Z-scores for a list of numbers."""
    if len(values) < 3:
        return [0.0] * len(values)
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = math.sqrt(variance) if variance > 0 else 0.0
    if std == 0:
        return [0.0] * len(values)
    return [round((v - mean) / std, 3) for v in values]


def detect_daily_anomalies(conn=None) -> list:
    """
    Find days where error volume is statistically abnormal (|Z| > 2.0).
    Uses all available history for baseline.
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c = conn.cursor()
    daily = defaultdict(int)

    for cat in CATEGORIES:
        try:
            c.execute(f"""
                SELECT date, COUNT(*) FROM logs_{cat}
                WHERE level IN ('ERROR', 'CRITICAL', 'FAILURE')
                AND date IS NOT NULL
                GROUP BY date
            """)
            for row in c.fetchall():
                if row[0]:
                    daily[row[0]] += row[1]
        except Exception:
            pass

    if close_conn:
        conn.close()

    if not daily:
        return []

    dates  = sorted(daily.keys())
    counts = [daily[d] for d in dates]
    zscores = _zscore_series(counts)

    anomalies = []
    for date, count, z in zip(dates, counts, zscores):
        if abs(z) > 2.0:
            anomalies.append({
                "date":       date,
                "count":      count,
                "zscore":     z,
                "is_anomaly": True,
                "severity":   "CRITICAL" if abs(z) > 3.5 else "HIGH" if abs(z) > 3.0 else "MEDIUM",
                "direction":  "spike" if z > 0 else "drop",
            })

    return sorted(anomalies, key=lambda a: abs(a["zscore"]), reverse=True)


def detect_hourly_anomalies(conn=None) -> list:
    """
    Detect hours of day where event volume is unusually high.
    Compares each hour's actual count against its historical average for that hour.
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c = conn.cursor()
    # bucket: hour_of_day → list of daily counts for that hour
    hour_buckets = defaultdict(list)

    for cat in CATEGORIES:
        try:
            c.execute(f"""
                SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, 
                       date, COUNT(*) as cnt
                FROM logs_{cat}
                WHERE level IN ('ERROR', 'CRITICAL', 'FAILURE')
                AND timestamp IS NOT NULL AND date IS NOT NULL
                GROUP BY hr, date
            """)
            for row in c.fetchall():
                hr, date, cnt = row
                if hr is not None:
                    hour_buckets[hr].append(cnt)
        except Exception:
            pass

    if close_conn:
        conn.close()

    anomalies = []
    for hr, counts in hour_buckets.items():
        if len(counts) < 3:
            continue
        zscores = _zscore_series(counts)
        # Check if the most recent value for this hour is anomalous
        last_z = zscores[-1] if zscores else 0
        last_v = counts[-1] if counts else 0
        if last_z > 2.5:
            anomalies.append({
                "hour":          hr,
                "hour_label":    f"{hr:02d}:00",
                "count":         last_v,
                "zscore":        last_z,
                "avg_for_hour":  round(sum(counts) / len(counts), 1),
                "severity":      "HIGH" if last_z > 3.5 else "MEDIUM",
            })

    return sorted(anomalies, key=lambda a: a["zscore"], reverse=True)


def detect_auth_time_anomaly(conn=None) -> dict:
    """
    Detect if successful logons are occurring at unusual hours.
    Builds a baseline of normal login hours and flags deviations.

    Returns: { "unusual_hours": [...], "baseline_hours": [...], "verdict": str }
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c = conn.cursor()
    hour_counts = defaultdict(int)

    try:
        c.execute("""
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, COUNT(*) as cnt
            FROM logs_security
            WHERE event_id = 4624
            AND timestamp IS NOT NULL
            GROUP BY hr
        """)
        for row in c.fetchall():
            if row[0] is not None:
                hour_counts[row[0]] = row[1]
    except Exception:
        pass

    if close_conn:
        conn.close()

    if not hour_counts:
        return {"unusual_hours": [], "baseline_hours": [], "verdict": "no_data"}

    # Business hours: 7am–8pm
    business_total   = sum(v for h, v in hour_counts.items() if 7 <= h <= 20)
    off_hours_total  = sum(v for h, v in hour_counts.items() if h < 7 or h > 20)
    total            = sum(hour_counts.values())

    off_hours_pct = (off_hours_total / total * 100) if total > 0 else 0

    unusual_hours = [
        {"hour": h, "count": v, "label": f"{h:02d}:00"}
        for h, v in hour_counts.items()
        if (h < 6 or h > 22) and v > 0
    ]

    verdict = "normal"
    if off_hours_pct > 30:
        verdict = "suspicious"
    elif unusual_hours:
        verdict = "review"

    return {
        "unusual_hours":    sorted(unusual_hours, key=lambda x: x["count"], reverse=True),
        "off_hours_pct":    round(off_hours_pct, 1),
        "business_total":   business_total,
        "off_hours_total":  off_hours_total,
        "total_logons":     total,
        "verdict":          verdict,
    }


def detect_source_spikes(conn=None) -> list:
    """
    Detect sources (applications/services) that have recently spiked in errors
    compared to their own historical average.
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    c = conn.cursor()
    spikes = []

    for cat in CATEGORIES:
        try:
            # Get per-source daily counts for the last 14 days
            c.execute(f"""
                SELECT source, date, COUNT(*) as cnt
                FROM logs_{cat}
                WHERE level IN ('ERROR', 'CRITICAL', 'FAILURE')
                AND date IS NOT NULL AND source IS NOT NULL
                AND timestamp >= datetime('now', '-14 days')
                GROUP BY source, date
                ORDER BY source, date
            """)
            rows = c.fetchall()

            # Group by source
            src_daily = defaultdict(list)
            for source, date, cnt in rows:
                if source:
                    src_daily[source].append(cnt)

            for source, counts in src_daily.items():
                if len(counts) < 3:
                    continue
                zscores = _zscore_series(counts)
                last_z  = zscores[-1] if zscores else 0
                last_v  = counts[-1] if counts else 0
                avg     = sum(counts) / len(counts)

                if last_z > 2.5 and last_v > 5:
                    spikes.append({
                        "source":     source,
                        "category":   cat,
                        "count":      last_v,
                        "avg":        round(avg, 1),
                        "zscore":     last_z,
                        "severity":   "HIGH" if last_z > 3.5 else "MEDIUM",
                    })
        except Exception:
            pass

    if close_conn:
        conn.close()

    return sorted(spikes, key=lambda s: s["zscore"], reverse=True)[:10]


def run_full_anomaly_detection(conn=None) -> dict:
    """
    Run all anomaly detectors and return a unified result.
    """
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    daily    = detect_daily_anomalies(conn)
    hourly   = detect_hourly_anomalies(conn)
    auth     = detect_auth_time_anomaly(conn)
    spikes   = detect_source_spikes(conn)

    if close_conn:
        conn.close()

    # Build a summary verdict
    critical_days = [d for d in daily if d["severity"] == "CRITICAL"]
    high_days     = [d for d in daily if d["severity"] == "HIGH"]

    if critical_days:
        verdict = "CRITICAL"
    elif high_days or auth.get("verdict") == "suspicious":
        verdict = "HIGH"
    elif daily or hourly or spikes:
        verdict = "MEDIUM"
    else:
        verdict = "NORMAL"

    return {
        "verdict":           verdict,
        "daily_anomalies":   daily,
        "hourly_anomalies":  hourly,
        "auth_time_analysis": auth,
        "source_spikes":     spikes,
        "summary": {
            "anomalous_days":   len(daily),
            "anomalous_hours":  len(hourly),
            "source_spikes":    len(spikes),
            "off_hours_logons": auth.get("off_hours_total", 0),
        },
    }
