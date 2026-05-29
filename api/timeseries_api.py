"""
api/timeseries_api.py
=====================
Time-Series Analysis endpoints.

GET /api/timeseries/logins?interval=10m&date=YYYY-MM-DD
    → Login attempts (EID 4624 success + 4625 failure) bucketed by interval
    → Anomaly flags per bucket (Z-score > 2.5)

GET /api/timeseries/errors?category=system&interval=1h
    → Error/Critical events per time bucket across a category

GET /api/timeseries/shutdowns
    → Shutdown/restart events (EID 41, 6008, 1074) over time

GET /api/timeseries/custom?event_id=5157&interval=30m
    → Any event ID bucketed over time

GET /api/timeseries/summary
    → All three streams in one call (dashboard overview)
"""

import math
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Blueprint, jsonify, request
from database.db import get_conn, LOG_CATEGORIES
from utils.logger import get_logger

ts_bp = Blueprint("timeseries", __name__)
log   = get_logger("timeseries_api")


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse_interval(s: str) -> int:
    """Convert '10m' / '1h' / '30s' → seconds."""
    s = (s or "10m").strip().lower()
    if s.endswith("h"):  return int(s[:-1]) * 3600
    if s.endswith("m"):  return int(s[:-1]) * 60
    if s.endswith("s"):  return int(s[:-1])
    return 600  # default 10 min

def _bucket_label(ts_str: str, bucket_secs: int) -> str:
    """Round an ISO timestamp down to the nearest bucket boundary."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", ""))
        epoch = int(dt.timestamp())
        floored = (epoch // bucket_secs) * bucket_secs
        floored_dt = datetime.fromtimestamp(floored)
        if bucket_secs < 3600:
            return floored_dt.strftime("%Y-%m-%dT%H:%M")
        elif bucket_secs < 86400:
            return floored_dt.strftime("%Y-%m-%dT%H:00")
        else:
            return floored_dt.strftime("%Y-%m-%d")
    except Exception:
        return ts_str[:16]

def _zscore_flag(series: list[int], threshold: float = 2.5) -> list[dict]:
    """
    Compute Z-scores and flag anomalies.
    Returns [{bucket, count, z_score, is_anomaly, label}]
    """
    if not series:
        return []
    n     = len(series)
    mean  = sum(series) / n
    var   = sum((x - mean) ** 2 for x in series) / max(n - 1, 1)
    std   = math.sqrt(var) if var > 0 else 1.0

    result = []
    for v in series:
        z = round((v - mean) / std, 2)
        result.append({
            "z_score":    z,
            "is_anomaly": abs(z) > threshold,
            "deviation":  round(abs(v - mean), 1),
        })
    return result


def _build_response(buckets: dict, bucket_secs: int,
                    stream_name: str, interval_label: str,
                    date_filter: str = "") -> dict:
    """
    Sort buckets, compute Z-scores, build the full response dict.
    """
    if not buckets:
        return {
            "ok": True, "stream": stream_name, "interval": interval_label,
            "buckets": [], "total": 0, "peak": None, "anomalies": [],
            "stats": {"mean": 0, "std_dev": 0, "peak_count": 0},
        }

    sorted_keys   = sorted(buckets.keys())
    counts        = [buckets[k] for k in sorted_keys]
    stats_raw     = _zscore_flag(counts)

    # pretty label for display
    def _pretty(k):
        try:
            dt = datetime.fromisoformat(k)
            if bucket_secs < 3600:
                return dt.strftime("%H:%M")
            elif bucket_secs < 86400:
                return dt.strftime("%b %d %H:00")
            else:
                return dt.strftime("%b %d")
        except Exception:
            return k

    result_buckets = []
    anomalies      = []
    peak_count     = 0
    peak_bucket    = None

    for i, key in enumerate(sorted_keys):
        c   = counts[i]
        st  = stats_raw[i] if stats_raw else {"z_score": 0, "is_anomaly": False, "deviation": 0}
        lbl = _pretty(key)
        entry = {
            "key":        key,
            "label":      lbl,
            "count":      c,
            "z_score":    st["z_score"],
            "is_anomaly": st["is_anomaly"],
        }
        result_buckets.append(entry)
        if st["is_anomaly"]:
            anomalies.append({**entry, "deviation": st["deviation"]})
        if c > peak_count:
            peak_count  = c
            peak_bucket = entry

    n    = len(counts)
    mean = round(sum(counts) / n, 1) if n else 0
    var  = sum((x - mean) ** 2 for x in counts) / max(n - 1, 1)
    std  = round(math.sqrt(var), 1) if var > 0 else 0

    return {
        "ok":       True,
        "stream":   stream_name,
        "interval": interval_label,
        "date":     date_filter,
        "buckets":  result_buckets,
        "total":    sum(counts),
        "peak":     peak_bucket,
        "anomalies": anomalies,
        "stats":    {"mean": mean, "std_dev": std, "peak_count": peak_count, "bucket_count": n},
    }


# ── routes ────────────────────────────────────────────────────────────────────

@ts_bp.route("/timeseries/logins")
def logins():
    """
    Failed logins (real ones only — EIDs 4625, 4771) + successful logins (EID 4624)
    bucketed over time from the security log.

    NOTE: This previously matched `level = 'FAILURE'`, which on Windows Security
    audit logs covers a LOT of non-login events: EID 4656/4663 LSASS handle
    denials, EID 5152/5157 Windows Filtering Platform drops, etc. On a normal
    machine those swamp the panel with tens of thousands of fake "failed logins".
    Stick to the actual logon-failure event IDs:
        4625 = An account failed to log on
        4771 = Kerberos pre-authentication failed
    """
    interval_str = request.args.get("interval", "10m")
    date_filter  = request.args.get("date", "")
    bucket_secs  = _parse_interval(interval_str)

    conn = get_conn()
    c    = conn.cursor()

    date_clause  = "AND date = ?" if date_filter else ""
    params_fail  = [date_filter] if date_filter else []
    params_ok    = [date_filter] if date_filter else []

    # Failed logons — use real logon-failure EIDs only (no `level='FAILURE'`!)
    c.execute(f"""
        SELECT timestamp FROM logs_security
        WHERE event_id IN (4625, 4771)
          AND timestamp IS NOT NULL {date_clause}
        ORDER BY timestamp ASC
    """, params_fail)
    failed_ts = [r["timestamp"] for r in c.fetchall()]

    # Successful logons: EID 4624
    c.execute(f"""
        SELECT timestamp FROM logs_security
        WHERE event_id = 4624 AND timestamp IS NOT NULL {date_clause}
        ORDER BY timestamp ASC
    """, params_ok)
    success_ts = [r["timestamp"] for r in c.fetchall()]

    conn.close()

    failed_buckets  = defaultdict(int)
    success_buckets = defaultdict(int)
    for ts in failed_ts:
        failed_buckets[_bucket_label(ts, bucket_secs)] += 1
    for ts in success_ts:
        success_buckets[_bucket_label(ts, bucket_secs)] += 1

    # Merge all bucket keys
    all_keys = sorted(set(list(failed_buckets.keys()) + list(success_buckets.keys())))

    failed_resp  = _build_response(failed_buckets,  bucket_secs, "Failed Logins",     interval_str, date_filter)
    success_resp = _build_response(success_buckets, bucket_secs, "Successful Logins", interval_str, date_filter)

    return jsonify({
        "ok":      True,
        "failed":  failed_resp,
        "success": success_resp,
        "all_keys": all_keys,
    })


@ts_bp.route("/timeseries/errors")
def errors():
    """
    ERROR + CRITICAL events bucketed over time for a given category.

    For the Security category, `level='FAILURE'` is *audit failure* (e.g. a
    handle-open denied, a packet dropped by the firewall) — not a system error.
    Counting them as "errors" inflates the chart by 10–20x on any normal
    machine. So we only count ERROR/CRITICAL in the Security log, and
    additionally exclude the noisiest object-access / WFP audit EIDs.
    """
    interval_str = request.args.get("interval", "1h")
    category     = request.args.get("category", "system")
    date_filter  = request.args.get("date", "")
    bucket_secs  = _parse_interval(interval_str)

    if category not in LOG_CATEGORIES:
        return jsonify({"ok": False, "error": "Unknown category"}), 400

    conn = get_conn()
    c    = conn.cursor()
    date_clause = "AND date = ?" if date_filter else ""
    params      = [date_filter] if date_filter else []

    # Security log: drop the audit-failure flood, keep real errors only
    if category == "security":
        c.execute(f"""
            SELECT timestamp, level FROM logs_security
            WHERE level IN ('ERROR','CRITICAL','WARNING')
              AND event_id NOT IN (4656, 4658, 4663, 5152, 5156, 5157, 5158)
              AND timestamp IS NOT NULL {date_clause}
            ORDER BY timestamp ASC
        """, params)
    else:
        c.execute(f"""
            SELECT timestamp, level FROM logs_{category}
            WHERE level IN ('ERROR','CRITICAL','FAILURE','WARNING')
              AND timestamp IS NOT NULL {date_clause}
            ORDER BY timestamp ASC
        """, params)
    rows = c.fetchall()
    conn.close()

    error_buckets   = defaultdict(int)
    warning_buckets = defaultdict(int)

    for row in rows:
        key = _bucket_label(row["timestamp"], bucket_secs)
        if row["level"] in ("ERROR", "CRITICAL", "FAILURE"):
            error_buckets[key] += 1
        else:
            warning_buckets[key] += 1

    error_resp   = _build_response(error_buckets,   bucket_secs, f"{category} Errors",   interval_str, date_filter)
    warning_resp = _build_response(warning_buckets, bucket_secs, f"{category} Warnings", interval_str, date_filter)

    return jsonify({
        "ok":       True,
        "category": category,
        "errors":   error_resp,
        "warnings": warning_resp,
    })


@ts_bp.route("/timeseries/shutdowns")
def shutdowns():
    """
    Shutdown / restart / crash events from system log:
    EID 41 (kernel power), 6008 (dirty shutdown), 1074 (shutdown initiated),
    1076, 6006, 6009 (normal boot/shutdown)
    """
    interval_str = request.args.get("interval", "1d")
    date_filter  = request.args.get("date", "")
    bucket_secs  = _parse_interval(interval_str)

    SHUTDOWN_EIDS = [41, 6008, 1074, 1076, 6006, 6009, 6013]
    placeholders  = ",".join("?" * len(SHUTDOWN_EIDS))

    conn = get_conn()
    c    = conn.cursor()
    date_clause = "AND date = ?" if date_filter else ""
    params      = SHUTDOWN_EIDS + ([date_filter] if date_filter else [])

    c.execute(f"""
        SELECT timestamp, event_id, level FROM logs_system
        WHERE event_id IN ({placeholders})
          AND timestamp IS NOT NULL {date_clause}
        ORDER BY timestamp ASC
    """, params)
    rows = c.fetchall()
    conn.close()

    EID_LABELS = {
        41:   "Kernel Power / Unexpected Shutdown",
        6008: "Dirty Shutdown (power loss)",
        1074: "Shutdown Initiated",
        1076: "Restart Reason Recorded",
        6006: "Clean Shutdown",
        6009: "System Boot",
        6013: "System Uptime Record",
    }

    buckets     = defaultdict(int)
    crash_buckets = defaultdict(int)
    events_list   = []

    for row in rows:
        key = _bucket_label(row["timestamp"], bucket_secs)
        buckets[key] += 1
        if row["event_id"] in (41, 6008):
            crash_buckets[key] += 1
        events_list.append({
            "timestamp": row["timestamp"],
            "event_id":  row["event_id"],
            "label":     EID_LABELS.get(row["event_id"], f"EID {row['event_id']}"),
            "level":     row["level"],
            "is_crash":  row["event_id"] in (41, 6008),
        })

    all_resp   = _build_response(buckets,       bucket_secs, "Shutdown/Restart Events", interval_str, date_filter)
    crash_resp = _build_response(crash_buckets, bucket_secs, "Unexpected Shutdowns",    interval_str, date_filter)

    return jsonify({
        "ok":      True,
        "all":     all_resp,
        "crashes": crash_resp,
        "events":  events_list[-50:],   # last 50 events for timeline table
    })


@ts_bp.route("/timeseries/custom")
def custom():
    """
    Bucket any event ID or keyword over time.
    Params: event_id, keyword, category, interval, date
    """
    interval_str = request.args.get("interval", "1h")
    event_id_str = request.args.get("event_id", "")
    keyword      = request.args.get("keyword", "")
    category     = request.args.get("category", "security")
    date_filter  = request.args.get("date", "")
    bucket_secs  = _parse_interval(interval_str)

    if category not in LOG_CATEGORIES:
        category = "security"

    conn = get_conn()
    c    = conn.cursor()

    conditions = ["timestamp IS NOT NULL"]
    params     = []

    if event_id_str:
        conditions.append("event_id = ?")
        params.append(int(event_id_str))
    if keyword:
        conditions.append("(message LIKE ? OR source LIKE ?)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    if date_filter:
        conditions.append("date = ?")
        params.append(date_filter)

    where = " AND ".join(conditions)
    c.execute(f"""
        SELECT timestamp, level, event_id, source FROM logs_{category}
        WHERE {where}
        ORDER BY timestamp ASC LIMIT 5000
    """, params)
    rows = c.fetchall()
    conn.close()

    buckets = defaultdict(int)
    for row in rows:
        key = _bucket_label(row["timestamp"], bucket_secs)
        buckets[key] += 1

    label = f"EID {event_id_str}" if event_id_str else f'"{keyword}"'
    resp  = _build_response(buckets, bucket_secs, label, interval_str, date_filter)

    return jsonify({"ok": True, "result": resp, "row_count": len(rows)})


@ts_bp.route("/timeseries/summary")
def summary():
    """
    All streams in one call — used to populate the Time-Series dashboard tab.
    Returns last 7 days of data for all three main streams.
    """
    conn = get_conn()
    c    = conn.cursor()

    cutoff = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S")

    # ── 1. Failed logins per hour — real failed-login EIDs only ──────────────
    # (NOT `level='FAILURE'`, which on Security audit logs covers thousands of
    # benign LSASS-handle / Windows-Filtering-Platform denials)
    c.execute("""
        SELECT timestamp FROM logs_security
        WHERE event_id IN (4625, 4771)
          AND timestamp >= ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, [cutoff])
    failed_ts = [r["timestamp"] for r in c.fetchall()]

    # ── 2. Errors per hour across all categories ───────────────────────────
    # Security log: count only real errors (ERROR/CRITICAL), and EXCLUDE
    # the noisy object-access / firewall audit-failure EIDs which would
    # otherwise dominate the chart.
    NOISY_AUDIT_EIDS = (4656, 4658, 4663, 5152, 5156, 5157, 5158)
    error_ts = []
    for cat in LOG_CATEGORIES:
        if cat == "security":
            c.execute(f"""
                SELECT timestamp FROM logs_security
                WHERE level IN ('ERROR','CRITICAL')
                  AND event_id NOT IN ({','.join('?'*len(NOISY_AUDIT_EIDS))})
                  AND timestamp >= ? AND timestamp IS NOT NULL
                ORDER BY timestamp ASC
            """, list(NOISY_AUDIT_EIDS) + [cutoff])
        else:
            c.execute(f"""
                SELECT timestamp FROM logs_{cat}
                WHERE level IN ('ERROR','CRITICAL','FAILURE')
                  AND timestamp >= ? AND timestamp IS NOT NULL
                ORDER BY timestamp ASC
            """, [cutoff])
        error_ts.extend([r["timestamp"] for r in c.fetchall()])
    error_ts.sort()

    # ── 3. Shutdowns ───────────────────────────────────────────────────────
    c.execute("""
        SELECT timestamp FROM logs_system
        WHERE event_id IN (41, 6008, 1074, 1076, 6006, 6009)
          AND timestamp >= ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, [cutoff])
    shutdown_ts = [r["timestamp"] for r in c.fetchall()]

    # ── 4. Network blocks per hour (EID 5152 / 5157) ──────────────────────
    c.execute("""
        SELECT timestamp FROM logs_security
        WHERE event_id IN (5152, 5157)
          AND timestamp >= ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, [cutoff])
    network_ts = [r["timestamp"] for r in c.fetchall()]

    # ── 5. Privilege escalation (EID 4672/4673) per hour ──────────────────
    c.execute("""
        SELECT timestamp FROM logs_security
        WHERE event_id IN (4672, 4673)
          AND timestamp >= ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, [cutoff])
    priv_ts = [r["timestamp"] for r in c.fetchall()]

    conn.close()

    def _bucket_all(ts_list, secs):
        d = defaultdict(int)
        for ts in ts_list:
            d[_bucket_label(ts, secs)] += 1
        return d

    H = 3600  # 1-hour buckets for summary

    return jsonify({
        "ok":          True,
        "period":      "last 7 days",
        "logins":      _build_response(_bucket_all(failed_ts,   H), H, "Failed Logins",          "1h"),
        "errors":      _build_response(_bucket_all(error_ts,    H), H, "All Error Events",        "1h"),
        "shutdowns":   _build_response(_bucket_all(shutdown_ts, H), H, "Shutdown/Restart Events", "1h"),
        "network":     _build_response(_bucket_all(network_ts,  H), H, "Network Blocks",          "1h"),
        "privileges":  _build_response(_bucket_all(priv_ts,     H), H, "Privilege Escalations",   "1h"),
    })
