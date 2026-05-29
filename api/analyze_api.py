"""
api/analyze_api.py
===================
Blueprint: /api/analyze/*

All analysis endpoints. Coordinates between HE engine and ML engine.

HOW JAVASCRIPT CALLS THESE:
    fetch('/api/analyze/frequency?category=system')
    fetch('/api/analyze/anomaly')
    fetch('/api/analyze/threats')        ← ML detections
    fetch('/api/analyze/search?q=disk')
    fetch('/api/analyze/timeline')
    fetch('/api/analyze/fullreport')     ← all of the above combined

WHAT GETS ENCRYPTED:
    - Error counts per source → BFV encrypted before summation
    - Daily event rates → CKKS encrypted before mean calculation
    - Z-scores → CKKS encrypted
    All decryption happens once, at the moment the JSON is built for response.
"""

import math
from flask import Blueprint, jsonify, request
from database.db import get_conn, log_activity, LOG_CATEGORIES
from core.he_engine import HE
from core.ml_engine import ML
from utils.logger import get_logger

analyze_bp = Blueprint("analyze", __name__)
log = get_logger("analyze_api")


@analyze_bp.route("/analyze/frequency")
def frequency():
    """
    BFV-encrypted frequency analysis.
    Counts error/warning events per source, encrypted, summed, then decrypted once.
    """
    category = request.args.get("category", "application")
    date     = request.args.get("date", "")
    if category not in LOG_CATEGORIES:
        return jsonify({"error": "Unknown category"}), 400

    conn = get_conn()
    c    = conn.cursor()
    extra  = "AND date = ?" if date else ""
    params = [date] if date else []

    c.execute(f"""
        SELECT source, level, COUNT(*) as cnt
        FROM logs_{category}
        WHERE source IS NOT NULL {extra}
        GROUP BY source, level
        ORDER BY cnt DESC LIMIT 100
    """, params)
    rows = c.fetchall()
    conn.close()

    if not rows:
        return jsonify({"results": [], "he_info": "No data"})

    # Build raw frequency map then encrypt it
    raw_map = {}
    for source, level, cnt in rows:
        key = f"{source}::{level}"
        raw_map[key] = cnt

    # HE analysis via BFV
    he_result = HE.frequency_analysis([
        {"source": r[0], "level": r[1]}
        for r in rows for _ in range(r[2])   # expand for HE input
    ])

    # Build response: top sources by error count
    results = []
    for source, level, cnt in rows[:30]:
        enc = HE.bfv.encrypt(cnt)
        results.append({
            "source":    source,
            "level":     level,
            "count":     cnt,
            "encrypted": f"ct={enc['ct']}",   # show the ciphertext string
            "scheme":    "BFV",
        })

    return jsonify({
        "category":          category,
        "results":           results,
        "total_errors_enc":  str(he_result.get("encrypted_total_err", {})),
        "total_errors_dec":  he_result.get("decrypted_total_err", 0),
        "he_scheme":         "BFV (Brakerski/Fan-Vercauteren)",
        "he_note":           "Error counts encrypted before summation. Decrypted once at output.",
    })


@analyze_bp.route("/analyze/anomaly")
def anomaly():
    """
    CKKS-encrypted Z-score anomaly detection.
    Computes encrypted mean of daily error counts, then Z-score per day.
    """
    conn = get_conn()
    c    = conn.cursor()
    result = {}

    for cat in LOG_CATEGORIES:
        c.execute(f"""
            SELECT date, COUNT(*) as cnt
            FROM logs_{cat}
            WHERE level IN ('ERROR','CRITICAL','FAILURE') AND date IS NOT NULL
            GROUP BY date ORDER BY date ASC LIMIT 60
        """)
        rows = c.fetchall()
        if not rows:
            result[cat] = {"days": [], "mean": 0, "std_dev": 0}
            continue

        dates  = [r[0] for r in rows]
        counts = [r[1] for r in rows]

        # HE anomaly detection via CKKS
        he_res = HE.anomaly_detection(counts)

        day_results = []
        for date, count, anom in zip(dates, counts, he_res["anomalies"]):
            day_results.append({
                "date":       date,
                "count":      count,
                "z_score":    anom["z_score"],
                "is_anomaly": anom["is_anomaly"],
                "scheme":     "CKKS",
            })

        result[cat] = {
            "days":      day_results,
            "mean":      he_res["mean"],
            "std_dev":   he_res["std_dev"],
            "threshold": he_res["threshold"],
            "he_note":   he_res["he_note"],
        }

    conn.close()
    return jsonify(result)


@analyze_bp.route("/analyze/threats")
def threats():
    """
    Run ML threat detection and return results.
    This coordinates the ml_engine to scan current database contents.
    """
    run_fresh = request.args.get("run", "false").lower() == "true"

    if run_fresh:
        result = ML.analyze_all()
        log_activity("ml_analysis", f"detections={result['summary']['total_detections']}")
        return jsonify(result)
    else:
        # Return cached results from last run
        detections = ML.get_last_detections()
        return jsonify({
            "detections": detections,
            "note": "Cached results. Add ?run=true to re-run analysis.",
        })


@analyze_bp.route("/analyze/search")
def search():
    """
    Full-text keyword search across all log categories.
    Query params: q=keyword, category=all|application|..., date=YYYY-MM-DD
    """
    keyword  = request.args.get("q", "").strip()
    category = request.args.get("category", "all")
    date     = request.args.get("date", "")

    if not keyword:
        return jsonify({"results": [], "total": 0})

    cats = LOG_CATEGORIES if category == "all" else [category]
    conn = get_conn()
    c    = conn.cursor()
    results = []

    for cat in cats:
        date_clause = "AND date = ?" if date else ""
        params = [f"%{keyword}%", f"%{keyword}%"]
        if date:
            params.append(date)

        c.execute(f"""
            SELECT id, timestamp, date, level, source, message, event_id
            FROM logs_{cat}
            WHERE (message LIKE ? OR source LIKE ?) {date_clause}
            ORDER BY timestamp DESC LIMIT 200
        """, params)

        for r in c.fetchall():
            results.append({
                "id": r[0], "timestamp": r[1], "date": r[2],
                "level": r[3], "source": r[4], "message": r[5],
                "event_id": r[6], "category": cat,
            })

    conn.close()
    results.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return jsonify({"results": results[:500], "total": len(results), "keyword": keyword})


@analyze_bp.route("/analyze/timeline")
def timeline():
    """Daily event volume per category (last 60 days)."""
    conn = get_conn()
    c    = conn.cursor()
    result = {}
    for cat in LOG_CATEGORIES:
        c.execute(f"""
            SELECT date, COUNT(*) as cnt
            FROM logs_{cat} WHERE date IS NOT NULL
            GROUP BY date ORDER BY date DESC LIMIT 60
        """)
        result[cat] = [{"date": r[0], "count": r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify(result)


@analyze_bp.route("/analyze/fullreport")
def full_report():
    """
    Runs the complete 7-method analysis suite.
    Returns a single comprehensive JSON report.
    """
    log_activity("full_analysis", "starting full report")
    conn = get_conn()
    c    = conn.cursor()

    report = {}

    # 1. Stats per category
    stats = {}
    for cat in LOG_CATEGORIES:
        c.execute(f"SELECT COUNT(*),SUM(level IN('ERROR','CRITICAL')),SUM(level='WARNING') FROM logs_{cat}")
        r = c.fetchone()
        stats[cat] = {"total": r[0] or 0, "errors": r[1] or 0, "warnings": r[2] or 0}
    report["stats"] = stats

    # 2. Top error sources
    top_sources = {}
    for cat in LOG_CATEGORIES:
        c.execute(f"""
            SELECT source, COUNT(*) as cnt FROM logs_{cat}
            WHERE level IN ('ERROR','CRITICAL') GROUP BY source ORDER BY cnt DESC LIMIT 5
        """)
        top_sources[cat] = [{"source": r[0], "count": r[1]} for r in c.fetchall()]
    report["top_sources"] = top_sources

    # 3. Event ID clusters
    event_id_map = {
        4625: "Failed Logon",       4720: "Account Created",
        4719: "Policy Changed",     41:   "Unexpected Shutdown",
        6008: "Dirty Shutdown",     7045: "Service Installed",
        1000: "App Crash",          1001: "BSOD",
        7:    "Disk Error",         11:   "Driver Error",
    }
    eid_clusters = []
    for cat in ["system", "security", "application"]:
        c.execute(f"""
            SELECT event_id, COUNT(*) as cnt FROM logs_{cat}
            WHERE event_id IS NOT NULL GROUP BY event_id ORDER BY cnt DESC LIMIT 20
        """)
        for r in c.fetchall():
            eid_clusters.append({
                "category":    cat,
                "event_id":    r[0],
                "count":       r[1],
                "description": event_id_map.get(r[0], f"Event {r[0]}"),
            })
    report["event_id_clusters"] = eid_clusters

    # 4. Temporal analysis (errors by day)
    temporal = {}
    for cat in ["system", "application"]:
        c.execute(f"""
            SELECT date, COUNT(*) FROM logs_{cat}
            WHERE level IN ('ERROR','CRITICAL') AND date IS NOT NULL
            GROUP BY date ORDER BY cnt DESC LIMIT 10
        """)
        temporal[cat] = [{"date": r[0], "count": r[1]} for r in c.fetchall()]
    report["temporal"] = temporal

    # 5. Cross-category correlation
    cat_counts = {}
    for cat in LOG_CATEGORIES:
        c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level IN ('ERROR','CRITICAL')")
        cat_counts[cat] = c.fetchone()[0] or 0
    max_cat = max(cat_counts, key=cat_counts.get) if cat_counts else "none"
    report["correlation"] = {
        "by_category": cat_counts,
        "highest_error_category": max_cat,
        "note": "High errors across multiple categories indicate system-level events.",
    }

    conn.close()

    # 6. ML detections
    ml_result = ML.analyze_all()
    report["ml_detections"] = ml_result

    # 7. Production risk summary
    report["risk_summary"] = {
        "overall_risk": ml_result["summary"]["risk_label"],
        "risk_score":   ml_result["summary"]["risk_score"],
    }

    log_activity("full_analysis", f"complete, risk={ml_result['summary']['risk_label']}")
    return jsonify(report)
