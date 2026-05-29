"""
api/analysis_api.py
===================
Blueprint: /api/analyze/*

All heavy analysis is delegated to core/ml_engine/analyzer.py.
This file is just the HTTP layer (URL → function → JSON).

ENDPOINTS:
  GET /api/analyze/frequency?category=application&date=
  GET /api/analyze/anomaly?category=all
  GET /api/analyze/patterns?category=all
  GET /api/analyze/offenders?category=application&date=
  GET /api/analyze/temporal?category=system
  GET /api/analyze/zeroday
  GET /api/analyze/security-threats
  GET /api/analyze/full
  GET /api/analyze/timeline
  GET /api/analyze/search?q=keyword&category=all&date=
"""

from flask import Blueprint, jsonify, request
from database.db import get_conn, CATEGORIES, log_app_event
from core.ml_engine.analyzer import (
    run_frequency_analysis,
    run_anomaly_detection,
    run_pattern_scan,
    run_top_offenders,
    run_temporal_analysis,
    run_zero_day_heuristics,
    run_security_threat_classification,
    run_full_analysis,
)

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/frequency")
def frequency():
    cat  = request.args.get("category", "application")
    date = request.args.get("date", "")
    log_app_event("analysis_run", {"type": "frequency", "category": cat})
    return jsonify(run_frequency_analysis(cat, date))


@analysis_bp.route("/anomaly")
def anomaly():
    cat = request.args.get("category", "all")
    return jsonify(run_anomaly_detection(cat))


@analysis_bp.route("/patterns")
def patterns():
    cat = request.args.get("category", "all")
    return jsonify({"patterns": run_pattern_scan(cat)})


@analysis_bp.route("/offenders")
def offenders():
    cat  = request.args.get("category", "application")
    date = request.args.get("date", "")
    return jsonify({"offenders": run_top_offenders(cat, date)})


@analysis_bp.route("/temporal")
def temporal():
    cat = request.args.get("category", "system")
    return jsonify(run_temporal_analysis(cat))


@analysis_bp.route("/zeroday")
def zeroday():
    cat = request.args.get("category", "all")
    return jsonify({"suspects": run_zero_day_heuristics(cat)})


@analysis_bp.route("/security-threats")
def security_threats():
    return jsonify(run_security_threat_classification())


@analysis_bp.route("/full")
def full_analysis():
    log_app_event("analysis_run", {"type": "full"})
    return jsonify(run_full_analysis())


@analysis_bp.route("/timeline")
def timeline():
    conn = get_conn()
    c    = conn.cursor()
    result = {}
    for cat in CATEGORIES:
        c.execute(f"""
            SELECT date, COUNT(*) as cnt
            FROM logs_{cat}
            WHERE date IS NOT NULL
            GROUP BY date ORDER BY date DESC LIMIT 60
        """)
        result[cat] = [{"date": r["date"], "count": r["cnt"]} for r in c.fetchall()]
    conn.close()
    return jsonify(result)


@analysis_bp.route("/search")
def search():
    q        = request.args.get("q", "").strip()
    category = request.args.get("category", "all")
    date     = request.args.get("date", "")

    if not q:
        return jsonify({"results": [], "total": 0})

    conn = get_conn()
    c    = conn.cursor()
    cats = CATEGORIES if category == "all" else [category]
    results = []

    for cat in cats:
        extra  = "AND date = ?" if date else ""
        params = [f"%{q}%", f"%{q}%"] + ([date] if date else [])
        c.execute(f"""
            SELECT id, timestamp, date, level, source, message, event_id,
                   '{cat}' as category
            FROM logs_{cat}
            WHERE (message LIKE ? OR source LIKE ?) {extra}
            ORDER BY timestamp DESC LIMIT 200
        """, params)
        results += [dict(r) for r in c.fetchall()]

    conn.close()
    results.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return jsonify({"results": results[:500], "total": len(results)})
