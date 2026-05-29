"""
api/logs_api.py
===============
Blueprint: /api/logs/<category>   /api/days/<category>

DATA FLOW:
  Browser JS (static/js/logs.js)
      ↓ GET /api/logs/application?date=2026-03-05&level=ERROR&page=1
  logs_api.py  → SELECT from SQLite
      ↓ JSON list of log rows
  static/js/logs.js renders table rows
"""

from flask import Blueprint, jsonify, request
from database.db import get_conn, CATEGORIES

logs_bp = Blueprint("logs", __name__)


@logs_bp.route("/logs/<category>")
def get_logs(category):
    if category not in CATEGORIES:
        return jsonify({"error": f"Unknown category: {category}"}), 404

    date    = request.args.get("date", "")
    level   = request.args.get("level", "")
    page    = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 100))
    offset  = (page - 1) * per_page

    where_clauses = []
    params        = []
    if date:
        where_clauses.append("date = ?")
        params.append(date)
    if level:
        where_clauses.append("level = ?")
        params.append(level)

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = get_conn()
    c    = conn.cursor()

    c.execute(f"SELECT COUNT(*) FROM logs_{category} {where}", params)
    total = c.fetchone()[0]

    c.execute(f"""
        SELECT id, timestamp, date, level, source, message, event_id
        FROM logs_{category}
        {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, params + [per_page, offset])

    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    return jsonify({
        "logs":     rows,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, -(-total // per_page)),  # ceiling division
    })


@logs_bp.route("/days/<category>")
def get_days(category):
    """Return list of dates with log counts (for the day picker)."""
    if category not in CATEGORIES:
        return jsonify({"error": "Unknown category"}), 404

    conn = get_conn()
    c    = conn.cursor()
    c.execute(f"""
        SELECT date,
               COUNT(*) as total,
               SUM(CASE WHEN level IN ('ERROR','CRITICAL','FAILURE') THEN 1 ELSE 0 END) as errors,
               SUM(CASE WHEN level='WARNING' THEN 1 ELSE 0 END) as warnings
        FROM logs_{category}
        WHERE date IS NOT NULL
        GROUP BY date
        ORDER BY date DESC
        LIMIT 90
    """)
    days = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"days": days, "category": category})
