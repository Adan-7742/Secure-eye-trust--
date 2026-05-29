"""
api/status_api.py
==================
Blueprint: /api/status

Returns live system status:
- Is pywin32 available?
- Is the app running as Administrator?
- Can it access Security log?
- Database stats

USED BY: frontend/static/js/dashboard.js on page load
"""

from flask import Blueprint, jsonify
from utils.admin_check import is_admin
from core.event_collector import WIN32_AVAILABLE
from database.db import get_conn, LOG_CATEGORIES

status_bp = Blueprint("status", __name__)


@status_bp.route("/status")
def status():
    admin = is_admin()
    conn  = get_conn()
    c     = conn.cursor()

    counts = {}
    for cat in LOG_CATEGORIES:
        try:
            c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
            counts[cat] = c.fetchone()[0]
        except Exception:
            counts[cat] = 0

    conn.close()

    return jsonify({
        "win32_available":  WIN32_AVAILABLE,
        "is_admin":         admin,
        "security_access":  admin and WIN32_AVAILABLE,
        "security_tip":     (
            "Run as Administrator to access Security logs"
            if not admin else "Security log accessible"
        ),
        "log_counts":       counts,
        "total_events":     sum(counts.values()),
    })
