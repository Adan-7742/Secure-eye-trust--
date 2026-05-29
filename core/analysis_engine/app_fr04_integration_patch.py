"""
app_fr04_integration_patch.py
==============================
Patch for app.py — wire FR04-03 and FR04-05 monitors into startup.

Find the section in app.py where existing monitors are started, e.g.:

    from core.event_collector.perf_monitor import get_perf_monitor
    get_perf_monitor().start()

    from core.event_collector.winlogin_watcher import start_winlogin_watcher
    start_winlogin_watcher()

Add the lines below AFTER those existing imports/starts.
Also add the two new API routes (task and service inventory endpoints).
"""

# ─────────────────────────────────────────────────────────────────────────────
# 1.  ADD THESE IMPORTS near the top of app.py (alongside existing collectors)
# ─────────────────────────────────────────────────────────────────────────────

from core.event_collector.task_scheduler_monitor import get_task_monitor
from core.event_collector.service_monitor import get_service_monitor

# ─────────────────────────────────────────────────────────────────────────────
# 2.  START MONITORS inside create_app() or the __main__ startup block
#     (place after `get_perf_monitor().start()` and `start_winlogin_watcher()`)
# ─────────────────────────────────────────────────────────────────────────────

# FR04-03: Task Scheduler monitoring (event log + active inventory)
get_task_monitor().start()

# FR04-05: Windows Services monitoring (event log + active status polling)
get_service_monitor().start()

# FR04-03 / FR04-05: Apply additional detection rules to the threat engine
from core.analysis_engine.threat_detector_fr04_patch import apply_patch_to_threat_rules
from core.analysis_engine import threat_detector as _td
_td.THREAT_RULES = apply_patch_to_threat_rules(_td.THREAT_RULES)

# ─────────────────────────────────────────────────────────────────────────────
# 3.  REGISTER NEW API ROUTES (add to the Blueprint registration block)
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask, jsonify, Blueprint

fr04_bp = Blueprint("fr04", __name__)


@fr04_bp.route("/api/tasks/inventory")
def task_inventory():
    """
    FR04-03 — Return the current live Task Scheduler inventory.
    Each entry: task_path, task_name, state, last_run, next_run,
                author, action_desc, enabled, suspicious.
    """
    tasks = get_task_monitor().get_inventory()
    suspicious = [t for t in tasks if t.get("suspicious")]
    return jsonify({
        "total":     len(tasks),
        "suspicious": len(suspicious),
        "tasks":     tasks,
    })


@fr04_bp.route("/api/tasks/events")
def task_events():
    """
    FR04-03 — Return recent task lifecycle events from the DB.
    Query params: limit (default 50), suspicious_only (0|1).
    """
    from flask import request
    from database.db import get_conn
    limit          = min(int(request.args.get("limit", 50)), 500)
    suspicious_only = request.args.get("suspicious_only", "0") == "1"

    try:
        conn = get_conn()
        c    = conn.cursor()
        if suspicious_only:
            c.execute("""
                SELECT ts, event_id, event_label, task_name, subject_user,
                       severity, suspicious, task_content
                FROM task_events WHERE suspicious=1
                ORDER BY id DESC LIMIT ?
            """, (limit,))
        else:
            c.execute("""
                SELECT ts, event_id, event_label, task_name, subject_user,
                       severity, suspicious, task_content
                FROM task_events
                ORDER BY id DESC LIMIT ?
            """, (limit,))
        cols = ["ts", "event_id", "event_label", "task_name", "subject_user",
                "severity", "suspicious", "task_content"]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        return jsonify({"events": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@fr04_bp.route("/api/services/inventory")
def service_inventory():
    """
    FR04-05 — Return the current live Windows service inventory.
    Each entry: service_name, display_name, state, start_type,
                binary_path, dependencies, suspicious, is_critical.
    Query params: state (RUNNING|STOPPED|ALL, default ALL),
                  suspicious_only (0|1).
    """
    from flask import request
    state_filter   = request.args.get("state", "ALL").upper()
    suspicious_only = request.args.get("suspicious_only", "0") == "1"

    services = get_service_monitor().get_snapshot()

    if state_filter != "ALL":
        services = [s for s in services if s.get("state") == state_filter]
    if suspicious_only:
        services = [s for s in services if s.get("suspicious")]

    stopped_critical = [
        s for s in services
        if s.get("is_critical") and s.get("state") == "STOPPED"
    ]

    return jsonify({
        "total":            len(services),
        "running":          sum(1 for s in services if s.get("state") == "RUNNING"),
        "stopped":          sum(1 for s in services if s.get("state") == "STOPPED"),
        "suspicious":       sum(1 for s in services if s.get("suspicious")),
        "stopped_critical": len(stopped_critical),
        "services":         services,
    })


@fr04_bp.route("/api/services/events")
def service_events():
    """
    FR04-05 — Return recent service events from the DB.
    Query params: limit (default 50), event_id (filter to specific EID).
    """
    from flask import request
    from database.db import get_conn
    limit    = min(int(request.args.get("limit", 50)), 500)
    event_id = request.args.get("event_id")

    try:
        conn = get_conn()
        c    = conn.cursor()
        if event_id:
            c.execute("""
                SELECT ts, event_id, event_label, service_name, severity,
                       suspicious, detail
                FROM service_events WHERE event_id=?
                ORDER BY id DESC LIMIT ?
            """, (int(event_id), limit))
        else:
            c.execute("""
                SELECT ts, event_id, event_label, service_name, severity,
                       suspicious, detail
                FROM service_events
                ORDER BY id DESC LIMIT ?
            """, (limit,))
        cols = ["ts", "event_id", "event_label", "service_name",
                "severity", "suspicious", "detail"]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        return jsonify({"events": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# 4.  REGISTER the blueprint  (inside create_app, after existing blueprints)
# ─────────────────────────────────────────────────────────────────────────────

# app.register_blueprint(fr04_bp)
