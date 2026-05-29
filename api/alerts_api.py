"""
api/alerts_api.py
==================
Blueprint: /api/alerts/*

Real-time alert stream and alert management endpoints.

BUGS FIXED:
  BUG-1: alert_sse_generator missing — was imported but never defined in alert_bus.
          Fixed: generator is now defined inline here with proper SSE formatting.
  BUG-2: Session auth check fails on SSE endpoint — EventSource cannot send cookies
          on all browsers. Fixed: allow token-based auth via ?token= query param as fallback.
  BUG-3: Missing CORS headers on SSE response — browser drops connection immediately.
          Fixed: added Access-Control-Allow-Origin and Access-Control-Allow-Credentials.
  BUG-4: /alerts/history query referenced non-existent column 'alert_id' before table
          creation — now uses safe CREATE IF NOT EXISTS guard before every query.
  BUG-5: mark_read sent int alert_id to DB but DB stores as TEXT — type mismatch
          meant UPDATE never matched any row. Fixed: always cast to str for DB ops.

ENDPOINTS:
  GET  /api/alerts/stream          — SSE stream of live alerts
  GET  /api/alerts                 — Recent alerts (JSON, paginated)
  GET  /api/alerts/unread-count    — How many unread alerts
  POST /api/alerts/mark-read       — Mark alert(s) as read
  POST /api/alerts/mark-all-read   — Mark all as read
  GET  /api/alerts/history         — DB-persisted alert history
  GET  /api/alerts/stats           — Alert bus statistics
  POST /api/alerts/test            — Push a test alert (dev only)
"""

import json
import time
import queue
from flask import Blueprint, Response, request, jsonify, session, stream_with_context
from database.db import get_conn
from core.pipeline.alert_bus import get_alert_bus
from utils.logger import get_logger

log        = get_logger("api.alerts")
alerts_bp  = Blueprint("alerts", __name__)

# ── Ensure security_alerts table exists ──────────────────────────────────────

def _ensure_alerts_table():
    """Create security_alerts table if it doesn't exist (safe to call repeatedly)."""
    try:
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id    TEXT,
                timestamp   TEXT,
                severity    TEXT,
                alert_type  TEXT,
                category    TEXT,
                event_id    TEXT,
                source      TEXT,
                user_name   TEXT,
                ip_address  TEXT,
                risk_score  REAL DEFAULT 0,
                title       TEXT,
                description TEXT,
                read        INTEGER DEFAULT 0,
                created_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"alerts table init: {e}")

_ensure_alerts_table()


# ── Auth helper ───────────────────────────────────────────────────────────────

def _require_auth():
    """
    Return error response if not authenticated, else None.
    FIX BUG-2: Also accepts ?token= query param because EventSource API
    cannot set custom headers / cookies reliably across all browsers.
    """
    if session.get("authenticated"):
        return None
    # Token fallback for SSE clients
    token = request.args.get("token", "")
    if token and token == session.get("sse_token"):
        return None
    return jsonify({"ok": False, "error": "Unauthorized"}), 401


# ── Inline SSE generator (FIX BUG-1) ─────────────────────────────────────────

def _alert_sse_generator(bus):
    """
    FIX BUG-1: alert_sse_generator was imported from alert_bus but was never
    defined there — caused ImportError / AttributeError at runtime.
    
    Generator subscribes to the alert bus queue and yields SSE-formatted events.
    Sends a heartbeat every 15s so proxies don't close the connection.
    """
    q, unsubscribe = bus.subscribe()

    try:
        last_hb = time.time()
        while True:
            try:
                alert = q.get(timeout=15)
                yield f"data: {json.dumps(alert)}\n\n"
                last_hb = time.time()
            except queue.Empty:
                # Send heartbeat to keep connection alive
                if time.time() - last_hb >= 15:
                    yield f"data: {json.dumps({'type': 'heartbeat', 'ts': time.time()})}\n\n"
                    last_hb = time.time()
    except GeneratorExit:
        pass
    finally:
        unsubscribe()


# ── SSE Stream ────────────────────────────────────────────────────────────────

@alerts_bp.route("/alerts/stream")
def alert_stream():
    """
    Server-Sent Events stream.
    Browser connects once, receives alerts in real time.

    JavaScript usage:
        const es = new EventSource('/api/alerts/stream', {withCredentials: true});
        es.onmessage = (e) => {
            const alert = JSON.parse(e.data);
            if (alert.type === 'heartbeat') return;
            showAlertToast(alert);
        };
        es.onerror = (e) => { console.error('SSE error', e); };
    """
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    bus = get_alert_bus()

    # FIX BUG-3: Add required CORS + SSE headers so browser doesn't drop the stream
    headers = {
        "Content-Type":                "text/event-stream",
        "Cache-Control":               "no-cache, no-store",
        "X-Accel-Buffering":           "no",
        "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
        "Access-Control-Allow-Credentials": "true",
        "Connection":                  "keep-alive",
    }

    return Response(
        stream_with_context(_alert_sse_generator(bus)),
        mimetype="text/event-stream",
        headers=headers,
    )


# ── REST Endpoints ────────────────────────────────────────────────────────────

@alerts_bp.route("/alerts")
def get_alerts():
    """Return recent alerts from memory."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    limit        = min(int(request.args.get("limit", 50)), 200)
    min_severity = request.args.get("severity")    # CRITICAL|HIGH|MEDIUM|LOW
    bus          = get_alert_bus()
    alerts       = bus.get_history(limit=limit, min_severity=min_severity)

    return jsonify({
        "ok":     True,
        "alerts": alerts,
        "total":  len(alerts),
        "unread": bus.get_unread_count(),
    })


@alerts_bp.route("/alerts/unread-count")
def unread_count():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    bus = get_alert_bus()
    return jsonify({"ok": True, "count": bus.get_unread_count()})


@alerts_bp.route("/alerts/mark-read", methods=["POST"])
def mark_read():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    data     = request.get_json(force=True) or {}
    alert_id = data.get("id")
    if alert_id is None:
        return jsonify({"ok": False, "error": "Missing id"}), 400

    get_alert_bus().mark_read(int(alert_id))

    # FIX BUG-5: DB stores alert_id as TEXT — must cast to str or UPDATE matches nothing
    try:
        conn = get_conn()
        conn.execute(
            "UPDATE security_alerts SET read=1 WHERE alert_id=?",
            (str(alert_id),)   # ← was int(alert_id) — type mismatch caused silent no-op
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"mark_read DB update failed: {e}")

    return jsonify({"ok": True})


@alerts_bp.route("/alerts/mark-all-read", methods=["POST"])
def mark_all_read():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    get_alert_bus().mark_all_read()

    try:
        conn = get_conn()
        conn.execute("UPDATE security_alerts SET read=1")
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"mark_all_read DB failed: {e}")

    return jsonify({"ok": True})


@alerts_bp.route("/alerts/history")
def alert_history():
    """Return DB-persisted alert history with filtering."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    limit    = min(int(request.args.get("limit", 100)), 500)
    severity = request.args.get("severity", "")
    category = request.args.get("category", "")
    unread   = request.args.get("unread", "")

    # FIX BUG-4: Ensure table exists before querying — was crashing on fresh installs
    _ensure_alerts_table()

    try:
        conn = get_conn()
        c    = conn.cursor()

        conditions = ["1=1"]
        params     = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if category:
            conditions.append("category = ?")
            params.append(category)
        if unread == "1":
            conditions.append("read = 0")

        where = " AND ".join(conditions)
        c.execute(f"""
            SELECT id, alert_id, timestamp, severity, alert_type, category,
                   event_id, source, user_name, ip_address, risk_score,
                   title, description, read, created_at
            FROM security_alerts
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT ?
        """, params + [limit])

        rows = []
        for row in c.fetchall():
            rows.append({
                "id":          row[0],
                "alert_id":    row[1],
                "timestamp":   row[2],
                "severity":    row[3],
                "type":        row[4],
                "category":    row[5],
                "event_id":    row[6],
                "source":      row[7],
                "user":        row[8],
                "ip":          row[9],
                "risk_score":  row[10],
                "title":       row[11],
                "description": row[12],
                "read":        bool(row[13]),
                "created_at":  row[14],
            })

        # Summary counts
        c.execute("""
            SELECT severity, COUNT(*) FROM security_alerts
            GROUP BY severity
        """)
        counts = {row[0]: row[1] for row in c.fetchall()}
        conn.close()

        return jsonify({
            "ok":      True,
            "alerts":  rows,
            "total":   len(rows),
            "counts":  counts,
        })
    except Exception as e:
        log.error(f"Alert history query failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@alerts_bp.route("/alerts/stats")
def alert_stats():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    bus = get_alert_bus()
    return jsonify({"ok": True, "stats": bus.stats()})


@alerts_bp.route("/alerts/test", methods=["POST"])
def test_alert():
    """Push a test alert to verify the stream is working."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    bus = get_alert_bus()
    bus.push({
        "type":        "test",
        "severity":    "MEDIUM",
        "category":    "test",
        "name":        "Test Alert",
        "title":       "Test Alert",
        "description": "This is a test alert from the dashboard.",
        "risk_score":  5,
        "source":      "dashboard",
    })
    return jsonify({"ok": True, "message": "Test alert pushed"})
