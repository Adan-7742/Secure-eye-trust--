"""
api/realtime_api.py
===================
Blueprint: GET /api/events  (Server-Sent Events stream)

Streams real-time app events to the browser using SSE.
Browser JS listens on this endpoint and updates the UI live.

Events pushed:
  - fetch_progress  (during Windows log fetch)
  - new_error       (when a new critical error arrives)
  - analysis_done   (after analysis completes)
  - heartbeat       (every 30s to keep connection alive)

DATA FLOW:
  database/app_events table
      ↓ polled every 2s
  /api/events (SSE stream)
      ↓ text/event-stream
  static/js/realtime.js  EventSource listener
      ↓
  UI toast / badge updates
"""

import json
import time
from flask import Blueprint, Response, stream_with_context
from database.db import get_conn

realtime_bp = Blueprint("realtime", __name__)

_last_event_id = {}   # per-client cursor


def _get_new_events(since_id: int) -> list:
    conn = get_conn()
    c    = conn.cursor()
    c.execute(
        "SELECT id, event_type, payload, ts FROM app_events WHERE id > ? ORDER BY id ASC LIMIT 20",
        (since_id,)
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


@realtime_bp.route("/events")
def sse_events():
    """Server-Sent Events stream for real-time UI updates."""
    def generate():
        cursor = 0
        # Start from last known ID
        conn = get_conn()
        c    = conn.cursor()
        c.execute("SELECT MAX(id) FROM app_events")
        row = c.fetchone()
        conn.close()
        cursor = row[0] or 0

        heartbeat_count = 0
        while True:
            events = _get_new_events(cursor)
            for ev in events:
                cursor = ev["id"]
                data   = json.dumps({
                    "type":    ev["event_type"],
                    "payload": json.loads(ev["payload"]) if ev["payload"] else {},
                    "ts":      ev["ts"],
                })
                yield f"data: {data}\n\n"

            heartbeat_count += 1
            if heartbeat_count >= 15:   # every ~30s
                yield f"data: {json.dumps({'type':'heartbeat','ts':time.strftime('%H:%M:%S')})}\n\n"
                heartbeat_count = 0

            time.sleep(2)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        }
    )
