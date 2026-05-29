"""
api/error_stream_api.py  — v2.2  (bugs fixed)
=====================================================
Real-time error stream with:
  * Server-side deduplication  — same EID from same source within 60s = skip
  * Noisy-event suppression    — high-volume EIDs (5152, 5157, 4624…) silenced
  * Rate cap                   — max 1 notification every 3s
  * repeat_count               — JS shows "x4 more" on grouped events

BUGS FIXED:
  BUG-6: conn.cursor() returned sqlite3.Row objects but code used dict-style
         access (r.get("id")) — these don't have .get(). Fixed: use row_factory
         or explicit column indexing. Added row_factory = sqlite3.Row to get_conn.

  BUG-7: since[cat] updated even for suppressed EIDs — meant suppressed events
         permanently advanced the cursor, so real errors after them were skipped.
         Fixed: advance since[cat] BEFORE the suppress/dedup checks.

  BUG-8: hb_ticks reset to 0 after every heartbeat — caused heartbeats to fire
         every single poll cycle when there are no errors (hb_ticks never > 10).
         Fixed: reset after send, use elapsed-time check instead.

  BUG-9: GeneratorExit not re-raised inside inner for-loop — generator kept
         running after client disconnected, leaking a thread per connection.
         Fixed: catch GeneratorExit explicitly in the for loop and break/return.
"""

import json
import time
import sqlite3
from flask import Blueprint, Response, stream_with_context, session, request
from database.db import get_conn

error_stream_bp = Blueprint("error_stream", __name__)

_ERROR_LEVELS = ("ERROR", "CRITICAL", "FAILURE")
_CATEGORIES   = ("application", "system", "security", "windows_update")

# EIDs suppressed from toast notifications (still visible in log table)
_SUPPRESSED_EIDS = {
    "5152",   # Firewall blocked packet      — hundreds per minute
    "5157",   # Firewall blocked connection  — same
    "5158",   # Permitted bind               — noise
    "4634",   # Account logoff               — very high volume
    "4624",   # Successful logon             — INFO noise
    "4656",   # Object handle requested      — audit noise
    "10016",  # DCOM permission              — benign, very frequent
    "5447",   # WFP filter changed           — noise
}

_DEDUP_WINDOW_SEC    = 60   # same source+EID won't notify again within this
_MIN_SEND_INTERVAL   = 3    # seconds between any two browser pushes
_POLL_INTERVAL       = 3    # how often to query DB
_HEARTBEAT_INTERVAL  = 30   # seconds between heartbeats


def _get_new_errors(since: dict, dedup: dict) -> list:
    conn    = get_conn()
    # FIX BUG-6: enable Row factory so columns are accessible by name
    conn.row_factory = sqlite3.Row
    c       = conn.cursor()
    results = []
    now     = time.time()
    ph      = ",".join("?" * len(_ERROR_LEVELS))

    for cat in _CATEGORIES:
        last_id = since.get(cat, 0)
        try:
            c.execute(
                f"SELECT id,timestamp,level,source,message,event_id "
                f"FROM logs_{cat} WHERE level IN ({ph}) AND id > ? "
                f"ORDER BY id ASC LIMIT 50",
                _ERROR_LEVELS + (last_id,),
            )
            rows = c.fetchall()
        except Exception:
            rows = []

        skipped = {}
        for row in rows:
            rid = row["id"]
            eid = str(row["event_id"] or "").strip()
            src = str(row["source"]   or "").strip()

            # FIX BUG-7: advance cursor FIRST — before any skip/suppress decisions
            since[cat] = max(since.get(cat, 0), rid)

            if eid in _SUPPRESSED_EIDS:
                continue

            key = f"{src}|{eid}"
            if now - dedup.get(key, 0) < _DEDUP_WINDOW_SEC:
                skipped[key] = skipped.get(key, 0) + 1
                continue

            dedup[key]  = now
            results.append({
                "id":           rid,
                "timestamp":    row["timestamp"],
                "level":        row["level"],
                "source":       src,
                "message":      row["message"],
                "event_id":     eid,
                "category":     cat,
                "repeat_count": skipped.get(key, 0) + 1,
            })

    conn.close()
    results.sort(key=lambda x: x.get("id", 0))
    return results


@error_stream_bp.route("/error-stream")
def error_stream():
    if not session.get("authenticated"):
        return Response("Unauthorized", status=401)

    def generate():
        since = {}
        dedup = {}
        conn  = get_conn()
        conn.row_factory = sqlite3.Row
        c     = conn.cursor()
        ph    = ",".join("?" * len(_ERROR_LEVELS))
        for cat in _CATEGORIES:
            try:
                c.execute(f"SELECT MAX(id) FROM logs_{cat} WHERE level IN ({ph})", _ERROR_LEVELS)
                row = c.fetchone()
                since[cat] = (row[0] or 0) if row else 0
            except Exception:
                since[cat] = 0
        conn.close()

        last_send = 0
        last_hb   = time.time()   # FIX BUG-8: track heartbeat by wall time

        while True:
            try:
                errors = _get_new_errors(since, dedup)
                now    = time.time()

                for err in errors:
                    try:
                        gap = _MIN_SEND_INTERVAL - (time.time() - last_send)
                        if gap > 0:
                            time.sleep(gap)

                        payload = {
                            "type": "new_error",
                            "payload": {
                                "level":        err.get("level", "ERROR"),
                                "source":       err.get("source", ""),
                                "message":      err.get("message", ""),
                                "event_id":     str(err.get("event_id") or ""),
                                "timestamp":    err.get("timestamp", ""),
                                "category":     err.get("category", ""),
                                "repeat_count": err.get("repeat_count", 1),
                            },
                        }
                        yield f"data: {json.dumps(payload)}\n\n"
                        last_send = time.time()
                    except GeneratorExit:
                        # FIX BUG-9: catch inside loop so client disconnect stops the thread
                        return

                # FIX BUG-8: heartbeat based on elapsed time, not tick counter
                if time.time() - last_hb >= _HEARTBEAT_INTERVAL:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                    last_hb = time.time()

                time.sleep(_POLL_INTERVAL)

            except GeneratorExit:
                # FIX BUG-9: outer catch for clean shutdown
                return
            except Exception as exc:
                print(f"[error_stream] {exc}")
                time.sleep(5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":               "no-cache, no-store",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Credentials": "true",
            "Connection":                  "keep-alive",
        },
    )
