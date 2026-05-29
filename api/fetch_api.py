"""
api/fetch_api.py
=================
Blueprint: /api/fetch-real

INCREMENTAL FETCH — works like Windows Event Viewer.

How it differs from the previous version
----------------------------------------
OLD behaviour:
    1. DELETE FROM logs_application / logs_system / logs_security / logs_windows_update
    2. Re-read EVERY event from Windows Event Viewer (all 100k+ records)
    3. INSERT them all back
    → Slow, wasteful, and you lose history if Windows rotates the log.

NEW behaviour (this file):
    1. Read the last RecordNumber we successfully ingested from `fetch_cursors`.
    2. Open each Windows channel, seek BACKWARDS, but stop the moment we hit a
       record we've already seen (RecordNumber <= cursor).
    3. INSERT OR IGNORE the new events keyed on a content_hash so re-runs and
       overlapping ranges never produce duplicates.
    4. Persist the new cursor (max RecordNumber seen this run).
    5. Return a summary: { added, already_seen, total_in_db, elapsed }.

So the very first fetch loads everything; every subsequent click only pulls
NEW events since last time — exactly how Event Viewer's "Refresh" works.

It also still supports a FULL re-sync via POST body { "full": true } or
?full=1 for the rare case you want to rebuild from scratch (e.g. corrupted DB).
"""

from flask import Blueprint, jsonify, request
from datetime import datetime
import hashlib
import time

from database.db import (
    get_conn, log_activity, LOG_CATEGORIES,
    ensure_fetch_cursors_table,        # added in db.py patch
    ensure_record_number_column,       # added in db.py patch
    get_cursor, set_cursor,            # added in db.py patch
)
from core.event_collector import fetch_all_logs, WIN32_AVAILABLE
from utils.admin_check import is_admin
from utils.logger import get_logger

# Use the incremental reader from the collector (returns RecordNumber too).
try:
    from core.event_collector.collector import read_channel_since, read_windows_update_since
    HAS_INCREMENTAL = True
except ImportError:
    HAS_INCREMENTAL = False

fetch_bp = Blueprint("fetch", __name__)
log = get_logger("fetch_api")


# Channels we ingest. windows_update is filtered out of System so it shares
# the System cursor — that way the WU events come from the same forward-sweep.
CHANNEL_TO_CATEGORY = {
    "Application": "application",
    "System":      "system",
    "Security":    "security",
}


def _content_hash(ev: dict) -> str:
    """
    Deterministic hash for INSERT OR IGNORE deduping.
    Uses record_number when present (perfectly unique per channel), falls back
    to (timestamp, event_id, source, message[:300]) so we still dedupe events
    pulled from sources without a stable record number.
    """
    rn = ev.get("record_number")
    if rn:
        # record_number is unique per channel, so include category for safety
        key = f"{ev.get('category','')}::{rn}"
    else:
        key = "|".join([
            str(ev.get("timestamp", "")),
            str(ev.get("event_id", "")),
            str(ev.get("source", "")),
            (ev.get("message", "") or "")[:300],
        ])
    return hashlib.sha1(key.encode("utf-8", errors="replace")).hexdigest()


def _ensure_dedupe_indexes(conn):
    """Create UNIQUE indexes on content_hash so INSERT OR IGNORE dedupes correctly."""
    for cat in LOG_CATEGORIES:
        try:
            conn.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{cat}_chash "
                f"ON logs_{cat}(content_hash)"
            )
        except Exception as e:
            log.warning(f"Could not create dedupe index on logs_{cat}: {e}")
    conn.commit()


def _insert_events(conn, cat: str, events: list[dict]) -> tuple[int, int]:
    """
    INSERT OR IGNORE into logs_{cat}.
    Returns (added, already_seen).
    Tracks the max record_number for cursor update.
    """
    c = conn.cursor()
    now = datetime.now().isoformat()
    added = 0
    seen  = 0

    for ev in events:
        ev["content_hash"] = _content_hash(ev)
        try:
            c.execute(f"""
                INSERT OR IGNORE INTO logs_{cat}
                (timestamp, date, level, source, message, event_id, raw,
                 record_number, content_hash, uploaded_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                ev.get("timestamp"),
                ev.get("date"),
                ev.get("level"),
                ev.get("source"),
                ev.get("message"),
                ev.get("event_id"),
                ev.get("raw"),
                ev.get("record_number"),
                ev["content_hash"],
                now,
            ))
            if c.rowcount > 0:
                added += 1
            else:
                seen += 1
        except Exception as ex:
            log.error(f"Insert error in {cat}: {ex}")

    conn.commit()
    return added, seen


@fetch_bp.route("/fetch-real", methods=["POST", "GET"])
def fetch_real():
    """
    INCREMENTAL Windows Event Log fetch.

    Body / query params:
        full=1   →  treat as a fresh sync (reset cursors, but DO NOT wipe data
                    unless wipe=1 is also given; we still dedupe by content_hash)
        wipe=1   →  in addition to full, DELETE existing rows before ingest
                    (use this only when the DB is broken — normally not needed)

    Response:
        {
          "status": "ok",
          "mode":   "incremental" | "full",
          "added":           { cat: int, ... },
          "already_seen":    { cat: int, ... },
          "total_in_db":     { cat: int, ... },
          "elapsed_seconds": float,
          "cursors":         { cat: int, ... },   ← last RecordNumber per channel
          ...
        }
    """
    admin = is_admin()
    t0    = time.time()

    # Parse mode
    full_sync = (request.args.get("full") == "1" or
                 (request.is_json and (request.get_json(silent=True) or {}).get("full")))
    wipe      = (request.args.get("wipe") == "1" or
                 (request.is_json and (request.get_json(silent=True) or {}).get("wipe")))

    # 1. Schema preconditions
    conn = get_conn()
    ensure_record_number_column(conn)
    ensure_fetch_cursors_table(conn)
    _ensure_dedupe_indexes(conn)

    # 2. Optional reset (cursor-only by default; data-wipe only if explicitly asked)
    if full_sync:
        log.info("Full sync requested — resetting cursors")
        for cat in LOG_CATEGORIES:
            set_cursor(conn, cat, 0)
        if wipe:
            log.warning("WIPE flag set — deleting all rows before re-sync")
            c = conn.cursor()
            for cat in LOG_CATEGORIES:
                try:
                    c.execute(f"DELETE FROM logs_{cat}")
                except Exception as e:
                    log.warning(f"Failed to clear {cat}: {e}")
            conn.commit()

    # 3. Read events from each channel, but only those past the cursor.
    added_all       = {cat: 0 for cat in LOG_CATEGORIES}
    seen_all        = {cat: 0 for cat in LOG_CATEGORIES}
    new_cursors     = {}

    if HAS_INCREMENTAL:
        # ── Preferred path: read newer-than-cursor only ─────────────────────────
        for channel, cat in CHANNEL_TO_CATEGORY.items():
            since = get_cursor(conn, cat)
            log.info(f"[{channel}] reading events with RecordNumber > {since}")
            try:
                events, max_rec = read_channel_since(channel, since)
            except Exception as e:
                log.error(f"Failed reading {channel}: {e}")
                continue

            log.info(f"[{channel}] {len(events)} new events from Windows")
            if events:
                # Tag category for content_hash uniqueness
                for ev in events:
                    ev.setdefault("category", cat)
                a, s = _insert_events(conn, cat, events)
                added_all[cat] += a
                seen_all[cat]  += s

            if max_rec and max_rec > since:
                set_cursor(conn, cat, max_rec)
            new_cursors[cat] = max(max_rec or 0, since)

        # ── Windows Update events live inside System; pull them with their own cursor
        try:
            wu_since = get_cursor(conn, "windows_update")
            wu_events, wu_max = read_windows_update_since(wu_since)
            log.info(f"[WindowsUpdate] {len(wu_events)} new events from System filter")
            if wu_events:
                for ev in wu_events:
                    ev.setdefault("category", "windows_update")
                a, s = _insert_events(conn, "windows_update", wu_events)
                added_all["windows_update"] += a
                seen_all["windows_update"]  += s
            if wu_max and wu_max > wu_since:
                set_cursor(conn, "windows_update", wu_max)
            new_cursors["windows_update"] = max(wu_max or 0, wu_since)
        except Exception as e:
            log.error(f"Windows Update incremental read failed: {e}")

    else:
        # ── Fallback path: collector doesn't support incremental yet.
        # Read everything but rely on content_hash dedupe to avoid duplicates.
        log.warning("Incremental reader not available — falling back to full read with dedupe")
        try:
            events_by_cat, _totals = fetch_all_logs()
        except Exception as e:
            conn.close()
            return jsonify({"error": f"Fetch failed: {e}"}), 500

        for cat, evs in events_by_cat.items():
            for ev in evs:
                ev.setdefault("category", cat)
            a, s = _insert_events(conn, cat, evs)
            added_all[cat] += a
            seen_all[cat]  += s
            new_cursors[cat] = 0  # unknown without record number

    # 4. Compute totals after ingest
    c = conn.cursor()
    total_in_db = {}
    for cat in LOG_CATEGORIES:
        try:
            c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
            total_in_db[cat] = c.fetchone()[0]
        except Exception:
            total_in_db[cat] = 0

    conn.close()

    elapsed = round(time.time() - t0, 2)
    total_added = sum(added_all.values())
    total_seen  = sum(seen_all.values())

    log_activity("fetch_done", {
        "mode":          "full" if full_sync else "incremental",
        "added":         added_all,
        "already_seen":  seen_all,
        "total_in_db":   total_in_db,
        "elapsed_sec":   elapsed,
        "cursors":       new_cursors,
    })

    log.info(
        f"Fetch ({'full' if full_sync else 'incremental'}) complete: "
        f"+{total_added} new, {total_seen} already-seen, "
        f"total {sum(total_in_db.values())} ({elapsed}s)"
    )

    return jsonify({
        "status":           "ok",
        "mode":             "full" if full_sync else "incremental",
        "added":            added_all,
        "already_seen":     seen_all,
        "total_added":      total_added,
        "total_already_seen": total_seen,
        "total_in_db":      total_in_db,
        "cursors":          new_cursors,
        "elapsed_seconds":  elapsed,
        "is_admin":         admin,
        "win32_available":  WIN32_AVAILABLE,
        "security_note":    (
            "✅ Security log up to date"
            if admin and total_in_db.get("security", 0) > 0
            else "⚠️  Security log empty — run app as Administrator"
        ),
        # Backwards-compat fields for older UI that expected `counts`/`total_inserted`
        "counts":           total_in_db,
        "total_inserted":   total_added,
        "total_failed":     0,
    })


@fetch_bp.route("/fetch-status")
def fetch_status():
    """
    Return current cursor positions and DB totals without doing any fetch.
    Useful for the UI to show "you are up to RecordNumber X out of Y".
    """
    conn = get_conn()
    ensure_record_number_column(conn)
    ensure_fetch_cursors_table(conn)

    c = conn.cursor()
    out = {}
    for cat in LOG_CATEGORIES:
        try:
            c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
            total = c.fetchone()[0]
        except Exception:
            total = 0
        out[cat] = {
            "rows_in_db":  total,
            "cursor":      get_cursor(conn, cat),
        }
    conn.close()
    return jsonify({"status": "ok", "categories": out})


@fetch_bp.route("/clear", methods=["POST"])
def clear_logs():
    """
    Wipe all log data AND reset the fetch cursors so the next fetch behaves
    like a first run (will pull everything from Event Viewer again).
    """
    conn = get_conn()
    ensure_fetch_cursors_table(conn)
    c = conn.cursor()
    for cat in LOG_CATEGORIES:
        try:
            c.execute(f"DELETE FROM logs_{cat}")
            set_cursor(conn, cat, 0)
        except Exception as e:
            log.warning(f"Failed to clear {cat}: {e}")
    try:
        c.execute("DELETE FROM ml_detections")
    except Exception:
        pass
    conn.commit()
    conn.close()
    log_activity("clear", "all logs and cursors cleared by user")
    log.info("All logs and cursors cleared")
    return jsonify({"status": "cleared"})


@fetch_bp.route("/activity")
def activity():
    """Recent activity log entries for the dashboard real-time feed."""
    limit = int(request.args.get("limit", 20))
    conn  = get_conn()
    c     = conn.cursor()
    c.execute("""
        SELECT event_type, details, timestamp
        FROM activity_log
        ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {"type": r[0], "details": r[1], "timestamp": r[2]}
        for r in rows
    ])
