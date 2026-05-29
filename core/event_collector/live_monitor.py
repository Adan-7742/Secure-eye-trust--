"""
core/event_collector/live_monitor.py
=====================================
Background thread that watches Windows Event Logs in real time.
Runs every 30 seconds, inserts only NEW events (no duplicates).

HOW IT WORKS:
  - Stores the last seen RecordNumber per channel in the database
  - On each poll, reads ONLY events newer than last seen
  - Inserts new events into logs_* tables
  - Fires an app_event so the SSE stream pushes update to browser

This means the dashboard updates LIVE without you clicking anything.

START: called once from app.py at startup via start_live_monitor()
STOP:  stops automatically when Flask shuts down
"""

import threading
import time
from datetime import datetime
from database.db import get_conn, log_app_event

POLL_INTERVAL = 30   # seconds between checks

# Track last RecordNumber seen per channel so we only fetch NEW events
_last_record = {
    "Application": 0,
    "System":      0,
    "Security":    0,
}

_stop_event = threading.Event()
_thread     = None


def _get_new_events(channel: str) -> list[dict]:
    """Read only events newer than last seen RecordNumber."""
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con

        TYPE_MAP = {
            win32con.EVENTLOG_ERROR_TYPE:       "ERROR",
            win32con.EVENTLOG_WARNING_TYPE:     "WARNING",
            win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
            win32con.EVENTLOG_AUDIT_SUCCESS:    "SUCCESS",
            win32con.EVENTLOG_AUDIT_FAILURE:    "FAILURE",
        }

        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        new_events  = []
        highest_rec = _last_record[channel]

        while True:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for ev in batch:
                rec = ev.RecordNumber
                if rec <= _last_record[channel]:
                    # Reached events we already have — stop reading
                    break
                if rec > highest_rec:
                    highest_rec = rec

                ts  = ev.TimeGenerated
                ts_str   = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""
                date_str = ts_str[:10]
                level    = TYPE_MAP.get(ev.EventType, "INFO")
                source   = ev.SourceName or ""

                try:
                    msg = win32evtlogutil.SafeFormatMessage(ev, source)
                except Exception:
                    inserts = ev.StringInserts
                    msg = " | ".join(inserts) if inserts else f"Event {ev.EventID & 0xFFFF}"

                new_events.append({
                    "timestamp": ts_str,
                    "date":      date_str,
                    "level":     level,
                    "source":    source,
                    "message":   (msg or "")[:2000],
                    "event_id":  ev.EventID & 0xFFFF,
                    "raw":       (msg or "")[:500],
                })
            else:
                continue
            break  # inner break hit — stop outer loop too

        win32evtlog.CloseEventLog(handle)

        if highest_rec > _last_record[channel]:
            _last_record[channel] = highest_rec

        return new_events

    except ImportError:
        return []   # pywin32 not installed
    except Exception as e:
        if "5" in str(e) or "access" in str(e).lower():
            pass    # Security log needs admin — silent
        else:
            print(f"[live_monitor] Error reading {channel}: {e}")
        return []


def _insert_events(cat: str, events: list[dict]):
    """Insert new events into the database."""
    if not events:
        return
    conn = get_conn()
    c    = conn.cursor()
    for ev in events:
        try:
            c.execute(f"""
                INSERT INTO logs_{cat}
                    (timestamp, date, level, source, message, event_id, raw)
                VALUES (?,?,?,?,?,?,?)
            """, (
                ev["timestamp"], ev["date"],    ev["level"],
                ev["source"],    ev["message"], ev["event_id"], ev["raw"],
            ))
        except Exception as ex:
            # Ignore duplicate unique constraint errors (they happen if the same event
            # is inserted from multiple ingestion paths). Only log unexpected errors.
            try:
                import sqlite3 as _sqlite
                if isinstance(ex, _sqlite.IntegrityError):
                    continue
            except Exception:
                pass
            print(f"[live_monitor] Insert error: {ex}")
    conn.commit()
    conn.close()


def _poll_once():
    """One poll cycle — check all channels for new events."""
    total_new = 0
    counts    = {}

    channel_to_cat = {
        "Application": "application",
        "System":      "system",
        "Security":    "security",
    }

    for channel, cat in channel_to_cat.items():
        new = _get_new_events(channel)
        if new:
            _insert_events(cat, new)
            counts[cat] = len(new)
            total_new  += len(new)

    if total_new > 0:
        print(f"[live_monitor] {datetime.now().strftime('%H:%M:%S')} — {total_new} new events: {counts}")
        log_app_event("live_update", {"new": total_new, "counts": counts})


def _monitor_loop():
    """Background thread loop."""
    print(f"[live_monitor] Started — polling every {POLL_INTERVAL}s")

    # Seed last_record with current max so we only get events from NOW onward
    try:
        import win32evtlog
        for channel in _last_record:
            try:
                h = win32evtlog.OpenEventLog(None, channel)
                n = win32evtlog.GetNumberOfEventLogRecords(h)
                o = win32evtlog.GetOldestEventLogRecord(h)
                _last_record[channel] = o + n - 1   # approx last record
                win32evtlog.CloseEventLog(h)
                print(f"[live_monitor] {channel}: seeded at record #{_last_record[channel]}")
            except Exception:
                pass
    except ImportError:
        pass

    while not _stop_event.is_set():
        try:
            _poll_once()
        except Exception as e:
            print(f"[live_monitor] Poll error: {e}")
        _stop_event.wait(POLL_INTERVAL)

    print("[live_monitor] Stopped.")


def start_live_monitor():
    """Start the background polling thread. Call once from app.py."""
    global _thread
    if _thread and _thread.is_alive():
        return   # already running
    _stop_event.clear()
    _thread = threading.Thread(target=_monitor_loop, daemon=True, name="live-monitor")
    _thread.start()


def stop_live_monitor():
    """Stop the polling thread gracefully."""
    _stop_event.set()
