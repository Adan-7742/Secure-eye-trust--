"""
chatbot/context_builder.py
===========================
Builds the live log context that gets injected into every AI chat prompt.

WHY THIS MATTERS:
    Without context, the AI gives generic Windows advice.
    With context, it says "You have 347 disk errors from ntfs source — likely corruption".
    The context comes from the LIVE database, so it always reflects current data.

WHAT'S INCLUDED IN CONTEXT:
    - Per-category stats (total, errors, warnings)
    - Top 5 most recent error events
    - Any ML threat detections from the last analysis
    - High-activity dates
"""

import json
from datetime import datetime
from database.db import get_conn, CATEGORIES as LOG_CATEGORIES
from utils.logger import get_logger

log = get_logger("context_builder")


def build_context() -> dict:
    """
    Pull live stats from SQLite and return as a structured dict.
    This is called on every chat request.
    """
    try:
        conn = get_conn()
        c    = conn.cursor()

        # ── Per-category stats ────────────────────────────────────────────────
        stats = {}
        for cat in LOG_CATEGORIES:
            try:
                c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
                total = c.fetchone()[0]

                c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level IN ('ERROR','CRITICAL','FAILURE')")
                errors = c.fetchone()[0]

                c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level='WARNING'")
                warnings = c.fetchone()[0]

                c.execute(f"""
                    SELECT source, COUNT(*) FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL')
                    GROUP BY source ORDER BY COUNT(*) DESC LIMIT 3
                """)
                top = [{"source": r[0], "count": r[1]} for r in c.fetchall()]

                stats[cat] = {"total": total, "errors": errors, "warnings": warnings, "top_error_sources": top}
            except Exception:
                stats[cat] = {"total": 0, "errors": 0, "warnings": 0, "top_error_sources": []}

        # ── Recent errors ─────────────────────────────────────────────────────
        recent_errors = []
        for cat in LOG_CATEGORIES:
            try:
                c.execute(f"""
                    SELECT timestamp, level, source, message, event_id
                    FROM logs_{cat}
                    WHERE level IN ('ERROR','CRITICAL','FAILURE')
                    ORDER BY timestamp DESC LIMIT 5
                """)
                for r in c.fetchall():
                    recent_errors.append({
                        "category": cat,
                        "timestamp": r[0],
                        "level": r[1],
                        "source": r[2],
                        "message": (r[3] or "")[:200],
                        "event_id": r[4],
                    })
            except Exception:
                pass

        recent_errors.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        # ── ML detections ─────────────────────────────────────────────────────
        ml_detections = []
        try:
            c.execute("""
                SELECT threat_type, severity, details FROM ml_detections
                ORDER BY detected_at DESC LIMIT 5
            """)
            for r in c.fetchall():
                d = json.loads(r[2] or "{}")
                ml_detections.append({
                    "threat_type": r[0], "severity": r[1],
                    "name": d.get("name",""), "description": d.get("description",""),
                })
        except Exception:
            pass

        conn.close()
        return {
            "stats":          stats,
            "recent_errors":  recent_errors[:15],
            "ml_detections":  ml_detections,
            "fetched_at":     datetime.now().isoformat(),
        }

    except Exception as e:
        log.error(f"Context build failed: {e}")
        return {"stats": {}, "recent_errors": [], "ml_detections": [], "error": str(e)}
