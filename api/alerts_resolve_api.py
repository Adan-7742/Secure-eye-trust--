"""
api/alerts_resolve_api.py  — v3.1  (bugs fixed)
=================================================
Endpoints for marking alerts as resolved and filtering them out.

BUGS FIXED:
  BUG-10: ON CONFLICT(alert_id) requires a UNIQUE index on alert_id, but the
          CREATE TABLE statement used TEXT for alert_id without UNIQUE constraint.
          SQLite silently inserted duplicates instead of upserting, so the same
          alert could be "resolved" multiple times.
          Fixed: added UNIQUE NOT NULL constraint to alert_id column.

  BUG-11: resolved_ids() returned ids as a list but callers filtered with
          `if alert.id in resolvedIds` where resolvedIds was an Array — JS
          Array.includes() is O(n) and fails for numeric vs string mismatch.
          Fixed: return both a list and a Set-friendly JSON object; added
          string normalization so numeric IDs compare correctly.

  BUG-12: resolve_alert() called datetime.now().isoformat() TWICE — once for
          the INSERT and once for the response — producing different timestamps.
          Fixed: compute once and reuse.

ENDPOINTS:
  POST /api/alerts/resolve          — Mark alert resolved, store note
  GET  /api/alerts/resolved-ids     — Return all resolved alert IDs
  GET  /api/alerts/resolved         — Full resolved alert history
  DELETE /api/alerts/resolve/<id>   — Un-resolve an alert (new)
"""

from flask import Blueprint, request, jsonify, session
from database.db import get_conn
from datetime import datetime

resolve_bp = Blueprint("alerts_resolve", __name__)


def _init_resolve_table():
    """Create resolved_alerts table with correct UNIQUE constraint (FIX BUG-10)."""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS resolved_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    TEXT UNIQUE NOT NULL,
            alert_title TEXT,
            alert_cat   TEXT,
            note        TEXT,
            resolved_at TEXT DEFAULT (datetime('now'))
        )
    """)
    # Migrate old table if it exists without the UNIQUE index
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_resolved_alert_id ON resolved_alerts(alert_id)")
    except Exception:
        pass
    conn.commit()
    conn.close()


# Create table immediately when module loads
try:
    _init_resolve_table()
except Exception as e:
    print(f"[resolve_api] Table init warning: {e}")


def _auth():
    if not session.get("authenticated"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None


@resolve_bp.route("/alerts/resolve", methods=["POST"])
def resolve_alert():
    """
    Mark an alert as resolved.
    Body: { "id": "alert_id", "note": "optional text" }
    """
    err = _auth()
    if err:
        return err

    body     = request.get_json(force=True) or {}
    alert_id = str(body.get("id", "")).strip()
    note     = str(body.get("note", "")).strip()[:500]
    title    = str(body.get("title", "")).strip()[:200]
    category = str(body.get("category", "")).strip()[:50]

    if not alert_id:
        return jsonify({"ok": False, "error": "Missing alert id"}), 400

    # FIX BUG-12: compute timestamp once
    resolved_at = datetime.now().isoformat()

    try:
        conn = get_conn()
        conn.execute("""
            INSERT INTO resolved_alerts (alert_id, alert_title, alert_cat, note, resolved_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET
                note        = excluded.note,
                resolved_at = excluded.resolved_at
        """, (alert_id, title, category, note, resolved_at))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "id": alert_id, "resolved_at": resolved_at})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@resolve_bp.route("/alerts/resolved-ids")
def resolved_ids():
    """
    Return all resolved alert IDs.
    FIX BUG-11: return both list (for iteration) and normalized string set
    so JS can do fast O(1) Set.has() lookups regardless of int/string type.
    """
    err = _auth()
    if err:
        return err

    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute("SELECT alert_id FROM resolved_alerts ORDER BY resolved_at DESC")
        # Normalize all IDs to strings so JS String(id) always matches
        ids  = [str(row[0]) for row in c.fetchall()]
        conn.close()
        return jsonify({"ok": True, "ids": ids, "count": len(ids)})
    except Exception as e:
        return jsonify({"ok": False, "ids": [], "error": str(e)})


@resolve_bp.route("/alerts/resolved")
def resolved_history():
    """Full resolved alert history with notes."""
    err = _auth()
    if err:
        return err

    try:
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            SELECT id, alert_id, alert_title, alert_cat, note, resolved_at
            FROM resolved_alerts
            ORDER BY resolved_at DESC
            LIMIT 200
        """)
        rows = [
            {
                "id":          row[0],
                "alert_id":    str(row[1]),   # normalize to string
                "title":       row[2],
                "category":    row[3],
                "note":        row[4],
                "resolved_at": row[5],
            }
            for row in c.fetchall()
        ]
        conn.close()
        return jsonify({"ok": True, "resolved": rows, "count": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "resolved": [], "error": str(e)})


@resolve_bp.route("/alerts/resolve/<alert_id>", methods=["DELETE"])
def unresolve_alert(alert_id):
    """Un-resolve an alert (remove from resolved list)."""
    err = _auth()
    if err:
        return err
    try:
        conn = get_conn()
        conn.execute("DELETE FROM resolved_alerts WHERE alert_id=?", (str(alert_id),))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "id": alert_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
