"""
api/upload_api.py
=================
Stores uploaded log files in uploads.db — completely isolated from main logs.db.
"""

import re
from datetime import datetime
from flask import Blueprint, jsonify, request
from database.uploads_db import get_upload_conn, init_uploads_db

upload_bp = Blueprint("upload", __name__)

PATTERNS = [
    re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(ERROR|WARNING|INFO|CRITICAL|FAILURE|SUCCESS)\s+(\S+)\s+(.+)$", re.I),
    re.compile(r"^\[(ERROR|WARNING|INFO|CRITICAL)\]\s+(\S+):\s+(.+)$", re.I),
    re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+):\s+(.+)$"),
]


def parse_line(line: str, filename: str = "") -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for p in PATTERNS:
        m = p.match(line)
        if m:
            g = m.groups()
            if len(g) == 4:
                ts, level, source, msg = g
            elif len(g) == 3:
                level, source, msg = g
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                continue
            return {"timestamp": ts[:19], "date": ts[:10], "level": level.upper(),
                    "source": source, "message": msg[:2000], "event_id": None,
                    "raw": line[:500], "filename": filename}
    return {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "date": datetime.now().strftime("%Y-%m-%d"), "level": "INFO",
            "source": "uploaded_file", "message": line[:2000], "event_id": None,
            "raw": line[:500], "filename": filename}


@upload_bp.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file     = request.files["file"]
    filename = file.filename or "unknown.log"
    category = request.form.get("category", "application")
    if category not in ["application", "system", "security", "windows_update"]:
        category = "application"

    content  = file.read().decode("utf-8", errors="replace")
    lines    = content.splitlines()

    conn     = get_upload_conn()
    c        = conn.cursor()
    inserted = 0
    skipped  = 0

    for line in lines[:50_000]:
        parsed = parse_line(line, filename)
        if parsed:
            c.execute(f"""
                INSERT INTO logs_{category}
                    (timestamp, date, level, source, message, event_id, raw, filename)
                VALUES (?,?,?,?,?,?,?,?)
            """, (parsed["timestamp"], parsed["date"], parsed["level"],
                  parsed["source"], parsed["message"], parsed["event_id"],
                  parsed["raw"], parsed["filename"]))
            inserted += 1
        else:
            skipped += 1

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "inserted": inserted,
                    "skipped": skipped, "total": len(lines), "category": category,
                    "db": "uploads.db"})
