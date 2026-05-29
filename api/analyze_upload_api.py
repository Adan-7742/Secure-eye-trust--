"""
api/analyze_upload_api.py
=========================
Analyze an uploaded log file IN MEMORY — never writes to the main database.
Returns summary stats + chart data for the Log Analyzer tab.
"""

import re, io
from datetime import datetime
from collections import defaultdict, Counter
from flask import Blueprint, jsonify, request

analyzer_bp = Blueprint("analyzer", __name__)

PATTERNS = [
    re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(ERROR|WARNING|INFO|CRITICAL|FAILURE|SUCCESS)\s+(\S+)\s+(\S+)\s+(.+)$", re.I),
    re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(ERROR|WARNING|INFO|CRITICAL|FAILURE|SUCCESS)\s+(\S+)\s+(.+)$", re.I),
    re.compile(r"^\[(ERROR|WARNING|INFO|CRITICAL)\]\s+(\S+):\s+(.+)$", re.I),
]

LEVEL_ORDER = {"CRITICAL": 0, "ERROR": 1, "FAILURE": 1, "WARNING": 2, "INFO": 3, "SUCCESS": 3}

def _parse(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    for p in PATTERNS:
        m = p.match(line)
        if m:
            g = m.groups()
            if len(g) == 5:
                ts, level, cat, source, msg = g
            elif len(g) == 4:
                ts, level, source, msg = g; cat = "general"
            else:
                level, source, msg = g; ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); cat = "general"
            return {"ts": ts[:19], "date": ts[:10], "hour": ts[11:13],
                    "level": level.upper(), "source": source, "message": msg[:500]}
    # fallback
    level = "INFO"
    for kw in ["error","critical","fail"]:
        if kw in line.lower(): level = "ERROR"; break
    for kw in ["warn"]:
        if kw in line.lower(): level = "WARNING"; break
    return {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "hour": datetime.now().strftime("%H"),
            "level": level, "source": "file", "message": line[:500]}


@analyzer_bp.route("/analyze-upload", methods=["POST"])
def analyze_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    content = request.files["file"].read().decode("utf-8", errors="replace")
    lines   = content.splitlines()[:50_000]

    entries = [e for e in (_parse(l) for l in lines) if e]
    total   = len(entries)

    if total == 0:
        return jsonify({"error": "No parseable log lines found", "raw_lines": len(lines)}), 400

    # ── Level counts ──────────────────────────────────────────
    level_counts = Counter(e["level"] for e in entries)

    # ── By hour (activity heatmap) ────────────────────────────
    by_hour = Counter(e["hour"] for e in entries)
    hourly  = [{"hour": f"{h:02d}:00", "count": by_hour.get(f"{h:02d}", 0)} for h in range(24)]

    # ── By date (timeline) ────────────────────────────────────
    by_date = Counter(e["date"] for e in entries)
    dates   = sorted(by_date.keys())
    timeline = [{"date": d, "count": by_date[d]} for d in dates]

    # ── Top sources ───────────────────────────────────────────
    source_counts = Counter(e["source"] for e in entries)
    top_sources   = [{"source": s, "count": c} for s, c in source_counts.most_common(10)]

    # ── Top error messages ────────────────────────────────────
    error_entries = [e for e in entries if e["level"] in ("ERROR","CRITICAL","FAILURE")]
    top_errors    = [{"message": e["message"][:120], "level": e["level"], "ts": e["ts"]}
                     for e in error_entries[:20]]

    # ── Risk score ────────────────────────────────────────────
    critical = level_counts.get("CRITICAL", 0)
    errors   = level_counts.get("ERROR", 0) + level_counts.get("FAILURE", 0)
    warnings = level_counts.get("WARNING", 0)
    score    = min(100, int((critical * 15 + errors * 3 + warnings * 0.5) / max(total, 1) * 100))
    risk     = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    # ── Key findings ──────────────────────────────────────────
    findings = []
    if critical > 0:
        findings.append({"type": "critical", "text": f"{critical} CRITICAL event{'s' if critical>1 else ''} detected"})
    if errors > 10:
        findings.append({"type": "error", "text": f"High error rate: {errors} errors in {total} entries ({errors*100//total}%)"})
    if errors > 0:
        findings.append({"type": "error", "text": f"{errors} error event{'s' if errors>1 else ''} found"})
    if warnings > 0:
        findings.append({"type": "warning", "text": f"{warnings} warning{'s' if warnings>1 else ''} recorded"})

    # Brute force detection
    fail_msgs  = [e for e in entries if "failed to log on" in e["message"].lower() or "4625" in e["message"]]
    if len(fail_msgs) >= 5:
        findings.append({"type": "critical", "text": f"Possible brute-force: {len(fail_msgs)} failed login attempts"})

    # Malware detection
    malware = [e for e in entries if any(w in e["message"].lower() for w in ["malware","trojan","virus","mimikatz","ransomware","backdoor"])]
    if malware:
        findings.append({"type": "critical", "text": f"Malware indicators detected: {len(malware)} event{'s' if len(malware)>1 else ''}"})

    # Unexpected reboots
    reboots = [e for e in entries if "unexpected" in e["message"].lower() and "reboot" in e["message"].lower()]
    if reboots:
        findings.append({"type": "warning", "text": f"{len(reboots)} unexpected system reboot{'s' if len(reboots)>1 else ''}"})

    return jsonify({
        "ok":           True,
        "total":        total,
        "raw_lines":    len(lines),
        "level_counts": dict(level_counts),
        "hourly":       hourly,
        "timeline":     timeline,
        "top_sources":  top_sources,
        "top_errors":   top_errors,
        "risk_score":   score,
        "risk_label":   risk,
        "findings":     findings,
        "filename":     request.files["file"].filename,
    })
