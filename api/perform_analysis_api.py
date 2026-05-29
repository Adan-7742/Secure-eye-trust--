"""
api/perform_analysis_api.py
===========================
- Runs deep time-based analysis, saves result to analysis_reports DB table
- Latest report persists until re-run
- Auto-triggers every 12 hours via background thread
- Saves named report to reports list (visible in Generated Reports)
"""
import re, math, json, socket, time, threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, session
from database.db import get_conn, CATEGORIES
from core.ml_engine.analyzer import (
    run_top_offenders,
    run_zero_day_heuristics,
    run_security_threat_classification,
)

perform_bp = Blueprint("perform", __name__)

THREAT_PATTERNS = [
    ("Brute Force Login",      r"4625|failed.*logon|login.*fail|wrong.*password",     "CRITICAL"),
    ("Account Lockout",        r"4740|account.*locked",                                "CRITICAL"),
    ("Privilege Escalation",   r"4672|4673|special.*priv|elevated.*token",             "HIGH"),
    ("Windows Defender Alert", r"defender|malware|threat.*detected|virus|mimikatz",    "CRITICAL"),
    ("Unexpected Shutdown",    r"kernel.power|event.id.41|6008|unexpected.*shut",      "HIGH"),
    ("Disk Hardware Error",    r"disk.*error|bad.*sector|ntfs|i.o.*error",             "HIGH"),
    ("Memory Corruption",      r"memory.*corrupt|bad.*pool|pool.*corrupt",             "HIGH"),
    ("Application Crash",      r"faulting.*application|access.*violation|event.1000", "MEDIUM"),
    ("New Admin Account",      r"4720|4728|user.*created|added.*admin",                "HIGH"),
    ("Scheduled Task Created", r"4698|task.*created|schtask",                          "MEDIUM"),
    ("Audit Policy Change",    r"4719|audit.*policy.*changed",                         "HIGH"),
    ("Service Failure",        r"7034|7035|service.*terminat|service.*fail",           "MEDIUM"),
    ("Registry Tampering",     r"4657|registry.*modif",                                "HIGH"),
    ("TLS/SSL Error",          r"schannel|tls.*error|ssl.*error",                      "MEDIUM"),
    ("Network Error",          r"tcpip|network.*unreachable|connection.*refused",      "LOW"),
]
SEV_SCORE = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}

# ── DB helpers ────────────────────────────────────────────────────────────────

def _table_exists(c, name):
    c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return c.fetchone() is not None

def _ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_reports (
            id           TEXT PRIMARY KEY,
            name         TEXT,
            generated_at TEXT,
            risk_label   TEXT,
            risk_score   INTEGER,
            report_json  TEXT,
            trigger      TEXT DEFAULT 'manual'
        )
    """)
    conn.commit()


def _ensure_suppression_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS suppressed_rules (
            rule_id TEXT PRIMARY KEY,
            added_at TEXT
        )
    """)
    conn.commit()

def _load_suppressed():
    try:
        conn = get_conn()
        _ensure_suppression_table(conn)
        rows = conn.execute("SELECT rule_id FROM suppressed_rules").fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:
        return set()

def _add_suppressed(rule_id: str):
    try:
        conn = get_conn()
        _ensure_suppression_table(conn)
        conn.execute("INSERT OR REPLACE INTO suppressed_rules (rule_id, added_at) VALUES (?, datetime('now'))", (rule_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def _remove_suppressed(rule_id: str):
    try:
        conn = get_conn()
        _ensure_suppression_table(conn)
        conn.execute("DELETE FROM suppressed_rules WHERE rule_id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def _save_report(report: dict, trigger: str = "manual"):
    conn = get_conn()
    _ensure_table(conn)
    conn.execute("""
        INSERT OR REPLACE INTO analysis_reports
            (id, name, generated_at, risk_label, risk_score, report_json, trigger)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        report["id"], report["name"], report["generated_at"],
        report["risk_summary"]["label"], report["risk_score"],
        json.dumps(report), trigger
    ))
    conn.commit()
    conn.close()

def _load_latest() -> dict | None:
    try:
        conn = get_conn()
        _ensure_table(conn)
        row = conn.execute(
            "SELECT report_json FROM analysis_reports ORDER BY generated_at DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return json.loads(row[0]) if row else None
    except Exception:
        return None

def _load_all() -> list:
    try:
        conn = get_conn()
        _ensure_table(conn)
        rows = conn.execute(
            "SELECT id,name,generated_at,risk_label,risk_score,trigger FROM analysis_reports ORDER BY generated_at DESC LIMIT 50"
        ).fetchall()
        conn.close()
        return [{"id":r[0],"name":r[1],"generated_at":r[2],
                 "risk_label":r[3],"risk_score":r[4],"trigger":r[5]} for r in rows]
    except Exception:
        return []

def _zscore(counts):
    if len(counts) < 3: return []
    mean = sum(counts) / len(counts)
    var  = sum((x - mean)**2 for x in counts) / len(counts)
    std  = math.sqrt(var) if var > 0 else 0
    if std == 0: return []
    return [(i, round((v - mean)/std, 2)) for i, v in enumerate(counts) if (v - mean)/std > 2.0]


# ── Core analysis engine ──────────────────────────────────────────────────────

def _require_auth():
    if not session.get("authenticated"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None


def _run_analysis(trigger: str = "manual", period_days: int = 30) -> dict:
    """
    UPGRADED: Smart Analysis Engine v2.0

    Uses the upgraded threat_detector and correlator for:
      - Frequency-based detection (threshold gates — eliminates single-event FPs)
      - Confidence scoring (0-100% per detection)
      - Temporal analysis (off-hours/weekend boosting)
      - Attack chain correlation with temporal ordering
      - Confidence-weighted risk scoring formula

    All existing output keys are preserved for full frontend/export compatibility.
    New keys added: threat_hits[].confidence, threat_hits[].human_summary,
                    threat_hits[].actions, correlations[], attack_chains[],
                    fp_suppressed, overall_confidence.
    """
    conn  = get_conn()
    c     = conn.cursor()
    now   = datetime.now()
    since = (now - timedelta(days=period_days)).strftime("%Y-%m-%d")

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "System"

    report_id   = f"pa_{int(now.timestamp())}"
    report_name = f"{hostname} — Analysis Report — {now.strftime('%Y-%m-%d %H:%M')}"
    data_as_of  = now.strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "id":            report_id,
        "name":          report_name,
        "hostname":      hostname,
        "generated_at":  now.strftime("%Y-%m-%d %H:%M:%S"),
        "period_days":   period_days,
        "trigger":       trigger,
        "categories":    {},
        "timeline":      [],
        "threat_hits":   [],
        "correlations":  [],
        "attack_chains": [],
        "anomaly_days":  [],
        "hourly_pattern":  [],
        "weekday_pattern": [],
        "top_sources":   [],
        "risk_summary":  {},
        "next_check":    "",
        "recommendations": [],
        "total_events":  0,
        "total_errors":  0,
        "risk_score":    0,
        "peak_hour":     "—",
        "fp_suppressed": 0,
        "overall_confidence": 0,
    }

    date_counts   = {}
    hour_counts   = {}
    source_counts = {}
    total_ev = total_err = 0

    # ── Per-category stats (all existing logic preserved) ─────────────────
    for cat in CATEGORIES:
        tbl = f"logs_{cat}"
        if not _table_exists(c, tbl):
            result["categories"][cat] = {
                "total":0,"errors":0,"critical":0,"warnings":0,"info":0,
                "daily":{},"top_error_sources":[]
            }
            continue

        c.execute(f"SELECT level, COUNT(*) FROM {tbl} GROUP BY level")
        lvl_all = {r[0]: r[1] for r in c.fetchall()}
        c.execute(f"SELECT COUNT(*) FROM {tbl}")
        total = c.fetchone()[0] or 0

        c.execute(f"SELECT date, COUNT(*) FROM {tbl} WHERE date >= ? AND date IS NOT NULL GROUP BY date", (since,))
        daily = {}
        for d, cnt in c.fetchall():
            daily[d] = cnt
            date_counts[d] = date_counts.get(d, 0) + cnt

        c.execute(f"""
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, COUNT(*)
            FROM {tbl} WHERE date >= ? AND timestamp IS NOT NULL GROUP BY hr
        """, (since,))
        for hr, cnt in c.fetchall():
            if hr is not None:
                hour_counts[hr] = hour_counts.get(hr, 0) + cnt

        c.execute(f"""
            SELECT source, COUNT(*) FROM {tbl}
            WHERE date >= ? AND level IN ('ERROR','CRITICAL','FAILURE') AND source IS NOT NULL
            GROUP BY source ORDER BY COUNT(*) DESC LIMIT 5
        """, (since,))
        top_src = [{"source": r[0], "count": r[1]} for r in c.fetchall()]

        c.execute(f"SELECT source, COUNT(*) FROM {tbl} WHERE date >= ? AND source IS NOT NULL GROUP BY source", (since,))
        for s, cnt in c.fetchall():
            source_counts[s] = source_counts.get(s, 0) + cnt

        n_err  = lvl_all.get("ERROR",0) + lvl_all.get("FAILURE",0)
        n_crit = lvl_all.get("CRITICAL",0)
        result["categories"][cat] = {
            "total":   total,
            "errors":  n_err,
            "critical":n_crit,
            "warnings":lvl_all.get("WARNING",0),
            "info":    lvl_all.get("INFO",0),
            "daily":   daily,
            "top_error_sources": top_src,
        }
        total_ev  += total
        total_err += n_err + n_crit

    conn.close()

    # ── FIM (preserved) ───────────────────────────────────────────────────
    try:
        from core.fim_engine import get_fim_events, get_fim_summary
        _fim_conn  = get_conn()
        fim_events = get_fim_events(_fim_conn, since_hours=24*period_days)
        _fim_conn.close()
        result["fim"] = get_fim_summary(fim_events)
    except Exception:
        result["fim"] = {"total":0,"critical":0,"high":0,"by_action":{},"top_files":[],"events":[]}

    # ── Timeline + anomalies (preserved) ──────────────────────────────────
    dates_sorted = sorted(date_counts.keys())
    result["timeline"] = [{"date": d, "count": date_counts[d]} for d in dates_sorted]

    counts = [date_counts[d] for d in dates_sorted]
    for idx, zscore in _zscore(counts):
        result["anomaly_days"].append({"date": dates_sorted[idx], "count": counts[idx], "zscore": zscore})

    result["hourly_pattern"] = [{"hour": f"{h:02d}:00", "count": hour_counts.get(h,0)} for h in range(24)]
    if hour_counts:
        peak_h = max(hour_counts, key=hour_counts.get)
        result["peak_hour"] = f"{peak_h:02d}:00"

    wd_counts = {}
    for d in dates_sorted:
        try:
            wd = datetime.strptime(d, "%Y-%m-%d").strftime("%A")
            wd_counts[wd] = wd_counts.get(wd,0) + date_counts[d]
        except Exception:
            pass
    result["weekday_pattern"] = [
        {"day": d[:3], "count": wd_counts.get(d,0)}
        for d in ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    ]

    result["top_sources"] = [
        {"source": s, "count": n}
        for s, n in sorted(source_counts.items(), key=lambda x: -x[1])[:12]
    ]

    # ══════════════════════════════════════════════════════════════════════
    # SMART THREAT DETECTION (replaces naive regex THREAT_PATTERNS)
    # Uses: frequency gates, confidence scoring, temporal analysis
    # ══════════════════════════════════════════════════════════════════════
    try:
        from core.analysis_engine.threat_detector import run_threat_detection
        smart_detections = run_threat_detection()
    except Exception as e:
        print(f"[perform_analysis] Smart detection error: {e}")
        smart_detections = []

    # Map smart detections to the existing threat_hits format
    # (adds new fields: confidence, human_summary, actions, mitre_tactic)
    # Respect any suppressed rule IDs so they are not reported
    _suppressed_rules = _load_suppressed()
    threat_hits = []
    for det in smart_detections:
        if det.get('id') and det.get('id') in _suppressed_rules:
            continue
        threat_hits.append({
            # Existing keys (frontend compatibility)
            "name":     det["name"],
            "severity": det["severity"],
            "count":    det["count"],
            "score":    det["risk_points"],
            "latest":   det["last_seen"],
            "examples": [],          # smart engine uses evidence instead
            # NEW keys (upgraded intelligence)
            "id":            det["id"],
            "category":      det["category"],
            "description":   det["description"],
            "human_summary": det["human_summary"],
            "mitigation":    det["mitigation"],
            "actions":       det["actions"],
            "evidence":      [
                f"{det['count']} events in {det['window_hours']}h window",
                f"First: {det['first_seen']}  Last: {det['last_seen']}",
                f"Off-hours events: {det.get('off_hours_count', 0)}",
            ],
            "mitre_tactic":    det.get("mitre_tactic", ""),
            "confidence":      det["confidence"],
            "confidence_pct":  det["confidence_pct"],
            "risk_points":     det["risk_points"],
            "first_seen":      det["first_seen"],
            "sources":         det["sources"],
            "event_ids":       det["event_ids"],
            "window_hours":    det["window_hours"],
            "off_hours_count": det.get("off_hours_count", 0),
            # LSASS-rule filter context (null for other rules) — drives the
            # "Mark as benign / Dismiss rule" UI in the threat-hit modal.
            "lsass_filter":    det.get("lsass_filter"),
        })

    result["threat_hits"] = threat_hits

    # ══════════════════════════════════════════════════════════════════════
    # ATTACK CHAIN CORRELATION (upgraded with temporal ordering)
    # ══════════════════════════════════════════════════════════════════════
    try:
        from core.analysis_engine.correlator import run_correlation
        correlations = run_correlation()
    except Exception as e:
        print(f"[perform_analysis] Correlation error: {e}")
        correlations = []

    result["correlations"]  = correlations
    result["attack_chains"] = [c for c in correlations if c.get("is_chain")]

    # ══════════════════════════════════════════════════════════════════════
    # SMART RISK SCORING (confidence-weighted formula)
    # ══════════════════════════════════════════════════════════════════════
    from core.analysis_engine.risk_scorer import compute_system_score

    anom_count  = len(result["anomaly_days"])
    score_result = compute_system_score(smart_detections, anom_count)
    raw_score   = score_result["score"]

    # Attack chain bonus
    chain_bonus = min(20, len(result["attack_chains"]) * 15)
    raw_score   = min(100, raw_score + chain_bonus)

    classification = score_result["classification"]
    risk_label = classification["level"]   # "Critical", "High", "Suspicious", "Normal"

    err_rate = (total_err / max(total_ev, 1)) * 100

    # ══════════════════════════════════════════════════════════════════════
    # EFFECTIVE SEVERITY — confidence-aware display severity
    # ══════════════════════════════════════════════════════════════════════
    # The rule files mark almost every detection CRITICAL or HIGH. That made
    # every Action Plan row scream "CRITICAL" even when the detection had
    # 0.4 confidence and was probably routine system noise. Effective
    # severity downgrades each hit based on its confidence, EXCEPT for
    # hard-evidence rules at high confidence (those keep their full severity
    # — those are the real attacks). NOTE: the scorer above sees the raw
    # severity (it has its own confidence weighting), so we don't
    # double-dampen the numeric score.
    from core.analysis_engine.risk_scorer import HARD_EVIDENCE_RULES as _HARD_RULES
    _SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def _effective_sev(rid, sev, conf):
        is_hard = rid in _HARD_RULES
        # Hard-evidence rule at high confidence → keep severity (real attack)
        if is_hard and conf >= 0.7:
            return sev
        idx = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 0
        if conf < 0.40:
            idx -= 3      # very low confidence → almost always LOW
        elif conf < 0.55:
            idx -= 2
        elif conf < 0.70:
            idx -= 1
        return _SEV_ORDER[max(0, idx)]

    # Stamp effective severity onto threat_hits (used by the UI display) and
    # onto smart_detections (used by the recommendations builder below).
    for _hit in threat_hits:
        _orig = _hit.get("severity", "LOW")
        _conf = float(_hit.get("confidence", 0.5))
        _eff  = _effective_sev(_hit.get("id", ""), _orig, _conf)
        _hit["original_severity"]  = _orig
        _hit["effective_severity"] = _eff
        _hit["severity"]           = _eff   # what the UI displays
        _hit["is_hard_evidence"]   = (_hit.get("id", "") in _HARD_RULES and _conf >= 0.7)

    for _det in smart_detections:
        _orig = _det.get("severity", "LOW")
        _conf = float(_det.get("confidence", 0.5))
        _eff  = _effective_sev(_det.get("id", ""), _orig, _conf)
        _det["original_severity"]  = _orig
        _det["effective_severity"] = _eff
        # Note: do NOT overwrite _det["severity"] here — the scorer at the
        # bottom of this function re-uses smart_detections with raw severity.

    # Sort threat_hits so the worst, highest-confidence ones surface first.
    # Hard-evidence hits always rank above non-hard ones at the same severity.
    _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threat_hits.sort(key=lambda h: (
        _SEV_RANK.get(h.get("severity", "LOW"), 99),
        0 if h.get("is_hard_evidence") else 1,
        -float(h.get("confidence", 0.0)),
        -int(h.get("count", 0)),
    ))
    result["threat_hits"] = threat_hits   # refresh — same list but reordered

    result["total_events"] = total_ev
    result["total_errors"] = total_err
    result["risk_score"]   = raw_score
    result["risk_summary"] = {
        "label":        risk_label,
        "score":        raw_score,
        "threat_types": len(threat_hits),
        "anomaly_days": anom_count,
        "error_rate":   round(err_rate, 1),
        "chain_count":  len(result["attack_chains"]),
        "risk_color":   classification.get("color", "#22c55e"),
        "risk_icon":    classification.get("icon", "✅"),
        "risk_message": classification.get("message", ""),
        "score_breakdown": score_result.get("breakdown", {}),
    }

    # Overall confidence score
    if smart_detections:
        total_w  = sum({"CRITICAL":30,"HIGH":18,"MEDIUM":8,"LOW":3}.get(d["severity"],1)
                       for d in smart_detections)
        wtd_conf = sum(d["confidence"] * {"CRITICAL":30,"HIGH":18,"MEDIUM":8,"LOW":3}.get(d["severity"],1)
                       for d in smart_detections)
        result["overall_confidence"] = int((wtd_conf / total_w) * 100) if total_w else 0
    else:
        result["overall_confidence"] = 95  # high confidence in "no threat" verdict

    # FP count
    result["fp_suppressed"] = 0  # Already filtered in threat_detector

    # ── Next check schedule ────────────────────────────────────────────────
    if raw_score >= 75:    hrs, msg = 1,  "Immediately — critical threats detected"
    elif raw_score >= 50:  hrs, msg = 2,  "Within 2 hours"
    elif raw_score >= 25:  hrs, msg = 6,  "Within 6 hours"
    else:                  hrs, msg = 12, "Next scheduled auto-check in 12 hours"
    result["next_check"] = (now + timedelta(hours=hrs)).strftime("%Y-%m-%d %H:%M") + f"  ({msg})"

    # ══════════════════════════════════════════════════════════════════════
    # SMART RECOMMENDATIONS (generated from confirmed detections + chains)
    # ══════════════════════════════════════════════════════════════════════
    recs  = []
    seen  = set()

    # Chain actions first (highest priority)
    for chain in result["attack_chains"]:
        for action in chain.get("actions", [])[:2]:
            if action not in seen:
                seen.add(action)
                recs.append({
                    "priority": "CRITICAL",
                    "text": f"[{chain['name']}] {action}",
                    "source": "chain",
                    "confidence": chain.get("confidence_pct", 80),
                })

    # Detection actions by effective severity (confidence-aware)
    for det in smart_detections:
        # Use effective_severity if it was stamped on; fall back to raw
        sev = det.get("effective_severity") or det.get("severity", "LOW")
        for action in det.get("actions", [])[:2]:
            if action not in seen:
                seen.add(action)
                recs.append({
                    "priority": sev,
                    "text": f"[{det['name']}] {action}",
                    "source": "detection",
                    "confidence": det.get("confidence_pct", 70),
                })

    if anom_count:
        recs.append({"priority":"HIGH","text":f"Investigate {anom_count} anomalous day(s) with statistically unusual event volumes","source":"anomaly","confidence":75})
    if err_rate > 20:
        recs.append({"priority":"MEDIUM","text":f"High error rate ({err_rate:.0f}%) — review system stability and hardware health","source":"stats","confidence":60})
    if not recs:
        recs.append({"priority":"LOW","text":"System appears healthy — continue routine monitoring","source":"system","confidence":95})

    # Sort by priority (CRITICAL first), then by confidence desc within band.
    # Chain-sourced items break ties up — they have the strongest evidence.
    _PRIO = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    _SRC  = {"chain": 0, "detection": 1, "anomaly": 2, "stats": 3, "system": 4}
    recs.sort(key=lambda r: (
        _PRIO.get(r.get("priority", "LOW"), 99),
        _SRC.get(r.get("source", "system"), 9),
        -int(r.get("confidence", 0)),
    ))

    result["recommendations"] = recs

    # Add full analysis fields so the Perform Analysis UI can show zero-day,
    # security threat classification, and top offending sources.
    try:
        result["zero_day"] = run_zero_day_heuristics("all")
        result["security_threats"] = run_security_threat_classification()
        result["top_offenders"] = {cat: run_top_offenders(cat) for cat in CATEGORIES}
    except Exception as e:
        print(f"[perform_analysis] full analysis extension failed: {e}")
        result["zero_day"] = []
        result["security_threats"] = {"threats": [], "critical_count": 0}
        result["top_offenders"] = {cat: [] for cat in CATEGORIES}


    # ══════════════════════════════════════════════════════════════════════
    # STEP 8 — UNIFIED ANALYSIS EXTENSION
    # Pulls REAL data from Sysmon, YARA, Sigma into the API response.
    # Also re-runs risk scoring with Sigma/YARA bonuses.
    # ══════════════════════════════════════════════════════════════════════

    # ── Initialise unified malware_analysis sub-object ────────────────────
    malware_analysis = {
        "suspicious_processes":  [],
        "file_drops":            [],
        "registry_persistence":  False,
        "sigma_hits":            [],
        "yara_hits":             [],
        "malware_family":        "",
        "attack_chain":          [],
        "sysmon_available":      False,
        "sysmon_events":         0,
        "yara_available":        False,
        "files_scanned":         0,
    }

    # ── Sysmon data ───────────────────────────────────────────────────────
    try:
        _conn2 = get_conn()
        _c2    = _conn2.cursor()
        _c2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs_sysmon'")
        if _c2.fetchone():
            malware_analysis["sysmon_available"] = True

            # Event count in period
            _c2.execute(
                "SELECT COUNT(*) FROM logs_sysmon WHERE timestamp >= ?", (since,)
            )
            malware_analysis["sysmon_events"] = _c2.fetchone()[0] or 0

            if malware_analysis["sysmon_events"] > 0:
                # Suspicious processes (EID 1 from temp/downloads/appdata OR
                # from Office parent)
                _c2.execute("""
                    SELECT timestamp, sysmon_command_line, sysmon_parent_image,
                           sysmon_image, sysmon_process_id, sysmon_signed
                    FROM logs_sysmon
                    WHERE event_id = 1
                      AND timestamp >= ?
                      AND (
                        LOWER(COALESCE(sysmon_command_line,'')) LIKE '%temp%'
                        OR LOWER(COALESCE(sysmon_command_line,'')) LIKE '%downloads%'
                        OR LOWER(COALESCE(sysmon_command_line,'')) LIKE '%appdata%'
                        OR LOWER(COALESCE(sysmon_parent_image,'')) LIKE '%winword.exe%'
                        OR LOWER(COALESCE(sysmon_parent_image,'')) LIKE '%excel.exe%'
                        OR LOWER(COALESCE(sysmon_parent_image,'')) LIKE '%powerpnt.exe%'
                        OR LOWER(COALESCE(sysmon_parent_image,'')) LIKE '%outlook.exe%'
                      )
                    ORDER BY timestamp DESC LIMIT 30
                """, (since,))
                for _r in _c2.fetchall():
                    _par = (_r[2] or "").rsplit(chr(92), 1)[-1]
                    _img = (_r[3] or "").rsplit(chr(92), 1)[-1]
                    _sus = _par.lower() in (
                        "winword.exe","excel.exe","powerpnt.exe","outlook.exe"
                    )
                    malware_analysis["suspicious_processes"].append({
                        "timestamp": str(_r[0]),
                        "command":   str(_r[1] or "")[:100],
                        "parent":    _par,
                        "image":     _img,
                        "pid":       _r[4],
                        "signed":    bool(_r[5]),
                        "suspicious":_sus,
                    })

                # File drops (EID 11)
                _c2.execute("""
                    SELECT timestamp, sysmon_target_file, sysmon_process_guid,
                           yara_matched, yara_rule, yara_severity
                    FROM logs_sysmon
                    WHERE event_id = 11
                      AND timestamp >= ?
                      AND (
                        LOWER(COALESCE(sysmon_target_file,'')) LIKE '%downloads%'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%temp%'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%appdata%'
                      )
                      AND (
                        LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.exe'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.dll'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.ps1'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.vbs'
                        OR LOWER(COALESCE(sysmon_target_file,'')) LIKE '%.bat'
                      )
                    ORDER BY timestamp DESC LIMIT 30
                """, (since,))
                for _r in _c2.fetchall():
                    _fn = str(_r[1] or "")
                    malware_analysis["file_drops"].append({
                        "timestamp":   str(_r[0]),
                        "filename":    _fn.rsplit(chr(92), 1)[-1] if chr(92) in _fn else _fn,
                        "path":        _fn,
                        "guid":        str(_r[2] or ""),
                        "yara_matched":bool(_r[3]),
                        "yara_rule":   str(_r[4] or ""),
                        "yara_severity":str(_r[5] or ""),
                    })

                # Registry persistence (EID 13)
                _c2.execute("""
                    SELECT COUNT(*), MAX(timestamp), MAX(sysmon_target_object)
                    FROM logs_sysmon
                    WHERE event_id = 13
                      AND timestamp >= ?
                      AND (
                        LOWER(COALESCE(sysmon_target_object,'')) LIKE '%currentversion%run%'
                        OR LOWER(COALESCE(sysmon_target_object,'')) LIKE '%userinit%'
                        OR LOWER(COALESCE(sysmon_target_object,'')) LIKE '%winlogon%'
                      )
                """, (since,))
                _reg = _c2.fetchone()
                if _reg and _reg[0]:
                    malware_analysis["registry_persistence"] = {
                        "count":   _reg[0],
                        "latest":  str(_reg[1] or ""),
                        "key":     str(_reg[2] or "")[-80:],
                    }

        _conn2.close()
    except Exception as _e:
        print(f"[perform_analysis] sysmon queries: {_e}")

    # ── Sigma detections ──────────────────────────────────────────────────
    _sigma_count = 0
    try:
        from core.analysis_engine.sigma_engine import run_sigma_detection
        _sigma_hits = run_sigma_detection(since_iso=since)
        # Filter suppressed sigma rule ids so they don't show in the UI
        _supp = _load_suppressed()
        if _supp:
            _sigma_hits = [h for h in _sigma_hits if str(h.get('rule_id','')) not in _supp]
        malware_analysis["sigma_hits"] = _sigma_hits
        _sigma_count = len(_sigma_hits)
    except Exception as _e:
        print(f"[perform_analysis] sigma: {_e}")

    # ── YARA file scan results ─────────────────────────────────────────────
    # FIX: Use "1970-01-01" instead of `since` so ALL ever-scanned files are
    # counted — not just files re-scanned within the last 30 days.
    # Previously the date filter was hiding .exe/.ps1/.bat/.vbs etc. that
    # the background FileScanner had already inspected before this analysis run.
    _yara_count  = 0
    _file_scanned = 0
    try:
        from core.event_collector.file_scanner import get_scan_stats, force_rescan_all
        _scan = get_scan_stats("1970-01-01")   # all-time total, no date cutoff
        if _scan.get("available"):
            malware_analysis["yara_available"]  = True
            malware_analysis["files_scanned"]   = _scan.get("total_scanned", 0)
            malware_analysis["yara_hits"]       = _scan.get("yara_matches", [])
            _yara_count  = _scan.get("yara_hits", 0)
            _file_scanned = _scan.get("total_scanned", 0)
            # Attach extension/directory breakdown
            malware_analysis["files_by_extension"] = _scan.get("by_extension", {})
            malware_analysis["files_by_directory"]  = _scan.get("by_directory",  {})

            # If file scan stats are unexpectedly low, force a full directory rescan
            # so the UI can show the real total of monitored files.
            if _file_scanned < 20:
                _rescan = force_rescan_all()
                if _rescan.get("ok"):
                    _scan = get_scan_stats("1970-01-01")
                    _file_scanned = _scan.get("total_scanned", _file_scanned)
                    malware_analysis["files_scanned"] = _file_scanned
                    malware_analysis["yara_hits"] = _scan.get("yara_matches", [])
                    _yara_count = _scan.get("yara_hits", 0)
                    malware_analysis["files_by_extension"] = _scan.get("by_extension", {})
                    malware_analysis["files_by_directory"] = _scan.get("by_directory", {})
                else:
                    print(f"[perform_analysis] rescan fallback failed: {_rescan.get('error')}")
    except Exception as _e:
        print(f"[perform_analysis] yara stats: {_e}")

    # ── Uploaded log files count — add to files_scanned total ─────────────
    # Manually uploaded files (via Log Upload tab) are stored in uploads.db,
    # not in file_scan_results, so they were previously missing from the count.
    _uploaded_file_count = 0
    try:
        from database.uploads_db import get_upload_conn
        _uconn = get_upload_conn()
        _uc    = _uconn.cursor()
        for _tbl in ["logs_application", "logs_system", "logs_security", "logs_windows_update"]:
            try:
                _uc.execute(f"SELECT COUNT(DISTINCT filename) FROM {_tbl}")
                _row = _uc.fetchone()
                _uploaded_file_count += (_row[0] or 0) if _row else 0
            except Exception:
                pass
        _uconn.close()
    except Exception as _ue:
        print(f"[perform_analysis] uploaded file count: {_ue}")

    _file_scanned += _uploaded_file_count
    malware_analysis["files_scanned"]        = _file_scanned
    malware_analysis["uploaded_files_count"] = _uploaded_file_count

    # ── Attack chains from Sysmon correlator (already in result) ──────────
    _sysmon_chains = [
        c for c in result["attack_chains"]
        if c.get("id", "").startswith("SYSMON_")
    ]
    malware_analysis["attack_chain"] = _sysmon_chains

    # ── Infer malware family from Sigma/YARA rule names ────────────────────
    _families = []
    for _sh in malware_analysis["sigma_hits"][:3]:
        if "OFFICE" in _sh.get("rule_id",""):     _families.append("Macro Dropper")
        elif "ENCODED" in _sh.get("rule_id",""):  _families.append("Obfuscated Payload")
        elif "CERTUTIL" in _sh.get("rule_id",""):  _families.append("LOLBin Abuse")
        elif "REGISTRY" in _sh.get("rule_id",""):  _families.append("Persistent Malware")
    for _yh in malware_analysis["yara_hits"][:2]:
        _yrn = str(_yh.get("yara_rule","")).lower()
        if "mimikatz" in _yrn:    _families.append("Mimikatz")
        elif "ransom"  in _yrn:   _families.append("Ransomware")
        elif "powershell" in _yrn:_families.append("PowerShell Stager")
    malware_analysis["malware_family"] = ", ".join(dict.fromkeys(_families)) or "Unknown"

    result["malware_analysis"] = malware_analysis

    # ── Recalculate risk score with Sigma/YARA bonuses ────────────────────
    # NOTE: attack_chains_count is now passed INTO the scorer so the
    # hard-evidence gate can factor it in. Previously we added the chain
    # bonus AFTER scoring, which bypassed the gate and let the score
    # saturate to 100 on systems with no real attack indicators.
    _sysmon_chain_count = len(_sysmon_chains)
    _attack_chain_count = len(result["attack_chains"])
    from core.analysis_engine.risk_scorer import compute_system_score
    _new_score = compute_system_score(
        smart_detections,
        anomaly_days=len(result["anomaly_days"]),
        sigma_hits=_sigma_count,
        yara_hits=_yara_count,
        sysmon_chains=_sysmon_chain_count,
        attack_chains_count=_attack_chain_count,
    )
    _final_score = _new_score["score"]
    result["risk_score"]           = _final_score
    result["risk_summary"]["score"]= _final_score
    result["unified_risk_score"]   = _final_score
    result["unified_breakdown"]    = _new_score.get("breakdown", {})

    # Update label to match final score
    if _final_score >= 75:   result["risk_summary"]["label"] = "Critical"
    elif _final_score >= 50: result["risk_summary"]["label"] = "High"
    elif _final_score >= 25: result["risk_summary"]["label"] = "Suspicious"
    else:                    result["risk_summary"]["label"] = "Low"

    # ── Files scanned summary (new top-level field) ────────────────────────
    result["files_scanned"] = _file_scanned

    return result


# ── Auto-scheduler (12-hour background thread) ────────────────────────────────

_scheduler_started = False

def _start_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        # Wait 12 hours, then run, repeat
        while True:
            time.sleep(12 * 3600)
            try:
                print("[perform_analysis] ⏰ Auto-running scheduled analysis...")
                report = _run_analysis(trigger="auto_12h")
                _save_report(report, trigger="auto_12h")
                # Also push into reports_api store
                try:
                    from api.reports_api import _report_store
                    _report_store.insert(0, _make_reports_entry(report))
                except Exception:
                    pass
                print(f"[perform_analysis] ✅ Auto-analysis complete — risk: {report['risk_summary']['label']}")
            except Exception as e:
                print(f"[perform_analysis] ❌ Auto-analysis failed: {e}")

    t = threading.Thread(target=_loop, daemon=True, name="pa_scheduler")
    t.start()
    print("[perform_analysis] ⏰ Auto-scheduler started — next run in 12 hours")


def _make_reports_entry(report: dict) -> dict:
    """Convert perform-analysis report into a format compatible with reports_api store."""
    rs = report.get("risk_summary", {})
    trigger = report.get("trigger","manual")
    tag = " 🤖 [Auto]" if "auto" in trigger else ""
    return {
        "id":           report["id"],
        "type":         "analysis",
        "name":         report["name"] + tag,
        "generated_at": report["generated_at"],
        "date":         report["generated_at"][:10],
        "generated_by": "Secure Eye Trust+ — Perform Analysis",
        "risk_score":   report.get("risk_score", 0),
        "risk_label":   rs.get("label","Low"),
        "risk_color":   {"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#10b981"}.get(rs.get("label","Low"),"#10b981"),
        "summary": {
            "total_logs":     report.get("total_events",0),
            "total_errors":   report.get("total_errors",0),
            "total_warnings": sum(v.get("warnings",0) for v in report.get("categories",{}).values()),
            "error_rate":     rs.get("error_rate",0),
            "threat_types":   rs.get("threat_types",0),
            "anomaly_days":   rs.get("anomaly_days",0),
        },
        "threat_hits":      report.get("threat_hits",[]),
        "anomaly_days":     report.get("anomaly_days",[]),
        "recommendations":  report.get("recommendations",[]),
        "timeline":         report.get("timeline",[]),
        "hourly_pattern":   report.get("hourly_pattern",[]),
        "weekday_pattern":  report.get("weekday_pattern",[]),
        "top_sources":      report.get("top_sources",[]),
        "categories":       report.get("categories",{}),
        "hostname":         report.get("hostname","System"),
        "period_days":      report.get("period_days",30),
        "next_check":       report.get("next_check",""),
        "logs":    {cat: {"total":v.get("total",0),"errors":v.get("errors",0),"warnings":v.get("warnings",0)}
                    for cat,v in report.get("categories",{}).items()},
        "system":  {}, "security": {}, "network": {},
        "recent_errors": [],
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@perform_bp.route("/perform-analysis", methods=["GET","POST"])
def perform_analysis():
    """Run fresh analysis, save to DB, push to reports list."""
    from flask import request
    days = request.args.get('days', 30, type=int)
    if days < 1 or days > 365:
        days = 30
    report = _run_analysis(trigger="manual", period_days=days)
    _save_report(report, trigger="manual")

    # Push into reports_api in-memory store so it appears in Generated Reports
    try:
        from api.reports_api import _report_store
        # Remove any previous perform-analysis entries for this session
        _report_store[:] = [r for r in _report_store if r.get("type") != "analysis" or r["id"] == report["id"]]
        _report_store.insert(0, _make_reports_entry(report))
    except Exception as e:
        print(f"[perform] could not push to report store: {e}")

    return jsonify({"ok": True, "report": report})


@perform_bp.route("/perform-analysis/latest")
def get_latest():
    """Return saved report without re-running."""
    report = _load_latest()
    if not report:
        return jsonify({"ok": False, "report": None})
    return jsonify({"ok": True, "report": report, "cached": True})


@perform_bp.route("/perform-analysis/history")
def get_history():
    return jsonify({"ok": True, "reports": _load_all()})


@perform_bp.route("/perform-analysis/export/<report_id>/<fmt>")
def export_report(report_id, fmt):
    """Export a saved analysis report as pdf/html/json/csv."""
    try:
        conn = get_conn()
        _ensure_table(conn)
        row = conn.execute(
            "SELECT report_json FROM analysis_reports WHERE id=? ORDER BY generated_at DESC LIMIT 1",
            (report_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Report not found"}), 404
        report = json.loads(row[0])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    fname_base = report.get("name","report").replace(" — ","_").replace(" ","_").replace(":","")[:60]
    no_cache_headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }

    if fmt == "json":
        from flask import Response
        return Response(json.dumps(report, indent=2), mimetype="application/json",
                        headers={**no_cache_headers, "Content-Disposition": f"attachment; filename={fname_base}.json"})

    if fmt == "csv":
        import io, csv
        from flask import Response
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Report Name", report.get("name","")])
        w.writerow(["Hostname",    report.get("hostname","")])
        w.writerow(["Generated",   report.get("generated_at","")])
        w.writerow(["Period",      f"Last {report.get('period_days',30)} days"])
        w.writerow(["Risk Score",  report.get("risk_score",0)])
        w.writerow(["Risk Label",  report.get("risk_summary",{}).get("label","")])
        w.writerow([])
        w.writerow(["Category","Total","Errors","Critical","Warnings","Info"])
        for cat, cv in report.get("categories",{}).items():
            w.writerow([cat, cv.get("total",0), cv.get("errors",0), cv.get("critical",0), cv.get("warnings",0), cv.get("info",0)])
        w.writerow([])
        w.writerow(["Threat Name","Severity","Count","Last Seen"])
        for h in report.get("threat_hits",[]):
            w.writerow([h["name"], h["severity"], h["count"], h.get("latest","")[:16]])
        w.writerow([])
        w.writerow(["Date","Total Events"])
        for t in report.get("timeline",[]):
            w.writerow([t["date"], t["count"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={**no_cache_headers, "Content-Disposition": f"attachment; filename={fname_base}.csv"})

    if fmt == "pdf":
        try:
            # Deep-sanitize all string fields in the report before PDF build
            report = _sanitize_report_for_pdf(report)
            pdf = _build_analysis_pdf(report)
            from flask import Response
            return Response(pdf, mimetype="application/pdf",
                            headers={**no_cache_headers, "Content-Disposition": f"attachment; filename={fname_base}.pdf"})
        except Exception as e:
            import traceback; traceback.print_exc()
            return jsonify({"error": f"PDF failed: {e}"}), 500

    # html (default)
    from flask import Response
    return Response(_build_analysis_html(report), mimetype="text/html",
                    headers={**no_cache_headers, "Content-Disposition": f"attachment; filename={fname_base}.html"})


# ── PDF builder ───────────────────────────────────────────────────────────────


def _safe(text):
    """Strip emojis/symbols, keep all normal text, escape XML for reportlab."""
    import re
    if not text:
        return ""
    text = str(text)
    # Remove only chars outside safe ranges (keeps ASCII, latin, dashes, quotes)
    _STRIP = re.compile(u'[^\u0009\u000A\u000D\u0020-\u007E\u00A0-\u024F\u2013-\u201D]')
    text = _STRIP.sub('', text)
    # Escape XML special chars that break reportlab paraparser
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return text.strip()


def _clean_msg(text, maxlen=160):
    """Remove Windows boilerplate, HTML entities, XML tags from log messages."""
    import re
    if not text:
        return ""
    text = str(text)
    # Decode HTML entities that came from XML-escaped storage
    text = text.replace("&lt;","<").replace("&gt;",">").replace("&amp;","&").replace("&quot;",'"')
    # Strip XML/HTML tags
    text = re.sub(r"<[^>]{0,300}>", "", text)
    # Remove Windows "description could not be found" boilerplate lines
    text = re.sub(r"The description for Event ID[^\n]*", "", text, flags=re.I)
    text = re.sub(r"The message resource is present but[^\n]*", "", text, flags=re.I)
    text = re.sub(r"The insert string[^\n]*", "", text, flags=re.I)
    text = re.sub(r"[^\n]*could not be found[^\n]*", "", text, flags=re.I)
    text = re.sub(r"[^\n]*message resource[^\n]*", "", text, flags=re.I)
    # Remove repeated dashes/underscores (separators)
    text = re.sub(r"[-_]{3,}", " ", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    if not text or len(text) < 5:
        return ""
    return _safe(text[:maxlen])



def _sanitize_report_for_pdf(r: dict) -> dict:
    """Recursively sanitize all string values in report dict for reportlab."""
    import copy
    r = copy.deepcopy(r)

    def clean(v):
        if isinstance(v, str):
            return _safe(v)
        if isinstance(v, dict):
            return {k: clean(val) for k, val in v.items()}
        if isinstance(v, list):
            return [clean(item) for item in v]
        return v

    # Sanitize dynamic fields that end up in Paragraph()
    r["hostname"]     = _safe(str(r.get("hostname", "")))
    r["generated_at"] = _safe(str(r.get("generated_at", "")))
    r["trigger"]      = _safe(str(r.get("trigger", "manual")))
    r["id"]           = _safe(str(r.get("id", "")))
    r["next_check"]   = _safe(str(r.get("next_check", "")))

    # Sanitize threat hits
    clean_threats = []
    for h in r.get("threat_hits", []):
        ch = dict(h)
        ch["name"]     = _safe(str(ch.get("name", "")))
        ch["severity"] = _safe(str(ch.get("severity", "")))
        ch["latest"]   = _safe(str(ch.get("latest", ""))[:16])
        clean_exs = []
        for ex in ch.get("examples", []):
            clean_exs.append({
                "message": _safe(str(ex.get("message", ""))[:80]),
                "ts":      _safe(str(ex.get("ts", "")))
            })
        ch["examples"] = clean_exs
        clean_threats.append(ch)
    r["threat_hits"] = clean_threats

    # Sanitize anomaly days
    clean_anom = []
    for a in r.get("anomaly_days", []):
        clean_anom.append({
            "date":   _safe(str(a.get("date", ""))),
            "count":  int(a.get("count", 0)),
            "zscore": float(a.get("zscore", 0)),
        })
    r["anomaly_days"] = clean_anom

    # Sanitize recommendations
    clean_recs = []
    for rec in r.get("recommendations", []):
        clean_recs.append({
            "priority": _safe(str(rec.get("priority", ""))),
            "text":     _safe(str(rec.get("text", ""))),
        })
    r["recommendations"] = clean_recs

    # Sanitize categories
    for cat in r.get("categories", {}):
        cv = r["categories"][cat]
        for key in ["total","errors","critical","warnings","info"]:
            try:
                cv[key] = int(cv.get(key, 0))
            except Exception:
                cv[key] = 0

    return r



def _generate_narrative(r):
    """
    UPGRADED: Generates intelligent human-readable narrative for PDF/HTML exports.
    Uses confidence scores, attack chains, human_summary, and temporal context.
    """
    rs        = r.get("risk_summary", {})
    cats      = r.get("categories", {})
    threats   = r.get("threat_hits", [])
    chains    = r.get("attack_chains", r.get("correlations", []))
    anomalies = r.get("anomaly_days", [])
    hostname  = _safe(r.get("hostname", "this system"))
    period    = r.get("period_days", 30)
    total_ev  = r.get("total_events", 0)
    total_err = r.get("total_errors", 0)
    risk      = rs.get("label", "Low")
    score     = rs.get("score", 0)
    err_rate  = rs.get("error_rate", 0.0)
    overall_conf = r.get("overall_confidence", 0)

    lines = []

    risk_desc = {
        "Critical":  "in a CRITICAL security state requiring immediate action",
        "High":      "showing HIGH-RISK activity that needs prompt attention",
        "Suspicious":"showing SUSPICIOUS patterns that warrant review",
        "Normal":    "operating normally with no major threats detected",
    }.get(risk, "under monitoring")

    lines.append(
        hostname + " is currently " + risk_desc + ". "
        "Over the past " + str(period) + " days, " + str(total_ev) + " log events were "
        "recorded across all categories, of which " + str(total_err) + " were errors or "
        "failures (error rate: " + str(round(err_rate, 1)) + "%). "
        "Analysis confidence: " + str(overall_conf) + "% "
        "(confidence-weighted by event frequency, temporal context, and pattern strength)."
    )

    # Category breakdown
    cat_parts = []
    for cat, cv in cats.items():
        if cv.get("total", 0) > 0:
            label = cat.replace("_", " ").title()
            n = cv.get("total", 0)
            e = cv.get("errors", 0) + cv.get("critical", 0)
            pct = round(e / n * 100, 1) if n > 0 else 0
            if e > 0:
                cat_parts.append(label + " (" + str(n) + " events, " + str(e) + " errors, " + str(pct) + "% error rate)")
            else:
                cat_parts.append(label + " (" + str(n) + " events, clean)")
    if cat_parts:
        lines.append("Activity by category: " + "; ".join(cat_parts) + ".")

    # Attack chains (most important — multi-stage confirmed activity)
    real_chains = [c for c in chains if c.get("is_chain")]
    if real_chains:
        chain_names = ", ".join(_safe(c.get("name","")) for c in real_chains[:3])
        lines.append(
            "ATTACK CHAINS CONFIRMED: " + str(len(real_chains)) + " multi-stage attack sequence(s) detected: " +
            chain_names + ". These are the most serious findings — they confirm coordinated, "
            "intentional attacker behavior across multiple event types. "
            "Attack chains are detected through temporal ordering of events, not simple co-occurrence."
        )
        for chain in real_chains[:2]:
            interp = _safe(chain.get("human_summary", chain.get("description", "")))
            conf   = chain.get("confidence_pct", 0)
            if interp:
                lines.append(
                    _safe(chain.get("name", "")) + " (confidence: " + str(conf) + "%): " + interp
                )

    # Threat detections with confidence
    critical_threats = [h for h in threats if h.get("severity") == "CRITICAL"]
    high_threats     = [h for h in threats if h.get("severity") == "HIGH"]
    med_threats      = [h for h in threats if h.get("severity") == "MEDIUM"]

    if critical_threats:
        names   = ", ".join(_safe(h.get("name","")) for h in critical_threats[:3])
        total_c = sum(h.get("count",0) for h in critical_threats)
        avg_c   = int(sum(h.get("confidence",0.7)*100 for h in critical_threats) / len(critical_threats))
        lines.append(
            "CRITICAL THREATS DETECTED: " + names + ". "
            "A total of " + str(total_c) + " matching events found "
            "(average detection confidence: " + str(avg_c) + "%). "
            "These require immediate investigation."
        )
        # Plain-English explanations for top 2
        for h in critical_threats[:2]:
            summary = _safe(h.get("human_summary", h.get("description", "")))
            conf    = h.get("confidence_pct", 0)
            off_h   = h.get("off_hours_count", 0)
            if summary:
                extra = ""
                if off_h > 0:
                    extra = " (" + str(off_h) + " events occurred outside normal business hours, increasing suspicion.)"
                lines.append(
                    _safe(h.get("name","")) + " [" + str(conf) + "% confidence]: " + summary + extra
                )

    if high_threats:
        names   = ", ".join(_safe(h.get("name","")) for h in high_threats[:4])
        total_h = sum(h.get("count",0) for h in high_threats)
        lines.append(
            "High-severity patterns: " + names + ". "
            "Combined event count: " + str(total_h) + ". "
            "Should be reviewed within 2 hours."
        )

    if med_threats:
        names = ", ".join(_safe(h.get("name","")) for h in med_threats[:3])
        lines.append("Medium-severity patterns found: " + names + ".")

    if not threats and not real_chains:
        lines.append(
            "No threat patterns exceeded the detection frequency thresholds. "
            "The smart engine requires a minimum number of events within a time window "
            "before flagging a threat — single events are treated as noise, not threats."
        )

    # Anomalies
    if anomalies:
        worst = max(anomalies, key=lambda a: a.get("zscore", 0))
        dates = ", ".join(_safe(str(a.get("date",""))) for a in anomalies[:3])
        lines.append(
            "Statistical anomalies detected on " + str(len(anomalies)) + " day(s): " + dates + ". "
            "Most significant spike: " + _safe(str(worst.get("date",""))) + " with " +
            str(worst.get("count",0)) + " events (Z-score: " + str(worst.get("zscore",0)) + "). "
            "Event spikes often indicate a security incident, system instability, or batch misfires."
        )
    else:
        lines.append(
            "No statistically anomalous days detected. "
            "Event volume has been consistent throughout the monitored period."
        )

    # Category-specific context
    sec_cv = cats.get("security", {})
    if sec_cv.get("total", 0) > 0:
        lines.append(
            "The Security log contains " + str(sec_cv.get("total",0)) + " events. "
            "Key Event IDs reviewed by the smart engine: 4625 (failed logons — brute force threshold: 5/hour), "
            "4740 (lockouts), 4672 (privilege escalation — threshold: 20/hour), "
            "4698 (scheduled tasks), 4719 (audit policy changes), 4728/4720 (account modifications)."
        )

    sys_cv = cats.get("system", {})
    if sys_cv.get("errors", 0) > 20:
        lines.append(
            "The System log shows " + str(sys_cv.get("errors",0)) + " errors. "
            "Hardware event IDs monitored: 11/7 (disk errors — threshold: 3/day), "
            "41/6008 (unexpected shutdowns), 5001 (Defender disabled), 7045 (new services)."
        )

    verdicts = {
        "Critical": (
            "OVERALL VERDICT: This system requires immediate security intervention. "
            "Confirmed attack chains indicate coordinated, intentional attacker behavior. "
            "Isolate affected processes, rotate ALL credentials, preserve logs, "
            "and begin full incident response immediately."
        ),
        "High": (
            "OVERALL VERDICT: This system is at high risk. "
            "Multiple high-confidence threat detections require investigation within 2 hours. "
            "Review all flagged Event IDs and implement the recommended actions."
        ),
        "Suspicious": (
            "OVERALL VERDICT: Suspicious patterns detected but no confirmed attack chains. "
            "Review the flagged events within 24 hours. "
            "Increase monitoring frequency and verify all privileged account activity."
        ),
        "Normal": (
            "OVERALL VERDICT: No significant threats detected. "
            "All events were within normal frequency thresholds. "
            "The confidence-based filter suppressed any low-signal noise. "
            "Continue routine monitoring."
        ),
    }
    lines.append(verdicts.get(risk, "Continue monitoring."))

    return " ".join(lines)



def _build_analysis_pdf(r: dict) -> bytes:
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    W = A4[0] - 36*mm

    C_BG    = colors.HexColor("#0f172a")
    C_BLUE  = colors.HexColor("#1a8cff")
    C_RED   = colors.HexColor("#ef4444")
    C_ORG   = colors.HexColor("#fb923c")
    C_YEL   = colors.HexColor("#fbbf24")
    C_GRN   = colors.HexColor("#10b981")
    C_GREY  = colors.HexColor("#64748b")
    C_LIGHT = colors.HexColor("#f1f5f9")
    C_WHITE = colors.white
    C_TEXT  = colors.HexColor("#1e293b")
    RCOLS   = {"Critical":C_RED,"High":C_ORG,"Medium":C_YEL,"Low":C_GRN}

    rs      = r.get("risk_summary",{})
    rlabel  = rs.get("label","Low")
    rcol    = RCOLS.get(rlabel, C_GRN)
    styles  = getSampleStyleSheet()
    def S(name,**kw): return ParagraphStyle(name,parent=styles["Normal"],**kw)

    s_h     = S("H",fontSize=18,textColor=C_WHITE,fontName="Helvetica-Bold",leading=22)
    s_sub   = S("Su",fontSize=9,textColor=colors.HexColor("#94a3b8"),fontName="Helvetica")
    s_h2    = S("H2",fontSize=11,textColor=C_TEXT,fontName="Helvetica-Bold",spaceBefore=4,spaceAfter=3)
    s_body  = S("B",fontSize=9,textColor=C_TEXT,fontName="Helvetica",leading=13)
    s_small = S("Sm",fontSize=8,textColor=C_GREY,fontName="Helvetica")
    s_mono  = S("Mo",fontSize=8,textColor=C_TEXT,fontName="Courier",leading=11)
    s_ctr   = S("Ce",fontSize=9,textColor=C_GREY,fontName="Helvetica",alignment=TA_CENTER)
    s_rt    = S("Rt",fontSize=9,textColor=C_GREY,fontName="Helvetica",alignment=TA_RIGHT)

    story = []

    # Header banner
    hdr = Table([[
        Paragraph(f"Secure Eye Trust+  -  Analysis Report", s_h),
        Paragraph(f"<b>{rlabel} Risk</b><br/>{rs.get('score',0)}/100",
                  ParagraphStyle("RB",fontSize=14,textColor=rcol,fontName="Helvetica-Bold",alignment=TA_RIGHT,leading=18))
    ]], colWidths=[W*0.72, W*0.28])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_BG),
        ("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14),
        ("LEFTPADDING",(0,0),(-1,-1),14),("RIGHTPADDING",(0,0),(-1,-1),14),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]))
    story.append(hdr)
    story.append(Spacer(1,3*mm))

    # Meta row
    meta = Table([[
        Paragraph(f"<b>Host:</b> {_safe(r.get('hostname',''))}", s_body),
        Paragraph(f"<b>Generated:</b> {r.get('generated_at','')}", s_body),
        Paragraph(f"<b>Period:</b> Last {r.get('period_days',30)} days", s_body),
        Paragraph(f"<b>Trigger:</b> {r.get('trigger','manual')}", s_small),
    ]], colWidths=[W*0.25,W*0.3,W*0.25,W*0.2])
    meta.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_LIGHT),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),
    ]))
    story.append(meta)
    story.append(Spacer(1,5*mm))

    # Stat cards
    def card(val,lbl,col):
        return Table([[Paragraph(str(val),ParagraphStyle("sv",fontSize=22,fontName="Helvetica-Bold",textColor=col,alignment=TA_CENTER,leading=26))],
                      [Paragraph(lbl,ParagraphStyle("sl",fontSize=8,fontName="Helvetica",textColor=col,alignment=TA_CENTER))]],
                     colWidths=[(W-10*mm)/6])
    cats    = r.get("categories",{})
    n_crit  = sum(v.get("critical",0) for v in cats.values())
    n_err   = sum(v.get("errors",0)   for v in cats.values())
    n_warn  = sum(v.get("warnings",0) for v in cats.values())
    n_info  = sum(v.get("info",0)     for v in cats.values())
    n_thr   = len(r.get("threat_hits",[]))
    n_anom  = len(r.get("anomaly_days",[]))

    cards_tbl = Table([[card(n_crit,"CRITICAL",C_RED),card(n_err,"ERRORS",C_ORG),
                        card(n_warn,"WARNINGS",C_YEL),card(n_info,"INFO",C_GRN),
                        card(n_thr,"THREATS",colors.HexColor("#a78bfa")),card(n_anom,"ANOMALY DAYS",C_ORG)]],
                      colWidths=[(W-10*mm)/6]*6, hAlign="LEFT")
    bg_map = [colors.HexColor("#fef2f2"),colors.HexColor("#fff7ed"),
              colors.HexColor("#fffbeb"),colors.HexColor("#f0fdf4"),
              colors.HexColor("#f5f3ff"),colors.HexColor("#fff7ed")]
    bd_map = [colors.HexColor("#fecaca"),colors.HexColor("#fed7aa"),
              colors.HexColor("#fde68a"),colors.HexColor("#bbf7d0"),
              colors.HexColor("#ddd6fe"),colors.HexColor("#fed7aa")]
    ts = [("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
          ("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4)]
    for i,(bg,bd) in enumerate(zip(bg_map,bd_map)):
        ts += [("BACKGROUND",(i,0),(i,0),bg),("BOX",(i,0),(i,0),0.5,bd)]
    cards_tbl.setStyle(TableStyle(ts))
    story.append(cards_tbl)
    story.append(Spacer(1,4*mm))

    total_ev  = r.get("total_events", 0)
    total_err = r.get("total_errors", 0)

    story.append(Paragraph("Report Highlights", s_h2))
    story.append(Spacer(1,1*mm))
    highlights = [
        f"Risk classification: {rlabel} ({rs.get('score',0)}/100)",
        f"Total events in period: {total_ev:,} with {total_err:,} errors and critical failures",
        f"Threat matches: {len(r.get('threat_hits',[]))} | Anomalous days: {len(r.get('anomaly_days',[]))}",
        f"Peak activity: {r.get('peak_hour','—')} | Next review scheduled: {r.get('next_check','—')}"
    ]
    for item in highlights:
        story.append(Paragraph(f'• {_safe(item)}', s_body))
    story.append(Spacer(1,5*mm))

    # ── System Status Narrative ──────────────────────────────────────────
    narrative_text = _generate_narrative(r)
    narrative_paras = narrative_text.split(". ")
    # Split into logical paragraphs (every ~3 sentences)
    chunk, chunks = [], []
    for i, sent in enumerate(narrative_paras):
        chunk.append(sent.strip())
        if len(chunk) >= 3 or i == len(narrative_paras)-1:
            chunks.append(". ".join(chunk) + ("." if not chunk[-1].endswith(".") else ""))
            chunk = []

    s_narr_title = ParagraphStyle("NT", parent=styles["Normal"],
        fontSize=12, fontName="Helvetica-Bold", textColor=C_TEXT,
        spaceBefore=6, spaceAfter=8)
    s_narr_body  = ParagraphStyle("NB", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica", textColor=colors.HexColor("#334155"),
        leading=15, spaceBefore=4, spaceAfter=4)

    narr_content = [[Paragraph("What Is Happening On This System", s_narr_title)]]
    for chunk_text in chunks:
        if chunk_text.strip():
            narr_content.append([Paragraph(_safe(chunk_text), s_narr_body)])

    narr_tbl = Table(narr_content, colWidths=[W])
    narr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("LEFTPADDING",   (0,0), (-1,-1), 16),
        ("RIGHTPADDING",  (0,0), (-1,-1), 16),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("BOX",           (0,0), (-1,-1), 0.7, colors.HexColor("#cbd5e1")),
        ("LINEBELOW",     (0,0), (-1,0),  0.7, colors.HexColor("#cbd5e1")),
    ]))
    story.append(narr_tbl)
    story.append(Spacer(1,6*mm))

    # Category breakdown
    story.append(Paragraph("Category Breakdown", s_h2))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    cat_rows = [[Paragraph(h,S("th",fontSize=8,fontName="Helvetica-Bold",textColor=C_GREY))
                 for h in ["Category","Total","Errors","Critical","Warnings","Error %"]]]
    for cat,cv in cats.items():
        pct = round((cv.get("errors",0)+cv.get("critical",0))/max(cv.get("total",1),1)*100,1)
        ec  = C_RED if pct>20 else C_ORG if pct>10 else C_GRN
        cat_rows.append([
            Paragraph(_safe(cat.replace("_"," ").title()),s_body),
            Paragraph(f"{cv.get('total',0):,}",    s_mono),
            Paragraph(f"{cv.get('errors',0):,}",   ParagraphStyle("er",fontSize=8,fontName="Courier",textColor=C_RED)),
            Paragraph(f"{cv.get('critical',0):,}", ParagraphStyle("cr",fontSize=8,fontName="Courier",textColor=C_RED)),
            Paragraph(f"{cv.get('warnings',0):,}", ParagraphStyle("wr",fontSize=8,fontName="Courier",textColor=C_YEL)),
            Paragraph(f"{pct}%",                   ParagraphStyle("pr",fontSize=8,fontName="Courier",textColor=ec)),
        ])
    ct = Table(cat_rows, colWidths=[40*mm,22*mm,22*mm,22*mm,22*mm,W-128*mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),6),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,colors.HexColor("#f8fafc")]),
        ("LINEBELOW",(0,0),(-1,-2),0.3,C_LIGHT),("BOX",(0,0),(-1,-1),0.5,C_LIGHT),
    ]))
    story.append(ct)
    story.append(Spacer(1,5*mm))

    # Threat hits
    story.append(Paragraph("Threat Pattern Matches", s_h2))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    threats = r.get("threat_hits",[])
    if threats:
        th_rows = [[Paragraph(h,S("th",fontSize=8,fontName="Helvetica-Bold",textColor=C_GREY))
                    for h in ["Severity","Threat","Count","Last Seen","Example"]]]
        SCOLS = {"CRITICAL":C_RED,"HIGH":C_ORG,"MEDIUM":C_YEL,"LOW":C_GRN}
        for h in threats[:12]:
            sc = SCOLS.get(h["severity"],C_GREY)
            ex = _clean_msg(h["examples"][0].get("message",""), 80) if h.get("examples") else ""
            th_rows.append([
                Paragraph(_safe(h["severity"]),ParagraphStyle("sev",fontSize=8,fontName="Helvetica-Bold",textColor=sc)),
                Paragraph(_safe(h["name"]),s_body),
                Paragraph(_safe(str(h["count"])),ParagraphStyle("cnt",fontSize=9,fontName="Helvetica-Bold",textColor=sc)),
                Paragraph(_safe(h.get("latest","")[:16]),s_small),
                Paragraph(_safe(ex),s_small),
            ])
        tt = Table(th_rows, colWidths=[22*mm,45*mm,16*mm,28*mm,W-111*mm])
        tt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,colors.HexColor("#f8fafc")]),
            ("LINEBELOW",(0,0),(-1,-2),0.3,C_LIGHT),("BOX",(0,0),(-1,-1),0.5,C_LIGHT),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(tt)
    else:
        story.append(Paragraph("No threat patterns matched in the selected period.", s_body))
    story.append(Spacer(1,5*mm))

    # Anomaly days
    story.append(Paragraph("Anomalous Days (Z-Score &gt; 2.0)", s_h2))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    anomalies = r.get("anomaly_days",[])
    if anomalies:
        an_rows = [[Paragraph(h,S("th",fontSize=8,fontName="Helvetica-Bold",textColor=C_GREY))
                    for h in ["Date","Event Count","Z-Score","Status"]]]
        for a in anomalies:
            zs = a.get("zscore",0)
            sc = C_RED if zs>3 else C_ORG
            an_rows.append([
                Paragraph(_safe(a["date"]),s_mono),
                Paragraph(_safe(f"{a['count']:,}"),s_body),
                Paragraph(f"{zs}", ParagraphStyle("zs",fontSize=9,fontName="Helvetica-Bold",textColor=sc)),
                Paragraph("!! Spike" if zs>3 else "^ Elevated", ParagraphStyle("st",fontSize=8,fontName="Helvetica",textColor=sc)),
            ])
        at = Table(an_rows, colWidths=[35*mm,35*mm,30*mm,W-100*mm])
        at.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,colors.HexColor("#f8fafc")]),
            ("BOX",(0,0),(-1,-1),0.5,C_LIGHT),
        ]))
        story.append(at)
    else:
        story.append(Paragraph("No anomalous days detected - event volume is consistent.", s_body))
    story.append(Spacer(1,5*mm))

    # Top sources
    story.append(Paragraph("Top Sources", s_h2))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    topSrcs = r.get("top_sources",[])
    if topSrcs:
        src_rows = [[Paragraph(h,S("th",fontSize=8,fontName="Helvetica-Bold",textColor=C_GREY))
                     for h in ["Source","Event Count"]]]
        for src in topSrcs[:10]:
            src_rows.append([
                Paragraph(_safe(src.get("source","")),s_body),
                Paragraph(_safe(f"{src.get('count',0):,}"),s_mono),
            ])
        st = Table(src_rows, colWidths=[W*0.7, W*0.3])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,colors.HexColor("#f8fafc")]),
            ("BOX",(0,0),(-1,-1),0.5,C_LIGHT),
            ("ALIGN",(1,1),(-1,-1),"RIGHT"),
        ]))
        story.append(st)
    else:
        story.append(Paragraph("Source data not available for this report.", s_body))
    story.append(Spacer(1,5*mm))

    # Recommendations
    story.append(Paragraph("Recommendations", s_h2))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    PCOL = {"CRITICAL":C_RED,"HIGH":C_ORG,"MEDIUM":C_YEL,"LOW":C_GRN}
    PBG  = {"CRITICAL":colors.HexColor("#fef2f2"),"HIGH":colors.HexColor("#fff7ed"),
            "MEDIUM":colors.HexColor("#fffbeb"),"LOW":colors.HexColor("#f0fdf4")}
    for rec in r.get("recommendations",[]):
        pc  = PCOL.get(rec["priority"],C_GREY)
        pbg = PBG.get(rec["priority"],C_WHITE)
        rt  = Table([[
            Paragraph(_safe(rec["priority"]),ParagraphStyle("rp",fontSize=8,fontName="Helvetica-Bold",textColor=pc,alignment=TA_CENTER)),
            Paragraph(_safe(rec["text"]),s_body)
        ]], colWidths=[20*mm,W-20*mm])
        rt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),pbg),("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),("LEFTPADDING",(0,0),(-1,-1),8),
            ("BOX",(0,0),(-1,-1),0.5,colors.HexColor("#e5e7eb")),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story.append(rt)
        story.append(Spacer(1,2*mm))

    story.append(Spacer(1,4*mm))
    story.append(HRFlowable(width=W,thickness=0.5,color=C_LIGHT))
    story.append(Spacer(1,2*mm))
    _footer = _safe("Secure Eye Trust+  |  " + str(r.get("hostname","")) + "  |  " + str(r.get("generated_at","")) + "  |  Report ID: " + str(r.get("id","")))
    story.append(Paragraph(_footer, s_ctr))

    doc.build(story)
    return buf.getvalue()


# ── HTML builder ──────────────────────────────────────────────────────────────

def _build_analysis_html(r: dict) -> str:
    rs     = r.get("risk_summary",{})
    rlabel = rs.get("label","Low")
    rcol   = {"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#10b981"}.get(rlabel,"#10b981")
    cats   = r.get("categories",{})

    cat_rows = ""
    for cat,cv in cats.items():
        pct = round((cv.get("errors",0)+cv.get("critical",0))/max(cv.get("total",1),1)*100,1)
        bc  = "#ef4444" if pct>20 else "#fb923c" if pct>10 else "#10b981"
        cat_rows += f"<tr><td>{cat.replace('_',' ').title()}</td><td>{cv.get('total',0):,}</td><td style='color:#f87171'>{cv.get('errors',0):,}</td><td style='color:#fbbf24'>{cv.get('warnings',0):,}</td><td style='color:{bc}'>{pct}%</td></tr>"

    threat_rows = ""
    SCOL = {"CRITICAL":"#ef4444","HIGH":"#fb923c","MEDIUM":"#fbbf24","LOW":"#4ade80"}
    for h in r.get("threat_hits",[]):
        sc = SCOL.get(h["severity"],"#94a3b8")
        ex = h["examples"][0]["message"][:100] if h.get("examples") else ""
        threat_rows += f"<tr><td style='color:{sc};font-weight:700'>{h['severity']}</td><td>{h['name']}</td><td style='color:{sc};font-weight:700'>{h['count']}x</td><td style='font-size:11px;color:#64748b'>{h.get('latest','')[:16]}</td><td style='font-size:11px;color:#94a3b8'>{ex}</td></tr>"

    anom_rows = ""
    for a in r.get("anomaly_days",[]):
        anom_rows += f"<tr><td>{a['date']}</td><td>{a['count']:,}</td><td style='color:#fb923c;font-weight:700'>Z={a['zscore']}</td></tr>"

    rec_html = ""
    PCOL = {"CRITICAL":"#ef4444","HIGH":"#fb923c","MEDIUM":"#fbbf24","LOW":"#4ade80"}
    PBCOL= {"CRITICAL":"rgba(239,68,68,.08)","HIGH":"rgba(251,146,60,.08)","MEDIUM":"rgba(251,191,36,.08)","LOW":"rgba(74,222,128,.08)"}
    for rec in r.get("recommendations",[]):
        pc=PCOL.get(rec["priority"],"#94a3b8"); pb=PBCOL.get(rec["priority"],"transparent")
        rec_html += f"<div style='display:flex;gap:12px;align-items:center;padding:10px 14px;border-radius:8px;background:{pb};border-left:3px solid {pc};margin-bottom:8px'><span style='color:{pc};font-weight:800;font-size:11px;min-width:60px'>{rec['priority']}</span><span style='color:#cbd5e1;font-size:13px'>{rec['text']}</span></div>"

    tl_bars = ""
    timeline = r.get("timeline",[])
    if timeline:
        max_c = max(t["count"] for t in timeline) or 1
        for t in timeline[-20:]:
            h = max(4, round(t["count"]/max_c*60))
            td = t["date"]; tc = t["count"]
            tl_bars += f'<div title="{td}: {tc}" style="flex:1;height:{h}px;background:#1a8cff88;border-radius:2px 2px 0 0;align-self:flex-end"></div>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{r.get('name','Report')}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#060c1a;color:#e2e8f0;padding:24px;min-height:100vh}}
.wrap{{max-width:980px;margin:0 auto}}
.hdr{{background:#0f172a;border-radius:14px;padding:24px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:20px;font-weight:900;color:#fff}}
.hdr p{{font-size:12px;color:#64748b;margin-top:4px}}
.risk-badge{{padding:8px 18px;border-radius:20px;font-size:14px;font-weight:800;background:{rcol}18;color:{rcol};border:1px solid {rcol}44}}
.stat-grid{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}}
.stat-card{{background:#0f172a;border-radius:10px;padding:14px;text-align:center;border:1px solid rgba(255,255,255,.06)}}
.stat-val{{font-size:24px;font-weight:900;margin-bottom:3px}}
.stat-lbl{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
.section{{background:#0f172a;border-radius:12px;padding:18px;margin-bottom:16px;border:1px solid rgba(255,255,255,.06)}}
.section h2{{font-size:13px;font-weight:800;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,.06)}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{padding:8px 12px;background:rgba(255,255,255,.04);color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.06em;text-align:left}}
td{{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);color:#cbd5e1}}
tr:last-child td{{border:none}}
.tl-bars{{display:flex;gap:3px;align-items:flex-end;height:70px;padding:8px 0}}
.footer{{text-align:center;font-size:11px;color:#334155;margin-top:24px;padding-top:16px;border-top:1px solid rgba(255,255,255,.06)}}
</style></head><body><div class="wrap">
<div class="hdr">
  <div><h1>🔐 {r.get('name','Analysis Report')}</h1><p>Host: {r.get('hostname','')} &nbsp;·&nbsp; {r.get('generated_at','')} &nbsp;·&nbsp; Last {r.get('period_days',30)} days</p></div>
  <div class="risk-badge">{rlabel} Risk · {rs.get('score',0)}/100</div>
</div>
<div class="stat-grid">
  <div class="stat-card"><div class="stat-val" style="color:#f87171">{sum(v.get('critical',0) for v in cats.values()):,}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#fb923c">{sum(v.get('errors',0) for v in cats.values()):,}</div><div class="stat-lbl">Errors</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#fbbf24">{sum(v.get('warnings',0) for v in cats.values()):,}</div><div class="stat-lbl">Warnings</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#4ade80">{sum(v.get('info',0) for v in cats.values()):,}</div><div class="stat-lbl">Info</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#a78bfa">{len(r.get('threat_hits',[]))}</div><div class="stat-lbl">Threats</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#fb923c">{len(r.get('anomaly_days',[]))}</div><div class="stat-lbl">Anomaly Days</div></div>
</div>
<div class="section"><h2>📅 30-Day Event Timeline</h2><div class="tl-bars">{tl_bars}</div></div>
<div class="section"><h2>📂 Category Breakdown</h2><table><thead><tr><th>Category</th><th>Total</th><th>Errors</th><th>Warnings</th><th>Error %</th></tr></thead><tbody>{cat_rows}</tbody></table></div>
<div class="section"><h2>🎯 Threat Pattern Matches</h2>{'<table><thead><tr><th>Severity</th><th>Threat</th><th>Count</th><th>Last Seen</th><th>Example</th></tr></thead><tbody>'+threat_rows+'</tbody></table>' if threat_rows else '<p style="color:#4ade80;font-size:13px">✅ No threats detected</p>'}</div>
<div class="section"><h2>📈 Anomalous Days</h2>{'<table><thead><tr><th>Date</th><th>Events</th><th>Z-Score</th></tr></thead><tbody>'+anom_rows+'</tbody></table>' if anom_rows else '<p style="color:#4ade80;font-size:13px">✅ No anomalous days</p>'}</div>
<div class="section"><h2>💡 Recommendations</h2>{rec_html}</div>
<div class="section"><h2>⏰ Next Check</h2><p style="font-size:15px;font-weight:700;color:#4da6ff">{r.get('next_check','—')}</p></div>
<div class="footer">Secure Eye Trust+ &nbsp;·&nbsp; {r.get('hostname','')} &nbsp;·&nbsp; {r.get('generated_at','')} &nbsp;·&nbsp; ID: {r.get('id','')}</div>
</div></body></html>"""


@perform_bp.route("/perform-analysis/delete/<report_id>", methods=["DELETE"])
def delete_report(report_id):
    """Delete a saved analysis report from DB."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    try:
        conn = get_conn()
        _ensure_table(conn)
        conn.execute("DELETE FROM analysis_reports WHERE id = ?", (report_id,))
        conn.commit()
        conn.close()
        # Also remove from reports_api in-memory store
        try:
            from api.reports_api import _report_store
            _report_store[:] = [r for r in _report_store if r.get("id") != report_id]
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@perform_bp.route('/perform-analysis/suppressed', methods=['GET'])
def get_suppressed():
    """Return list of suppressed rule IDs."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    s = sorted(list(_load_suppressed()))
    return jsonify({"ok": True, "suppressed": s})


@perform_bp.route('/perform-analysis/suppress', methods=['POST'])
def add_suppression():
    """Add a rule_id to suppression list (body JSON: {"rule_id":"..."})."""
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    from flask import request
    j = request.get_json(force=True, silent=True) or {}
    rid = j.get('rule_id') or j.get('id')
    if not rid:
        return jsonify({"ok": False, "error": "missing rule_id"}), 400
    ok = _add_suppressed(str(rid))
    return jsonify({"ok": ok})


@perform_bp.route('/perform-analysis/suppress/<rule_id>', methods=['DELETE'])
def remove_suppression(rule_id):
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    ok = _remove_suppressed(str(rule_id))
    return jsonify({"ok": ok})


@perform_bp.route("/fim-events")
def fim_events_live():
    """Live FIM event refresh — last 24 hours."""
    try:
        from core.fim_engine import get_fim_events, get_fim_summary
        conn   = get_conn()
        events = get_fim_events(conn, since_hours=24*30)
        conn.close()
        return jsonify({"ok": True, "fim": get_fim_summary(events)})
    except Exception as e:
        return jsonify({"ok": False, "fim": {"total":0,"critical":0,"high":0,
                        "by_action":{},"top_files":[],"events":[]}, "error": str(e)})



# ── AI Insights endpoint ──────────────────────────────────────────────────────

@perform_bp.route("/perform-analysis/ai-insights", methods=["POST"])
def ai_insights():
    """AI-driven interpretation of real analysis data. No generic definitions."""
    import os, json, re as _re
    try:
        import requests as _req
    except ImportError:
        return jsonify({"ok": False, "error": "requests not installed"}), 503

    report = request.get_json(silent=True) or {}
    if not report:
        return jsonify({"ok": False, "error": "No report data"}), 400

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "No GROQ_API_KEY"}), 503

    GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
    GROQ_MODEL = "llama-3.3-70b-versatile"

    rs        = report.get("risk_summary", {})
    cats      = report.get("categories", {})
    threats   = report.get("threat_hits", [])
    anomalies = report.get("anomaly_days", [])
    recs      = report.get("recommendations", [])
    timeline  = report.get("timeline", [])
    hourly    = report.get("hourly_pattern", [])
    weekday   = report.get("weekday_pattern", [])
    hostname  = report.get("hostname", "this system")
    peak_h    = report.get("peak_hour", "unknown")
    total_ev  = report.get("total_events", 0)
    total_err = report.get("total_errors", 0)
    risk      = rs.get("label", "Low")
    err_rate  = rs.get("error_rate", 0.0)

    cat_lines = "; ".join(
        "{}: {:,} events, {} errors".format(c, v.get("total",0), v.get("errors",0)+v.get("critical",0))
        for c, v in cats.items()
    )
    threat_lines = "; ".join(
        "{} [{}] x{} last:{}".format(h["name"], h["severity"], h["count"], h.get("latest","")[:10])
        for h in threats[:6]
    ) or "none"
    anom_lines = "; ".join(
        "{} had {:,} events Z={}".format(a["date"], a["count"], a["zscore"])
        for a in anomalies
    ) or "none"
    avg_per_day = int(total_ev / 30) if total_ev else 0
    top_hours = sorted(hourly, key=lambda h: h["count"], reverse=True)[:3]
    peak_str  = ", ".join("{} ({} events)".format(h["hour"], h["count"]) for h in top_hours)
    top_day   = max(weekday, key=lambda w: w["count"]) if weekday else {}
    tl_last7  = timeline[-7:] if len(timeline) >= 7 else timeline
    trend_str = "stable"
    if len(timeline) >= 4:
        first = sum(t["count"] for t in timeline[:len(timeline)//2])
        last  = sum(t["count"] for t in timeline[len(timeline)//2:])
        trend_str = "increasing" if last > first*1.1 else "decreasing" if last < first*0.9 else "stable"

    SYSTEM = (
        "You are a senior Windows cybersecurity analyst reviewing real live log data from a production system. "
        "You MUST interpret ONLY the actual numbers given. Do NOT give generic definitions or explanations of what event types are. "
        "Every sentence must reference specific numbers, dates, counts, or names from the data. "
        "Be direct and specific — like a briefing to a sysadmin. "
        "2-3 sentences maximum per response. "
        "No markdown, no bullet points, no asterisks. Plain sentences only."
    )

    def ask(data_context, specific_question):
        prompt = "LIVE DATA:\n" + data_context + "\n\nQUESTION: " + specific_question
        try:
            resp = _req.post(GROQ_URL, json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                "max_tokens": 200,
                "temperature": 0.25,
            }, headers={
                "Authorization": "Bearer " + api_key,
                "Content-Type":  "application/json",
                "User-Agent":    "SecureEyeTrust/2.0",
            }, timeout=15)
            text = resp.json().get("choices",[{}])[0].get("message",{}).get("content","").strip()
            text = _re.sub(r"[*#]+", "", text).strip()
            return text
        except Exception:
            return ""

    results = {}

    results["overview"] = ask(
        "System: {}. Risk: {} ({}/100). Events: {:,} total, {:,} errors ({:.1f}% error rate). "
        "Threats: {}. Anomalies: {}.".format(
            hostname, risk, rs.get("score",0), total_ev, total_err, err_rate,
            threat_lines, anom_lines),
        "What is actually happening on {} right now based on these exact numbers? "
        "Is the {:.1f}% error rate and {} risk concerning? Do not define terms — interpret the numbers.".format(
            hostname, err_rate, risk)
    )

    results["timeline"] = ask(
        "System: {}. 30-day event trend: {}. Average: {:,}/day. "
        "Anomalous spikes: {}. Last 7 days: {}.".format(
            hostname, trend_str, avg_per_day, anom_lines,
            ", ".join("{}: {:,}".format(t["date"], t["count"]) for t in tl_last7)),
        "The trend is {} with anomalies on {}. What does this specific pattern tell us about {}? "
        "Is the most recent week normal?".format(trend_str, anom_lines, hostname)
    )

    results["hourly"] = ask(
        "System: {}. Peak activity hours today: {}. Peak hour: {}.".format(
            hostname, peak_str, peak_h),
        "Activity peaks at {} on {}. Is this consistent with legitimate use or does it suggest "
        "automated/malicious processes running at odd hours?".format(peak_h, hostname)
    )

    results["categories"] = ask(
        "System: {}. Categories: {}. Security: {:,} events {} errors. "
        "System log: {:,} events {} errors. Application: {:,} events {} errors.".format(
            hostname, cat_lines,
            cats.get("security",{}).get("total",0), cats.get("security",{}).get("errors",0),
            cats.get("system",{}).get("total",0),   cats.get("system",{}).get("errors",0),
            cats.get("application",{}).get("total",0), cats.get("application",{}).get("errors",0)),
        "Which of these specific category numbers is most alarming and what does it indicate is happening on {}?".format(hostname)
    )

    results["threats"] = ask(
        "System: {}. Detected threats: {}. Total threat-matching events: {:,}.".format(
            hostname, threat_lines, sum(h.get("count",0) for h in threats)),
        "These specific threats were found on {}: {}. "
        "What is concretely happening on this machine based on these counts and timestamps? "
        "Which threat is most urgent?".format(hostname, threat_lines)
    )

    results["anomalies"] = ask(
        "System: {}. Anomalous days: {}. 30-day average: {:,}/day.".format(
            hostname, anom_lines, avg_per_day),
        "On {}, these days had massive event spikes vs the {:,}/day average: {}. "
        "Cross-referencing with threats ({}), what most likely caused these spikes?".format(
            hostname, avg_per_day, anom_lines, threat_lines[:100])
    )

    results["recommendations"] = ask(
        "System: {} at {} risk. Top threats: {}. Recommendations: {}.".format(
            hostname, risk, threat_lines[:150],
            "; ".join(r.get("text","") for r in recs[:3])),
        "Given {} risk with these specific threats on {}, what is the single most critical action "
        "in the next hour and what happens if nothing is done?".format(risk, hostname)
    )

    return jsonify({"ok": True, "insights": results})

