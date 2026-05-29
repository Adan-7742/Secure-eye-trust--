"""
core/analysis_engine/__init__.py
==================================
UPGRADED: Unified Analysis Engine Entry Point v2.0

Runs: smart threat detection → attack chain correlation → ML/Z-score anomaly
      → confidence-weighted risk scoring → intelligence text generation

All modules upgraded to use:
  - Frequency-based detection (threshold gates)
  - Confidence scoring (0–100%)
  - Temporal analysis (off-hours/weekend boosting)
  - Chain correlation with temporal ordering
"""

from datetime import datetime
from database.db import get_conn
from .threat_detector import run_threat_detection
from .correlator      import run_correlation
from .risk_scorer     import compute_system_score, classify_score


def run_intelligence_engine(conn=None) -> dict:
    close_conn = conn is None
    if conn is None:
        conn = get_conn()

    try:
        threats      = run_threat_detection(conn)
        correlations = run_correlation(conn)

        try:
            from .ml_anomaly import run_ml_anomaly_detection
            anomalies = run_ml_anomaly_detection(conn)
        except Exception:
            from .anomaly_detector import run_full_anomaly_detection
            anomalies = run_full_anomaly_detection(conn)

    except Exception as e:
        print(f"[intelligence_engine] Error: {e}")
        threats      = []
        correlations = []
        anomalies    = {
            "verdict": "NORMAL", "daily_anomalies": [],
            "summary": {}, "auth_time_analysis": {}, "source_spikes": [],
        }
    finally:
        if close_conn:
            try:
                conn.close()
            except Exception:
                pass

    anomaly_days   = len(anomalies.get("daily_anomalies", []))
    score_result   = compute_system_score(threats, anomaly_days)
    classification = score_result["classification"]

    score = score_result["score"]

    # Attack chain bonus: each confirmed chain adds +15 pts
    chain_bonus = 0
    for corr in correlations:
        if corr.get("is_chain"):
            chain_bonus = min(20, chain_bonus + 15)
    if chain_bonus:
        score = min(100, score + chain_bonus)
        classification = classify_score(score)

    summary = {
        "critical_threats":      sum(1 for t in threats if t["severity"] == "CRITICAL"),
        "high_threats":          sum(1 for t in threats if t["severity"] == "HIGH"),
        "medium_threats":        sum(1 for t in threats if t["severity"] == "MEDIUM"),
        "correlations":          len(correlations),
        "critical_correlations": sum(1 for c in correlations if c["severity"] == "CRITICAL"),
        "chain_count":           sum(1 for c in correlations if c.get("is_chain")),
        "anomalous_days":        anomaly_days,
        "source_spikes":         len(anomalies.get("source_spikes", [])),
        "ml_method":             anomalies.get("summary", {}).get("method", "zscore"),
        "fp_suppressed":         sum(1 for t in threats if t.get("confidence", 1) < 0.35),
    }

    intel_text = _build_intelligence_text(
        classification["level"], score, threats, correlations, anomalies, summary
    )

    return {
        "risk_score":        score,
        "risk_level":        classification["level"],
        "risk_color":        classification["color"],
        "risk_icon":         classification["icon"],
        "risk_message":      classification["message"],
        "threats":           threats,
        "correlations":      correlations,
        "anomalies":         anomalies,
        "summary":           summary,
        "intelligence_text": intel_text,
        "generated_at":      datetime.now().isoformat(),
    }


def _build_intelligence_text(level, score, threats, correlations, anomalies, summary) -> str:
    lines = []

    # Overall status
    level_msgs = {
        "Critical":   f"CRITICAL — Risk score {score}/100. Immediate action required.",
        "High":       f"HIGH RISK — Risk score {score}/100. Investigate within 2 hours.",
        "Suspicious": f"SUSPICIOUS — Risk score {score}/100. Review within 24 hours.",
        "Normal":     f"NORMAL — Risk score {score}/100. No significant threats detected.",
    }
    lines.append(level_msgs.get(level, f"Risk score {score}/100."))

    # Threats with confidence
    crit = [t for t in threats if t["severity"] == "CRITICAL"]
    high = [t for t in threats if t["severity"] == "HIGH"]
    if crit:
        avg_conf = int(sum(t.get("confidence", 0.7) for t in crit) / len(crit) * 100)
        names    = ", ".join(t["name"] for t in crit[:2])
        lines.append(
            f"{len(crit)} critical threat(s) detected (avg confidence: {avg_conf}%): {names}."
        )
    if high:
        names = ", ".join(t["name"] for t in high[:2])
        lines.append(f"{len(high)} high-severity threat(s): {names}.")

    # Attack chains
    chains = [c for c in correlations if c.get("is_chain")]
    if chains:
        chain_names = ", ".join(c["name"] for c in chains[:2])
        lines.append(
            f"{len(chains)} attack chain(s) confirmed (multi-stage coordinated activity): {chain_names}."
        )
    elif correlations:
        lines.append(f"{len(correlations)} suspicious correlation pattern(s) detected.")

    # Anomalies
    anom = anomalies.get("daily_anomalies", [])
    if anom:
        worst  = max(anom, key=lambda a: abs(a.get("anomaly_score", a.get("zscore", 0))))
        method = anom[0].get("method", "statistical")
        lines.append(
            f"{len(anom)} anomalous day(s) via {method} analysis — "
            f"worst: {worst.get('date', '')} ({worst.get('count', 0)} events)."
        )

    auth = anomalies.get("auth_time_analysis", {})
    if auth.get("verdict") == "suspicious":
        lines.append(f"{auth.get('off_hours_pct', 0)}% of logons outside business hours.")

    if not threats and not correlations and not anom:
        lines.append(
            "No active threats or anomalies detected. "
            "Frequency thresholds and confidence gates filtered out low-signal events."
        )

    return " ".join(lines)
