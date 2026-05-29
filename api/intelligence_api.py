"""
api/intelligence_api.py
========================
Blueprint: GET /api/intelligence

Runs the full security intelligence engine and returns:
  - risk score + classification
  - threat detections
  - correlation alerts (attack chains)
  - anomaly detection results
  - plain-English summary

This powers the "Security Intelligence" panel on the dashboard.
"""

from flask import Blueprint, jsonify
from core.analysis_engine import run_intelligence_engine
from database.db import log_app_event

intelligence_bp = Blueprint("intelligence", __name__)


@intelligence_bp.route("/intelligence")
def intelligence():
    """Run the full intelligence engine and return results."""
    try:
        result = run_intelligence_engine()
        log_app_event("intelligence_run", {
            "risk_score": result.get("risk_score"),
            "risk_level": result.get("risk_level"),
            "threats":    len(result.get("threats", [])),
        })
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/intelligence/threats")
def threats_only():
    """Return only threat detections (faster, no anomaly detection)."""
    try:
        from core.analysis_engine.threat_detector import run_threat_detection
        threats = run_threat_detection()
        return jsonify({"ok": True, "threats": threats, "count": len(threats)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/intelligence/correlations")
def correlations_only():
    """Return only correlation alerts (attack chain detection)."""
    try:
        from core.analysis_engine.correlator import run_correlation
        correlations = run_correlation()
        return jsonify({"ok": True, "correlations": correlations, "count": len(correlations)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/intelligence/anomalies")
def anomalies_only():
    """Return only anomaly detection results."""
    try:
        from core.analysis_engine.anomaly_detector import run_full_anomaly_detection
        anomalies = run_full_anomaly_detection()
        return jsonify({"ok": True, "anomalies": anomalies})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/intelligence/ml-status")
def ml_status():
    """Return ML model training status and metadata."""
    try:
        from core.analysis_engine.ml_anomaly import get_ml_detector
        detector = get_ml_detector()
        return jsonify({"ok": True, "models": detector.model_info()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/pipeline/stats")
def pipeline_stats():
    """Return processing pipeline statistics."""
    try:
        from core.pipeline.orchestrator import get_pipeline
        from core.pipeline.worker       import get_worker
        from core.pipeline.alert_bus    import get_alert_bus
        return jsonify({
            "ok":       True,
            "pipeline": get_pipeline().stats(),
            "worker":   get_worker().stats(),
            "alerts":   get_alert_bus().stats(),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@intelligence_bp.route("/pipeline/retrain", methods=["POST"])
def retrain_models():
    """Force retrain ML anomaly detection models."""
    try:
        from core.analysis_engine.ml_anomaly import get_ml_detector
        from database.db import get_conn
        detector = get_ml_detector()
        conn     = get_conn()
        # Force retrain by clearing trained_at
        detector._trained_at.clear()
        daily = detector.detect_daily_anomalies(conn)
        auth  = detector.detect_auth_anomalies(conn)
        conn.close()
        return jsonify({
            "ok":            True,
            "models_trained": list(detector._models.keys()),
            "anomalies_found": len(daily) + len(auth),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
