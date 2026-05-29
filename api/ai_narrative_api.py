"""
api/ai_narrative_api.py
=======================
Single endpoint: POST /api/ai-narrative
Accepts the raw report JSON and returns AI-generated narrative from Groq/Llama.
Also serves the AI report viewer page at GET /ai-report.
"""

from flask import Blueprint, request, jsonify, send_from_directory
import os

ai_narrative_bp = Blueprint("ai_narrative", __name__)


@ai_narrative_bp.route("/ai-narrative", methods=["POST"])
def ai_narrative():
    """
    Accepts: { "report": { ...perform_analysis report dict... } }
    Returns: AI narrative dict (see ai_narrative.generate_ai_narrative)
    """
    try:
        body   = request.get_json(force=True) or {}
        report = body.get("report")
        if not report:
            return jsonify({"error": "Missing 'report' in request body"}), 400

        from api.ai_narrative import generate_ai_narrative
        narrative = generate_ai_narrative(report)
        return jsonify(narrative)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "ai_available": False}), 500


@ai_narrative_bp.route("/ai-report")
def ai_report_page():
    """Serve the AI report viewer HTML page."""
    from flask import session, redirect
    if not session.get("authenticated"):
        return redirect("/login")
    return send_from_directory("templates", "ai_report.html")
