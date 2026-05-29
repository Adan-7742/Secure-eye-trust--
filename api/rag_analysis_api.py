"""
api/rag_analysis_api.py
=======================
Flask blueprint that exposes the RAG service as HTTP endpoints.

Endpoints:
    POST /api/rag-analysis            — analyze a single log entry
    POST /api/rag-analysis/bulk       — analyze a list of log entries
    POST /api/rag-analysis/index-logs — manually push logs into the FAISS index
    GET  /api/rag-analysis/status     — health check + store stats
    GET  /api/rag-analysis/retrieve   — retrieval-only (no LLM) for debugging
"""

from flask import Blueprint, request, jsonify
from services.rag_service import get_rag_service

rag_bp = Blueprint("rag_analysis", __name__)


# ── POST /api/rag-analysis ────────────────────────────────────────────────────

@rag_bp.route("/rag-analysis", methods=["POST"])
def rag_analyze():
    """
    Analyze a single Windows event log entry using RAG + Groq LLM.

    Request body (JSON):
        {
            "log":          string | object,   // required — the event log to analyze
            "context_logs": [ ... ],            // optional — surrounding log lines
            "k":            4                   // optional — number of docs to retrieve (default 4)
        }

    Response:
        {
            "ok": true,
            "severity":            "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "mitre":               [{"id":"T1110","tactic":"...","technique":"..."}],
            "attack_description":  "What is happening in plain English",
            "recommended_actions": ["Action 1", "Action 2", ...],
            "retrieved_context":   "What the RAG system found",
            "elapsed_s":           0.95,
            "timestamp":           "2025-04-26 14:32:00",
            "retrieval_stats":     {"keyword_matches":2, "vector_results":4, "store_size":220}
        }
    """
    body = request.get_json(silent=True) or {}

    log = body.get("log")
    if not log:
        return jsonify({"ok": False, "error": "Missing 'log' field in request body"}), 400

    context_logs = body.get("context_logs", [])
    k            = min(int(body.get("k", 4)), 10)

    try:
        svc    = get_rag_service()
        result = svc.analyze_log(log=log, context_logs=context_logs, k=k)
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


# ── POST /api/rag-analysis/bulk ───────────────────────────────────────────────

@rag_bp.route("/rag-analysis/bulk", methods=["POST"])
def rag_analyze_bulk():
    """
    Analyze multiple log entries in one call.
    Logs are first indexed so they provide mutual context.

    Request body:
        {
            "logs": [ "log string" | {log dict}, ... ],
            "k": 3
        }

    Response:
        { "ok": true, "results": [ {analysis}, ... ], "count": N }
    """
    body = request.get_json(silent=True) or {}
    logs = body.get("logs", [])

    if not logs or not isinstance(logs, list):
        return jsonify({"ok": False, "error": "Missing or invalid 'logs' array"}), 400

    if len(logs) > 50:
        return jsonify({"ok": False, "error": "Max 50 logs per bulk call"}), 400

    k = min(int(body.get("k", 3)), 8)

    try:
        svc     = get_rag_service()
        results = svc.bulk_analyze(logs=logs, k=k)
        return jsonify({"ok": True, "results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── POST /api/rag-analysis/index-logs ────────────────────────────────────────

@rag_bp.route("/rag-analysis/index-logs", methods=["POST"])
def rag_index_logs():
    """
    Manually push log entries into the FAISS/TF-IDF index.
    Useful after running a fresh analysis to update the knowledge base.

    Request body:
        {
            "logs": [ {log dict}, ... ],    // optional
            "from_db": true,                // optional — re-index from SQLite DB
            "db_limit": 500                 // optional — max rows from DB
        }
    """
    body     = request.get_json(silent=True) or {}
    logs     = body.get("logs", [])
    from_db  = body.get("from_db", False)
    db_limit = min(int(body.get("db_limit", 500)), 2000)

    indexed = 0
    svc = get_rag_service()

    try:
        if logs:
            svc.index_logs(logs)
            indexed += len(logs)

        if from_db:
            n = svc.index_logs_from_db(limit=db_limit)
            indexed += n

        return jsonify({
            "ok":      True,
            "indexed": indexed,
            "stats":   svc.stats,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── GET /api/rag-analysis/status ──────────────────────────────────────────────

@rag_bp.route("/rag-analysis/status", methods=["GET"])
def rag_status():
    """
    Health check for the RAG service.

    Response:
        {
            "ok": true,
            "store_size":   220,
            "store_type":   "PythonVectorStore",
            "mitre_seeded": true,
            "groq_key_set": true
        }
    """
    try:
        svc = get_rag_service()
        return jsonify({"ok": True, **svc.stats})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── GET /api/rag-analysis/retrieve ────────────────────────────────────────────

@rag_bp.route("/rag-analysis/retrieve", methods=["GET"])
def rag_retrieve():
    """
    Debug endpoint: run retrieval only (no LLM call).

    Query params:
        q   — the query string
        k   — number of results (default 5)

    Response:
        { "ok": true, "results": [...], "count": N }
    """
    q = request.args.get("q", "").strip()
    k = min(int(request.args.get("k", 5)), 20)

    if not q:
        return jsonify({"ok": False, "error": "Missing 'q' query parameter"}), 400

    try:
        svc     = get_rag_service()
        results = svc.retrieve(q, k=k)
        kw      = svc._keyword_match(q)
        return jsonify({
            "ok":              True,
            "results":         results,
            "keyword_matches": [{"id": m["id"], "technique": m["technique"]} for m in kw[:5]],
            "count":           len(results),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
