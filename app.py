"""
LogVault — Encrypted Windows Log Analyzer
==========================================
Entry point. Starts Flask + live event monitor background thread.

Run:
    python app.py                 (normal)
    python app.py                 (as Administrator — Security logs)

FR04 COMPLIANCE (updated):
  FR04-01: PerfMonitor       — continuous Windows performance monitoring (CPU/RAM/Disk/Net)
  FR04-02: StreamCollector   — Security log EIDs 4624/4625/4648/4672/4673/4688/4698+ (≤2s)
           winlogin_watcher  — EID 4625 with screenshot capture (every 5s)
  FR04-03: TaskSchedulerMonitor — Task lifecycle EIDs 4698-4702 + active inventory (COM)
  FR04-04: StreamCollector   — Windows Update events via WU_SOURCES filter (≤2s)
  FR04-05: ServiceMonitor    — Service EIDs 7000/7001/7009/7023/7031/7034/7040/7045
                               + active EnumServicesStatus polling (every 30s)
                               + dependency-chain health checks

FR10 COMPLIANCE (new):
  FR10-03: windows_integration_api — Windows Update patch level via WUA COM API
  FR10-04: windows_integration_api — Windows Action Center toast notifications
  FR10-05: windows_integration_api — Start Menu shortcut creation/removal
"""

import os
import sys
from pathlib import Path
from datetime import timedelta

# ── Load .env FIRST ────────────────────────────────────────────────────────────
from dotenv import load_dotenv
_HERE = Path(__file__).resolve().parent
_ENV  = _HERE / ".env"
load_dotenv(dotenv_path=_ENV, override=True)

_key = os.environ.get("GROQ_API_KEY", "")
print(f"[startup] .env   : {'✅ found' if _ENV.exists() else '❌ not found'}")
print(f"[startup] Groq   : {'✅ key loaded (' + _key[:8] + '...)' if _key else '❌ no key — add GROQ_API_KEY to .env'}")

# ── Flask imports ──────────────────────────────────────────────────────────────
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS

from api.system_api              import system_bp
from api.auth_api                import auth_bp
from api.locker_api              import locker_bp
from api.reports_api             import reports_bp
from api.logs_api                import logs_bp
from api.analysis_api            import analysis_bp
from api.upload_api              import upload_bp
from api.realtime_api            import realtime_bp
from api.network_api             import network_bp
from api.analyze_upload_api      import analyzer_bp
from api.upload_report_pdf_api   import pdf_report_bp
from api.perform_analysis_api    import perform_bp
from api.ai_narrative_api        import ai_narrative_bp
from api.analysis_ai_api         import analysis_ai_bp
from api.intelligence_api        import intelligence_bp
from api.alerts_api              import alerts_bp
from api.fetch_api               import fetch_bp
from api.log_explain_api         import log_explain_bp
from api.error_stream_api        import error_stream_bp   # v2 — real-time error notifications
from api.alerts_resolve_api      import resolve_bp         # v3 — mark alerts resolved
from api.rt_status_api           import rt_api_bp          # FR — RT pipeline status + perf API
# ── FR10-03 / FR10-04 / FR10-05 ───────────────────────────────────────────────
from api.windows_integration_api import windows_integration_bp  # FR10
from api.fr11_health_api         import fr11_bp                 # FR11
from chatbot.bot                 import chatbot_bp
from api.rag_analysis_api        import rag_bp
from api.timeseries_api          import ts_bp
from api.sysmon_api              import sysmon_bp   # Sysmon v2
from api.response_actions_api    import response_actions_bp  # Active response (kill/quarantine/etc.)
from api.fix_all_api             import fix_all_bp           # NEW: one-click Fix All endpoint
from api.threat_actions_api      import threat_actions_bp, ensure_threat_whitelist_table  # Whitelist / dismiss actions

from database.db        import init_db
from database.uploads_db import init_uploads_db
from core.event_collector.windows_reader  import is_admin, WIN32_AVAILABLE
from core.event_collector.live_monitor    import start_live_monitor
from core.event_collector.winlogin_watcher import start_winlogin_watcher, screenshot_engine


# ── FR04-03: Task Scheduler monitor ───────────────────────────────────────────
from core.event_collector.task_scheduler_monitor import get_task_monitor

# ── FR04-05: Windows Services monitor ─────────────────────────────────────────
from core.event_collector.service_monitor import get_service_monitor


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24))

    # ── Persistent session configuration ──────────────────────────────────────
    app.config["SESSION_PERMANENT"]         = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
    app.config["SESSION_COOKIE_SECURE"]     = False   # set True for HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"]   = True
    app.config["SESSION_COOKIE_SAMESITE"]   = "Lax"

    CORS(app, supports_credentials=True)

    # ── Existing blueprints ────────────────────────────────────────────────────
    app.register_blueprint(system_bp,       url_prefix="/api")
    app.register_blueprint(auth_bp,         url_prefix="")
    app.register_blueprint(locker_bp,       url_prefix="/api/locker")
    app.register_blueprint(reports_bp,      url_prefix="/api/reports")
    app.register_blueprint(logs_bp,         url_prefix="/api")
    app.register_blueprint(analysis_bp,     url_prefix="/api/analyze")
    app.register_blueprint(upload_bp,       url_prefix="/api")
    app.register_blueprint(realtime_bp,     url_prefix="/api")
    app.register_blueprint(network_bp,      url_prefix="/api/network")
    app.register_blueprint(chatbot_bp,      url_prefix="/api/chat")
    app.register_blueprint(analyzer_bp,     url_prefix="/api")
    app.register_blueprint(pdf_report_bp,   url_prefix="/api")
    app.register_blueprint(perform_bp,      url_prefix="/api")
    app.register_blueprint(ai_narrative_bp, url_prefix="/api")
    app.register_blueprint(analysis_ai_bp,  url_prefix="/api")
    app.register_blueprint(intelligence_bp, url_prefix="/api")
    app.register_blueprint(alerts_bp,       url_prefix="/api")
    app.register_blueprint(fetch_bp,        url_prefix="/api")
    app.register_blueprint(log_explain_bp,  url_prefix="/api")
    app.register_blueprint(error_stream_bp, url_prefix="/api")   # v2
    app.register_blueprint(resolve_bp,      url_prefix="/api")   # v3
    app.register_blueprint(rt_api_bp,       url_prefix="/api")   # FR
    # ── FR10: Windows integration (patch level, Action Center, Start Menu) ────
    app.register_blueprint(windows_integration_bp, url_prefix="/api")  # FR10
    app.register_blueprint(fr11_bp,                   url_prefix="/api")  # FR11
    app.register_blueprint(rag_bp,                    url_prefix="/api")  # RAG analysis
    app.register_blueprint(ts_bp,                     url_prefix="/api")  # Time-Series
    app.register_blueprint(sysmon_bp, url_prefix="")      # Sysmon v2
    app.register_blueprint(response_actions_bp, url_prefix="/api")  # Kill/Quarantine/Delete/Block/Remove-Persistence
    app.register_blueprint(fix_all_bp,          url_prefix="/api")  # NEW: /api/action/fix-all (one-click Fix All)
    app.register_blueprint(threat_actions_bp,   url_prefix="/api")  # Whitelist caller / Dismiss rule

    # Make sure threat_whitelist table exists on startup
    try:
        ensure_threat_whitelist_table()
    except Exception as e:
        print(f"[startup] Could not create threat_whitelist table: {e}")

    # ── FR04-03 / FR04-05 API routes ──────────────────────────────────────────
    _register_fr04_routes(app)

    @app.route("/favicon.ico")
    def favicon():
        from flask import Response
        return Response(status=204)

    @app.route("/")
    def index():
        from flask import session, redirect
        if not session.get("authenticated"):
            return redirect("/login")
        return send_from_directory("templates", "index.html")

    # ── Global error handlers ─────────────────────────────────────────────────
    import traceback as _tb

    @app.errorhandler(500)
    def handle_500(e):
        _tb.print_exc()
        print(f"[500 ERROR] {e}")
        orig = getattr(e, "original_exception", e)
        return {"ok": False, "error": str(orig), "traceback": _tb.format_exc()}, 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        _tb.print_exc()
        print(f"[UNHANDLED] {type(e).__name__}: {e}")
        return {"ok": False, "error": str(e)}, 500

    return app


# ── FR04-03 / FR04-05 route registration ──────────────────────────────────────

def _register_fr04_routes(app):
    """
    Register FR04-03 (Task Scheduler) and FR04-05 (Services) API endpoints.
    """

    @app.route("/api/tasks/inventory")
    def task_inventory():
        suspicious_only = request.args.get("suspicious_only", "0") == "1"
        tasks = get_task_monitor().get_inventory()
        if suspicious_only:
            tasks = [t for t in tasks if t.get("suspicious")]
        suspicious_count = sum(1 for t in tasks if t.get("suspicious"))
        enabled_count    = sum(1 for t in tasks if t.get("enabled"))
        return jsonify({"ok": True, "total": len(tasks), "enabled": enabled_count,
                        "suspicious": suspicious_count, "tasks": tasks})

    @app.route("/api/tasks/events")
    def task_events():
        from database.db import get_conn
        limit           = min(int(request.args.get("limit", 50)), 500)
        suspicious_only = request.args.get("suspicious_only", "0") == "1"
        filter_eid      = request.args.get("event_id")
        try:
            conn = get_conn(); c = conn.cursor()
            wheres, params = [], []
            if suspicious_only: wheres.append("suspicious=1")
            if filter_eid: wheres.append("event_id=?"); params.append(int(filter_eid))
            where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""
            c.execute(f"""SELECT ts, event_id, event_label, task_name, subject_user,
                       severity, suspicious, task_content FROM task_events
                       {where_clause} ORDER BY id DESC LIMIT ?""", params + [limit])
            cols = ["ts","event_id","event_label","task_name","subject_user","severity","suspicious","task_content"]
            rows = [dict(zip(cols, row)) for row in c.fetchall()]
            conn.close()
            return jsonify({"ok": True, "events": rows, "count": len(rows)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/tasks/summary")
    def task_summary():
        from database.db import get_conn
        try:
            conn = get_conn(); c = conn.cursor()
            c.execute("""SELECT event_id, event_label, COUNT(*) as cnt, SUM(suspicious) as sus_cnt
                FROM task_events WHERE ts >= datetime('now', '-24 hours')
                GROUP BY event_id, event_label ORDER BY cnt DESC""")
            rows = [{"event_id":r[0],"label":r[1],"count":r[2],"suspicious":r[3]} for r in c.fetchall()]
            conn.close()
            return jsonify({"ok": True, "summary": rows})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/services/inventory")
    def service_inventory():
        state_filter    = request.args.get("state", "ALL").upper()
        suspicious_only = request.args.get("suspicious_only", "0") == "1"
        critical_only   = request.args.get("critical_only",   "0") == "1"
        services = get_service_monitor().get_snapshot()
        if state_filter != "ALL":
            services = [s for s in services if s.get("state") == state_filter]
        if suspicious_only: services = [s for s in services if s.get("suspicious")]
        if critical_only:   services = [s for s in services if s.get("is_critical")]
        stopped_critical = [s["service_name"] for s in services
                            if s.get("is_critical") and s.get("state") == "STOPPED"]
        return jsonify({"ok": True, "total": len(services),
            "running": sum(1 for s in services if s.get("state")=="RUNNING"),
            "stopped": sum(1 for s in services if s.get("state")=="STOPPED"),
            "suspicious": sum(1 for s in services if s.get("suspicious")),
            "stopped_critical": stopped_critical, "services": services})

    @app.route("/api/services/events")
    def service_events():
        from database.db import get_conn
        limit      = min(int(request.args.get("limit", 50)), 500)
        filter_eid = request.args.get("event_id")
        svc_filter = request.args.get("service", "").strip()
        try:
            conn = get_conn(); c = conn.cursor()
            wheres, params = [], []
            if filter_eid: wheres.append("event_id=?"); params.append(int(filter_eid))
            if svc_filter: wheres.append("service_name LIKE ?"); params.append(f"%{svc_filter}%")
            where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""
            c.execute(f"""SELECT ts, event_id, event_label, service_name,
                       severity, suspicious, detail FROM service_events
                       {where_clause} ORDER BY id DESC LIMIT ?""", params + [limit])
            cols = ["ts","event_id","event_label","service_name","severity","suspicious","detail"]
            rows = [dict(zip(cols, row)) for row in c.fetchall()]
            conn.close()
            return jsonify({"ok": True, "events": rows, "count": len(rows)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/services/dependencies")
    def service_dependencies():
        services = get_service_monitor().get_snapshot()
        svc_map  = {s["service_name"].lower(): s for s in services}
        broken   = []
        for svc in services:
            if svc.get("state") != "RUNNING": continue
            for dep in svc.get("dependencies", []):
                dep_svc = svc_map.get(dep.lower())
                if dep_svc and dep_svc.get("state") == "STOPPED":
                    broken.append({"service": svc["service_name"],
                        "display_name": svc.get("display_name",""),
                        "missing_dep": dep,
                        "dep_display_name": dep_svc.get("display_name", dep),
                        "severity": "CRITICAL" if svc.get("is_critical") else "HIGH"})
        return jsonify({"ok": True, "broken": broken, "count": len(broken)})

    @app.route("/api/services/summary")
    def service_summary():
        from database.db import get_conn
        try:
            conn = get_conn(); c = conn.cursor()
            c.execute("""SELECT event_id, event_label, COUNT(*) as cnt, SUM(suspicious) as sus_cnt
                FROM service_events WHERE ts >= datetime('now', '-24 hours')
                GROUP BY event_id, event_label ORDER BY event_id""")
            rows = [{"event_id":r[0],"label":r[1],"count":r[2],"suspicious":r[3]} for r in c.fetchall()]
            conn.close()
            return jsonify({"ok": True, "summary": rows})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    init_uploads_db()

    # ── Sysmon + Sigma + FileScanner schema ──────────────────────────────────
    try:
        from core.event_collector.sysmon_collector import _ensure_sysmon_table
        _ensure_sysmon_table()
        print("✅ logs_sysmon table ready")
    except Exception as _e:
        print(f"⚠  sysmon table: {_e}")

    try:
        from core.analysis_engine.sigma_engine import _ensure_sigma_table
        _ensure_sigma_table()
        print("✅ sigma_hits table ready")
    except Exception as _e:
        print(f"⚠  sigma table: {_e}")

    try:
        from core.event_collector.file_scanner import _ensure_scan_table
        _ensure_scan_table()
        print("✅ file_scan_results table ready")
    except Exception as _e:
        print(f"⚠  file scan table: {_e}")


    from core.pipeline.worker import get_worker
    _worker = get_worker()
    print("✅ Background worker queue started (3 threads)")

    from core.pipeline.orchestrator import get_pipeline
    get_pipeline()
    print("✅ Processing pipeline initialized")

    try:
        from core.analysis_engine.threat_detector_fr04_patch import apply_patch_to_threat_rules
        from core.analysis_engine import threat_detector as _td
        _td.THREAT_RULES = apply_patch_to_threat_rules(_td.THREAT_RULES)
        print("✅ FR04 threat detection rules applied (task lifecycle + service health)")
    except Exception as _patch_err:
        print(f"⚠  FR04 rule patch skipped: {_patch_err}")

    admin    = is_admin()
    port     = int(os.environ.get("PORT", 5000))
    groq_key = os.environ.get("GROQ_API_KEY", "")

    print("")
    print("=" * 65)
    print("  🔐  Secure Eye Trust+ — Log Vault")
    print("=" * 65)
    print(f"  pywin32  : {'✅ available' if WIN32_AVAILABLE else '❌ missing  →  pip install pywin32'}")
    print(f"  Admin    : {'✅ YES — full log access' if admin else '⚠  NO  — Security logs unavailable (restart as Administrator)'}")
    print(f"  AI Chat  : {'✅ Groq ready (' + groq_key[:8] + '...)' if groq_key else '❌ No key — add GROQ_API_KEY to .env'}")
    print(f"  URL      : http://localhost:{port}")
    if not admin:
        print("")
        print("  ⚠  TIP: Right-click app.py → 'Run as administrator'")
        print("          to enable Security, Firewall & Login monitoring.")
    print("=" * 65)
    print("")

    if WIN32_AVAILABLE:
        try:
            from core.event_collector.rt_pipeline import get_rt_pipeline
            get_rt_pipeline().start()
            print("  ✅ Real-Time Pipeline started (Application + System + Defender + Firewall)")
        except Exception as _rte:
            print(f"  ⚠  RT Pipeline error: {_rte} — falling back to legacy monitor")
            start_live_monitor()

        start_winlogin_watcher()
        ss = screenshot_engine()
        print(f"  ✅ Login watcher started (EID 4625 every 5s, screenshot: {ss or 'none — pip install mss Pillow'})")

        try:
            get_task_monitor().start()
            print("  ✅ Task Scheduler Monitor started")
        except Exception as _te:
            print(f"  ⚠  Task Scheduler Monitor: {_te}")

        try:
            get_service_monitor().start()
            print("  ✅ Service Monitor started")
        except Exception as _se:
            print(f"  ⚠  Service Monitor: {_se}")

        try:
            from core.event_collector.usb_monitor import start_usb_monitor
            start_usb_monitor()
            print("  ✅ USB / external drive monitor started")
        except Exception as _ue:
            print(f"  ⚠  USB Monitor: {_ue}")

        if not admin:
            print("")
            print("  ℹ  Running without Administrator — Security/Firewall/Task logs")
            print("     are unavailable. Restart as Administrator to enable them.")
            print("     Application and System logs are fully operational.")

    else:
        print("  ⚠  pywin32 not available — live monitoring disabled")
        print("     Install with: pip install pywin32")

    print("")

    # ── FR10-04: Send startup Action Center notification ──────────────────────
    try:
        from api.windows_integration_api import _send_action_center_toast
        _send_action_center_toast(
            title="Secure Eye Trust+ Started",
            message="Security monitoring is now active and running.",
            severity="info",
            duration="short",
        )
        print("✅ FR10-04: Startup notification sent to Windows Action Center")
    except Exception as _n_err:
        print(f"⚠  FR10-04: Action Center notify skipped: {_n_err}")

    from api.perform_analysis_api import _start_scheduler
    _start_scheduler()

    application = create_app()
    application.run(host="0.0.0.0", debug=False, port=port, threaded=True)
