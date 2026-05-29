"""
api/locker_api.py  —  App & Folder Locker
"""
import os, sys, traceback
from flask import Blueprint, request, jsonify

locker_bp = Blueprint("locker", __name__)

def _norm(path: str) -> str:
    """Fix Windows paths — ensure backslashes are correct."""
    if not path:
        return path
    return path.strip().replace('/', '\\') if len(path) >= 2 and path[1] == ':' else path.strip()


# ── lazy import helpers so startup errors are caught cleanly ──────────────────
def _db():
    from database.locker_db import (
        add_locked_app, get_locked_apps, remove_locked_app,
        verify_app_password, toggle_app_lock,
        add_locked_folder, get_locked_folders, remove_locked_folder,
        verify_folder_password, update_folder_lock_state, get_folder_by_path,
        log_lock_attempt, save_lock_capture, get_lock_captures,
        dismiss_lock_capture, delete_lock_capture, get_locker_stats,
    )
    import database.locker_db as m
    return m

# ── Stats ─────────────────────────────────────────────────────────────────────
@locker_bp.route("/stats")
def stats():
    try:
        return jsonify(_db().get_locker_stats())
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

# ══ APPS ══════════════════════════════════════════════════════════════════════

@locker_bp.route("/apps")
def list_apps():
    try:
        return jsonify({"apps": _db().get_locked_apps()})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/apps/add", methods=["POST"])
def add_app():
    try:
        d        = request.get_json(silent=True) or {}
        name     = (d.get("name") or "").strip()
        exe_path = (d.get("exe_path") or "").strip()
        password = (d.get("password") or "").strip()
        if not name or not exe_path or not password:
            return jsonify({"ok": False, "error": "Name, exe path and password are required"}), 400
        if len(password) < 4:
            return jsonify({"ok": False, "error": "Password must be at least 4 characters"}), 400
        return jsonify(_db().add_locked_app(name, exe_path, password))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/apps/remove", methods=["POST"])
def remove_app():
    try:
        d      = request.get_json(silent=True) or {}
        result = _db().remove_locked_app(int(d.get("id", 0)), (d.get("password") or "").strip())
        return jsonify(result) if result.get("ok") else (jsonify(result), 401)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/apps/toggle", methods=["POST"])
def toggle_app():
    try:
        d = request.get_json(silent=True) or {}
        _db().toggle_app_lock(int(d.get("id", 0)), bool(d.get("enabled", True)))
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/apps/unlock", methods=["POST"])
def unlock_app():
    try:
        d          = request.get_json(silent=True) or {}
        app_id     = int(d.get("id", 0))
        password   = (d.get("password") or "").strip()
        app_name   = (d.get("name") or "App").strip()
        exe_path   = (d.get("exe_path") or "").strip()
        db         = _db()
        success    = db.verify_app_password(app_id, password)
        attempt_no = db.log_lock_attempt("app", app_id, app_name, success)
        if success:
            launched = False
            err = ""
            try:
                if sys.platform == "win32":
                    os.startfile(exe_path)
                    launched = True
            except Exception as ex:
                err = str(ex)
            return jsonify({"ok": True, "launched": launched, "error": err})
        return jsonify({
            "ok": False,
            "attempt_no": attempt_no,
            "capture_needed": attempt_no >= 2,
            "message": "Wrong password."
        }), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

# ══ FOLDERS ═══════════════════════════════════════════════════════════════════

@locker_bp.route("/folders")
def list_folders():
    try:
        return jsonify({"folders": _db().get_locked_folders()})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/add", methods=["POST"])
def add_folder():
    try:
        d           = request.get_json(silent=True) or {}
        name        = (d.get("name") or "").strip()
        folder_path = _norm((d.get("folder_path") or "").strip())
        password    = (d.get("password") or "").strip()
        if not name or not folder_path or not password:
            return jsonify({"ok": False, "error": "Name, folder path and password are required"}), 400
        if len(password) < 4:
            return jsonify({"ok": False, "error": "Password must be at least 4 characters"}), 400

        db   = _db()
        port = int(os.environ.get("PORT", 5000))

        # Register or get existing
        result    = db.add_locked_folder(name, folder_path, password)
        existing  = db.get_folder_by_path(folder_path)
        if not existing:
            return jsonify({"ok": False, "error": result.get("error", "Failed to register")})
        folder_id = existing["id"]

        # Apply Windows filesystem lock
        lock_msg = ""
        locked = False
        if sys.platform == "win32":
            try:
                from core.folder_lock.lock_engine import lock_folder
                lr = lock_folder(folder_path, app_port=port)
                if lr.get("ok"):
                    locked = True
                    db.update_folder_lock_state(
                        folder_id, is_locked=True,
                        acl_backup=lr.get("acl_backup", ""),
                        shortcut_path=lr.get("shortcut_path", ""),
                        hidden_path=lr.get("hidden_path", ""),
                        lock_token=lr.get("token", ""),
                    )
                    lock_msg = lr.get("message", "")
                else:
                    lock_msg = lr.get("error", "Failed to lock folder")
                    db.update_folder_lock_state(folder_id, is_locked=False)
            except Exception as e:
                traceback.print_exc()
                db.update_folder_lock_state(folder_id, is_locked=False)
                lock_msg = str(e)
        else:
            locked = True
            db.update_folder_lock_state(folder_id, is_locked=True)

        return jsonify({"ok": locked, "id": folder_id, "locked": locked, "message": lock_msg})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/remove", methods=["POST"])
def remove_folder():
    try:
        d         = request.get_json(silent=True) or {}
        folder_id = int(d.get("id", 0))
        password  = (d.get("password") or "").strip()
        db        = _db()

        # 1. Get folder info BEFORE touching DB
        folders = db.get_locked_folders()
        folder  = next((f for f in folders if f["id"] == folder_id), None)
        if not folder:
            return jsonify({"ok": False, "error": "Folder not found"}), 404

        # 2. Verify password
        if not db.verify_folder_password(folder_id, password):
            return jsonify({"ok": False, "error": "Wrong password"}), 401

        # 3. Restore folder on filesystem FIRST (before removing from DB)
        fp = _norm(folder.get("folder_path", ""))
        if fp and sys.platform == "win32":
            try:
                from core.folder_lock.lock_engine import unlock_folder, _cleanup_old_files
                from pathlib import Path
                unlock_result = unlock_folder(fp)
                print(f"[remove] unlock result: {unlock_result}")
                _cleanup_old_files(Path(fp).parent, Path(fp).name)
            except Exception as ex:
                traceback.print_exc()
                # Still proceed with DB removal even if filesystem restore fails

        # 4. Remove from DB
        db.remove_locked_folder(folder_id, password)
        return jsonify({"ok": True, "message": "Lock removed. Folder restored to original location."})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/unlock", methods=["POST"])
def unlock_folder_route():
    try:
        d           = request.get_json(silent=True) or {}
        folder_id   = int(d.get("id", 0))
        password    = (d.get("password") or "").strip()
        folder_name = (d.get("name") or "Folder").strip()
        folder_path = _norm((d.get("folder_path") or "").strip())
        db          = _db()
        success     = db.verify_folder_password(folder_id, password)
        attempt_no  = db.log_lock_attempt("folder", folder_id, folder_name, success)
        if success:
            if sys.platform == "win32":
                try:
                    from core.folder_lock.lock_engine import unlock_folder, open_folder_in_explorer
                    # Get hidden_path from DB for reliability
                    row = db.get_locked_folders()
                    hidden = next((f.get("hidden_path","") for f in row if f["id"]==folder_id), "")
                    result = unlock_folder(folder_path, hidden_path=hidden or None)
                    if result.get("ok"):
                        open_folder_in_explorer(folder_path)
                    else:
                        print(f"[unlock] {result.get('error')}")
                except Exception as ex:
                    traceback.print_exc()
            db.update_folder_lock_state(folder_id, is_locked=False)
            return jsonify({"ok": True, "path": folder_path})
        return jsonify({
            "ok": False,
            "attempt_no": attempt_no,
            "capture_needed": attempt_no >= 2,
            "message": "Wrong password."
        }), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/lock", methods=["POST"])
def relock_folder():
    try:
        d           = request.get_json(silent=True) or {}
        folder_id   = int(d.get("id", 0))
        folder_path = _norm((d.get("folder_path") or "").strip())
        password    = (d.get("password") or "").strip()
        db          = _db()
        if not db.verify_folder_password(folder_id, password):
            return jsonify({"ok": False, "error": "Wrong password"}), 401
        if sys.platform == "win32":
            from core.folder_lock.lock_engine import lock_folder
            port   = int(os.environ.get("PORT", 5000))
            result = lock_folder(folder_path, app_port=port)
            if result.get("ok"):
                db.update_folder_lock_state(
                    folder_id, is_locked=True,
                    acl_backup=result.get("acl_backup", ""),
                    shortcut_path=result.get("shortcut_path", ""),
                )
            return jsonify(result)
        return jsonify({"ok": False, "error": "Windows only"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/unlock-by-path", methods=["POST"])
def unlock_by_path():
    """Called by the VBScript shortcut when user double-clicks the folder."""
    try:
        d           = request.get_json(silent=True) or {}
        folder_path = _norm((d.get("folder_path") or "").strip())
        password    = (d.get("password") or "").strip()
        db          = _db()
        folder      = db.get_folder_by_path(folder_path)
        if not folder:
            return jsonify({"ok": False, "error": "Folder not registered"}), 404
        folder_id   = folder["id"]
        folder_name = folder["name"]
        success     = db.verify_folder_password(folder_id, password)
        attempt_no  = db.log_lock_attempt("folder", folder_id, folder_name, success)
        if success:
            if sys.platform == "win32":
                try:
                    from core.folder_lock.lock_engine import unlock_folder, open_folder_in_explorer
                    hidden = folder.get("hidden_path", "") or None
                    result = unlock_folder(folder_path, hidden_path=hidden)
                    if result.get("ok"):
                        open_folder_in_explorer(folder_path)
                    else:
                        print(f"[unlock-by-path] {result.get('error')}")
                except Exception as ex:
                    traceback.print_exc()
            db.update_folder_lock_state(folder_id, is_locked=False)
            return jsonify({"ok": True})
        return jsonify({
            "ok": False,
            "attempt_no": attempt_no,
            "capture_needed": attempt_no >= 2,
            "message": "Wrong password."
        }), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/folders/lock-no-pw", methods=["POST"])
def relock_folder_no_pw():
    """Re-lock a folder that was already unlocked — no password needed."""
    try:
        d           = request.get_json(silent=True) or {}
        folder_id   = int(d.get("id", 0))
        folder_path = _norm((d.get("folder_path") or "").strip())
        db          = _db()
        port        = int(os.environ.get("PORT", 5000))
        if sys.platform == "win32":
            from core.folder_lock.lock_engine import lock_folder
            result = lock_folder(folder_path, app_port=port)
            if result.get("ok"):
                db.update_folder_lock_state(
                    folder_id, is_locked=True,
                    acl_backup=result.get("acl_backup", ""),
                    shortcut_path=result.get("shortcut_path", ""),
                    hidden_path=result.get("hidden_path", ""),
                    lock_token=result.get("token", ""),
                )
                return jsonify({"ok": True, "message": result.get("message", "Locked")})
            return jsonify({"ok": False, "error": result.get("error", "Lock failed — run as Administrator")})
        db.update_folder_lock_state(folder_id, is_locked=True)
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@locker_bp.route("/folders/open", methods=["POST"])
def open_folder_route():
    """Open an already-unlocked folder in Windows Explorer."""
    try:
        d           = request.get_json(silent=True) or {}
        folder_path = _norm((d.get("folder_path") or "").strip())
        if sys.platform == "win32":
            from core.folder_lock.lock_engine import open_folder_in_explorer
            open_folder_in_explorer(folder_path)
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500




@locker_bp.route("/folders/restore-all", methods=["POST"])
def restore_all_folders():
    """Restore all stuck hidden folders back to their original locations."""
    try:
        if sys.platform != "win32":
            return jsonify({"ok": True, "restored": 0, "message": "Windows only"})
        from core.folder_lock.lock_engine import unlock_folder, _cleanup_old_files
        from pathlib import Path
        db      = _db()
        folders = db.get_locked_folders()
        restored = 0
        for f in folders:
            fp  = _norm(f.get("folder_path", ""))
            fid = f["id"]
            if not fp:
                continue
            p = Path(fp)
            result = unlock_folder(fp)
            if result.get("ok"):
                db.update_folder_lock_state(fid, is_locked=False)
                restored += 1
            _cleanup_old_files(p.parent, p.name)
        return jsonify({"ok": True, "restored": restored,
                        "message": f"Restored {restored} folder(s) to their original locations."})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


@locker_bp.route("/folders/cleanup-desktop", methods=["POST"])
def cleanup_desktop():
    """Remove leftover .vbs/.lnk/.bat files from all locked folder locations."""
    try:
        if sys.platform != "win32":
            return jsonify({"ok": True, "cleaned": 0})
        from core.folder_lock.lock_engine import _cleanup_old_files
        from pathlib import Path
        db      = _db()
        folders = db.get_locked_folders()
        for f in folders:
            fp = f.get("folder_path", "")
            if fp:
                p = Path(_norm(fp))
                _cleanup_old_files(p.parent, p.name)
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

# ══ CAPTURES ══════════════════════════════════════════════════════════════════

@locker_bp.route("/intruder-photo", methods=["POST"])
def locker_photo():
    try:
        d           = request.get_json(silent=True) or {}
        target_type = d.get("target_type", "app")
        target_name = d.get("target_name", "Unknown")
        target_path = d.get("target_path", "")
        photo_b64   = d.get("photo", "")
        attempt_no  = int(d.get("attempt_no", 3))
        if photo_b64.startswith("data:"):
            photo_b64 = photo_b64.split(",", 1)[-1]
        _db().save_lock_capture(target_type, target_name, target_path, photo_b64, attempt_no)
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/captures")
def captures():
    try:
        return jsonify({"captures": _db().get_lock_captures(100)})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/captures/dismiss/<int:cid>", methods=["POST"])
def dismiss_cap(cid):
    try:
        _db().dismiss_lock_capture(cid)
        return jsonify({"ok": True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@locker_bp.route("/captures/delete/<int:cid>", methods=["POST"])
def delete_cap(cid):
    try:
        d      = request.get_json(silent=True) or {}
        result = _db().delete_lock_capture(cid, (d.get("password") or "").strip())
        return jsonify(result) if result.get("ok") else (jsonify(result), 401)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500
