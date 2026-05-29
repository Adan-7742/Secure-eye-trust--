"""
api/windows_integration_api.py
================================
FR10-03  Windows Update status and patch levels
FR10-04  Windows Action Center integration
FR10-05  Windows Start Menu shortcut management

PLACE THIS FILE AT:
    <your_project>/api/windows_integration_api.py

REQUIRED PIP PACKAGES (install on Windows host):
    pip install pywin32      # Windows Update COM + shortcut creation
    pip install winotify     # Action Center toasts  (preferred)
    # OR: pip install win10toast
    # OR: pip install plyer

ENDPOINTS:
    GET  /api/windows/update-status      FR10-03 patch level + installed/pending updates
    GET  /api/windows/notify             FR10-04 send Action Center toast (query params)
    POST /api/windows/notify             FR10-04 send Action Center toast (JSON body)
    GET  /api/windows/shortcut-status    FR10-05 check if Start Menu shortcut exists
    POST /api/windows/create-shortcut    FR10-05 create Start Menu shortcut
    DELETE /api/windows/remove-shortcut  FR10-05 remove Start Menu shortcut
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, jsonify, request

windows_integration_bp = Blueprint("windows_integration", __name__)

# ── App identity ──────────────────────────────────────────────────────────────
_APP_NAME  = "Secure Eye Trust+"
_ICON_PATH = str(Path(__file__).resolve().parent.parent / "static" / "assets" / "icon.ico")


# ── Platform helpers ──────────────────────────────────────────────────────────

def _is_windows() -> bool:
    return os.name == "nt"


def _win32_available() -> bool:
    try:
        import win32com.client  # noqa: F401
        return True
    except ImportError:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# FR10-03 — Windows Update status + patch levels
# ══════════════════════════════════════════════════════════════════════════════

def _extract_kb(title: str) -> str:
    import re
    m = re.search(r"KB\d+", title, re.IGNORECASE)
    return m.group(0).upper() if m else ""


def _extract_categories(item) -> list:
    cats = []
    try:
        for i in range(item.Categories.Count):
            cats.append(item.Categories.Item(i).Name)
    except Exception:
        pass
    return cats


def _query_windows_update() -> dict:
    """
    Use the WUA COM API (Microsoft.Update.Session) to enumerate
    installed and pending updates.
    """
    import win32com.client

    result = {
        "ok": True,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "patch_level": "Unknown",
        "os_version": "",
        "installed": [],
        "pending": [],
        "installed_count": 0,
        "pending_count": 0,
        "reboot_required": False,
        "last_install_date": None,
        "error": None,
    }

    # OS version
    try:
        import platform
        result["os_version"] = platform.version()
    except Exception:
        pass

    # Check reboot-pending registry key
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        )
        winreg.CloseKey(key)
        result["reboot_required"] = True
    except FileNotFoundError:
        result["reboot_required"] = False
    except Exception:
        pass

    # Installed update history (last 50)
    try:
        session  = win32com.client.Dispatch("Microsoft.Update.Session")
        searcher = session.CreateUpdateSearcher()
        total    = searcher.GetTotalHistoryCount()
        history  = searcher.QueryHistory(0, min(total, 50))

        installed = []
        last_install_dt = None

        for i in range(history.Count):
            item = history.Item(i)
            if item.ResultCode != 2:   # 2 = Succeeded
                continue
            install_date_str = None
            try:
                d = item.Date
                install_date_str = d.strftime("%Y-%m-%d %H:%M:%S")
                if last_install_dt is None or d > last_install_dt:
                    last_install_dt = d
            except Exception:
                pass

            installed.append({
                "title":      item.Title or "Unknown",
                "kb":         _extract_kb(item.Title or ""),
                "date":       install_date_str,
                "categories": _extract_categories(item),
            })

        result["installed"]       = installed
        result["installed_count"] = len(installed)
        if last_install_dt:
            try:
                result["last_install_date"] = last_install_dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    except Exception as e:
        result["error"] = f"History query failed: {e}"

    # Pending / available updates
    try:
        session  = win32com.client.Dispatch("Microsoft.Update.Session")
        searcher = session.CreateUpdateSearcher()
        search_result = searcher.Search("IsInstalled=0 and IsHidden=0")
        pending = []
        for i in range(search_result.Updates.Count):
            u = search_result.Updates.Item(i)
            pending.append({
                "title":        u.Title or "Unknown",
                "kb":           _extract_kb(u.Title or ""),
                "severity":     getattr(u, "MsrcSeverity", None) or "Unknown",
                "is_mandatory": bool(getattr(u, "IsMandatory", False)),
                "categories":   _extract_categories(u),
            })
        result["pending"]       = pending
        result["pending_count"] = len(pending)
    except Exception as e:
        if not result.get("error"):
            result["error"] = f"Pending search failed: {e}"

    # Derive patch-level label
    if result["pending_count"] == 0 and not result["reboot_required"]:
        result["patch_level"] = "Fully Patched"
    elif result["reboot_required"]:
        result["patch_level"] = "Reboot Required"
    elif result["pending_count"] > 0:
        result["patch_level"] = f"{result['pending_count']} Update(s) Pending"
    else:
        result["patch_level"] = "Unknown"

    return result


@windows_integration_bp.route("/windows/update-status")
def update_status():
    """
    GET /api/windows/update-status
    FR10-03: Returns Windows patch level, installed updates (with KB numbers +
    install dates), pending updates (with severity), OS version, and reboot status.
    """
    if not _is_windows():
        return jsonify({
            "ok": False, "error": "Not running on Windows",
            "patch_level": "N/A", "installed": [], "pending": [],
            "installed_count": 0, "pending_count": 0,
        })

    if not _win32_available():
        return jsonify({
            "ok": False,
            "error": "pywin32 not installed. Run: pip install pywin32",
            "patch_level": "Unavailable", "installed": [], "pending": [],
            "installed_count": 0, "pending_count": 0,
        })

    try:
        data = _query_windows_update()
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# FR10-04 — Windows Action Center integration
# ══════════════════════════════════════════════════════════════════════════════

def _send_action_center_toast(
    title: str,
    message: str,
    severity: str = "info",    # info | warning | critical
    duration: str = "short",   # short | long
) -> dict:
    """
    Send a native Windows Action Center notification.
    Priority: winotify → win10toast → plyer
    """
    if not _is_windows():
        return {"ok": False, "error": "Not running on Windows"}

    icon = _ICON_PATH if Path(_ICON_PATH).exists() else ""

    # ── winotify (best — supports app ID, Action Center history) ─────────────
    try:
        from winotify import Notification, audio
        toast = Notification(
            app_id=_APP_NAME,
            title=title,
            msg=message,
            duration=duration,
            icon=icon,
        )
        audio_map = {
            "critical": audio.LoopingAlarm,
            "warning":  audio.Default,
            "info":     audio.Mail,
        }
        toast.set_audio(audio_map.get(severity, audio.Default), loop=False)
        toast.show()
        return {"ok": True, "method": "winotify"}
    except ImportError:
        pass
    except Exception:
        pass

    # ── win10toast (fallback) ─────────────────────────────────────────────────
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(
            title, message,
            icon_path=icon or None,
            duration=5 if duration == "short" else 10,
            threaded=True,
        )
        return {"ok": True, "method": "win10toast"}
    except ImportError:
        pass
    except Exception:
        pass

    # ── plyer (fallback) ─────────────────────────────────────────────────────
    try:
        from plyer import notification as plyer_notif
        plyer_notif.notify(
            title=title, message=message, app_name=_APP_NAME,
            timeout=5 if duration == "short" else 10,
        )
        return {"ok": True, "method": "plyer"}
    except ImportError:
        pass
    except Exception as e:
        return {"ok": False, "error": str(e)}

    return {
        "ok": False,
        "error": (
            "No notification library found. "
            "Install one: pip install winotify  OR  pip install win10toast  OR  pip install plyer"
        ),
    }


@windows_integration_bp.route("/windows/notify", methods=["GET", "POST"])
def action_center_notify():
    """
    GET  /api/windows/notify?title=...&message=...&severity=info|warning|critical
    POST /api/windows/notify  body: {title, message, severity, duration}

    FR10-04: Sends a toast notification to the Windows Action Center.
    """
    if request.method == "POST":
        body     = request.get_json(silent=True) or {}
        title    = body.get("title",    _APP_NAME)
        message  = body.get("message",  "Security monitoring active.")
        severity = body.get("severity", "info")
        duration = body.get("duration", "short")
    else:
        title    = request.args.get("title",    _APP_NAME)
        message  = request.args.get("message",  "Security monitoring active.")
        severity = request.args.get("severity", "info")
        duration = request.args.get("duration", "short")

    result = _send_action_center_toast(title, message, severity, duration)
    return jsonify(result)


def notify_critical_alert(alert: dict) -> None:
    """
    Call this from the live-alerts pipeline to push CRITICAL alerts
    to the Windows Action Center in a background thread.
    Usage in api/system_api.py live_alerts() after alert list is built:
        from api.windows_integration_api import notify_critical_alert
        for a in alerts:
            if a.get("type") == "critical":
                notify_critical_alert(a)
    """
    def _send():
        _send_action_center_toast(
            title=f"🚨 {alert.get('title', 'Critical Alert')}",
            message=alert.get("detail", "A critical security event was detected."),
            severity="critical",
            duration="long",
        )
    threading.Thread(target=_send, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# FR10-05 — Windows Start Menu integration
# ══════════════════════════════════════════════════════════════════════════════

def _start_menu_path() -> Path:
    import winreg
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    )
    programs_dir, _ = winreg.QueryValueEx(key, "Programs")
    winreg.CloseKey(key)
    return Path(programs_dir)


def _shortcut_path() -> Path:
    return _start_menu_path() / _APP_NAME / f"{_APP_NAME}.lnk"


def _create_start_menu_shortcut() -> dict:
    if not _is_windows():
        return {"ok": False, "error": "Not on Windows"}
    if not _win32_available():
        return {"ok": False, "error": "pywin32 required: pip install pywin32"}

    try:
        import win32com.client

        lnk_path = _shortcut_path()
        lnk_path.parent.mkdir(parents=True, exist_ok=True)

        shell    = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(lnk_path))

        app_dir     = Path(__file__).resolve().parent.parent
        python_exe  = Path(sys.executable)
        pythonw_exe = python_exe.parent / "pythonw.exe"
        target      = str(pythonw_exe) if pythonw_exe.exists() else str(python_exe)
        app_main    = app_dir / "app.py"

        shortcut.Targetpath       = target
        shortcut.Arguments        = f'"{app_main}"'
        shortcut.WorkingDirectory = str(app_dir)
        shortcut.Description      = f"{_APP_NAME} — Windows Security Monitor"
        shortcut.WindowStyle      = 1  # Normal window

        icon_ico = app_dir / "static" / "assets" / "icon.ico"
        if icon_ico.exists():
            shortcut.IconLocation = str(icon_ico)

        shortcut.save()

        return {"ok": True, "path": str(lnk_path), "target": target, "app_dir": str(app_dir)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _remove_start_menu_shortcut() -> dict:
    if not _is_windows():
        return {"ok": False, "error": "Not on Windows"}
    try:
        lnk = _shortcut_path()
        if lnk.exists():
            lnk.unlink()
            try:
                lnk.parent.rmdir()
            except OSError:
                pass
            return {"ok": True, "removed": str(lnk)}
        return {"ok": True, "removed": None, "note": "Shortcut did not exist"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@windows_integration_bp.route("/windows/shortcut-status")
def shortcut_status():
    """GET /api/windows/shortcut-status — FR10-05 check if Start Menu shortcut exists."""
    if not _is_windows():
        return jsonify({"ok": False, "exists": False, "error": "Not on Windows"})
    try:
        lnk = _shortcut_path()
        return jsonify({"ok": True, "exists": lnk.exists(),
                        "path": str(lnk) if lnk.exists() else None})
    except Exception as e:
        return jsonify({"ok": False, "exists": False, "error": str(e)})


@windows_integration_bp.route("/windows/create-shortcut", methods=["POST"])
def create_shortcut():
    """POST /api/windows/create-shortcut — FR10-05 create Start Menu shortcut."""
    result = _create_start_menu_shortcut()
    return jsonify(result), (200 if result["ok"] else 500)


@windows_integration_bp.route("/windows/remove-shortcut", methods=["DELETE"])
def remove_shortcut():
    """DELETE /api/windows/remove-shortcut — FR10-05 remove Start Menu shortcut."""
    result = _remove_start_menu_shortcut()
    return jsonify(result)
