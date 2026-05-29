"""
core/event_collector/usb_monitor.py
====================================
USB / external-drive monitor.

Polls the set of mounted drive letters every few seconds. When a new
drive appears (a USB stick is plugged in, a removable drive is mounted,
etc.) the monitor enumerates suspicious-extension files on the drive's
root + the first level of folders, runs them through the same YARA
scanner the resident FileScanner uses, and pushes a single summary alert
to the alert bus.

Also exposes a manual entry point — `scan_external_drive(path)` —
that the UI / API can call to force a re-scan on demand.

PLATFORM:
    Designed for Windows (uses drive letters A:\\..Z:\\). On other
    platforms it degrades to scanning mount points under /media,
    /mnt, /run/media so dev / test work too.

SAFETY:
    Read-only. The monitor never writes to the external drive and never
    moves or deletes files. The Active Response action buttons in the
    report UI are the *only* mutating code paths.
"""

from __future__ import annotations

import os
import platform
import string
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger("event_collector.usb_monitor")

# Extensions we'll deep-scan from a freshly attached drive.
# Same set as the resident scanner but kept independent so it can evolve.
_SCAN_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".pif",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe",
    ".js",  ".jse",  ".wsh", ".wsf", ".hta",
    ".lnk",
}

# Cap the per-drive scan to keep the UI snappy. Anything beyond this is
# left to the resident scanner when the user copies files to Downloads.
_MAX_FILES_PER_SCAN  = 500
_MAX_DEPTH           = 3
_POLL_INTERVAL_SEC   = 3
_RESCAN_COOLDOWN_SEC = 60     # don't rescan the same drive within this window


# ── Drive enumeration ─────────────────────────────────────────────────────

def _list_drives_windows() -> list[Path]:
    """Return drive letters that currently exist (A:\\ .. Z:\\)."""
    drives = []
    if hasattr(os, "listdrives"):   # Python 3.12+
        try:
            return [Path(d) for d in os.listdrives() if Path(d).exists()]
        except Exception:
            pass
    for letter in string.ascii_uppercase:
        root = Path(f"{letter}:\\")
        try:
            if root.exists():
                drives.append(root)
        except (OSError, PermissionError):
            continue
    return drives


def _list_mounts_posix() -> list[Path]:
    """Return mount points typical for removable media on Linux/macOS."""
    candidates = []
    for base in ("/media", "/run/media", "/mnt", "/Volumes"):
        p = Path(base)
        if not p.exists():
            continue
        try:
            for entry in p.iterdir():
                if entry.is_dir():
                    candidates.append(entry)
                    if entry.is_dir():  # also one level deeper, e.g. /media/user/STICK
                        for sub in entry.iterdir():
                            if sub.is_dir():
                                candidates.append(sub)
        except (PermissionError, OSError):
            continue
    return candidates


def list_external_drives() -> list[Path]:
    """Cross-platform drive enumeration."""
    if platform.system().lower() == "windows":
        all_drives = _list_drives_windows()
        # Filter to removable / external — best-effort. On Windows the system
        # drive is typically C:\\ so we exclude that. If the user has a single
        # data drive D:\\ we'll still include it; the worst case is one extra
        # scan, not a false positive.
        return [d for d in all_drives if str(d).upper() not in ("C:\\",)]
    return _list_mounts_posix()


# ── Per-drive scanner ─────────────────────────────────────────────────────

def _scan_drive_files(root: Path, max_files: int = _MAX_FILES_PER_SCAN) -> dict:
    """
    Walk `root` up to _MAX_DEPTH levels, YARA-scan every file whose
    extension is in _SCAN_EXTENSIONS. Returns a summary dict.
    """
    from core.event_collector.file_scanner import (
        _yara_scan, _sha256, _entropy, _record_scan, _push_yara_alert,
        _load_yara,
    )
    _load_yara()  # ensure rules are compiled

    summary = {
        "drive":         str(root),
        "started_at":    datetime.now().isoformat(timespec="seconds"),
        "files_scanned": 0,
        "yara_hits":     [],
        "errors":        0,
    }

    def _walk(d: Path, depth: int):
        if depth > _MAX_DEPTH:
            return
        if summary["files_scanned"] >= max_files:
            return
        try:
            entries = list(d.iterdir())
        except (PermissionError, OSError):
            return
        # files first — finish quick wins before recursing
        files = [e for e in entries if e.is_file()]
        dirs  = [e for e in entries if e.is_dir() and not e.is_symlink()]
        for f in files:
            if summary["files_scanned"] >= max_files:
                return
            if f.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            try:
                sha = _sha256(f)
                ent = _entropy(f)
                matched, rule, severity = _yara_scan(f)
                _record_scan(f, sha, ent, matched, rule, severity)
                summary["files_scanned"] += 1
                if matched:
                    summary["yara_hits"].append({
                        "path":     str(f),
                        "name":     f.name,
                        "rule":     rule,
                        "severity": severity,
                        "sha256":   sha,
                        "entropy":  ent,
                    })
                    _push_yara_alert(f, sha, rule, severity)
            except Exception as e:
                log.debug(f"usb_monitor scan error {f}: {e}")
                summary["errors"] += 1
        for sub in dirs:
            _walk(sub, depth + 1)

    _walk(root, 0)
    summary["finished_at"] = datetime.now().isoformat(timespec="seconds")
    return summary


def _push_drive_attached_alert(drive: Path, summary: dict):
    """Push a single summary alert to the bus — one per drive attach."""
    try:
        from core.pipeline.alert_bus import get_alert_bus
        hits     = summary.get("yara_hits", []) or []
        scanned  = summary.get("files_scanned", 0)
        if hits:
            top_sev = "CRITICAL" if any(h.get("severity") == "CRITICAL" for h in hits) \
                 else "HIGH"     if any(h.get("severity") == "HIGH"     for h in hits) \
                 else "MEDIUM"
            title  = f"External drive scanned — {len(hits)} threat(s) found on {drive}"
            desc   = (f"USB / external drive at {drive} was scanned automatically on attach. "
                      f"{scanned} files inspected, {len(hits)} YARA match(es) — review the "
                      "Active Response panel in Perform Analysis to act.")
        else:
            top_sev = "LOW"
            title   = f"External drive scanned — clean ({scanned} files)"
            desc    = (f"USB / external drive at {drive} was scanned automatically on attach. "
                       f"{scanned} files inspected, no threats detected.")
        get_alert_bus().push({
            "type":           "external_drive_scan",
            "severity":       top_sev,
            "category":       "external_device",
            "title":          title,
            "description":    desc,
            "drive":          str(drive),
            "files_scanned":  scanned,
            "yara_hits":      len(hits),
            "hits_preview":   [
                {"name": h["name"], "rule": h["rule"], "severity": h["severity"]}
                for h in hits[:5]
            ],
            "risk_score":     85 if top_sev == "CRITICAL" else 60 if top_sev == "HIGH" else 30 if top_sev == "MEDIUM" else 5,
            "source":         "USBMonitor",
        })
    except Exception as e:
        log.debug(f"usb_monitor alert push failed: {e}")


# ── Public manual entry point ─────────────────────────────────────────────

def scan_external_drive(path: str) -> dict:
    """Manually scan a drive path. Returns the summary dict."""
    p = Path(path)
    if not p.exists() or not p.is_dir():
        return {"ok": False, "error": "path does not exist or is not a directory"}
    summary = _scan_drive_files(p)
    _push_drive_attached_alert(p, summary)
    return {"ok": True, **summary}


# ── Monitor thread ────────────────────────────────────────────────────────

class USBMonitor:
    """Background thread that watches for new external drives and scans them."""

    def __init__(self):
        self._stop      = threading.Event()
        self._thread:   Optional[threading.Thread] = None
        self._seen:     set = set()
        self._last_scan_ts: dict = {}    # drive_str → last scan epoch
        self._stats     = {"drives_seen": 0, "scans_completed": 0, "started_at": None}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="USBMonitor", daemon=True
        )
        self._thread.start()
        self._stats["started_at"] = datetime.now().isoformat()
        log.info("USBMonitor started")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def status(self) -> dict:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "seen":    list(self._seen),
            **self._stats,
        }

    def _loop(self):
        # Pre-seed `_seen` with the drives present at startup so we don't
        # treat the system drive / pre-mounted drives as fresh attaches.
        try:
            for d in list_external_drives():
                self._seen.add(str(d))
        except Exception as e:
            log.debug(f"usb_monitor pre-seed failed: {e}")

        while not self._stop.is_set():
            try:
                current = {str(d): d for d in list_external_drives()}
                now     = time.time()

                # New drives
                for key, drive in current.items():
                    if key in self._seen:
                        continue
                    last = self._last_scan_ts.get(key, 0)
                    if now - last < _RESCAN_COOLDOWN_SEC:
                        continue
                    self._seen.add(key)
                    self._stats["drives_seen"] += 1
                    self._last_scan_ts[key]     = now
                    log.info(f"USBMonitor: new external drive detected at {drive}")
                    # Scan in a worker thread so the polling loop stays responsive
                    threading.Thread(
                        target=self._scan_and_alert,
                        args=(drive,),
                        daemon=True,
                    ).start()

                # Removed drives
                for stale in list(self._seen):
                    if stale not in current:
                        self._seen.discard(stale)
                        log.info(f"USBMonitor: drive detached: {stale}")

            except Exception as e:
                log.error(f"usb_monitor loop error: {e}")

            self._stop.wait(_POLL_INTERVAL_SEC)

    def _scan_and_alert(self, drive: Path):
        try:
            summary = _scan_drive_files(drive)
            _push_drive_attached_alert(drive, summary)
            self._stats["scans_completed"] += 1
            log.info(
                f"USBMonitor scan complete: {drive} — "
                f"{summary['files_scanned']} files, {len(summary['yara_hits'])} YARA hit(s)"
            )
        except Exception as e:
            log.error(f"usb_monitor scan error on {drive}: {e}")


# ── Module-level singleton accessor ───────────────────────────────────────

_monitor: Optional[USBMonitor] = None
_monitor_lock = threading.Lock()


def get_usb_monitor() -> USBMonitor:
    global _monitor
    with _monitor_lock:
        if _monitor is None:
            _monitor = USBMonitor()
        return _monitor


def start_usb_monitor():
    """Start the singleton USBMonitor. Safe to call multiple times."""
    get_usb_monitor().start()


def stop_usb_monitor():
    if _monitor:
        _monitor.stop()
