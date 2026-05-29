"""
api/bitlocker_api.py
=====================
FR07-02 — Windows BitLocker Storage Encryption Integration

WHAT THIS MODULE DOES:
  Satisfies FR07-02 by integrating with Windows BitLocker at three levels:

  1. STATUS QUERY   — reads BitLocker protection state for all volumes that
                      hold application data (DB path, log path, key store path)
                      using both WMI (Win32_EncryptableVolume) and PowerShell
                      Get-BitLockerVolume as a cross-version fallback.

  2. ENFORCEMENT    — startup_check() is called by app.py on boot. If the
                      volume containing logs.db is not BitLocker-protected,
                      the check logs a CRITICAL alert and (in strict mode)
                      raises BitLockerNotEnabledError so the application refuses
                      to start without storage encryption in place.

  3. MONITORING     — BitLockerMonitor runs as a background thread, polling
                      every POLL_INTERVAL seconds and writing state changes to
                      the he_audit_log table. Any volume that transitions from
                      Protected → Unprotected fires an immediate pipeline alert.

ENDPOINTS:
  GET  /api/bitlocker/status          — current protection state of all watched volumes
  GET  /api/bitlocker/status/<drive>  — state of a specific drive letter (e.g. C:)
  POST /api/bitlocker/enforce         — trigger enforcement check + alert on failure
  GET  /api/bitlocker/audit-log       — last N BitLocker state-change events from DB

BITLOCKER PROTECTION STATES (Win32_EncryptableVolume.ProtectionStatus):
  0 = Unprotected   (BitLocker off — data readable without key)
  1 = Protected     (BitLocker on  — satisfies FR07-02)
  2 = Unknown       (transitioning or error)

INTEGRATION WITH OTHER FR07 LAYERS:
  FR07-01: Application-layer AES-256-GCM (field_encryptor.py) remains active
           even when BitLocker is on. BitLocker + AES-256-GCM = true double-layer
           encryption at rest: OS storage layer + application data layer.
  FR07-04: encrypt_event_at_ingestion() still fires before every DB write.
           BitLocker adds the volume-level layer underneath.
  FR07-05: DPAPI key blobs stored in keys/master.dpapi are also BitLocker-protected
           when this module confirms the volume is encrypted.

DEPENDENCIES (Windows only):
  - wmi         : pip install wmi          (preferred — fastest WMI query)
  - pywin32     : pip install pywin32      (fallback: subprocess PowerShell)
  - Neither required on non-Windows (module degrades gracefully)

USAGE IN app.py:
    from api.bitlocker_api import bitlocker_bp, startup_check, BitLockerMonitor
    app.register_blueprint(bitlocker_bp, url_prefix="/api")
    startup_check(strict=False)        # strict=True raises on unprotected volume
    BitLockerMonitor.start()           # background polling thread
"""

from __future__ import annotations

import os
import json
import platform
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Blueprint, jsonify, request
from utils.logger import get_logger
from database.db import get_conn, DB_PATH

log = get_logger("bitlocker_api")

bitlocker_bp = Blueprint("bitlocker", __name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_ON_WINDOWS   = platform.system() == "Windows"
POLL_INTERVAL = 300   # seconds between background polls (5 minutes)

# Protection status codes from Win32_EncryptableVolume
_STATUS_LABELS = {
    0: "Unprotected",
    1: "Protected",
    2: "Unknown",
}

# Paths whose volumes must be BitLocker-protected (FR07-02)
_WATCHED_PATHS = [
    Path(DB_PATH),                                         # logs.db
    Path(__file__).resolve().parent.parent / "keys",       # keystore + master.dpapi
]

# ── Custom exception ───────────────────────────────────────────────────────────

class BitLockerNotEnabledError(RuntimeError):
    """Raised by startup_check(strict=True) when a required volume is unprotected."""


# ── Drive letter helpers ───────────────────────────────────────────────────────

def _drive_letter(path: Path) -> str:
    """Return the drive letter (e.g. 'C:') for a given path on Windows."""
    if _ON_WINDOWS:
        return str(path.resolve()).split("\\")[0].upper()   # e.g. 'C:'
    # On non-Windows, return a synthetic label based on the mount point
    return str(path.drive) or "/"


def _watched_drives() -> list[str]:
    """Return unique drive letters for all watched paths."""
    seen: list[str] = []
    for p in _WATCHED_PATHS:
        d = _drive_letter(p)
        if d not in seen:
            seen.append(d)
    return seen


# ══════════════════════════════════════════════════════════════════════════════
# FR07-02 — BitLocker status query
# Two strategies: WMI (preferred) and PowerShell (fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _query_via_wmi(drive_letter: str) -> Optional[dict]:
    """
    Query BitLocker protection status using WMI Win32_EncryptableVolume.
    Requires the `wmi` package (pip install wmi) and Windows.
    Returns a status dict or None if WMI is unavailable.
    """
    if not _ON_WINDOWS:
        return None
    try:
        import wmi  # type: ignore
        c = wmi.WMI(namespace="root\\CIMv2\\Security\\MicrosoftVolumeEncryption")
        results = c.Win32_EncryptableVolume(DriveLetter=drive_letter)
        if not results:
            return {
                "drive":            drive_letter,
                "protection_status": 0,
                "protection_label":  "Unprotected",
                "encryption_method": "None",
                "encryption_pct":    0,
                "lock_status":       "Unknown",
                "key_protectors":    [],
                "source":            "wmi",
                "ok":                True,
                "note":              "Volume not found in Win32_EncryptableVolume",
            }

        vol = results[0]
        status_code = int(vol.ProtectionStatus)

        # Key protector types (FR07-03 / FR07-05 cross-reference)
        key_protectors: list[str] = []
        try:
            for kp_id in (vol.GetKeyProtectors(0)[1] or []):
                kp_type = vol.GetKeyProtectorType(kp_id)[1]
                # KeyProtectorType codes: 0=Unknown,1=TPM,2=ExternalKey,3=NumericalPwd,
                #  4=TPM+PIN,5=TPM+Startup,6=TPM+PIN+Startup,7=PublicKey,
                #  8=PassPhrase,9=TPM+Certificate,10=CryptoAPI
                kp_labels = {
                    0: "Unknown", 1: "TPM", 2: "ExternalKey", 3: "RecoveryPassword",
                    4: "TPM+PIN", 5: "TPM+StartupKey", 6: "TPM+PIN+StartupKey",
                    7: "PublicKey", 8: "Passphrase", 9: "TPM+Certificate",
                    10: "CryptoAPI (Certificate)",
                }
                key_protectors.append(kp_labels.get(kp_type, f"Type{kp_type}"))
        except Exception:
            pass

        # Encryption percentage
        enc_pct = 0
        try:
            enc_pct = int(vol.GetEncryptionMethod()[0])
        except Exception:
            pass

        # Encryption method name
        method_map = {
            0: "None", 1: "AES-128-with-Diffuser", 2: "AES-256-with-Diffuser",
            3: "AES-128", 4: "AES-256", 5: "Hardware Encryption",
            6: "XTS-AES-128", 7: "XTS-AES-256",
        }
        try:
            method_code = int(vol.GetEncryptionMethod()[1])
            method_name = method_map.get(method_code, f"Method{method_code}")
        except Exception:
            method_name = "Unknown"

        return {
            "drive":             drive_letter,
            "protection_status": status_code,
            "protection_label":  _STATUS_LABELS.get(status_code, "Unknown"),
            "encryption_method": method_name,
            "encryption_pct":    enc_pct,
            "lock_status":       getattr(vol, "LockStatus", "Unknown"),
            "key_protectors":    key_protectors,
            "source":            "wmi",
            "ok":                True,
        }

    except ImportError:
        log.debug("wmi package not installed — falling back to PowerShell")
        return None
    except Exception as e:
        log.warning("WMI BitLocker query failed for %s: %s", drive_letter, e)
        return None


def _query_via_powershell(drive_letter: str) -> dict:
    """
    Query BitLocker status via PowerShell Get-BitLockerVolume.
    Works on Windows 8+ without the `wmi` package.
    FR07-02 fallback path.
    """
    if not _ON_WINDOWS:
        return _non_windows_stub(drive_letter)

    # Strip trailing colon for PS cmdlet if present
    mount_point = drive_letter.rstrip("\\")

    ps_cmd = (
        f"$v = Get-BitLockerVolume -MountPoint '{mount_point}' -ErrorAction SilentlyContinue; "
        "if ($v) { "
        "  $kp = ($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ','; "
        "  [PSCustomObject]@{ "
        "    ProtectionStatus=$v.ProtectionStatus; "
        "    VolumeStatus=$v.VolumeStatus; "
        "    EncryptionMethod=$v.EncryptionMethod; "
        "    EncryptionPercentage=$v.EncryptionPercentage; "
        "    LockStatus=$v.LockStatus; "
        "    KeyProtectors=$kp "
        "  } | ConvertTo-Json "
        "} else { "
        "  '{\"ProtectionStatus\":\"Off\",\"VolumeStatus\":\"FullyDecrypted\","
        "    \"EncryptionMethod\":\"None\",\"EncryptionPercentage\":0,"
        "    \"LockStatus\":\"Unlocked\",\"KeyProtectors\":\"\"}' "
        "}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {
                "drive":             drive_letter,
                "protection_status": 0,
                "protection_label":  "Unprotected",
                "encryption_method": "Unknown",
                "encryption_pct":    0,
                "lock_status":       "Unknown",
                "key_protectors":    [],
                "source":            "powershell",
                "ok":                False,
                "error":             result.stderr.strip() or "No output from Get-BitLockerVolume",
            }

        data = json.loads(result.stdout.strip())

        # Normalise ProtectionStatus — PS returns "On"/"Off" or 0/1
        raw_status = data.get("ProtectionStatus", "Off")
        if isinstance(raw_status, str):
            status_code = 1 if raw_status.lower() in ("on", "protected") else 0
        else:
            status_code = int(raw_status)

        kp_raw = data.get("KeyProtectors") or ""
        kp_list = [k.strip() for k in kp_raw.split(",") if k.strip()] if kp_raw else []

        return {
            "drive":             drive_letter,
            "protection_status": status_code,
            "protection_label":  _STATUS_LABELS.get(status_code, "Unknown"),
            "encryption_method": str(data.get("EncryptionMethod", "Unknown")),
            "encryption_pct":    int(data.get("EncryptionPercentage", 0)),
            "lock_status":       str(data.get("LockStatus", "Unknown")),
            "volume_status":     str(data.get("VolumeStatus", "Unknown")),
            "key_protectors":    kp_list,
            "source":            "powershell",
            "ok":                True,
        }

    except subprocess.TimeoutExpired:
        return _error_stub(drive_letter, "PowerShell query timed out after 30s")
    except json.JSONDecodeError as e:
        return _error_stub(drive_letter, f"JSON parse error from PS output: {e}")
    except Exception as e:
        return _error_stub(drive_letter, str(e))


def _non_windows_stub(drive_letter: str) -> dict:
    """Return a clearly-labelled stub on non-Windows platforms."""
    return {
        "drive":             drive_letter,
        "protection_status": 2,
        "protection_label":  "Unknown",
        "encryption_method": "N/A",
        "encryption_pct":    0,
        "lock_status":       "N/A",
        "key_protectors":    [],
        "source":            "stub",
        "ok":                False,
        "error":             "BitLocker is a Windows-only feature. Not running on Windows.",
    }


def _error_stub(drive_letter: str, error: str) -> dict:
    return {
        "drive":             drive_letter,
        "protection_status": 2,
        "protection_label":  "Unknown",
        "encryption_method": "Unknown",
        "encryption_pct":    0,
        "lock_status":       "Unknown",
        "key_protectors":    [],
        "source":            "error",
        "ok":                False,
        "error":             error,
    }


def get_volume_status(drive_letter: str) -> dict:
    """
    FR07-02: Get BitLocker protection status for a volume.
    Tries WMI first, falls back to PowerShell, falls back to stub.
    """
    drive_letter = drive_letter.rstrip("\\").upper()
    if not drive_letter.endswith(":"):
        drive_letter += ":"

    result = _query_via_wmi(drive_letter)
    if result is None:
        result = _query_via_powershell(drive_letter)

    result["is_protected"] = result.get("protection_status") == 1
    result["satisfies_fr07_02"] = result["is_protected"]
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    return result


def get_all_watched_volumes() -> list[dict]:
    """FR07-02: Get BitLocker status for every volume containing application data."""
    drives = _watched_drives()
    statuses = []
    for d in drives:
        s = get_volume_status(d)
        # Annotate which application paths live on this drive
        s["watched_paths"] = [
            str(p) for p in _WATCHED_PATHS
            if _drive_letter(p) == d
        ]
        statuses.append(s)
    return statuses


# ══════════════════════════════════════════════════════════════════════════════
# FR07-02 — Startup enforcement check
# ══════════════════════════════════════════════════════════════════════════════

def startup_check(strict: bool = False) -> dict:
    """
    FR07-02: Verify BitLocker protection on startup.

    Call from app.py before serving requests:
        from api.bitlocker_api import startup_check
        startup_check(strict=True)   # raises if unprotected
        startup_check(strict=False)  # logs CRITICAL but continues

    Returns a summary dict with overall compliance status.
    Raises BitLockerNotEnabledError if strict=True and any watched volume
    is unprotected.
    """
    volumes = get_all_watched_volumes()
    unprotected = [v for v in volumes if not v.get("is_protected")]
    protected   = [v for v in volumes if v.get("is_protected")]

    summary = {
        "fr07_02_satisfied": len(unprotected) == 0,
        "checked_at":        datetime.now(timezone.utc).isoformat(),
        "total_volumes":     len(volumes),
        "protected_count":   len(protected),
        "unprotected_count": len(unprotected),
        "volumes":           volumes,
    }

    if unprotected:
        drives_str = ", ".join(v["drive"] for v in unprotected)
        msg = (
            f"[FR07-02] BitLocker NOT enabled on: {drives_str}. "
            "Log data and encryption keys are stored on unprotected volumes. "
            "Enable BitLocker: Enable-BitLocker -MountPoint '<drive>' "
            "-EncryptionMethod XtsAes256 -TpmProtector"
        )
        log.critical(msg)
        _write_audit(
            operation="bitlocker_startup_check",
            notes=f"FAIL — unprotected volumes: {drives_str}",
        )
        if strict:
            raise BitLockerNotEnabledError(msg)
    else:
        log.info(
            "[FR07-02] BitLocker startup check PASSED — all %d volume(s) protected.",
            len(protected),
        )
        _write_audit(
            operation="bitlocker_startup_check",
            notes=f"PASS — {len(protected)} volume(s) protected",
        )

    return summary


# ══════════════════════════════════════════════════════════════════════════════
# FR07-02 — Background monitor thread
# ══════════════════════════════════════════════════════════════════════════════

class BitLockerMonitor:
    """
    FR07-02: Background thread that polls BitLocker status every POLL_INTERVAL
    seconds and fires alerts when a volume transitions to Unprotected.

    Usage (in app.py after registering the blueprint):
        BitLockerMonitor.start()
    """

    _thread: Optional[threading.Thread] = None
    _stop_event = threading.Event()
    _last_states: dict[str, int] = {}   # drive → last protection_status

    @classmethod
    def start(cls) -> None:
        if cls._thread and cls._thread.is_alive():
            log.debug("BitLockerMonitor already running")
            return
        cls._stop_event.clear()
        cls._thread = threading.Thread(
            target=cls._run,
            name="bitlocker-monitor",
            daemon=True,
        )
        cls._thread.start()
        log.info("[FR07-02] BitLockerMonitor started (interval=%ds)", POLL_INTERVAL)

    @classmethod
    def stop(cls) -> None:
        cls._stop_event.set()

    @classmethod
    def _run(cls) -> None:
        # Initial baseline
        for v in get_all_watched_volumes():
            cls._last_states[v["drive"]] = v.get("protection_status", 2)

        while not cls._stop_event.wait(POLL_INTERVAL):
            cls._poll()

    @classmethod
    def _poll(cls) -> None:
        try:
            volumes = get_all_watched_volumes()
            for v in volumes:
                drive       = v["drive"]
                new_status  = v.get("protection_status", 2)
                old_status  = cls._last_states.get(drive, new_status)

                if old_status != new_status:
                    cls._handle_transition(drive, old_status, new_status, v)
                    cls._last_states[drive] = new_status

                elif new_status != 1:
                    # Still unprotected — re-log periodically
                    log.warning(
                        "[FR07-02] BitLocker STILL unprotected on %s (%s)",
                        drive, v.get("protection_label"),
                    )
        except Exception as e:
            log.error("[FR07-02] BitLockerMonitor poll error: %s", e)

    @classmethod
    def _handle_transition(
        cls,
        drive: str,
        old_status: int,
        new_status: int,
        volume_info: dict,
    ) -> None:
        old_label = _STATUS_LABELS.get(old_status, "Unknown")
        new_label = _STATUS_LABELS.get(new_status, "Unknown")

        if new_status != 1:
            log.critical(
                "[FR07-02] CRITICAL: BitLocker on %s changed from %s → %s. "
                "Application data is no longer protected at the storage layer!",
                drive, old_label, new_label,
            )
            _write_audit(
                operation="bitlocker_protection_lost",
                notes=f"Drive {drive}: {old_label} → {new_label}",
            )
            _push_pipeline_alert(drive, old_label, new_label, volume_info)
        else:
            log.info(
                "[FR07-02] BitLocker on %s changed from %s → %s (now protected).",
                drive, old_label, new_label,
            )
            _write_audit(
                operation="bitlocker_protection_gained",
                notes=f"Drive {drive}: {old_label} → {new_label}",
            )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _write_audit(operation: str, notes: str = "") -> None:
    """Write a BitLocker event to he_audit_log (FR07-02 compliance trail)."""
    try:
        conn = get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO he_audit_log "
            "(operation, kid, field_name, category, performed_by, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                operation,
                "bitlocker",
                notes,
                "storage_encryption",
                "bitlocker_monitor",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.debug("Could not write BitLocker audit entry: %s", e)


def _push_pipeline_alert(
    drive: str,
    old_label: str,
    new_label: str,
    volume_info: dict,
) -> None:
    """
    Inject a CRITICAL alert into the pipeline alert bus when BitLocker
    protection is lost. Integrates with core/pipeline/alert_bus.py.
    """
    try:
        from core.pipeline.alert_bus import AlertBus
        AlertBus.push({
            "id":           f"BITLOCKER_UNPROTECTED_{drive.replace(':', '')}",
            "name":         f"BitLocker Protection Lost — {drive}",
            "severity":     "CRITICAL",
            "category":     "storage_encryption",
            "description":  (
                f"BitLocker on {drive} transitioned from {old_label} to {new_label}. "
                "Application log data and encryption keys are now stored on an "
                "unprotected volume. FR07-02 compliance broken."
            ),
            "human_summary": (
                f"The storage encryption protecting your log database on {drive} "
                "has been disabled. All logs are now readable without credentials."
            ),
            "mitigation": (
                f"Re-enable BitLocker immediately: "
                f"Enable-BitLocker -MountPoint '{drive}' "
                f"-EncryptionMethod XtsAes256 -TpmProtector. "
                f"While unprotected, all log data is accessible without Windows credentials."
            ),
            "actions": [
                f"Run: Enable-BitLocker -MountPoint '{drive}' -EncryptionMethod XtsAes256 -TpmProtector",
                "Check who disabled BitLocker: Get-WinEvent -FilterHashtable @{LogName='System'; Id=24578} | Select-Object -First 10",
                "Verify TPM state: Get-Tpm",
                "Backup recovery key: Backup-BitLockerKeyProtector",
            ],
            "volume_info":  volume_info,
            "ts":           datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        log.debug("Could not push BitLocker alert to pipeline: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# Flask endpoints
# ══════════════════════════════════════════════════════════════════════════════

@bitlocker_bp.route("/bitlocker/status")
def bitlocker_status_all():
    """
    GET /api/bitlocker/status
    FR07-02: Return BitLocker protection status for all watched volumes.
    """
    volumes  = get_all_watched_volumes()
    all_ok   = all(v.get("is_protected") for v in volumes)
    return jsonify({
        "ok":                True,
        "fr07_02_satisfied": all_ok,
        "volumes":           volumes,
        "checked_at":        datetime.now(timezone.utc).isoformat(),
        "note": (
            "All application data volumes are BitLocker-protected."
            if all_ok else
            "WARNING: One or more volumes are NOT BitLocker-protected. FR07-02 not satisfied."
        ),
    })


@bitlocker_bp.route("/bitlocker/status/<drive>")
def bitlocker_status_drive(drive: str):
    """
    GET /api/bitlocker/status/C:
    FR07-02: Return BitLocker status for a specific drive letter.
    """
    # Sanitise input — accept 'C', 'C:', 'c', 'c:' etc.
    safe_drive = drive.strip().upper().rstrip("\\")
    if not safe_drive.endswith(":"):
        safe_drive += ":"
    if len(safe_drive) != 2 or not safe_drive[0].isalpha():
        return jsonify({"ok": False, "error": "Invalid drive letter"}), 400

    result = get_volume_status(safe_drive)
    return jsonify(result)


@bitlocker_bp.route("/bitlocker/enforce", methods=["POST"])
def bitlocker_enforce():
    """
    POST /api/bitlocker/enforce
    FR07-02: Run enforcement check. Returns compliance status.
    Body (optional JSON): { "strict": true }  — if strict, returns 503 on failure.
    """
    body   = request.get_json(silent=True) or {}
    strict = bool(body.get("strict", False))

    try:
        summary = startup_check(strict=False)
        if not summary["fr07_02_satisfied"] and strict:
            return jsonify({
                "ok":    False,
                "error": "BitLocker not enabled on required volumes",
                **summary,
            }), 503
        return jsonify({"ok": True, **summary})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bitlocker_bp.route("/bitlocker/audit-log")
def bitlocker_audit_log():
    """
    GET /api/bitlocker/audit-log?limit=50
    FR07-02: Return recent BitLocker state-change audit events.
    """
    limit = min(int(request.args.get("limit", 50)), 500)
    try:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM he_audit_log "
            "WHERE kid = 'bitlocker' "
            "ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return jsonify({
            "ok":    True,
            "count": len(rows),
            "events": [dict(r) for r in rows],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
