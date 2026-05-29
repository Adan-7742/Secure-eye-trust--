"""
api/fr11_health_api.py
=======================
FR11: Windows System Health Analysis

PLACE THIS FILE AT:
    <your_project>/api/fr11_health_api.py

ENDPOINTS:
    GET /api/health/cpu          FR11-01  CPU usage + full process breakdown
    GET /api/health/memory       FR11-02  RAM consumption + page file (swap) usage
    GET /api/health/disk         FR11-03  Disk health + SMART status via WMI
    GET /api/health/optimize     FR11-04  Windows-specific optimization recommendations
    GET /api/health/bsod         FR11-05  BSOD risk prediction (crash dumps + EIDs)
    GET /api/health/drivers      FR11-06  Driver health and compatibility check

REQUIRED PACKAGES:
    pip install psutil pywin32 wmi
"""

from __future__ import annotations
import os
import re
import json
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, jsonify, request, session

fr11_bp = Blueprint("fr11_health", __name__)

# ── Auth guard ────────────────────────────────────────────────────────────────
def _auth():
    if not session.get("authenticated"):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None

def _is_windows():
    return os.name == "nt"

@contextmanager
def _wmi_com():
    """Initialize COM for WMI usage in the current thread."""
    import pythoncom
    pythoncom.CoInitializeEx(0)
    try:
        yield
    finally:
        pythoncom.CoUninitialize()

# ══════════════════════════════════════════════════════════════════════════════
# FR11-01 — CPU usage with full process breakdown
# ══════════════════════════════════════════════════════════════════════════════

@fr11_bp.route("/health/cpu")
def cpu_health():
    """
    FR11-01: Returns CPU usage (total + per-core) plus a full process
    breakdown table — pid, name, cpu%, ram%, status, user.
    """
    err = _auth()
    if err: return err

    try:
        import psutil

        # Overall CPU
        cpu_pct      = psutil.cpu_percent(interval=0.3)
        per_core     = psutil.cpu_percent(interval=None, percpu=True)
        freq         = psutil.cpu_freq()
        logical_cnt  = psutil.cpu_count(logical=True)
        physical_cnt = psutil.cpu_count(logical=False)

        # Full process list — sorted by cpu% descending
        own_pid = os.getpid()
        procs = []
        for p in psutil.process_iter(
            ["pid","name","cpu_percent","memory_percent",
             "status","username","create_time","num_threads"]
        ):
            try:
                info = p.info
                if info["pid"] == own_pid:
                    continue
                procs.append({
                    "pid":         info["pid"],
                    "name":        info["name"] or "Unknown",
                    "cpu_pct":     round(info["cpu_percent"] or 0, 1),
                    "ram_pct":     round(info["memory_percent"] or 0, 2),
                    "status":      info["status"] or "",
                    "user":        (info["username"] or "").split("\\")[-1],
                    "threads":     info["num_threads"] or 0,
                    "started":     datetime.fromtimestamp(
                                     info["create_time"]).strftime("%H:%M:%S")
                                   if info.get("create_time") else "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        procs.sort(key=lambda x: x["cpu_pct"], reverse=True)

        # CPU status
        status = ("CRITICAL" if cpu_pct > 90 else
                  "HIGH"     if cpu_pct > 75 else "NORMAL")

        # Top CPU consumer summary for quick alert
        top = procs[:5]

        return jsonify({
            "ok":            True,
            "cpu": {
                "total_percent":    round(cpu_pct, 1),
                "per_core_percent": [round(c, 1) for c in (per_core or [])],
                "logical_cores":    logical_cnt,
                "physical_cores":   physical_cnt,
                "frequency_mhz":    round(freq.current) if freq else 0,
                "max_freq_mhz":     round(freq.max)     if freq else 0,
                "status":           status,
            },
            "processes":     procs,
            "process_count": len(procs),
            "top_consumers": top,
            "generated_at":  datetime.now(timezone.utc).isoformat(),
        })

    except ImportError:
        return jsonify({"ok": False, "error": "psutil not installed: pip install psutil"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# FR11-02 — RAM consumption + page file (swap) usage
# ══════════════════════════════════════════════════════════════════════════════

@fr11_bp.route("/health/memory")
def memory_health():
    """
    FR11-02: Returns RAM (virtual memory) details AND page file (swap)
    usage — total, used, available, percent for both.
    Also lists top RAM-consuming processes.
    """
    err = _auth()
    if err: return err

    try:
        import psutil

        vm  = psutil.virtual_memory()
        sw  = psutil.swap_memory()

        # Per-process RAM breakdown
        own_pid = os.getpid()
        procs = []
        for p in psutil.process_iter(
            ["pid","name","memory_info","memory_percent","status"]
        ):
            try:
                if p.pid == own_pid:
                    continue
                mi = p.info.get("memory_info")
                procs.append({
                    "pid":      p.pid,
                    "name":     p.info.get("name") or "Unknown",
                    "rss_mb":   round((mi.rss if mi else 0) / (1024*1024), 1),
                    "vms_mb":   round((mi.vms if mi else 0) / (1024*1024), 1),
                    "ram_pct":  round(p.info.get("memory_percent") or 0, 2),
                    "status":   p.info.get("status") or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        procs.sort(key=lambda x: x["rss_mb"], reverse=True)

        # Page file (commit charge) via WMI on Windows
        pagefile_info = {"available": False, "error": None}
        if _is_windows():
            try:
                import wmi
                with _wmi_com():
                    w = wmi.WMI()
                    pf_list = []
                    for pf in w.Win32_PageFileUsage():
                        pf_list.append({
                            "name":          pf.Name,
                            "current_mb":    pf.CurrentUsage,
                            "allocated_mb":  pf.AllocatedBaseSize,
                            "peak_mb":       pf.PeakUsage,
                            "percent":       round((pf.CurrentUsage / pf.AllocatedBaseSize * 100)
                                                   if pf.AllocatedBaseSize else 0, 1),
                        })
                pagefile_info = {"available": True, "pagefiles": pf_list}
            except Exception as e:
                pagefile_info = {
                    "available": False,
                    "error": str(e),
                    # Fall back to psutil swap as approximation
                    "swap_fallback": {
                        "total_mb":   round(sw.total  / (1024*1024), 0),
                        "used_mb":    round(sw.used   / (1024*1024), 0),
                        "free_mb":    round(sw.free   / (1024*1024), 0),
                        "percent":    round(sw.percent, 1),
                    }
                }
        else:
            pagefile_info = {
                "available": True,
                "swap_fallback": {
                    "total_mb":  round(sw.total  / (1024*1024), 0),
                    "used_mb":   round(sw.used   / (1024*1024), 0),
                    "free_mb":   round(sw.free   / (1024*1024), 0),
                    "percent":   round(sw.percent, 1),
                }
            }

        ram_status = ("CRITICAL" if vm.percent > 90 else
                      "HIGH"     if vm.percent > 80 else "NORMAL")

        return jsonify({
            "ok": True,
            "ram": {
                "total_gb":     round(vm.total      / 1e9, 2),
                "used_gb":      round(vm.used       / 1e9, 2),
                "available_gb": round(vm.available  / 1e9, 2),
                "percent":      round(vm.percent, 1),
                "status":       ram_status,
            },
            "page_file":      pagefile_info,
            "top_ram_procs":  procs[:10],
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        })

    except ImportError:
        return jsonify({"ok": False, "error": "psutil not installed: pip install psutil"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# FR11-03 — Disk health + SMART status
# ══════════════════════════════════════════════════════════════════════════════

def _query_smart_wmi() -> list:
    """
    Query disk health via WMI Win32_DiskDrive.
    Returns list of disks with model, size, status, partitions.
    """
    import wmi
    disks = []
    with _wmi_com():
        w = wmi.WMI()
        for disk in w.Win32_DiskDrive():
            # DiskDrive Status: OK, Degraded, Unknown, Pred Fail, Error, etc.
            health = disk.Status or "Unknown"
            size_gb = round(int(disk.Size or 0) / 1e9, 1) if disk.Size else 0

            # Map WMI status to our severity levels
            if health in ("OK", "OK "):
                sev = "HEALTHY"
            elif health in ("Pred Fail",):
                sev = "CRITICAL"   # Predicted failure — SMART warning
            elif health in ("Degraded", "Error", "Unknown error"):
                sev = "WARNING"
            else:
                sev = "UNKNOWN"

            disks.append({
                "device_id":    disk.DeviceID or "",
                "model":        (disk.Model or "").strip(),
                "serial":       (disk.SerialNumber or "").strip(),
                "interface":    disk.InterfaceType or "",
                "media_type":   disk.MediaType or "",
                "size_gb":      size_gb,
                "partitions":   disk.Partitions or 0,
                "status":       health,
                "health":       sev,
                "sectors_bad":  None,  # populated below if SMART available
            })

    # Try to get SMART failure prediction via Win32_DiskDriveToDiskPartition
    # and MSStorageDriver_FailurePredictStatus (requires admin)
    try:
        with _wmi_com():
            wmi_storage = wmi.WMI(namespace="root/wmi")
            smart_results = wmi_storage.MSStorageDriver_FailurePredictStatus()
        for sr in smart_results:
            instance = sr.InstanceName or ""
            # Match to disk by partial instance name
            for d in disks:
                dev = d["device_id"].replace("\\\\", "").replace("\\", "").lower()
                if dev in instance.lower() or instance.lower() in dev:
                    d["smart_predict_failure"] = bool(sr.PredictFailure)
                    if sr.PredictFailure:
                        d["health"] = "CRITICAL"
                        d["status"] = "Pred Fail"
    except Exception:
        pass   # SMART WMI namespace not always accessible without admin

    return disks


def _query_disk_io_stats() -> dict:
    """Get disk I/O counters via psutil."""
    try:
        import psutil
        io = psutil.disk_io_counters()
        parts = []
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                parts.append({
                    "device":     p.device,
                    "mountpoint": p.mountpoint,
                    "fstype":     p.fstype,
                    "total_gb":   round(u.total / 1e9, 1),
                    "used_gb":    round(u.used  / 1e9, 1),
                    "free_gb":    round(u.free  / 1e9, 1),
                    "percent":    round(u.percent, 1),
                    "status":     ("CRITICAL" if u.percent > 90 else
                                   "WARNING"  if u.percent > 80 else "OK"),
                })
            except Exception:
                continue
        return {
            "read_mb":    round(io.read_bytes  / 1e6, 1) if io else 0,
            "write_mb":   round(io.write_bytes / 1e6, 1) if io else 0,
            "read_count": io.read_count  if io else 0,
            "write_count":io.write_count if io else 0,
            "partitions": parts,
        }
    except Exception as e:
        return {"error": str(e), "partitions": []}


def _query_disk_event_log_errors() -> list:
    """
    Query Windows event log for disk-related error EIDs:
      7  = disk error (atapi / disk controller)
      11 = driver detected controller error
      51 = a paging operation failed (disk hardware error)
    """
    errors = []
    if not _is_windows():
        return errors
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            SELECT timestamp, event_id, source, level, message
            FROM logs_system
            WHERE event_id IN (7, 11, 51)
            ORDER BY timestamp DESC LIMIT 20
        """)
        for row in c.fetchall():
            errors.append({
                "timestamp": row[0], "event_id": row[1],
                "source":    row[2], "level":    row[3],
                "message":   (row[4] or "")[:200],
            })
        conn.close()
    except Exception:
        pass
    return errors


@fr11_bp.route("/health/disk")
def disk_health():
    """
    FR11-03: Disk health — SMART status via WMI, partition usage,
    I/O counters, and Windows disk error event log entries (EIDs 7, 11, 51).
    """
    err = _auth()
    if err: return err

    smart_disks  = []
    smart_error  = None
    if _is_windows():
        try:
            smart_disks = _query_smart_wmi()
        except ImportError:
            smart_error = "wmi not installed: pip install wmi"
        except Exception as e:
            smart_error = str(e)

    io_stats   = _query_disk_io_stats()
    log_errors = _query_disk_event_log_errors()

    # Overall health summary
    critical_disks = [d for d in smart_disks if d["health"] == "CRITICAL"]
    warning_disks  = [d for d in smart_disks if d["health"] == "WARNING"]

    overall = ("CRITICAL" if critical_disks or len(log_errors) > 5 else
               "WARNING"  if warning_disks  or len(log_errors) > 0 else
               "HEALTHY")

    return jsonify({
        "ok":             True,
        "overall_health": overall,
        "smart": {
            "available":      len(smart_disks) > 0,
            "error":          smart_error,
            "disks":          smart_disks,
            "critical_count": len(critical_disks),
            "warning_count":  len(warning_disks),
        },
        "io":               io_stats,
        "disk_event_errors": log_errors,
        "error_count":      len(log_errors),
        "generated_at":     datetime.now(timezone.utc).isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
# FR11-04 — Windows-specific optimization recommendations
# ══════════════════════════════════════════════════════════════════════════════

def _get_startup_items() -> list:
    """Read startup items from Windows registry."""
    items = []
    if not _is_windows():
        return items
    try:
        import winreg
        keys = [
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, path in keys:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        items.append({"name": name, "command": val,
                                      "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                continue
    except Exception:
        pass
    return items


def _get_temp_folder_size() -> dict:
    """Estimate Windows temp folder size."""
    result = {"size_mb": 0, "file_count": 0, "error": None}
    if not _is_windows():
        return result
    try:
        temp = Path(os.environ.get("TEMP", "C:\\Windows\\Temp"))
        size = sum(f.stat().st_size for f in temp.rglob("*") if f.is_file())
        count = sum(1 for _ in temp.rglob("*") if _.is_file())
        result["size_mb"]    = round(size / (1024 * 1024), 1)
        result["file_count"] = count
        result["path"]       = str(temp)
    except Exception as e:
        result["error"] = str(e)
    return result


def _get_power_plan() -> str:
    """Get active Windows power plan name via powercfg."""
    if not _is_windows():
        return "N/A"
    try:
        out = subprocess.check_output(
            ["powercfg", "/getactivescheme"],
            timeout=5, stderr=subprocess.DEVNULL, text=True
        )
        m = re.search(r"\((.+?)\)$", out.strip())
        return m.group(1) if m else out.strip()
    except Exception:
        return "Unknown"


@fr11_bp.route("/health/optimize")
def optimize_recommendations():
    """
    FR11-04: Windows-specific optimization recommendations.
    Checks: disk space, RAM usage, startup items, temp folder,
    power plan, page file, high-CPU processes, and update errors.
    """
    err = _auth()
    if err: return err

    recs = []
    details = {}

    try:
        import psutil

        # ── RAM ──────────────────────────────────────────────────────────────
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        details["ram_percent"] = round(vm.percent, 1)
        details["swap_percent"] = round(sw.percent, 1)
        if vm.percent > 85:
            recs.append({
                "priority": "HIGH",
                "category": "Memory",
                "title":    "High RAM usage detected",
                "detail":   f"RAM is {vm.percent:.0f}% used ({round(vm.available/1e9,1)} GB free). "
                            f"Consider closing unused applications or adding more RAM.",
                "action":   "Open Task Manager → Processes, sort by Memory, close unneeded apps.",
            })
        if sw.percent > 50:
            recs.append({
                "priority": "MEDIUM",
                "category": "Page File",
                "title":    "Page file heavily used",
                "detail":   f"Page file is {sw.percent:.0f}% used. "
                            f"Heavy paging slows the system significantly.",
                "action":   "Set page file to 'System managed' or increase its size via "
                            "System Properties → Advanced → Performance → Virtual Memory.",
            })

        # ── Disk ─────────────────────────────────────────────────────────────
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
                details[f"disk_{part.mountpoint}"] = round(u.percent, 1)
                if u.percent > 85:
                    recs.append({
                        "priority": "HIGH",
                        "category": "Disk Space",
                        "title":    f"Low disk space on {part.mountpoint}",
                        "detail":   f"{round(u.free/1e9,1)} GB free of {round(u.total/1e9,1)} GB "
                                    f"({u.percent:.0f}% used).",
                        "action":   "Run Disk Cleanup (cleanmgr.exe), remove temp files, "
                                    "uninstall unused programs, or move files to external storage.",
                    })
            except Exception:
                continue

        # ── CPU ──────────────────────────────────────────────────────────────
        cpu = psutil.cpu_percent(interval=0.3)
        details["cpu_percent"] = round(cpu, 1)
        if cpu > 80:
            top_procs = sorted(
                [p for p in psutil.process_iter(["name","cpu_percent"])
                 if p.pid != os.getpid()],
                key=lambda p: p.info.get("cpu_percent") or 0,
                reverse=True
            )[:3]
            names = [p.info.get("name","?") for p in top_procs]
            recs.append({
                "priority": "HIGH",
                "category": "CPU",
                "title":    f"High CPU usage ({cpu:.0f}%)",
                "detail":   f"Top processes: {', '.join(names)}",
                "action":   "Identify high-CPU processes in Task Manager. "
                            "Disable unnecessary startup programs or schedule heavy tasks for off-hours.",
            })

        # ── Startup items ────────────────────────────────────────────────────
        startup = _get_startup_items()
        details["startup_count"] = len(startup)
        if len(startup) > 10:
            recs.append({
                "priority": "MEDIUM",
                "category": "Startup",
                "title":    f"{len(startup)} startup programs found",
                "detail":   "Many startup programs slow Windows boot time and consume background resources.",
                "action":   "Open Task Manager → Startup tab and disable non-essential startup items.",
            })

        # ── Temp folder ──────────────────────────────────────────────────────
        temp_info = _get_temp_folder_size()
        details["temp_mb"] = temp_info.get("size_mb", 0)
        if temp_info.get("size_mb", 0) > 500:
            recs.append({
                "priority": "LOW",
                "category": "Temp Files",
                "title":    f"Temp folder is {temp_info['size_mb']:.0f} MB "
                            f"({temp_info.get('file_count',0)} files)",
                "detail":   "Large temp folders waste disk space and can slow some operations.",
                "action":   "Run Disk Cleanup (cleanmgr.exe) or manually clear %TEMP%.",
            })

        # ── Power plan ───────────────────────────────────────────────────────
        plan = _get_power_plan()
        details["power_plan"] = plan
        if plan and ("power saver" in plan.lower() or "balanced" in plan.lower()):
            recs.append({
                "priority": "LOW",
                "category": "Power Plan",
                "title":    f"Power plan is set to '{plan}'",
                "detail":   "Power Saver / Balanced plans throttle CPU and disk, reducing performance.",
                "action":   "For a security monitoring server, switch to 'High Performance' plan via "
                            "Control Panel → Power Options.",
            })

        # ── Windows Update errors ─────────────────────────────────────────────
        try:
            from database.db import get_conn
            conn = get_conn()
            c = conn.cursor()
            c.execute("""
                SELECT COUNT(*) FROM logs_windows_update
                WHERE level IN ('ERROR','CRITICAL')
                AND timestamp >= datetime('now','-7 days')
            """)
            wu_errs = c.fetchone()[0]
            conn.close()
            details["update_errors_7d"] = wu_errs
            if wu_errs > 0:
                recs.append({
                    "priority": "HIGH",
                    "category": "Windows Update",
                    "title":    f"{wu_errs} Windows Update error(s) in last 7 days",
                    "detail":   "Failed updates leave the system unpatched and vulnerable.",
                    "action":   "Open Settings → Windows Update → View update history "
                                "to find and resolve failed updates. Run 'sfc /scannow' "
                                "to repair system files.",
                })
        except Exception:
            pass

        # Healthy fallback
        if not recs:
            recs.append({
                "priority": "OK",
                "category": "System",
                "title":    "System appears well-optimized",
                "detail":   "No significant optimization issues detected.",
                "action":   "Continue routine monitoring and monthly Windows Update checks.",
            })

        return jsonify({
            "ok":             True,
            "recommendations": recs,
            "details":        details,
            "startup_items":  startup,
            "temp_folder":    temp_info,
            "power_plan":     plan,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        })

    except ImportError:
        return jsonify({"ok": False, "error": "psutil not installed: pip install psutil"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# FR11-05 — BSOD / Blue Screen risk prediction
# ══════════════════════════════════════════════════════════════════════════════

def _scan_minidumps() -> list:
    """Scan %SystemRoot%\\Minidump for recent crash dump files."""
    dumps = []
    if not _is_windows():
        return dumps
    minidump_dir = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "Minidump"
    if not minidump_dir.exists():
        return dumps
    for dmp in sorted(minidump_dir.glob("*.dmp"), reverse=True)[:10]:
        try:
            stat = dmp.stat()
            dumps.append({
                "filename":    dmp.name,
                "size_kb":     round(stat.st_size / 1024, 1),
                "created":     datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                "modified":    datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue
    return dumps


def _get_bsod_event_log_entries() -> list:
    """
    Query Windows event log for BSOD-related EIDs:
      1001 — BugCheck (recorded after reboot from BSOD)
      41   — Kernel-Power (unexpected shutdown / reboot — precedes BSOD record)
      6008 — Unexpected shutdown
    """
    entries = []
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()
        # Check system log for these EIDs
        c.execute("""
            SELECT timestamp, event_id, source, level, message
            FROM logs_system
            WHERE event_id IN (1001, 41, 6008, 6, 26)
            ORDER BY timestamp DESC LIMIT 30
        """)
        for row in c.fetchall():
            entries.append({
                "timestamp": row[0], "event_id": row[1],
                "source":    row[2], "level":    row[3],
                "message":   (row[4] or "")[:300],
                "meaning": {
                    1001: "BugCheck — BSOD occurred, system recorded crash",
                    41:   "Kernel-Power — unexpected shutdown (possible BSOD)",
                    6008: "Unexpected previous shutdown",
                    6:    "System boot after unexpected shutdown",
                    26:   "System entered sleep after unexpected shutdown",
                }.get(row[1], "System event"),
            })
        conn.close()
    except Exception:
        pass
    return entries


def _get_whea_errors() -> list:
    """
    Query for WHEA (Windows Hardware Error Architecture) errors —
    hardware errors that are strong BSOD precursors.
    EID 18/19 in WHEA-Logger channel.
    """
    errors = []
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            SELECT timestamp, event_id, source, level, message
            FROM logs_system
            WHERE (source LIKE '%WHEA%' OR source LIKE '%whea%'
                   OR message LIKE '%hardware error%'
                   OR message LIKE '%machine check%')
            ORDER BY timestamp DESC LIMIT 20
        """)
        for row in c.fetchall():
            errors.append({
                "timestamp": row[0], "event_id": row[1],
                "source":    row[2], "level":    row[3],
                "message":   (row[4] or "")[:200],
            })
        conn.close()
    except Exception:
        pass
    return errors


def _calculate_bsod_risk(dumps: list, bsod_entries: list,
                          whea_errors: list, ram_percent: float) -> dict:
    """
    Score BSOD risk from 0–100 based on crash evidence.
    """
    score = 0
    factors = []

    if dumps:
        pts = min(40, len(dumps) * 10)
        score += pts
        factors.append(f"{len(dumps)} crash dump file(s) found in Minidump (+{pts}pts)")

    bsod_actual = [e for e in bsod_entries if e["event_id"] == 1001]
    if bsod_actual:
        pts = min(30, len(bsod_actual) * 10)
        score += pts
        factors.append(f"{len(bsod_actual)} BugCheck event(s) (EID 1001) (+{pts}pts)")

    unexpected_shutdowns = [e for e in bsod_entries if e["event_id"] in (41, 6008)]
    if unexpected_shutdowns:
        pts = min(20, len(unexpected_shutdowns) * 5)
        score += pts
        factors.append(f"{len(unexpected_shutdowns)} unexpected shutdown event(s) (+{pts}pts)")

    if whea_errors:
        pts = min(20, len(whea_errors) * 7)
        score += pts
        factors.append(f"{len(whea_errors)} WHEA hardware error(s) detected (+{pts}pts)")

    if ram_percent > 95:
        score += 10
        factors.append("Critically low RAM — memory pressure BSOD risk (+10pts)")

    score = min(100, score)
    level = ("CRITICAL" if score >= 60 else
             "HIGH"     if score >= 30 else
             "MEDIUM"   if score >= 10 else
             "LOW")

    return {"score": score, "level": level, "factors": factors}


@fr11_bp.route("/health/bsod")
def bsod_risk():
    """
    FR11-05: BSOD risk prediction.
    Scans Minidump folder for crash files, queries BugCheck (EID 1001),
    Kernel-Power (EID 41), unexpected shutdown (EID 6008), and WHEA
    hardware errors. Produces a risk score 0-100.
    """
    err = _auth()
    if err: return err

    dumps        = _scan_minidumps()
    bsod_entries = _get_bsod_event_log_entries()
    whea_errors  = _get_whea_errors()

    # Get current RAM for memory-pressure risk factor
    ram_pct = 0.0
    try:
        import psutil
        ram_pct = psutil.virtual_memory().percent
    except Exception:
        pass

    risk = _calculate_bsod_risk(dumps, bsod_entries, whea_errors, ram_pct)

    return jsonify({
        "ok":                True,
        "risk":              risk,
        "crash_dumps":       dumps,
        "crash_dump_count":  len(dumps),
        "bsod_events":       bsod_entries,
        "whea_errors":       whea_errors,
        "minidump_dir":      str(Path(os.environ.get("SystemRoot","C:\\Windows")) / "Minidump"),
        "generated_at":      datetime.now(timezone.utc).isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
# FR11-06 — Driver health and compatibility
# ══════════════════════════════════════════════════════════════════════════════

def _query_drivers_wmi() -> tuple[list, str | None]:
    """
    Enumerate all installed drivers via WMI Win32_SystemDriver.
    Returns a tuple of (drivers, error_message).
    """
    drivers = []
    if not _is_windows():
        return drivers, None

    try:
        import wmi
    except ImportError:
        return [], "wmi not installed: pip install wmi"

    try:
        with _wmi_com():
            w = wmi.WMI()
            for d in w.Win32_SystemDriver():
                state      = d.State     or "Unknown"
                start_mode = d.StartMode or "Unknown"
                path       = d.PathName  or ""

                # Flag unsigned or suspicious drivers
                suspicious = (
                    not path.lower().startswith("c:\\windows") and
                    not path.lower().startswith(r"\\systemroot")
                )

                drivers.append({
                    "name":        d.Name        or "",
                    "display":     d.DisplayName or "",
                    "state":       state,
                    "start_mode":  start_mode,
                    "path":        path,
                    "signed":      None,      # populated below
                    "suspicious":  suspicious,
                    "status":      d.Status or "",
                })
    except Exception as e:
        return [], f"WMI driver query failed: {e}"

    # Try to get signing info via PnP signed driver table
    try:
        with _wmi_com():
            w = wmi.WMI()
            pnp_drivers = {}
            for p in w.Win32_PnPSignedDriver():
                name = (p.DeviceName or "").lower()
                pnp_drivers[name] = {
                    "signed":     p.IsSigned,
                    "signer":     p.Signer or "",
                    "driver_ver": p.DriverVersion or "",
                    "inf_name":   p.InfName or "",
                }
            # Merge into driver list
            for d in drivers:
                key = d["display"].lower()
                if key in pnp_drivers:
                    d.update(pnp_drivers[key])
    except Exception:
        pass

    return drivers, None


def _get_driver_event_log_errors() -> list:
    """
    Query Windows event log for driver-related error EIDs:
      219  — driver failed to load
      7026 — boot-start or system-start driver failed to load
      10110 — driver blocked from loading (unsigned / compatibility)
    """
    entries = []
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()
        c.execute("""
            SELECT timestamp, event_id, source, level, message
            FROM logs_system
            WHERE event_id IN (219, 7026, 10110, 257, 263)
            ORDER BY timestamp DESC LIMIT 30
        """)
        for row in c.fetchall():
            entries.append({
                "timestamp": row[0], "event_id": row[1],
                "source":    row[2], "level":    row[3],
                "message":   (row[4] or "")[:300],
                "meaning": {
                    219:   "Driver failed to load",
                    7026:  "Boot/system-start driver failed to load",
                    10110: "Driver blocked — unsigned or incompatible",
                    257:   "WHEA — machine check error (hardware driver issue)",
                    263:   "WHEA — PCI Express error",
                }.get(row[1], "Driver event"),
            })
        conn.close()
    except Exception:
        pass
    return entries


@fr11_bp.route("/health/drivers")
def driver_health():
    """
    FR11-06: Driver health and compatibility.
    Enumerates all installed drivers via WMI Win32_SystemDriver,
    checks signing status via Win32_PnPSignedDriver,
    flags drivers outside C:\\Windows as suspicious,
    and queries driver failure EIDs (219, 7026, 10110).
    """
    err = _auth()
    if err: return err

    drivers, wmi_error = _query_drivers_wmi()
    if not drivers and not wmi_error and _is_windows():
        wmi_error = (
            "WMI query returned no drivers. "
            "Ensure the Windows WMI service is running and the process has access."
        )

    log_errors   = _get_driver_event_log_errors()

    # Categorise
    failed       = [d for d in drivers if d["state"] in ("Stopped","Error") and d["start_mode"] in ("Boot","System","Auto")]
    unsigned     = [d for d in drivers if d.get("signed") is False]
    suspicious   = [d for d in drivers if d.get("suspicious")]
    running      = [d for d in drivers if d["state"] == "Running"]

    overall = ("CRITICAL" if log_errors or failed else
               "WARNING"  if unsigned or suspicious else
               "HEALTHY")

    return jsonify({
        "ok":             True,
        "overall_health": overall,
        "summary": {
            "total":     len(drivers),
            "running":   len(running),
            "failed":    len(failed),
            "unsigned":  len(unsigned),
            "suspicious": len(suspicious),
        },
        "failed_drivers":    failed,
        "unsigned_drivers":  unsigned,
        "suspicious_drivers":suspicious,
        "all_drivers":       drivers,
        "driver_log_errors": log_errors,
        "wmi_error":         wmi_error,
        "generated_at":      datetime.now(timezone.utc).isoformat(),
    })
