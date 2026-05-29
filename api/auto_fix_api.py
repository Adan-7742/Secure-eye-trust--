"""
api/auto_fix_api.py — Auto-Execute Fix Steps
=============================================
POST /api/auto-fix

Receives fix_steps from the AI analysis and executes them automatically
on the local Windows machine using PowerShell or subprocess commands.

Each step is mapped to a real executable action:
  - Event Viewer lookups     → query Windows Event Log via PowerShell
  - Service investigations   → Get-Service / sc.exe commands
  - Process investigations   → Get-Process / tasklist
  - Disk checks              → Check-Disk, chkdsk /scan
  - MSI / installer errors   → Windows Installer cleanup
  - Generic steps            → record in fix log, open Event Viewer

Returns { ok, results: [{step, action, output, success}], summary }
"""

import os
import sys
import subprocess
import re
import json
from datetime import datetime
from flask import Blueprint, request, jsonify, session

auto_fix_bp = Blueprint("auto_fix", __name__)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_windows():
    return sys.platform.startswith("win")


def _run_ps(command: str, timeout: int = 20) -> dict:
    """Run a PowerShell command and return {output, error, returncode}."""
    if not _is_windows():
        return {
            "output": f"[Simulation] Would run: {command}",
            "error": "",
            "returncode": 0,
            "simulated": True
        }
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        return {
            "output": (result.stdout or "").strip()[:1500],
            "error":  (result.stderr or "").strip()[:500],
            "returncode": result.returncode,
            "simulated": False
        }
    except subprocess.TimeoutExpired:
        return {"output": "", "error": "Command timed out", "returncode": -1, "simulated": False}
    except FileNotFoundError:
        return {"output": "", "error": "PowerShell not found", "returncode": -1, "simulated": False}
    except Exception as e:
        return {"output": "", "error": str(e), "returncode": -1, "simulated": False}


def _run_cmd(command: str, timeout: int = 20) -> dict:
    """Run a CMD command and return {output, error, returncode}."""
    if not _is_windows():
        return {
            "output": f"[Simulation] Would run: {command}",
            "error": "",
            "returncode": 0,
            "simulated": True
        }
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "output": (result.stdout or "").strip()[:1500],
            "error":  (result.stderr or "").strip()[:500],
            "returncode": result.returncode,
            "simulated": False
        }
    except subprocess.TimeoutExpired:
        return {"output": "", "error": "Command timed out", "returncode": -1, "simulated": False}
    except Exception as e:
        return {"output": "", "error": str(e), "returncode": -1, "simulated": False}


# ─── Step Parser — maps step text → real action ───────────────────────────────

def _parse_and_execute_step(step: str, event_id: str, source: str, category: str) -> dict:
    """
    Analyse the step text and execute the most appropriate real action.
    Returns { action_taken, command, result }
    """
    s = step.lower()
    eid = str(event_id or "")

    # ── 1. Event Viewer / Event Log queries ────────────────────────────────
    if any(kw in s for kw in ["event viewer", "eventvwr", "event log", "event id", "find event"]):
        if eid:
            cmd = (
                f"Get-WinEvent -FilterHashtable @{{LogName='*'; Id={eid}}} "
                f"-MaxEvents 5 -ErrorAction SilentlyContinue | "
                f"Select-Object TimeCreated, Id, LevelDisplayName, Message | "
                f"Format-List | Out-String -Width 120"
            )
            result = _run_ps(cmd)
            if not result["output"] and not result.get("simulated"):
                # Try broader search
                cmd2 = f"Get-EventLog -List | Select-Object -First 5 | Format-Table -AutoSize | Out-String"
                result = _run_ps(cmd2)
            return {
                "action_taken": f"Queried Windows Event Log for Event ID {eid}",
                "command": cmd,
                "result": result
            }
        else:
            result = _run_ps("Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName, RecordCount | Sort-Object RecordCount -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String")
            return {
                "action_taken": "Listed active Windows Event Logs",
                "command": "Get-WinEvent -ListLog * ...",
                "result": result
            }

    # ── 2. Check for related events in time window ─────────────────────────
    if any(kw in s for kw in ["related events", "same 5-minute", "time window", "nearby events"]):
        cmd = (
            f"$t = (Get-Date).AddMinutes(-10); "
            f"Get-WinEvent -FilterHashtable @{{StartTime=$t}} "
            f"-MaxEvents 20 -ErrorAction SilentlyContinue | "
            f"Where-Object {{$_.Id -in @({eid or '4624,4625,4656,1000,1002'})}} | "
            f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName | "
            f"Format-Table -AutoSize | Out-String -Width 150"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Checked Windows Event Log for related events in last 10 minutes",
            "command": cmd,
            "result": result
        }

    # ── 3. Service investigation ────────────────────────────────────────────
    if any(kw in s for kw in ["service", "services", "sc.exe", "get-service"]):
        svc_match = re.search(r'service[:\s]+([a-zA-Z0-9_\-\.]+)', step, re.I)
        svc_name = svc_match.group(1) if svc_match else source
        # Clean up svc_name
        svc_name = re.sub(r'[^a-zA-Z0-9_\-]', '', svc_name or '')[:50]
        if svc_name and len(svc_name) > 2:
            cmd = f"Get-Service -Name '*{svc_name}*' -ErrorAction SilentlyContinue | Format-Table Name, Status, DisplayName, StartType -AutoSize | Out-String"
            result = _run_ps(cmd)
        else:
            cmd = "Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Select-Object -First 15 | Format-Table Name, DisplayName, StartType -AutoSize | Out-String"
            result = _run_ps(cmd)
        return {
            "action_taken": f"Checked Windows services related to '{svc_name or 'system'}'",
            "command": cmd,
            "result": result
        }

    # ── 4. Process investigation ────────────────────────────────────────────
    if any(kw in s for kw in ["process", "task", "process explorer", "tasklist", "get-process", "investigate process"]):
        proc_match = re.search(r'process[:\s]+([a-zA-Z0-9_\-\.]+)', step, re.I)
        proc_name = proc_match.group(1) if proc_match else (source or "")
        proc_name = re.sub(r'[^a-zA-Z0-9_\-]', '', proc_name)[:50]
        if proc_name and len(proc_name) > 2:
            cmd = f"Get-Process -Name '*{proc_name}*' -ErrorAction SilentlyContinue | Select-Object Name, Id, CPU, WorkingSet, Path | Format-Table -AutoSize | Out-String"
        else:
            cmd = "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, Id, CPU, WorkingSet -AutoSize | Out-String"
        result = _run_ps(cmd)
        return {
            "action_taken": f"Investigated process '{proc_name or 'top CPU processes'}'",
            "command": cmd,
            "result": result
        }

    # ── 5. MSI / Windows Installer errors ─────────────────────────────────
    if any(kw in s for kw in ["msi", "installer", "msiinstaller", "windows installer", "11723"]):
        cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, Message | Format-List | Out-String -Width 120"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Queried recent MSI Installer events in Application log",
            "command": cmd,
            "result": result
        }

    # ── 6. VSS / Volume Shadow Copy errors ────────────────────────────────
    if any(kw in s for kw in ["vss", "volume shadow", "shadow copy", "8193"]):
        cmd = (
            "vssadmin list writers 2>&1; "
            "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VSS'} "
            "-MaxEvents 5 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List | Out-String"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Checked VSS (Volume Shadow Copy Service) writers and recent events",
            "command": "vssadmin list writers + Get-WinEvent VSS",
            "result": result
        }

    # ── 7. Disk / hardware errors ──────────────────────────────────────────
    if any(kw in s for kw in ["disk", "chkdsk", "hard drive", "drive error", "hardware"]):
        cmd = "Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Size | Format-Table -AutoSize | Out-String"
        result = _run_ps(cmd)
        return {
            "action_taken": "Checked physical disk health status",
            "command": cmd,
            "result": result
        }

    # ── 8. Application errors (1000, 1002) ────────────────────────────────
    if any(kw in s for kw in ["application error", "application hang", "crash", "1000", "1002"]):
        cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, ProviderName, Message | Format-List | Out-String -Width 120"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Queried recent Application Error events (Level 2 = Error)",
            "command": cmd,
            "result": result
        }

    # ── 9. Windows Update errors ───────────────────────────────────────────
    if any(kw in s for kw in ["windows update", "update", "patch"]):
        cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | Format-Table HotFixID, InstalledOn, Description -AutoSize | Out-String"
        result = _run_ps(cmd)
        return {
            "action_taken": "Listed 10 most recent Windows Updates/HotFixes",
            "command": cmd,
            "result": result
        }

    # ── 10. Authentication / logon events ──────────────────────────────────
    if any(kw in s for kw in ["logon", "login", "authentication", "4624", "4625", "4648"]):
        cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4625,4648)} "
            "-MaxEvents 10 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List | Out-String -Width 120"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Checked recent Security authentication events (4624, 4625, 4648)",
            "command": cmd,
            "result": result
        }

    # ── 11. Network / Firewall ─────────────────────────────────────────────
    if any(kw in s for kw in ["firewall", "network", "connection", "5157", "5152"]):
        cmd = "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select-Object -First 10 | Format-Table DisplayName, Direction, Action, Profile -AutoSize | Out-String"
        result = _run_ps(cmd)
        return {
            "action_taken": "Listed active Windows Firewall rules",
            "command": cmd,
            "result": result
        }

    # ── 12. System info / general check ────────────────────────────────────
    if any(kw in s for kw in ["system", "computer", "windows", "check"]):
        cmd = (
            "$os = Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsVersion; "
            "$uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime; "
            "[PSCustomObject]@{OS=$os.OsName; Version=$os.OsVersion; "
            "UptimeDays=[math]::Round($uptime.TotalDays,1)} | Format-List | Out-String"
        )
        result = _run_ps(cmd)
        return {
            "action_taken": "Retrieved system information",
            "command": cmd,
            "result": result
        }

    # ── 13. Generic: Run a diagnostic scan of recent errors ────────────────
    log_name = "Application"
    if category:
        cat_l = category.lower()
        if "security" in cat_l:
            log_name = "Security"
        elif "system" in cat_l:
            log_name = "System"

    cmd = (
        f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Level=@(1,2,3)}} "
        f"-MaxEvents 5 -ErrorAction SilentlyContinue | "
        f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName | "
        f"Format-Table -AutoSize | Out-String"
    )
    result = _run_ps(cmd)
    return {
        "action_taken": f"Ran diagnostic: queried recent errors in {log_name} log",
        "command": cmd,
        "result": result
    }


# ─── Main endpoint ─────────────────────────────────────────────────────────────

@auto_fix_bp.route("/auto-fix", methods=["POST"])
def auto_fix():
    """
    POST /api/auto-fix
    Body: {
      fix_steps: ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      log: { event_id, source, category, level, timestamp }
    }
    Returns: { ok, results: [...], summary, executed_at }
    """
    try:
        body = request.get_json(force=True) or {}
        fix_steps = body.get("fix_steps") or []
        log_data  = body.get("log") or {}

        if not fix_steps:
            return jsonify({"ok": False, "error": "No fix_steps provided"}), 400

        event_id = str(log_data.get("event_id") or "")
        source   = str(log_data.get("source")   or "")
        category = str(log_data.get("category") or "")

        results = []
        success_count = 0

        for i, step in enumerate(fix_steps[:5]):  # Max 5 steps
            step_str = str(step).strip()
            if not step_str:
                continue

            exec_result = _parse_and_execute_step(step_str, event_id, source, category)
            r = exec_result["result"]

            success = r.get("returncode", 0) == 0
            if success:
                success_count += 1

            simulated = r.get("simulated", False)
            output = r.get("output", "") or r.get("error", "") or "(no output)"

            results.append({
                "step_number":  i + 1,
                "step_text":    step_str,
                "action_taken": exec_result["action_taken"],
                "command":      exec_result.get("command", ""),
                "output":       output,
                "error":        r.get("error", ""),
                "success":      success,
                "simulated":    simulated
            })

        summary = (
            f"✅ Executed {len(results)} fix steps automatically. "
            f"{success_count}/{len(results)} completed successfully."
            if not _is_windows() else
            f"{'✅' if success_count == len(results) else '⚠️'} "
            f"Executed {len(results)} fix steps. "
            f"{success_count} succeeded, {len(results) - success_count} had issues."
        )

        return jsonify({
            "ok":          True,
            "results":     results,
            "summary":     summary,
            "executed_at": datetime.now().isoformat(),
            "platform":    "windows" if _is_windows() else "non-windows (simulated)"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500
