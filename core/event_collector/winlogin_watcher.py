"""
core/event_collector/winlogin_watcher.py
=========================================
Windows Login Failure Screenshot Monitor
==========================================

WHAT THIS DOES:
  Monitors the Windows Security Event Log in real time for Event ID 4625
  (Failed Logon) — this is what Windows logs every time someone enters the
  wrong password on the Windows login screen or any Windows login prompt.

  When a 4625 event is detected:
    1. Takes a screenshot of the current screen using mss/Pillow/pyautogui
    2. Extracts: username attempted, logon type, source IP, workstation name,
       failure reason from the event XML
    3. Saves screenshot as JPEG (base64) + metadata to the intruder_captures DB
    4. Fires a live alert so it appears in your dashboard immediately

HOW WINDOWS EID 4625 WORKS:
  - Fires for EVERY failed Windows login:
      * Wrong password on the Windows lock screen
      * Failed RDP login attempt
      * Failed network share login
      * Runas.exe with wrong credentials
      * Any app that calls LogonUser() with wrong creds
  - Logon Type 2 = Interactive (physical keyboard at the machine)
  - Logon Type 3 = Network
  - Logon Type 10 = Remote Interactive (RDP)
  - Logon Type 7 = Unlock (lock screen unlock failed)

REQUIREMENTS:
  pip install mss Pillow pywin32

LIMITATIONS:
  - Requires running as Administrator (Security log access)
  - Screenshot captures what is ON SCREEN when the event is detected.
    Because Windows processes login failures quickly, the screenshot may
    show the desktop rather than the login screen itself — this is normal.
    The important data (WHO tried, WHEN, from WHERE) is in the event log.
  - If Windows Fast User Switching is on, the screenshot is of the current
    active desktop session, not the login screen session (which is Session 0).

NOTE ON "LOGIN SCREEN SCREENSHOT":
  The Windows login screen (winlogon.exe) runs in a separate isolated
  session (Session 0 / Winlogon desktop). No standard API can screenshot
  it from a user-mode process — this is a Windows security boundary.
  What we CAN do (and do here):
    - Detect the event instantly via Event Log
    - Screenshot the CURRENT desktop at the moment of detection
    - Capture all metadata from the event (user, IP, machine, reason)
  This is what professional SIEM tools like Splunk and Wazuh also do.
"""

import os
import io
import base64
import threading
import time
from datetime import datetime

# ── Screenshot engine — tries mss first, falls back to Pillow ─────────────────
_SS_ENGINE = None

def _init_screenshot():
    global _SS_ENGINE
    try:
        import mss
        _SS_ENGINE = 'mss'
        return
    except ImportError:
        pass
    try:
        from PIL import ImageGrab
        _SS_ENGINE = 'pillow'
        return
    except ImportError:
        pass
    try:
        import pyautogui
        _SS_ENGINE = 'pyautogui'
        return
    except ImportError:
        pass
    _SS_ENGINE = None
    print("[winlogin_watcher] ⚠ No screenshot library found. "
          "Install: pip install mss Pillow")

_init_screenshot()


def take_screenshot() -> str:
    """
    Take a screenshot and return it as a base64 JPEG string.
    Returns empty string if no screenshot library is available.
    """
    try:
        if _SS_ENGINE == 'mss':
            import mss, mss.tools
            with mss.mss() as sct:
                # Capture the primary monitor
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                img = sct.grab(monitor)
                # Convert to JPEG bytes
                from PIL import Image
                pil_img = Image.frombytes('RGB', img.size, img.bgra, 'raw', 'BGRX')
                buf = io.BytesIO()
                pil_img.save(buf, format='JPEG', quality=60)
                return base64.b64encode(buf.getvalue()).decode('utf-8')

        elif _SS_ENGINE == 'pillow':
            from PIL import ImageGrab
            img = ImageGrab.grab()
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=60)
            return base64.b64encode(buf.getvalue()).decode('utf-8')

        elif _SS_ENGINE == 'pyautogui':
            import pyautogui
            img = pyautogui.screenshot()
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=60)
            return base64.b64encode(buf.getvalue()).decode('utf-8')

    except Exception as e:
        print(f"[winlogin_watcher] Screenshot failed: {e}")

    return ''


# ── Windows Event ID 4625 parser ──────────────────────────────────────────────

def _parse_4625(ev) -> dict:
    """
    Extract meaningful fields from a Windows EID 4625 event.
    Returns a dict with: username, domain, logon_type, workstation,
                         source_ip, source_port, failure_reason, sub_status
    """
    result = {
        'username':       '—',
        'domain':         '—',
        'logon_type':     '—',
        'logon_type_name':'—',
        'workstation':    '—',
        'source_ip':      '—',
        'source_port':    '—',
        'failure_reason': 'Unknown',
        'sub_status':     '',
        'process_name':   '—',
    }

    LOGON_TYPES = {
        '2':  'Interactive (Console/Lock Screen)',
        '3':  'Network',
        '4':  'Batch',
        '5':  'Service',
        '7':  'Unlock (Screen Lock)',
        '8':  'Network Cleartext',
        '9':  'New Credentials',
        '10': 'Remote Interactive (RDP)',
        '11': 'Cached Interactive',
        '12': 'Cached Remote Interactive',
        '13': 'Cached Unlock',
    }

    FAILURE_REASONS = {
        '0xC000006A': 'Wrong password',
        '0xC0000064': 'Username does not exist',
        '0xC000006D': 'Bad username or password',
        '0xC000006F': 'Login outside allowed hours',
        '0xC0000070': 'Restricted workstation',
        '0xC0000071': 'Password expired',
        '0xC0000072': 'Account disabled',
        '0xC0000193': 'Account expired',
        '0xC0000224': 'Must change password',
        '0xC0000234': 'Account locked out',
        '0xC000015B': 'Logon type not granted',
    }

    try:
        inserts = ev.StringInserts or []
        # Standard EID 4625 string inserts layout:
        # [0]=SubjectUserSid [1]=SubjectUserName [2]=SubjectDomainName [3]=SubjectLogonId
        # [4]=TargetUserSid  [5]=TargetUserName  [6]=TargetDomainName
        # [7]=Status         [8]=FailureReason   [9]=SubStatus
        # [10]=LogonType     [11]=LogonProcessName [12]=AuthPackageName
        # [13]=WorkstationName [14]=TransmittedServices [15]=LmPackageName
        # [16]=KeyLength      [17]=ProcessId      [18]=ProcessName
        # [19]=IpAddress      [20]=IpPort

        if len(inserts) > 5:
            uname = str(inserts[5]).strip()
            if uname and uname not in ('-', '', 'ANONYMOUS LOGON'):
                result['username'] = uname
        if len(inserts) > 6:
            result['domain'] = str(inserts[6]).strip() or '—'
        if len(inserts) > 10:
            lt = str(inserts[10]).strip()
            result['logon_type'] = lt
            result['logon_type_name'] = LOGON_TYPES.get(lt, f'Type {lt}')
        if len(inserts) > 13:
            ws = str(inserts[13]).strip()
            if ws and ws != '-':
                result['workstation'] = ws
        if len(inserts) > 18:
            pn = str(inserts[18]).strip()
            if pn and pn != '-':
                result['process_name'] = pn
        if len(inserts) > 19:
            ip = str(inserts[19]).strip()
            if ip and ip not in ('-', '::1', '127.0.0.1'):
                result['source_ip'] = ip
        if len(inserts) > 20:
            result['source_port'] = str(inserts[20]).strip()
        if len(inserts) > 9:
            ss = str(inserts[9]).strip().upper()
            result['sub_status'] = ss
            result['failure_reason'] = FAILURE_REASONS.get(ss, FAILURE_REASONS.get(
                str(inserts[7]).strip().upper() if len(inserts) > 7 else '', 'Authentication failure'))
    except Exception as e:
        print(f"[winlogin_watcher] Parse error: {e}")

    return result


# ── Watcher thread ────────────────────────────────────────────────────────────

_watcher_stop  = threading.Event()
_watcher_thread = None
_last_record_id = 0   # last Security log record number we processed
_priv_warned    = False  # suppress repeated privilege warnings


def _watch_loop():
    global _last_record_id, _priv_warned

    print("[winlogin_watcher] 🔍 Started — watching for Windows login failures (EID 4625)")

    try:
        import win32evtlog, win32evtlogutil, win32con
    except ImportError:
        print("[winlogin_watcher] ❌ pywin32 not installed. Run: pip install pywin32")
        return

    # Seed — start from current end of log so we don't replay old events
    try:
        h = win32evtlog.OpenEventLog(None, 'Security')
        n = win32evtlog.GetNumberOfEventLogRecords(h)
        o = win32evtlog.GetOldestEventLogRecord(h)
        _last_record_id = o + n - 1
        win32evtlog.CloseEventLog(h)
        print(f"[winlogin_watcher] Seeded at Security log record #{_last_record_id}")
    except Exception as e:
        err = str(e)
        if "1314" in err or "access" in err.lower() or "not held" in err.lower() or "privilege" in err.lower():
            print("[winlogin_watcher] ⚠ Security log requires Administrator — login failure monitoring limited. Run as admin to enable.")
        else:
            print(f"[winlogin_watcher] Could not seed record ID: {e}")

    POLL_SEC = 5   # check every 5 seconds for fast detection

    while not _watcher_stop.is_set():
        try:
            _check_for_failures()
        except Exception as e:
            print(f"[winlogin_watcher] Error: {e}")
        _watcher_stop.wait(POLL_SEC)

    print("[winlogin_watcher] Stopped.")


def _check_for_failures():
    global _last_record_id

    try:
        import win32evtlog, win32evtlogutil, win32con
    except ImportError:
        return

    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, 'Security')
        flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                  win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        new_events   = []
        highest_seen = _last_record_id

        while True:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for ev in batch:
                rec = ev.RecordNumber
                if rec <= _last_record_id:
                    # Past what we've already processed — stop
                    break
                if rec > highest_seen:
                    highest_seen = rec

                # Only care about EID 4625 — failed logon
                eid = ev.EventID & 0xFFFF
                if eid == 4625:
                    new_events.append(ev)
            else:
                continue
            break

        if highest_seen > _last_record_id:
            _last_record_id = highest_seen

        # Process each failure
        for ev in new_events:
            _handle_failure(ev)

    except Exception as e:
        global _priv_warned
        err = str(e)
        if ("1314" in err or "not held" in err.lower() or
                "access" in err.lower() or "privilege" in err.lower()):
            if not _priv_warned:
                print("[winlogin_watcher] ⚠ Security log requires Administrator — some login events may be missed. (This message will not repeat.)")
                _priv_warned = True
        elif ('5' not in err and 'handle is invalid' not in err.lower()):
            print(f"[winlogin_watcher] Check error: {e}")
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                if 'handle is invalid' not in str(e).lower():
                    print(f"[winlogin_watcher] CloseEventLog error: {e}")


def _handle_failure(ev):
    """Process one EID 4625 event: screenshot + parse + save."""
    ts  = ev.TimeGenerated
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else datetime.now().isoformat()

    parsed = _parse_4625(ev)

    # Take screenshot immediately
    print(f"[winlogin_watcher] 🚨 Failed login detected: user='{parsed['username']}' "
          f"type='{parsed['logon_type_name']}' ip='{parsed['source_ip']}' — taking screenshot…")

    screenshot_b64 = take_screenshot()

    if screenshot_b64:
        print(f"[winlogin_watcher] 📸 Screenshot captured ({len(screenshot_b64)//1024}KB)")
    else:
        print("[winlogin_watcher] ⚠ Screenshot not captured (no screenshot library)")

    # Build detail string for the photo card note
    detail = (
        f"Logon Type: {parsed['logon_type_name']} | "
        f"Reason: {parsed['failure_reason']} | "
        f"Domain: {parsed['domain']} | "
        f"Workstation: {parsed['workstation']} | "
        f"Process: {parsed['process_name']}"
    )

    # Save to intruder_captures table
    try:
        from database.db import get_conn
        conn = get_conn(); c = conn.cursor()
        c.execute("""
            INSERT INTO intruder_captures
                (username, ip, timestamp, photo_b64, attempt_no, dismissed)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            parsed['username'],
            parsed['source_ip'] if parsed['source_ip'] != '—' else parsed['workstation'],
            ts_str,
            screenshot_b64,
            int(parsed['logon_type']),
        ))
        conn.commit()
        conn.close()
        print(f"[winlogin_watcher] ✅ Saved to intruder_captures DB")
    except Exception as e:
        print(f"[winlogin_watcher] DB save error: {e}")

    # Also log as a live alert
    try:
        from database.db import log_app_event
        log_app_event('windows_login_failure', {
            'username':       parsed['username'],
            'logon_type':     parsed['logon_type_name'],
            'source_ip':      parsed['source_ip'],
            'workstation':    parsed['workstation'],
            'failure_reason': parsed['failure_reason'],
            'timestamp':      ts_str,
            'has_screenshot': bool(screenshot_b64),
        })
    except Exception:
        pass


# ── Public API ────────────────────────────────────────────────────────────────

def start_winlogin_watcher():
    """
    Start the Windows login failure watcher.
    Call this from app.py alongside start_live_monitor().
    Requires: Administrator + pywin32 + mss or Pillow.
    """
    global _watcher_thread
    if _watcher_thread and _watcher_thread.is_alive():
        return

    # Check requirements
    try:
        import win32evtlog
    except ImportError:
        print("[winlogin_watcher] ⚠ Skipping — pywin32 not installed")
        return

    if _SS_ENGINE is None:
        print("[winlogin_watcher] ⚠ No screenshot library. "
              "Install: pip install mss Pillow — watcher will run WITHOUT screenshots")

    _watcher_stop.clear()
    _watcher_thread = threading.Thread(
        target=_watch_loop, daemon=True, name="winlogin-watcher"
    )
    _watcher_thread.start()


def stop_winlogin_watcher():
    _watcher_stop.set()


def screenshot_engine() -> str:
    return _SS_ENGINE or 'none'
