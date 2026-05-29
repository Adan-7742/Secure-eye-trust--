"""
core/analysis_engine/normalizer.py
===================================
Extracts structured fields from raw Windows log messages.

Windows logs are messy XML blobs. This module parses them into a clean,
consistent structure that the threat detector and correlator can work with.

Output schema:
{
  "user":       "DOMAIN\\username" | None,
  "ip":         "192.168.1.1" | None,
  "logon_type": 2 | 3 | 10 | None,   # 2=interactive, 3=network, 10=remote
  "workstation": "DESKTOP-XYZ" | None,
  "process":    "svchost.exe" | None,
  "status":     "0xC000006D" | None,  # failure status code
  "hour":       14,                   # hour of day (0-23)
  "weekday":    1,                    # 0=Mon … 6=Sun
}
"""

import re
from datetime import datetime


# ── Regex patterns for common Windows log fields ─────────────────────────────

_PATTERNS = {
    "user":        [
        r"Account Name:\s+(\S+)",
        r"Security ID:\s+\S+\s+Account Name:\s+(\S+)",
        r"Subject:\s+[^\n]*\n\s+Account Name:\s+(\S+)",
        r"New Logon:\s+[^\n]*\n\s+Account Name:\s+(\S+)",
        r"Logon Account:\s+(\S+)",
        r"User Name:\s+(\S+)",
    ],
    "ip":          [
        r"Source Network Address:\s+([\d\.]+)",
        r"Client Address:\s+([\d\.]+)",
        r"IP Address:\s+([\d\.]+)",
        r"Workstation Name:\s+[^\n]*\n\s+Source Network Address:\s+([\d\.]+)",
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    ],
    "logon_type":  [
        r"Logon Type:\s+(\d+)",
    ],
    "workstation": [
        r"Workstation Name:\s+(\S+)",
        r"Computer Name:\s+(\S+)",
    ],
    "process":     [
        r"Process Name:\s+([^\r\n]+)",
        r"Application Name:\s+([^\r\n]+)",
    ],
    "status":      [
        r"Status:\s+(0x[0-9A-Fa-f]+)",
        r"Sub Status:\s+(0x[0-9A-Fa-f]+)",
        r"Failure Reason:\s+([^\r\n]+)",
    ],
}

# IPs that are noise and should be ignored
_IGNORE_IPS = {"127.0.0.1", "::1", "0.0.0.0", "-", ""}

# Usernames that are noise (machine accounts, built-in)
_IGNORE_USERS = {
    "-", "anonymous logon", "anonymous", "system",
    "local service", "network service", "",
}


def normalize(event: dict) -> dict:
    """
    Takes a raw event dict from the DB and extracts structured fields.

    Input:  { timestamp, level, source, message, event_id, ... }
    Output: normalized field dict (never raises)
    """
    msg       = (event.get("message") or event.get("raw") or "").lower()
    msg_raw   = (event.get("message") or event.get("raw") or "")
    timestamp = event.get("timestamp", "")

    result = {
        "user":        None,
        "ip":          None,
        "logon_type":  None,
        "workstation": None,
        "process":     None,
        "status":      None,
        "hour":        None,
        "weekday":     None,
    }

    # Parse each field using the regex list — use first match
    for field, patterns in _PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, msg_raw, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if field == "logon_type":
                    try:
                        result[field] = int(val)
                    except ValueError:
                        pass
                elif field == "ip":
                    if val not in _IGNORE_IPS:
                        result[field] = val
                elif field == "user":
                    clean = val.lower()
                    # Strip domain prefix
                    if "\\" in clean:
                        clean = clean.split("\\")[-1]
                    if clean not in _IGNORE_USERS and not clean.endswith("$"):
                        result[field] = clean
                else:
                    result[field] = val[:200]
                break

    # Parse timestamp for hour/weekday
    if timestamp:
        try:
            dt = datetime.strptime(timestamp[:19], "%Y-%m-%d %H:%M:%S")
            result["hour"]    = dt.hour
            result["weekday"] = dt.weekday()   # 0=Monday
        except Exception:
            pass

    return result


def normalize_batch(events: list) -> list:
    """Normalize a list of events. Returns list of (event, normalized) tuples."""
    return [(ev, normalize(ev)) for ev in events]
