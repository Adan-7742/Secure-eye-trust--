"""
core/event_collector/file_scanner.py
======================================
YARA File Scanner — monitors user-writable directories for malicious files.

Monitors:
  %USERPROFILE%\\Downloads
  %USERPROFILE%\\Desktop
  %TEMP%
  %APPDATA%

When a new file with a suspicious extension appears:
  1. Compute SHA256 hash
  2. Run YARA scan
  3. Write result to logs_sysmon (yara_matched, yara_rule, yara_severity)
  4. Feed alert to AlertBus if matched
  5. Log stats to file_scan_stats table

Extensions monitored: .exe .dll .bat .ps1 .vbs .js .scr .hta .pif

YARA rules are loaded from:
  rules/yara/malware.yar  (bundled)
  rules/yara/*.yar        (user-added)

If yara-python is not installed, scanner runs without YARA
(still records SHA256, timestamps, and file stats).
"""

import hashlib
import math
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger("file_scanner")

POLL_INTERVAL   = 5        # seconds
SCAN_EXTENSIONS = {".exe", ".bat", ".ps1", ".vbs", ".js", ".txt"}
MAX_FILE_SIZE   = 50 * 1024 * 1024   # 50 MB cap for YARA scan

# ── Determine monitored directories ──────────────────────────────────────────

def _monitored_dirs() -> list[Path]:
    dirs = []
    for env_var in ("USERPROFILE", "HOME"):
        base = os.environ.get(env_var)
        if base:
            dirs.append(Path(base) / "Downloads")
            dirs.append(Path(base) / "Desktop")
            break
    temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp:
        dirs.append(Path(temp))
    appdata = os.environ.get("APPDATA")
    if appdata:
        dirs.append(Path(appdata))
    return [d for d in dirs if d.exists()]


# ── SHA256 ───────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


# ── Entropy (high entropy = packed/encrypted = suspicious) ───────────────────

def _entropy(path: Path) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        e = 0.0
        for c in freq:
            if c:
                p = c / n
                e -= p * math.log2(p)
        return round(e, 3)
    except Exception:
        return 0.0


# ── YARA loading ──────────────────────────────────────────────────────────────

_yara_rules = None
_yara_loaded = False
_yara_available = False

# ── YARA ruleset version ──────────────────────────────────────────────────
# Bump this whenever _DEFAULT_YARA_RULES changes. On startup the rules file
# on disk is checked for a matching `// VERSION: N` marker — if missing or
# older, the file is overwritten with the new ruleset AND stale yara hits
# in file_scan_results (whose rule names are no longer in the new ruleset)
# are wiped. Without this the OLD broken rules persist on disk forever and
# stale hits keep showing up in reports.
YARA_RULES_VERSION = 2


def _load_yara():
    global _yara_rules, _yara_loaded, _yara_available
    if _yara_loaded:
        return
    _yara_loaded = True
    try:
        import yara
        _yara_available = True
    except ImportError:
        log.warning("yara-python not installed. File scanner runs without YARA matching.")
        return

    # Rule directory
    rules_dir = Path(__file__).parent.parent.parent / "rules" / "yara"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # ── Refresh rules file if the on-disk version is older than the code ──
    default_rule_path = rules_dir / "malware.yar"
    version_header    = f"// VERSION: {YARA_RULES_VERSION}\n"

    needs_refresh = True
    if default_rule_path.exists():
        try:
            existing = default_rule_path.read_text(encoding="utf-8", errors="ignore")
            if existing.startswith(version_header):
                needs_refresh = False
        except Exception:
            needs_refresh = True

    if needs_refresh:
        default_rule_path.write_text(version_header + _DEFAULT_YARA_RULES, encoding="utf-8")
        log.info(
            f"YARA rules refreshed to version {YARA_RULES_VERSION}: {default_rule_path}"
        )
        # Wipe stale hits from prior rule versions so reports show clean state
        try:
            _clear_stale_yara_hits()
        except Exception as e:
            log.warning(f"Could not clear stale YARA hits: {e}")

    # Compile all .yar files
    yar_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not yar_files:
        log.warning("No YARA rule files found in rules/yara/")
        return

    try:
        import yara
        filepaths = {f.stem: str(f) for f in yar_files}
        _yara_rules = yara.compile(filepaths=filepaths)
        log.info(f"YARA: compiled {len(yar_files)} rule file(s) from {rules_dir}")
    except Exception as e:
        log.error(f"YARA compile error: {e}")
        _yara_rules = None


# Names of every rule defined in _DEFAULT_YARA_RULES v2. Anything in the
# file_scan_results table that references a different rule is from an
# earlier ruleset and should be wiped on upgrade.
_CURRENT_RULE_NAMES = {
    "UPX_Packed_Binary",
    "MPRESS_Packed_Binary",
    "Themida_VMProtect_Packed",
    "ASPack_Packed_Binary",
    "Mimikatz_Binary",
    "Cobalt_Strike_Beacon",
    "Ransomware_Note_Indicators",
    "RAT_Common_Strings",
    "PowerShell_Download_Cradle",
    "PowerShell_Encoded_Command",
    "PowerShell_AMSI_Bypass",
    "Suspicious_VBScript_Dropper",
    "Suspicious_Batch_LOLbin",
    "LNK_Powershell_Launcher",
}


def _clear_stale_yara_hits():
    """Clear YARA hits in the DB whose rule names are NOT in the current ruleset.

    Returns count of rows cleared. Idempotent.
    """
    from database.db import get_conn
    placeholders = ",".join("?" for _ in _CURRENT_RULE_NAMES)
    if not _CURRENT_RULE_NAMES:
        return 0
    conn = get_conn()
    c    = conn.cursor()
    # Clear stale file_scan_results rows (set yara_matched=0 for old rule names)
    try:
        c.execute(
            f"UPDATE file_scan_results "
            f"SET yara_matched=0, yara_rule='', yara_severity='' "
            f"WHERE yara_matched=1 AND yara_rule NOT IN ({placeholders})",
            tuple(_CURRENT_RULE_NAMES),
        )
        n1 = c.rowcount or 0
    except Exception:
        n1 = 0

    # Clear stale Sysmon-side YARA columns (best-effort — table may not exist)
    try:
        c.execute(
            f"UPDATE logs_sysmon "
            f"SET yara_matched=0, yara_rule='', yara_severity='' "
            f"WHERE yara_matched=1 AND yara_rule NOT IN ({placeholders})",
            tuple(_CURRENT_RULE_NAMES),
        )
        n2 = c.rowcount or 0
    except Exception:
        n2 = 0

    conn.commit()
    conn.close()
    total = n1 + n2
    if total > 0:
        log.info(f"Cleared {total} stale YARA hit(s) from prior rule versions "
                 f"(file_scan_results={n1}, logs_sysmon={n2})")
    return total


def clear_file_scan_record(path: str) -> int:
    """Clear DB rows for a single file path after an Active Response action
    (quarantine / delete) has handled it. Without this the next analysis
    keeps showing the file as a YARA hit even though it's already neutralised.

    Returns total rows affected across all tables.
    """
    from database.db import get_conn
    if not path:
        return 0
    conn = get_conn()
    c    = conn.cursor()
    total = 0
    try:
        c.execute("DELETE FROM file_scan_results WHERE file_path = ?", (path,))
        total += c.rowcount or 0
    except Exception:
        pass
    # Also clear the Sysmon-side flag if the same file was logged via Sysmon EID 11
    try:
        c.execute(
            "UPDATE logs_sysmon SET yara_matched=0, yara_rule='', yara_severity='' "
            "WHERE sysmon_target_file = ?",
            (path,),
        )
        total += c.rowcount or 0
    except Exception:
        pass
    conn.commit()
    conn.close()
    return total


def force_rescan_all() -> dict:
    """Wipe the file scanner's seen-set + cached hits and trigger a fresh
    walk of monitored directories. Used by the UI's "Rescan Files" button.
    """
    from database.db import get_conn
    conn = get_conn()
    c    = conn.cursor()
    try:
        c.execute("DELETE FROM file_scan_results")
        wiped = c.rowcount or 0
    except Exception:
        wiped = 0
    conn.commit()
    conn.close()

    # Reset the singleton's seen set so the next poll re-scans everything.
    try:
        scanner = get_file_scanner()
        if not scanner._dirs:
            scanner._dirs = _monitored_dirs()
        with scanner._lock:
            scanner._seen.clear()
            scanner._files_scanned = 0
            scanner._yara_hits     = 0
        # Poll synchronously to give an immediate result
        scanner._poll()
        return {
            "ok": True,
            "wiped_rows":     wiped,
            "files_scanned":  scanner._files_scanned,
            "yara_hits":      scanner._yara_hits,
            "dirs":           [str(d) for d in scanner._dirs],
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "wiped_rows": wiped}


_DEFAULT_YARA_RULES = r'''
/*
 * ═════════════════════════════════════════════════════════════════════════
 *  SecureEyeTrust+ YARA ruleset v2 — strict, low-false-positive
 * ─────────────────────────────────────────────────────────────────────────
 *  Each rule has a meta `scope` tag that the Python side uses to decide
 *  which file extensions a rule may match against:
 *
 *      scope = "binary_only"  →  .exe .dll .scr .sys .ocx .cpl
 *      scope = "script_only"  →  .ps1 .psm1 .bat .cmd .txt .ini .vbs .vbe
 *                                .js  .jse  .wsh .hta .wsf
 *      scope = "lnk_only"     →  .lnk
 *      scope = "any"          →  every scanned extension
 *
 *  The previous ruleset had two killer false-positive rules:
 *      - Packed_Executable    — matched every Windows .exe under 5 MB
 *      - Encoded_PowerShell   — matched `-e ` or `-enc ` byte sequences
 *                               inside ANY binary by random chance
 *  Both have been removed/rewritten.
 * ═════════════════════════════════════════════════════════════════════════
 */

/* ── Binary-only rules ─────────────────────────────────────────────────── */

rule UPX_Packed_Binary {
    meta:
        description = "UPX-packed binary (informational — UPX is widely used by legitimate software too)"
        severity    = "LOW"
        scope       = "binary_only"
        mitre       = "T1027.002"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx_sig = "$Info: This file is packed with the UPX" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($upx0, $upx1, $upx2) or $upx_sig)
}

rule MPRESS_Packed_Binary {
    meta:
        description = "MPRESS packer — sometimes legitimate, often malicious"
        severity    = "MEDIUM"
        scope       = "binary_only"
        mitre       = "T1027.002"
    strings:
        $a = ".MPRESS1" ascii
        $b = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Themida_VMProtect_Packed {
    meta:
        description = "Themida or VMProtect — strong malware indicator (these packers are almost never used by legitimate software)"
        severity    = "HIGH"
        scope       = "binary_only"
        mitre       = "T1027.002"
    strings:
        $themida = ".themida" ascii
        $tmd_str = "Themida" ascii wide
        $vmp0    = ".vmp0" ascii
        $vmp1    = ".vmp1" ascii
        $vmp2    = ".vmp2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule ASPack_Packed_Binary {
    meta:
        description = "ASPack packer — frequently used by malware"
        severity    = "MEDIUM"
        scope       = "binary_only"
        mitre       = "T1027.002"
    strings:
        $a = ".aspack" ascii
        $b = ".adata" ascii
        $c = "aPLib v" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Mimikatz_Binary {
    meta:
        description = "Mimikatz credential-theft tool"
        severity    = "CRITICAL"
        scope       = "binary_only"
        mitre       = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" nocase ascii wide
        $b = "sekurlsa::pth" nocase ascii wide
        $c = "kerberos::list" nocase ascii wide
        $d = "lsadump::sam" nocase ascii wide
        $e = "mimikatz" nocase ascii wide
        $f = "privilege::debug" nocase ascii wide
        $g = "gentilkiwi" nocase ascii wide
        $h = "Benjamin DELPY" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Cobalt Strike beacon markers"
        severity    = "CRITICAL"
        scope       = "binary_only"
        mitre       = "T1055"
    strings:
        $b1 = "beacon.x64.dll" ascii nocase
        $b2 = "beacon.dll" ascii nocase
        $b3 = "ReflectiveLoader" ascii
        $b4 = "%s as %s\\%s: %d" ascii wide
        $b5 = "Could not connect to pipe" ascii
        $b6 = "(admin)" ascii  /* Beacon's admin marker — weak alone */
    condition:
        uint16(0) == 0x5A4D and 2 of ($b1, $b2, $b3, $b4, $b5)
}

rule Ransomware_Note_Indicators {
    meta:
        description = "Strings characteristic of ransomware ransom notes / binaries"
        severity    = "CRITICAL"
        scope       = "any"
        mitre       = "T1486"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" nocase ascii wide
        $b = "HOW TO DECRYPT" nocase ascii wide
        $c = "send us .* bitcoin" nocase ascii wide
        $d = "DECRYPT_INSTRUCTIONS" nocase ascii wide
        $e = "your personal ID" nocase ascii wide
        $f = "all your data has been locked" nocase ascii wide
        $g = "tor browser to contact us" nocase ascii wide
        $h = ".onion" ascii wide
    condition:
        3 of them
}

rule RAT_Common_Strings {
    meta:
        description = "Common RAT (njRAT / DarkComet / AsyncRAT / QuasarRAT) strings"
        severity    = "HIGH"
        scope       = "binary_only"
        mitre       = "T1219"
    strings:
        $a = "njRAT" ascii wide
        $b = "DarkComet" ascii wide
        $c = "AsyncRAT" ascii wide
        $d = "QuasarRAT" ascii wide
        $e = "RemoteShell" ascii wide
        $f = "ddoser" ascii wide nocase
        $g = "Keylogger" ascii wide nocase
        $h = "ScreenCapture" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

/* ── Script-only rules ─────────────────────────────────────────────────── */

rule PowerShell_Download_Cradle {
    meta:
        description = "PowerShell download-and-execute (Invoke-Expression on remote content)"
        severity    = "HIGH"
        scope       = "script_only"
        mitre       = "T1059.001"
    strings:
        /* Group A: a network fetch primitive */
        $a1 = "DownloadString" nocase
        $a2 = "DownloadFile"   nocase
        $a3 = "Invoke-WebRequest" nocase
        $a4 = "Net.WebRequest" nocase
        /* Group B: an HTTP client */
        $b1 = "WebClient"      nocase
        $b2 = "Net.WebClient"  nocase
        $b3 = "HttpClient"     nocase
        /* Group C: an execution sink */
        $c1 = "Invoke-Expression" nocase
        $c2 = "IEX("           nocase
        $c3 = "iex "           nocase
        $c4 = ".Invoke()"      nocase
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}

rule PowerShell_Encoded_Command {
    meta:
        description = "PowerShell -EncodedCommand with a long base64 blob (obfuscation)"
        severity    = "HIGH"
        scope       = "script_only"
        mitre       = "T1027"
    strings:
        $ps           = "powershell" nocase
        $enc1         = "-EncodedCommand" nocase
        $enc2         = " -enc "          nocase
        $enc3         = " -ec "           nocase
        /* Require a long uninterrupted base64 blob — random binary
           bytes will almost never produce 120 consecutive base64 chars. */
        $base64_long  = /[A-Za-z0-9\+\/]{120,}={0,2}/
    condition:
        $ps and any of ($enc1, $enc2, $enc3) and $base64_long
}

rule PowerShell_AMSI_Bypass {
    meta:
        description = "PowerShell AMSI bypass attempt"
        severity    = "CRITICAL"
        scope       = "script_only"
        mitre       = "T1562.001"
    strings:
        $a = "amsiInitFailed" nocase
        $b = "AmsiUtils"      nocase
        $c = "amsi.dll"       nocase
        $d = "[Ref].Assembly.GetType" nocase
        $e = "System.Management.Automation.AmsiUtils" nocase
    condition:
        2 of them
}

rule Suspicious_VBScript_Dropper {
    meta:
        description = "Suspicious VBScript dropper (combo of shell + network + execute)"
        severity    = "HIGH"
        scope       = "script_only"
        mitre       = "T1059.005"
    strings:
        $a = "WScript.Shell"   nocase
        $b = "ADODB.Stream"    nocase
        $c = "MSXML2.XMLHTTP"  nocase
        $d = "Shell.Application" nocase
        $e = "powershell"      nocase
        $f = "cmd.exe"         nocase
        $g = "winmgmts:"       nocase
        $h = "Scripting.FileSystemObject" nocase
        $i = ".Run "           nocase
    condition:
        4 of them
}

rule Suspicious_Batch_LOLbin {
    meta:
        description = "Batch / cmd script abusing multiple Living-Off-The-Land binaries"
        severity    = "MEDIUM"
        scope       = "script_only"
        mitre       = "T1218"
    strings:
        $a = "certutil -urlcache"  nocase
        $b = "certutil -decode"    nocase
        $c = "bitsadmin /transfer" nocase
        $d = "powershell -nop"     nocase
        $e = "powershell -w hidden" nocase
        $f = "mshta "              nocase
        $g = "regsvr32 /s /n /u /i:http" nocase
        $h = "schtasks /create"    nocase
        $i = "reg add HKLM"        nocase
        $j = "wmic process call create" nocase
    condition:
        3 of them
}

/* ── LNK-only rule ─────────────────────────────────────────────────────── */

rule LNK_Powershell_Launcher {
    meta:
        description = "Shortcut (.lnk) pointing at powershell/cmd with hidden/encoded args"
        severity    = "HIGH"
        scope       = "lnk_only"
        mitre       = "T1547.009"
    strings:
        $ps    = "powershell" nocase wide ascii
        $cmd   = "cmd.exe"    nocase wide ascii
        $enc   = "-EncodedCommand" nocase wide ascii
        $nop   = "-nop"       nocase wide ascii
        $hidd  = "hidden"     nocase wide ascii
        $bypass= "-ExecutionPolicy Bypass" nocase wide ascii
    condition:
        ($ps or $cmd) and 2 of ($enc, $nop, $hidd, $bypass)
}
'''


# ── Extension gating for YARA rules ──────────────────────────────────────────
# Map each file extension to the rule scope(s) that may match it. Anything
# else is silently ignored. This is what kept WinRAR / VLC / WhatsApp from
# matching the script-context rules in the previous design — those rules
# can no longer fire against binaries.
_RULE_SCOPE_FOR_EXT = {
    ".exe":  ("binary_only", "any"),
    ".dll":  ("binary_only", "any"),
    ".scr":  ("binary_only", "any"),
    ".sys":  ("binary_only", "any"),
    ".ocx":  ("binary_only", "any"),
    ".cpl":  ("binary_only", "any"),
    ".pif":  ("binary_only", "any"),

    ".ps1":  ("script_only", "any"),
    ".psm1": ("script_only", "any"),
    ".bat":  ("script_only", "any"),
    ".cmd":  ("script_only", "any"),
    ".vbs":  ("script_only", "any"),
    ".vbe":  ("script_only", "any"),
    ".js":   ("script_only", "any"),
    ".jse":  ("script_only", "any"),
    ".wsh":  ("script_only", "any"),
    ".wsf":  ("script_only", "any"),
    ".hta":  ("script_only", "any"),
    ".txt":  ("script_only", "any"),

    ".lnk":  ("lnk_only",    "any"),
}


# ── Trusted-publisher / known-installer filename allowlist ──────────────────
# These name fragments mark widely-distributed legitimate installers that
# regularly match generic packer/heuristic rules by coincidence. A YARA hit
# on a file whose name fragment is in this list will be downgraded to "LOW"
# and only reported if it's the CRITICAL Mimikatz / Cobalt / Ransomware kind.
#
# This is INTENTIONALLY conservative — it doesn't suppress real malware
# rules (Mimikatz, Cobalt, Ransomware notes, Themida, AMSI bypass); it only
# suppresses informational / weak-confidence rules on known-good installers.
_TRUSTED_INSTALLER_FRAGMENTS = (
    # Compression / archivers
    "winrar", "7z", "winzip",
    # Browsers
    "chrome", "firefox", "edge", "opera", "brave",
    # Comms / collaboration
    "whatsapp", "slack", "discord", "zoom", "teams", "skype", "signal", "telegram",
    # Media
    "vlc", "obs-studio", "spotify", "audacity", "handbrake",
    # Microsoft signed installers / runtimes
    "vc_redist", "vcredist", "vc_runtime", "dotnet", ".net", "ndp", "wmf",
    "msoffice", "officesetup", "onedrive", "msteams",
    "powertoys", "windowsterminal", "winget",
    # Dev tools
    "vscode", "vs_buildtools", "vs_community", "vs_professional",
    "jetbrains", "pycharm", "webstorm", "intellij", "clion", "rider",
    "git-", "github", "node-", "nodejs", "python-3", "rustup",
    # Common consumer apps
    "logexpert", "notepad", "putty", "winscp", "filezilla", "etcher",
    "iobit", "ccleaner",                 # widely-used cleaners
    "adobe", "acrobat", "creativecloud", # Adobe family
    "uniconverter", "imageeraser",       # Wondershare suite from the screenshot
    # Steam / Epic / game launchers
    "steam", "epicgames", "battle.net", "uplay", "origin",
    # Java / runtimes
    "jdk-", "jre-", "openjdk", "oracle",
    # Suffixes that strongly imply "installer"
    "-setup", "_setup", "setup-", "setup_",
    "installer", "-install", "_install",
)

# Rules whose match is strong enough to override the trusted-installer
# allowlist (true malware indicators — never suppress these).
_HIGH_CONFIDENCE_RULES = {
    "Mimikatz_Binary",
    "Cobalt_Strike_Beacon",
    "Ransomware_Note_Indicators",
    "Themida_VMProtect_Packed",
    "PowerShell_AMSI_Bypass",
    "RAT_Common_Strings",
}


def _ext_scopes(path: Path) -> tuple:
    """Return the YARA rule scopes that may match this file extension.
    Empty tuple means: don't scan this file."""
    return _RULE_SCOPE_FOR_EXT.get(path.suffix.lower(), ())


def _is_trusted_installer(path: Path) -> bool:
    """Check whether the filename matches a known-good installer fragment."""
    name = path.name.lower()
    return any(frag in name for frag in _TRUSTED_INSTALLER_FRAGMENTS)


def _yara_scan(path: Path) -> tuple[bool, str, str]:
    """
    Returns (matched, rule_name, severity).

    v2 — applies two layers of false-positive suppression:

      1. **Extension gating.** A rule may only match a file whose extension
         is compatible with the rule's `scope` meta. Script-context rules
         (PowerShell / VBScript / batch) cannot match against binaries even
         if random byte sequences happen to look like script strings —
         which was the root cause of WinRAR/VLC/WhatsApp being flagged as
         "Encoded_PowerShell" or "Packed_Executable" before.

      2. **Trusted-installer allowlist.** A weak / informational hit
         (UPX_Packed_Binary, MPRESS_Packed_Binary, etc.) on a file whose
         name fragment matches a known-legitimate installer (winrar, vlc,
         whatsapp, vcredist, dotnet, etc.) is suppressed. Strong rules —
         Mimikatz, Cobalt Strike, ransomware notes, Themida, AMSI bypass —
         are *never* suppressed by the allowlist.
    """
    if not _yara_available or _yara_rules is None:
        return False, "", ""

    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return False, "", ""

        # Scope filter — skip entirely when the extension is unknown.
        allowed_scopes = _ext_scopes(path)
        if not allowed_scopes:
            return False, "", ""

        matches = _yara_rules.match(str(path))
        if not matches:
            return False, "", ""

        # Filter matches by scope compatibility, then severity-sort.
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        eligible = []
        for m in matches:
            scope = m.meta.get("scope", "any")
            if scope not in allowed_scopes:
                continue  # rule not applicable to this file type
            eligible.append(m)

        if not eligible:
            return False, "", ""

        # Pick the highest-severity eligible match
        eligible.sort(
            key=lambda m: severity_order.get(
                m.meta.get("severity", "MEDIUM"), 2
            ),
            reverse=True,
        )
        best = eligible[0]
        sev  = best.meta.get("severity", "MEDIUM")
        rule = best.rule

        # Trusted-installer allowlist suppression
        if rule not in _HIGH_CONFIDENCE_RULES and _is_trusted_installer(path):
            log.debug(
                f"[YARA] suppressed weak rule '{rule}' on trusted installer: {path.name}"
            )
            return False, "", ""

        return True, rule, sev

    except Exception as e:
        log.debug(f"YARA scan error {path}: {e}")
        return False, "", ""


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_scan_table():
    try:
        from database.db import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_scan_results (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at   TEXT,
                file_path    TEXT,
                file_name    TEXT,
                extension    TEXT,
                file_size    INTEGER,
                sha256       TEXT,
                entropy      REAL,
                directory    TEXT,
                yara_matched INTEGER DEFAULT 0,
                yara_rule    TEXT,
                yara_severity TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fscan_time ON file_scan_results(scanned_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fscan_hash ON file_scan_results(sha256)")
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"file_scan table init: {e}")


def _record_scan(path: Path, sha256: str, entropy: float,
                 yara_matched: bool, yara_rule: str, yara_severity: str):
    try:
        from database.db import get_conn
        conn = get_conn()
        stat = path.stat()
        conn.execute("""
            INSERT OR IGNORE INTO file_scan_results
                (scanned_at, file_path, file_name, extension, file_size,
                 sha256, entropy, directory, yara_matched, yara_rule, yara_severity)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            str(path), path.name, path.suffix.lower(),
            stat.st_size, sha256, entropy,
            str(path.parent),
            1 if yara_matched else 0,
            yara_rule, yara_severity,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.debug(f"record_scan error: {e}")


def _push_yara_alert(path: Path, sha256: str, rule: str, severity: str):
    try:
        from core.pipeline.alert_bus import get_alert_bus
        get_alert_bus().push({
            "type":        "yara_match",
            "severity":    severity,
            "category":    "malware",
            "title":       f"YARA: {rule} — {path.name}",
            "description": f"YARA rule '{rule}' matched in {path}. SHA256: {sha256[:16]}…",
            "risk_score":  85 if severity == "CRITICAL" else 65,
            "source":      "FileScanner",
            "file_path":   str(path),
            "sha256":      sha256,
            "yara_rule":   rule,
        })
    except Exception:
        pass


# ── Scanner state ─────────────────────────────────────────────────────────────

class FileScanner:
    """
    Polls monitored directories every 5 seconds.
    Tracks seen files by path+mtime to detect new arrivals.
    Scans new files with YARA and records results in DB.
    """

    def __init__(self):
        self._stop          = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock          = threading.Lock()
        self._seen: dict    = {}      # path_str → mtime
        self._files_scanned = 0
        self._yara_hits     = 0
        self._dirs: list    = []

    def _poll(self):
        for d in self._dirs:
            if not d.exists():
                continue
            try:
                for entry in d.rglob("*"):
                    if not entry.is_file():
                        continue
                    if entry.suffix.lower() not in SCAN_EXTENSIONS:
                        continue
                    try:
                        mtime = entry.stat().st_mtime
                    except Exception:
                        continue
                    key = str(entry)
                    if self._seen.get(key) == mtime:
                        continue
                    self._seen[key] = mtime
                    self._scan_file(entry)
            except PermissionError:
                pass
            except Exception as e:
                log.debug(f"FileScanner dir error {d}: {e}")

    def _scan_file(self, path: Path):
        try:
            sha    = _sha256(path)
            ent    = _entropy(path)
            matched, rule, severity = _yara_scan(path)
            _record_scan(path, sha, ent, matched, rule, severity)
            self._files_scanned += 1
            if matched:
                self._yara_hits += 1
                log.warning(f"[FileScanner] YARA HIT: {rule} ({severity}) — {path.name}")
                _push_yara_alert(path, sha, rule, severity)
            else:
                log.debug(f"[FileScanner] scanned: {path.name}  SHA={sha[:10]}  entropy={ent}")
        except Exception as e:
            log.debug(f"scan_file error {path}: {e}")

    def _loop(self):
        log.info(f"FileScanner started — watching: {[str(d) for d in self._dirs]}")
        _ensure_scan_table()
        _load_yara()
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                log.error(f"FileScanner poll error: {e}")
            self._stop.wait(POLL_INTERVAL)
        log.info(f"FileScanner stopped — {self._files_scanned} files, {self._yara_hits} YARA hits")

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._dirs = _monitored_dirs()
            if not self._dirs:
                log.warning("FileScanner: no monitored directories found")
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="file-scanner"
            )
            self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def stats(self) -> dict:
        return {
            "files_scanned": self._files_scanned,
            "yara_hits":     self._yara_hits,
            "dirs_watched":  [str(d) for d in self._dirs],
            "yara_loaded":   _yara_available and _yara_rules is not None,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_fs_instance: Optional[FileScanner] = None
_fs_lock = threading.Lock()


def get_file_scanner() -> FileScanner:
    global _fs_instance
    if _fs_instance is None:
        with _fs_lock:
            if _fs_instance is None:
                _fs_instance = FileScanner()
    return _fs_instance


# ── Public query helpers (used by perform_analysis_api) ───────────────────────

def get_scan_stats(since_iso: str) -> dict:
    """Return file scan stats for the perform_analysis report."""
    try:
        from database.db import get_conn
        conn = get_conn()
        c    = conn.cursor()

        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_scan_results'")
        if not c.fetchone():
            conn.close()
            return {"available": False}

        c.execute("SELECT COUNT(*) FROM file_scan_results WHERE scanned_at >= ?", (since_iso,))
        total = c.fetchone()[0] or 0

        c.execute("""
            SELECT COUNT(*) FROM file_scan_results
            WHERE scanned_at >= ? AND yara_matched = 1
        """, (since_iso,))
        yara_hits = c.fetchone()[0] or 0

        c.execute("""
            SELECT file_path, file_name, sha256, yara_rule, yara_severity,
                   entropy, file_size, scanned_at
            FROM file_scan_results
            WHERE scanned_at >= ? AND yara_matched = 1
            ORDER BY scanned_at DESC LIMIT 30
        """, (since_iso,))
        hits = []
        for row in c.fetchall():
            hits.append({
                "path":      row[0],
                "filename":  row[1],
                "sha256":    row[2],
                "yara_rule": row[3],
                "severity":  row[4],
                "entropy":   row[5],
                "size":      row[6],
                "scanned_at":row[7],
            })

        # Extension breakdown
        c.execute("""
            SELECT extension, COUNT(*) FROM file_scan_results
            WHERE scanned_at >= ?
            GROUP BY extension ORDER BY COUNT(*) DESC
        """, (since_iso,))
        by_ext = {row[0]: row[1] for row in c.fetchall()}

        # Directory breakdown
        c.execute("""
            SELECT directory, COUNT(*) FROM file_scan_results
            WHERE scanned_at >= ?
            GROUP BY directory ORDER BY COUNT(*) DESC LIMIT 10
        """, (since_iso,))
        by_dir = {row[0]: row[1] for row in c.fetchall()}

        conn.close()
        return {
            "available":    True,
            "total_scanned":total,
            "yara_hits":    yara_hits,
            "yara_matches": hits,
            "by_extension": by_ext,
            "by_directory": by_dir,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}
