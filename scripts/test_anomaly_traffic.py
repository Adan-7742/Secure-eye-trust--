#!/usr/bin/env python3
"""
test_anomaly_traffic.py
=======================
Opens a controlled set of suspicious-looking network connections to local
sink IPs so the Network Analyzer's Anomaly Detection scanner has real data
to find when you click "Scan Now".

Two ways to run it:

    # Foreground (you'll see what happens):
    python test_anomaly_traffic.py

    # Background daemon (silent, managed by test_payloads.py):
    python test_payloads.py deploy --traffic

When daemon-managed, this script writes its PID to ~/.set_test_anomaly.pid
and runs silently. `test_payloads.py remove --traffic` reads that PID and
terminates the process, which closes every socket cleanly.

Triggers all of these built-in detection methods:

  • suspicious_port    – conns to Metasploit 4444, IRC 6667, Netbus 12345, etc.
  • port_scan          – ≥ 8 ports targeted on the same sink IP
  • syn_flood          – 30 half-open SYN_SENT connections
  • connection_spike   – 80+ active connections (well above baseline)
  • beaconing          – 15 connections to one public IP (RFC 5737 reserved)

No real host is touched. Targets are RFC 1918 / 5737 reserved IPs that don't
route to a live machine. Every SYN sits in SYN_SENT and times out.

Flags:
  --subnet 192.168.0    Private /24 subnet to use (default: 192.168.0)
  --short               Don't auto-refresh; exit after one wave (~60s)
  --skip-beacon         Skip the public-IP beaconing pattern
  --verbose             Log every socket open / close
  --quiet               Suppress all output (used when run as a daemon)
"""

import argparse
import os
import signal
import socket
import sys
import time
from pathlib import Path


PID_FILE = Path.home() / ".set_test_anomaly.pid"


# ─────────────────────────────────────────────────────────────────────────────
# What we send.  Keep these in sync with _THREAT_PORTS in api/network_api.py.
# ─────────────────────────────────────────────────────────────────────────────

# Ports the detector explicitly recognises → one "suspicious_port" alert each.
THREAT_PORTS = [
    4444,    # Metasploit default
    1337,    # Common backdoor / leet
    31337,   # Back Orifice
    6667,    # IRC (botnet C2)
    9001,    # Tor
    23,      # Telnet
    12345,   # Netbus
    27374,   # Sub7
    5555,    # ADB / RAT
]

# 12 distinct ports targeted at ONE sink IP → triggers "port_scan" (needs ≥8).
SCAN_PORTS = [80, 443, 22, 21, 25, 8080, 3306, 5432, 6379, 8443, 5984, 27017]

# 30 half-open conns to random high ports → triggers "syn_flood" (needs >20).
SYN_FLOOD_COUNT = 30

# Public sink for beaconing (must NOT be in 10/172/192.168 — those are
# private and the detector filters them out). 198.51.100.0/24 is TEST-NET-2,
# reserved by RFC 5737 for documentation. No real host responds.
PUBLIC_SINK    = "198.51.100.5"
BEACON_PORT    = 443
BEACON_COUNT   = 15

# Auto-refresh interval. Windows times SYN_SENT out around 21s; Linux about
# 75s. Reopening every 15s keeps every wave visible in psutil.
REFRESH_INTERVAL = 15


# ─────────────────────────────────────────────────────────────────────────────

def open_socket(ip: str, port: int, verbose: bool = False):
    """Open a non-blocking TCP socket that will sit in SYN_SENT.

    We use setblocking(False) + connect() so connect() returns immediately
    with BlockingIOError. The OS keeps the SYN going in the background and
    the socket shows up in `psutil.net_connections()` with status SYN_SENT
    until it times out.

    Returns the socket object so the caller can hold a reference (without
    one, Python's GC closes it and the SYN_SENT entry disappears from
    psutil).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((ip, port))
        except BlockingIOError:
            pass   # expected — connect happens asynchronously now
        except OSError as e:
            # Some routes return "Network is unreachable" instantly. That's
            # still fine; we keep the socket so it shows up in the count.
            if verbose:
                print(f"   note: {ip}:{port} → {e.__class__.__name__}")
        if verbose:
            print(f"   opened  {ip}:{port}")
        return s
    except Exception as e:
        print(f"   ! failed {ip}:{port} — {e}", file=sys.stderr)
        return None


def fire_wave(subnet: str, skip_beacon: bool, verbose: bool):
    """Open one complete set of suspicious connections. Returns the list of
    sockets so the caller can hold them (and close them later)."""

    sink_ip = f"{subnet}.50"
    held    = []

    # 1. Threat ports
    for p in THREAT_PORTS:
        s = open_socket(sink_ip, p, verbose)
        if s: held.append(s)

    # 2. Port-scan pattern: many distinct ports targeted at the SAME ip
    for p in SCAN_PORTS:
        s = open_socket(sink_ip, p, verbose)
        if s: held.append(s)

    # 3. SYN flood: many random high ports, half-open
    for i in range(SYN_FLOOD_COUNT):
        s = open_socket(sink_ip, 50_000 + i, verbose)
        if s: held.append(s)

    # 4. Connection spike: also touch several other IPs in the same /24 so
    #    the total connection count clears the 50-conn threshold easily.
    for i in range(30):
        s = open_socket(f"{subnet}.{60 + i}", 80 + (i % 50), verbose)
        if s: held.append(s)

    # 5. Beaconing (public IP, not private). Skipped with --skip-beacon.
    if not skip_beacon:
        for _ in range(BEACON_COUNT):
            s = open_socket(PUBLIC_SINK, BEACON_PORT, verbose)
            if s: held.append(s)

    return held


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--subnet", default="192.168.0",
                    help="Private /24 subnet prefix (default: 192.168.0)")
    ap.add_argument("--short", action="store_true",
                    help="Open once, hold for 60s, then exit")
    ap.add_argument("--skip-beacon", action="store_true",
                    help="Skip the public-IP beaconing pattern (no beaconing alert)")
    ap.add_argument("--verbose", action="store_true",
                    help="Print every socket open")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress all output (used when run as a daemon)")
    args = ap.parse_args()

    # Write our PID so test_payloads.py remove can find us
    try:
        PID_FILE.write_text(str(os.getpid()))
    except Exception:
        pass

    held: list = []

    def _emit(line: str = ""):
        if not args.quiet:
            print(line)

    def _cleanup_and_exit(signum=None, frame=None):
        _emit()
        _emit("  ⏹  signal received — releasing sockets…")
        for s in held:
            try: s.close()
            except Exception: pass
        try: PID_FILE.unlink()
        except Exception: pass
        sys.exit(0)

    # Catch SIGTERM (sent by test_payloads.py remove) and SIGINT (Ctrl+C)
    try:
        signal.signal(signal.SIGTERM, _cleanup_and_exit)
        signal.signal(signal.SIGINT,  _cleanup_and_exit)
    except (ValueError, AttributeError):
        # Some embedded interpreters disallow signal handlers
        pass

    _emit("=" * 74)
    _emit(" Secure Eye Trust+ — Anomaly Detector Test Harness")
    _emit("=" * 74)
    _emit(f"   PID             : {os.getpid()}  ({PID_FILE})")
    _emit(f"   Local sink IP   : {args.subnet}.50")
    _emit(f"   Subnet          : {args.subnet}.0/24")
    _emit(f"   Public sink IP  : {PUBLIC_SINK} "
          f"({'skipped' if args.skip_beacon else 'will be used for beaconing'})")
    _emit(f"   Refresh interval: every {REFRESH_INTERVAL}s "
          f"({'disabled — single wave' if args.short else 'enabled'})")
    _emit()

    _emit("→ Opening initial wave of sockets…")
    held = fire_wave(args.subnet, args.skip_beacon, args.verbose and not args.quiet)
    time.sleep(1)
    _emit(f"✓ {len(held)} sockets opened and held in SYN_SENT.")
    _emit()

    # Expected-alerts cheat-sheet
    sink_ip = f"{args.subnet}.50"
    _emit("┌─ EXPECTED ALERTS WHEN YOU CLICK 'Scan Now' ──────────────────────────┐")
    _emit(f"│ • Suspicious port (×{len(THREAT_PORTS)})  4444, 1337, 31337, 6667, 23, …          │")
    _emit(f"│ • Port scan from {sink_ip:<20}                              │")
    _emit(f"│ • SYN flood  ({SYN_FLOOD_COUNT} half-open connections)                       │")
    _emit(f"│ • Connection spike  (>{len(held)} active sockets)                       │")
    if not args.skip_beacon:
        _emit(f"│ • Beaconing to {PUBLIC_SINK:<20}                              │")
    _emit("└──────────────────────────────────────────────────────────────────────┘")
    _emit()
    _emit("→ Now open the UI:")
    _emit("    Network Analyzer  →  Anomaly Detection  →  Scan Now")
    _emit()

    if args.short:
        _emit(f"  (--short) Holding for 60 seconds then exiting.")
        time.sleep(60)
    else:
        _emit(f"  Auto-refresh every {REFRESH_INTERVAL}s — sockets stay live until you stop.")
        _emit(f"  Press Ctrl+C when you're done.")
        _emit()
        try:
            wave_n = 1
            while True:
                time.sleep(REFRESH_INTERVAL)
                # Tear down the previous wave and fire a fresh one.
                for s in held:
                    try: s.close()
                    except Exception: pass
                wave_n += 1
                held = fire_wave(args.subnet, args.skip_beacon,
                                  args.verbose and not args.quiet)
                _emit(f"  refresh #{wave_n} @ {time.strftime('%H:%M:%S')} "
                      f"— {len(held)} sockets active")
        except KeyboardInterrupt:
            _emit()
            _emit("  ⏹  Ctrl+C — releasing sockets…")

    # Clean up
    for s in held:
        try: s.close()
        except Exception: pass
    try: PID_FILE.unlink()
    except Exception: pass
    _emit(f"✓ Closed {len(held)} sockets. Done.")


if __name__ == "__main__":
    main()
