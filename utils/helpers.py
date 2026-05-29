"""
utils/helpers.py
================
Shared utility functions used across multiple modules.
"""

from datetime import datetime


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def truncate(s: str, n: int = 200) -> str:
    if not s:
        return ""
    return s[:n] + "…" if len(s) > n else s


def safe_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
