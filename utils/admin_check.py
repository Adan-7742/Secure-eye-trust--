"""
utils/admin_check.py
=====================
Check if LogVault is running with Windows Administrator privileges.
Required for reading the Security Event Log.
"""

import ctypes
import sys


def is_admin() -> bool:
    """
    Returns True if the current process has Administrator privileges.
    Uses Windows API: shell32.IsUserAnAdmin()
    Always returns False on non-Windows systems.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Not on Windows
        return False
    except Exception:
        return False
