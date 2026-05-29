"""
core/folder_lock/lock_engine.py  —  OneDrive-safe folder locking
"""
import os, sys, subprocess, secrets
from pathlib import Path


def _ps(script: str) -> tuple:
    """Run a PowerShell script, return (success, output)."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=20
        )
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def _cmd(args: list) -> tuple:
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=15, shell=False)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


def _hide(path: Path):
    """Hide a folder — 3 methods for reliability."""
    path_s = str(path)
    # Method 1: attrib
    _cmd(["attrib", "+h", "+s", path_s])
    # Method 2: PowerShell (most reliable on OneDrive paths)
    _ps(f'$p = Get-Item -LiteralPath "{path_s}" -Force; '
        f'$p.Attributes = $p.Attributes -bor '
        f'[System.IO.FileAttributes]::Hidden -bor '
        f'[System.IO.FileAttributes]::System')


def _unhide(path: Path):
    """Remove hidden+system attributes — 3 methods."""
    path_s = str(path)
    _cmd(["attrib", "-h", "-s", path_s])
    _ps(f'$p = Get-Item -LiteralPath "{path_s}" -Force; '
        f'$p.Attributes = $p.Attributes '
        f'-band (-bnot [System.IO.FileAttributes]::Hidden) '
        f'-band (-bnot [System.IO.FileAttributes]::System)')
    _refresh_explorer()


def _refresh_explorer(path: Path = None):
    if sys.platform != "win32":
        return
    try:
        import ctypes
        SHChangeNotify = ctypes.windll.shell32.SHChangeNotify
        SHCNF_PATHW = 0x0005
        SHCNE_UPDATEDIR = 0x00001000
        SHCNE_DISKEVENTS = 0x00023800
        if path is not None:
            SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, str(path), None)
        else:
            SHChangeNotify(SHCNE_DISKEVENTS, SHCNF_PATHW, None, None)
    except Exception:
        pass


def _get_hidden_root(parent: Path) -> Path:
    if sys.platform != "win32":
        root = Path.home() / ".secureeye_hidden"
    else:
        appdata = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if not appdata:
            appdata = str(Path.home() / "AppData" / "Local")
        root = Path(appdata) / "SecureEyeTrust" / "hidden"
        if parent.drive and root.drive != parent.drive:
            root = Path(parent.drive + os.sep) / "SecureEyeTrust" / "hidden"
    try:
        root.mkdir(parents=True, exist_ok=True)
        _hide(root)
    except Exception:
        pass
    return root


def _get_hidden_store(parent: Path) -> Path:
    return _get_hidden_root(parent)


def _find_hidden(parent: Path, name: str) -> Path:
    """
    Find .name.token.locked — uses PowerShell Get-ChildItem -Force
    which sees hidden files even on OneDrive synced paths.
    """
    parent_s = str(parent)
    hidden_store = _get_hidden_store(parent)

    for search_root in [parent, hidden_store]:
        root_s = str(search_root)

        # Method 1: PowerShell (best — sees hidden files on OneDrive)
        ok, out = _ps(
            f'Get-ChildItem -LiteralPath "{root_s}" -Force | '
            f'Where-Object {{ $_.Name -like ".{name}.*.locked" }} | '
            f'Select-Object -ExpandProperty Name'
        )
        if ok and out.strip():
            for line in out.strip().splitlines():
                line = line.strip()
                if line.startswith(f".{name}.") and line.endswith(".locked"):
                    return search_root / line

        # Method 2: cmd dir /a:h (fallback)
        try:
            r = subprocess.run(
                ["cmd", "/c", f'dir /a:h /b "{root_s}"'],
                capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith(f".{name}.") and line.endswith(".locked"):
                    return search_root / line
        except Exception:
            pass

        # Method 3: pathlib iterdir (last resort)
        try:
            for p in search_root.iterdir():
                if p.name.startswith(f".{name}.") and p.name.endswith(".locked"):
                    return p
        except Exception:
            pass

    return None


def _cleanup_old_files(parent: Path, name: str):
    """Delete leftover .vbs/.lnk/.bat files."""
    for suffix in [".lnk", ".bat"]:
        p = parent / f"{name}{suffix}"
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass

    # Hidden .vbs via PowerShell
    ok, out = _ps(
        f'Get-ChildItem -LiteralPath "{parent}" -Force | '
        f'Where-Object {{ $_.Name -like ".{name}_*.vbs" -or '
        f'$_.Name -like ".{name}.*.vbs" }} | '
        f'Select-Object -ExpandProperty FullName'
    )
    if ok and out.strip():
        for line in out.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    _unhide(Path(line))
                    Path(line).unlink()
                except Exception:
                    pass


def _token_from(hidden_name: str, name: str) -> str:
    try:
        parts = hidden_name.split(".")
        return parts[-2] if len(parts) >= 4 else "0000"
    except Exception:
        return "0000"


# ─────────────────────────────────────────────────────────────
def lock_folder(folder_path: str, app_port: int = 5000) -> dict:
    if sys.platform != "win32":
        return {"ok": False, "error": "Windows only"}

    folder = Path(folder_path)
    parent = folder.parent
    name   = folder.name

    # Clean up old shortcut junk
    _cleanup_old_files(parent, name)

    # Already locked?
    if not folder.is_dir():
        hidden = _find_hidden(parent, name)
        if hidden:
            return {"ok": True, "already_locked": True,
                    "hidden_path": str(hidden), "shortcut_path": "",
                    "token": _token_from(hidden.name, name), "acl_backup": "",
                    "message": f'"{name}" is already locked.'}
        return {"ok": False, "error": f"Folder not found: {folder_path}"}

    # Restore any old hidden version first
    old = _find_hidden(parent, name)
    if old:
        try:
            _unhide(old)
            old.rename(folder_path)
        except Exception:
            pass

    token        = secrets.token_hex(4)
    hidden_name  = f".{name}.{token}.locked"
    hidden_store = _get_hidden_store(parent)
    hidden_path  = hidden_store / hidden_name

    try:
        hidden_store.mkdir(exist_ok=True)
        _hide(hidden_store)
    except Exception:
        pass

    # Rename into hidden store
    try:
        Path(folder_path).rename(hidden_path)
    except Exception as e:
        return {"ok": False, "error": f"Cannot rename folder: {e}"}

    # Hide moved folder
    _hide(hidden_path)
    _refresh_explorer(parent)

    print(f"[lock_engine] LOCKED: {folder_path} → {hidden_path}")
    return {"ok": True, "hidden_path": str(hidden_path),
            "shortcut_path": "", "token": token, "acl_backup": "",
            "message": f'"{name}" is now hidden.'}


# ─────────────────────────────────────────────────────────────
def unlock_folder(folder_path: str, hidden_path: str = None,
                  token: str = None) -> dict:
    if sys.platform != "win32":
        return {"ok": False, "error": "Windows only"}

    folder = Path(folder_path)
    parent = folder.parent
    name   = folder.name

    # Find hidden folder
    if not hidden_path:
        hidden = _find_hidden(parent, name)
        if hidden:
            hidden_path = str(hidden)

    if not hidden_path:
        return {"ok": False, "error": f"Hidden folder not found for: {name}"}

    hp = Path(hidden_path)

    # Verify it exists (PowerShell can see hidden items)
    ok, out = _ps(f'Test-Path -LiteralPath "{hp}" -PathType Container')
    exists = ok and "True" in out
    if not exists and not hp.exists():
        return {"ok": False, "error": f"Hidden path does not exist: {hidden_path}"}

    # 1. Remove hidden attributes
    _unhide(hp)

    # 2. Restore NTFS access for current user (in case it was denied before)
    user = os.environ.get("USERNAME", "")
    if user:
        _cmd(["icacls", str(hp), "/remove:d", "Everyone", "/T", "/C"])
        _cmd(["icacls", str(hp), "/grant", f"{user}:(OI)(CI)F", "/T", "/C"])

    # 3. Rename back — try 4 different methods
    renamed = False

    # Method A: PowerShell Rename-Item
    ok, out = _ps(f'Rename-Item -LiteralPath "{hp}" -NewName "{name}" -Force')
    if ok:
        renamed = True

    # Method B: cmd move
    if not renamed:
        ok2, out2 = _cmd(["cmd", "/c", f'move /Y "{hp}" "{folder_path}"'])
        if ok2:
            renamed = True

    # Method C: Python rename
    if not renamed:
        try:
            hp.rename(folder_path)
            renamed = True
        except Exception:
            pass

    # Method D: PowerShell Move-Item
    if not renamed:
        ok4, out4 = _ps(f'Move-Item -LiteralPath "{hp}" -Destination "{folder_path}" -Force')
        renamed = ok4

    if not renamed:
        return {"ok": False, "error": f"Cannot restore folder — tried 4 methods. PS error: {out}"}

    _refresh_explorer(parent)
    print(f"[lock_engine] UNLOCKED: {hidden_path} → {folder_path}")
    return {"ok": True}


def open_folder_in_explorer(folder_path: str):
    try:
        if sys.platform == "win32":
            os.startfile(folder_path)
    except Exception:
        pass
