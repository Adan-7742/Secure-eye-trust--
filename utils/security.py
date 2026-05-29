"""
utils/security.py
==================
Input validation, sanitization, and security utilities.

Used by all API endpoints to validate and clean incoming data
before it reaches the database or processing pipeline.

PRINCIPLES:
  - Allowlist over denylist (define what IS valid, reject everything else)
  - Fail closed (reject on doubt)
  - Never trust client input
  - Log all validation failures for security auditing
"""

import re
import json
import hashlib
import secrets
import string
from typing import Any, Optional, Union
from utils.logger import get_logger

log = get_logger("security")

# ── Constants ─────────────────────────────────────────────────────────────────

# Valid category names (used everywhere to prevent SQL injection via category param)
VALID_CATEGORIES = frozenset({"application", "system", "security", "windows_update", "all"})

# Valid log level strings
VALID_LEVELS = frozenset({"ERROR", "WARNING", "INFO", "SUCCESS", "FAILURE", "CRITICAL", "ALL"})

# Valid severity levels for alerts/detections
VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

# Characters allowed in filenames
_SAFE_FILENAME = re.compile(r'^[a-zA-Z0-9_\-\.]{1,200}$')

# Basic IP pattern (not a full validator — use for quick sanity check)
_IP_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
)

# Control characters to strip from string inputs
_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')

# SQL injection pattern — extra safety layer (primary protection is parameterized queries)
_SQL_PATTERNS = re.compile(
    r"(--|;|/\*|\*/|xp_|EXEC\s|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|'.*')",
    re.IGNORECASE
)


# ── String sanitization ───────────────────────────────────────────────────────

def sanitize_string(
    value: Any,
    max_length: int = 500,
    allow_newlines: bool = False,
    field_name: str = "field",
) -> Optional[str]:
    """
    Clean and validate a string value.

    Returns cleaned string, or None if input is None/empty.
    Raises ValueError if value is present but invalid.
    """
    if value is None:
        return None

    text = str(value)

    # Strip control characters
    if allow_newlines:
        text = _CONTROL_CHARS.sub("", text)
    else:
        text = re.sub(r'[\x00-\x1f\x7f]', "", text)

    # Truncate
    text = text[:max_length].strip()

    if not text:
        return None

    return text


def sanitize_message(text: Any, max_length: int = 8000) -> Optional[str]:
    """Sanitize a log message — allows newlines, longer length."""
    return sanitize_string(text, max_length=max_length, allow_newlines=True)


def sanitize_source(value: Any) -> Optional[str]:
    """Sanitize a Windows event source name."""
    s = sanitize_string(value, max_length=256)
    if s and _SQL_PATTERNS.search(s):
        log.warning(f"SQL pattern detected in source field: {s[:50]}")
        return None
    return s


# ── Type validators ───────────────────────────────────────────────────────────

def validate_category(value: Any) -> str:
    """Validate a log category name. Returns cleaned value or raises ValueError."""
    if value is None:
        return "application"
    clean = str(value).lower().strip()
    if clean not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category: {value!r}. Must be one of {VALID_CATEGORIES}")
    return clean


def validate_event_id(value: Any) -> Optional[int]:
    """Validate a Windows Event ID (0–65535)."""
    if value is None:
        return None
    try:
        eid = int(value)
        if 0 <= eid <= 65535:
            return eid
        raise ValueError(f"Event ID out of range: {eid}")
    except (TypeError, ValueError):
        raise ValueError(f"Invalid event_id: {value!r}")


def validate_limit(value: Any, default: int = 100, max_val: int = 1000) -> int:
    """Validate a pagination limit."""
    if value is None:
        return default
    try:
        n = int(value)
        if n < 1:
            return 1
        return min(n, max_val)
    except (TypeError, ValueError):
        return default


def validate_date(value: Any) -> Optional[str]:
    """Validate a YYYY-MM-DD date string."""
    if not value:
        return None
    s = str(value).strip()
    if re.match(r'^\d{4}-\d{2}-\d{2}$', s):
        return s
    raise ValueError(f"Invalid date format: {value!r}. Expected YYYY-MM-DD")


def validate_severity(value: Any) -> Optional[str]:
    """Validate a severity level string."""
    if not value:
        return None
    clean = str(value).upper().strip()
    if clean in VALID_SEVERITIES:
        return clean
    raise ValueError(f"Invalid severity: {value!r}. Must be one of {VALID_SEVERITIES}")


def validate_ip(value: Any) -> Optional[str]:
    """Basic IP address validation."""
    if not value:
        return None
    s = str(value).strip()
    if _IP_PATTERN.match(s):
        return s
    return None  # Invalid IP — return None rather than raising


def validate_filename(value: Any) -> Optional[str]:
    """Validate a filename for upload/download operations."""
    if not value:
        return None
    s = str(value).strip()
    # Strip path separators
    s = s.replace("/", "").replace("\\", "").replace("..", "")
    if _SAFE_FILENAME.match(s):
        return s
    raise ValueError(f"Invalid filename: {value!r}")


# ── Request body validators ───────────────────────────────────────────────────

def validate_json_body(data: Any, required_fields: list = None, optional_fields: dict = None) -> dict:
    """
    Validate a parsed JSON request body.

    Args:
        data:            Parsed JSON dict (from request.get_json())
        required_fields: List of field names that must be present
        optional_fields: Dict of {field: validator_fn} for optional fields

    Returns:
        Cleaned dict with validated fields.
    Raises:
        ValueError with descriptive message on failure.
    """
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object")

    result = {}

    for field in (required_fields or []):
        if field not in data:
            raise ValueError(f"Missing required field: '{field}'")
        result[field] = data[field]

    for field, validator in (optional_fields or {}).items():
        if field in data:
            try:
                result[field] = validator(data[field])
            except ValueError as e:
                raise ValueError(f"Invalid value for '{field}': {e}")

    return result


# ── Hashing utilities ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password with SHA-256. For production use bcrypt."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def safe_compare(a: str, b: str) -> bool:
    """Constant-time string comparison (prevents timing attacks)."""
    return secrets.compare_digest(a.encode(), b.encode())


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


# ── SQL injection guard for dynamic column names ─────────────────────────────

def safe_column_name(name: str) -> str:
    """
    Validate a column name used in dynamic SQL.
    Only alphanumerics and underscores allowed.
    """
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$', str(name)):
        return name
    raise ValueError(f"Invalid column name: {name!r}")


def safe_table_name(name: str, allowed: frozenset = None) -> str:
    """
    Validate a table name for use in dynamic SQL.
    Optionally checks against an allowlist.
    """
    clean = str(name).strip()
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$', clean):
        raise ValueError(f"Invalid table name: {name!r}")
    if allowed and clean not in allowed:
        raise ValueError(f"Table not in allowlist: {name!r}")
    return clean


# ── API response helpers ──────────────────────────────────────────────────────

def error_response(message: str, status: int = 400) -> tuple:
    """Standard error response dict + status code."""
    return {"ok": False, "error": str(message)}, status


def success_response(data: dict = None) -> dict:
    """Standard success response."""
    resp = {"ok": True}
    if data:
        resp.update(data)
    return resp
