"""
core/he_engine/field_encryptor.py
====================================
FR02-03 — Selective Encryption for Windows-Specific Log Formats
FR02-01 — Encrypt Windows log data before analysis

WHAT THIS MODULE DOES:
  Windows Security Event Logs contain PII fields that must be encrypted:
    • username / account_name  (who performed the action)
    • ip_address / source IP   (where the action came from)
    • machine_name / workstation (which machine)

  These fields are extracted from raw Windows log strings using the same
  regex patterns that the normalizer.py already uses, then encrypted with
  AES-256-GCM before any analysis runs on them.

  Non-sensitive fields (event_id, level, timestamp, source application, message body)
  remain PLAINTEXT so the existing regex threat detection in threat_detector.py,
  rule_engine.py, and analyzer.py continues to work with ZERO changes.

SELECTIVE ENCRYPTION STRATEGY (FR02-03):
  ┌─────────────────────────────────────────────────────────────────┐
  │  FIELD              ENCRYPTED?   REASON                         │
  │  ─────────────────────────────────────────────────────────────  │
  │  username           ✅ YES       PII — who attempted the login   │
  │  ip_address         ✅ YES       PII — attacker's source IP      │
  │  machine_name       ✅ YES       PII — workstation identity      │
  │  event_id           ❌ NO        Needed for regex rule matching  │
  │  level              ❌ NO        Needed for threat classification │
  │  timestamp          ❌ NO        Needed for temporal correlation  │
  │  source             ❌ NO        Needed for frequency analysis    │
  │  message (body)     ❌ NO        Needed for threat detection      │
  └─────────────────────────────────────────────────────────────────┘

PSEUDONYM SYSTEM:
  Every encrypted field also carries a pseudonym = HMAC-SHA256(plaintext, sign_key).
  The pseudonym is deterministic per value — same IP always gives same pseudonym.
  This allows GROUP BY / dedup WITHOUT ever seeing the plaintext IP/username.

WIRE FORMAT per encrypted field (stored as JSON in enc_* columns):
  {
    "_encrypted": true,
    "field":      "ip_address",
    "enc":        "<base64 AES-GCM ciphertext + 16-byte auth tag>",
    "nonce":      "<base64 12-byte random nonce>",
    "kid":        "<key-id for decryption routing>",
    "pseudonym":  "<64-hex HMAC — safe to store/index, reveals no info>"
  }
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_mod
import re
import secrets
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ── Sensitive field names (FR02-03: Windows-specific) ─────────────────────────
SENSITIVE_FIELDS = frozenset({
    "username", "user", "account_name", "target_user", "subject_user",
    "ip_address", "ip", "source_ip", "dest_ip", "client_address",
    "machine_name", "computer", "workstation_name", "workstation",
})

# ── Windows log regex patterns (mirrors normalizer.py patterns) ────────────────
_IP_RE      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE    = re.compile(
    r"(?:Account Name|User(?:name)?|Logon Account|Target Account Name)"
    r"[\s:]+([^\s\r\n\t|]+)", re.I
)
_MACHINE_RE = re.compile(
    r"(?:Workstation(?: Name)?|Computer(?: Name)?|Machine)"
    r"[\s:]+([^\s\r\n\t|]+)", re.I
)

# Values that look like data but are not real PII
_IGNORE_VALUES = {"-", "N/A", "n/a", "", "SYSTEM", "LOCAL SERVICE",
                  "NETWORK SERVICE", "ANONYMOUS LOGON", "::1", "127.0.0.1",
                  "0.0.0.0", "-"}


def _b64e(b: bytes) -> str:  return base64.b64encode(b).decode()
def _b64d(s: str) -> bytes:  return base64.b64decode(s)


class FieldEncryptor:
    """
    AES-256-GCM selective field encryptor for Windows log PII.

    Parameters
    ----------
    fek : bytes   32-byte field encryption key from KeyManager
    kid : str     Key-id embedded in every ciphertext for rotation support
    """

    def __init__(self, fek: bytes, kid: str):
        if len(fek) != 32:
            raise ValueError("FEK must be 32 bytes (AES-256)")
        self._aes     = AESGCM(fek)
        self._fek     = fek
        self._kid     = kid
        # Separate signing key (domain-separated from encryption key)
        self._sign_k  = hashlib.sha256(fek + b"\x01PSEUDONYM").digest()

    # ── Core encrypt / decrypt ─────────────────────────────────────────────────

    def encrypt_field(self, field_name: str, plaintext: str) -> Dict[str, Any]:
        """
        Encrypt a single sensitive field value.
        Returns a dict that replaces the plaintext value in the log record.
        The nonce is random per call — same plaintext produces different enc each time.
        The pseudonym is deterministic — same plaintext always gives same pseudonym.
        """
        pt_bytes  = plaintext.encode("utf-8")
        nonce     = secrets.token_bytes(12)
        # AAD = field name — binds ciphertext to this specific field (prevents field-swap attacks)
        ct        = self._aes.encrypt(nonce, pt_bytes, field_name.encode())
        pseudonym = _hmac_mod.new(self._sign_k, pt_bytes, digestmod=hashlib.sha256).hexdigest()
        return {
            "_encrypted": True,
            "field":      field_name,
            "enc":        _b64e(ct),
            "nonce":      _b64e(nonce),
            "kid":        self._kid,
            "pseudonym":  pseudonym,
        }

    def decrypt_field(self, enc_dict: Dict[str, Any]) -> str:
        """
        Decrypt an encrypted field dict back to the original plaintext string.
        Raises ValueError on tamper detection or wrong key.
        """
        if not enc_dict.get("_encrypted"):
            raise ValueError("Not an encrypted field dict")
        nonce = _b64d(enc_dict["nonce"])
        ct    = _b64d(enc_dict["enc"])
        aad   = enc_dict.get("field", "").encode()
        try:
            return self._aes.decrypt(nonce, ct, aad).decode("utf-8")
        except InvalidTag as e:
            raise ValueError(f"Decryption failed — tamper detected or wrong key: {e}") from e

    def is_encrypted(self, value: Any) -> bool:
        return isinstance(value, dict) and value.get("_encrypted") is True

    # ── Record-level operations ────────────────────────────────────────────────

    def encrypt_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Selectively encrypt all sensitive fields in a log record dict.
        Non-sensitive fields pass through untouched.
        Returns a NEW dict — original is not mutated.
        """
        out = {}
        for key, value in record.items():
            if key in SENSITIVE_FIELDS and isinstance(value, str) and value not in _IGNORE_VALUES:
                out[key] = self.encrypt_field(key, value)
            else:
                out[key] = value
        return out

    def decrypt_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt all encrypted fields in a record. Returns new dict."""
        out = {}
        for key, value in record.items():
            out[key] = self.decrypt_field(value) if self.is_encrypted(value) else value
        return out

    # ── Raw Windows log extraction (FR02-03) ──────────────────────────────────

    def extract_sensitive_from_raw(self, raw_log: str) -> Dict[str, str]:
        """
        Parse a raw Windows log string and extract sensitive field values.
        Uses the same patterns as normalizer.py to stay consistent.
        Returns {field_name: plaintext_value} for found fields.
        """
        found: Dict[str, str] = {}

        # IPs (take the first non-noise one)
        for ip in _IP_RE.findall(raw_log):
            if ip not in _IGNORE_VALUES:
                found["ip_address"] = ip
                break

        # Username
        m = _USER_RE.search(raw_log)
        if m:
            val = m.group(1).strip()
            # Strip domain prefix (DOMAIN\user → user)
            if "\\" in val:
                val = val.split("\\")[-1]
            if val and val not in _IGNORE_VALUES and not val.endswith("$"):
                found["username"] = val

        # Machine name
        m = _MACHINE_RE.search(raw_log)
        if m:
            val = m.group(1).strip()
            if val and val not in _IGNORE_VALUES:
                found["machine_name"] = val

        return found

    def encrypt_raw_log(self, raw_log: str) -> Dict[str, Any]:
        """
        Extract sensitive fields from a raw log string and encrypt them.
        Returns {field_name: encrypted_dict, ...}  for all found fields.
        Non-found fields are not present in the result.
        """
        stubs = self.extract_sensitive_from_raw(raw_log)
        return {
            field_name: self.encrypt_field(field_name, value)
            for field_name, value in stubs.items()
        }
