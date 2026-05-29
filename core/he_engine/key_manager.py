"""
core/crypto/key_manager.py
============================
PART 4 — Key Management System

RESPONSIBILITIES
────────────────
  1. Generate AES-256 master keys (CSPRNG via os.urandom)
  2. Persist keys to disk (encrypted key-store or OS keychain)
  3. Load keys at startup with integrity verification
  4. Key rotation: generate new key, re-encrypt key-store, retire old
  5. Windows integration: optional WinCAPI/Cert-Store bridge

KEY STORE FORMAT (keys/keystore.json)
──────────────────────────────────────
  {
    "version": 1,
    "keys": [
      {
        "key_id":    "2025-01-15T09:00:00Z-abc123",
        "created":   1705312800,
        "retired":   null,
        "active":    true,
        "key_data":  "<base64(AES-256-GCM(master_key, store_password))>",
        "hmac":      "<base64(HMAC-SHA256(key_data, store_password))>",
        "he_seed":   42,           ← seed for BFV/CKKS key regeneration
      }
    ],
    "active_key_id": "2025-01-15T09:00:00Z-abc123"
  }

SECURITY NOTES
──────────────
  - Key material is AES-GCM encrypted with a store_password before writing to disk
  - HMAC integrity check on every load
  - Retired keys are kept for decryption-only (re-encryption uses active key)
  - For production: replace file-based store with Windows DPAPI or HSM

WINDOWS INTEGRATION
───────────────────
  WinCertStore class provides a simulation of the Windows Certificate Store API.
  In production: use win32crypt.CryptProtectData / CryptUnprotectData.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import json
import os
import secrets
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

KEY_SIZE        = 32         # AES-256: 32 bytes
PBKDF2_ITERS    = 260_000    # OWASP 2024 recommendation for PBKDF2-SHA256
SALT_SIZE       = 32         # Salt for PBKDF2
NONCE_SIZE      = 12         # AES-GCM nonce
KEYSTORE_FILE   = "keys/keystore.json"
MAX_KEY_AGE_SEC = 86400 * 90 # 90-day rotation policy


# ══════════════════════════════════════════════════════════════════════════════
# Password-Based Key Derivation (protects the key-store file)
# ══════════════════════════════════════════════════════════════════════════════

def _derive_store_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from store_password + salt using PBKDF2-SHA256."""
    if _CRYPTO_AVAILABLE:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())
    # Fallback: repeated SHA-256 (weaker but functional for dev)
    key = password.encode() + salt
    for _ in range(10_000):
        key = hashlib.sha256(key).digest()
    return key


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt bytes with AES-256-GCM. Returns nonce || ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    if _CRYPTO_AVAILABLE:
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
    else:
        ct = _xor_cipher(key, nonce, plaintext)
    return nonce + ct


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt bytes produced by _aes_gcm_encrypt."""
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    if _CRYPTO_AVAILABLE:
        return AESGCM(key).decrypt(nonce, ct, None)
    return _xor_cipher(key, nonce, ct)


def _xor_cipher(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Dev-only XOR stream cipher fallback."""
    ks = b"".join(hashlib.sha256(key + nonce + bytes([i])).digest() for i in range(len(data)//32+1))
    return bytes(a ^ b for a, b in zip(data, ks))


# ══════════════════════════════════════════════════════════════════════════════
# Key Record
# ══════════════════════════════════════════════════════════════════════════════

class KeyRecord:
    """Represents a single versioned encryption key."""

    def __init__(
        self,
        key_id:   str,
        key_data: bytes,
        he_seed:  int,
        created:  float,
        active:   bool   = True,
        retired:  Optional[float] = None,
    ) -> None:
        self.key_id   = key_id
        self.key_data = key_data   # raw 32-byte AES key
        self.he_seed  = he_seed    # integer seed for BFV/CKKS reproducibility
        self.created  = created
        self.active   = active
        self.retired  = retired

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created

    @property
    def needs_rotation(self) -> bool:
        return self.active and self.age_seconds > MAX_KEY_AGE_SEC

    def __repr__(self) -> str:
        status = "ACTIVE" if self.active else f"RETIRED@{datetime.fromtimestamp(self.retired)}"
        return f"<KeyRecord id={self.key_id[:20]}… status={status} age={self.age_seconds/86400:.1f}d>"


# ══════════════════════════════════════════════════════════════════════════════
# Key Manager
# ══════════════════════════════════════════════════════════════════════════════

class KeyManager:
    """
    Manages the lifecycle of encryption keys for the HE pipeline.

    Usage
    -----
    km = KeyManager(store_path="keys/keystore.json", store_password="your-password")
    km.initialize()          # creates keystore if not exists
    key  = km.active_key     # get current active KeyRecord
    seed = km.active_he_seed # HE numeric seed for BFV/CKKS

    # Rotation (call on schedule, e.g. from a cron or startup check)
    if km.should_rotate:
        new_key = km.rotate_key()
        print(f"Rotated to key {new_key.key_id}")
    """

    def __init__(
        self,
        store_path:     str  = KEYSTORE_FILE,
        store_password: str  = "default-dev-password-CHANGE-ME",
    ) -> None:
        self._store_path = Path(store_path)
        self._password   = store_password
        self._keys:       dict[str, KeyRecord] = {}
        self._active_id:  Optional[str]        = None
        self._salt:       Optional[bytes]       = None   # per-store PBKDF2 salt

    # ── Public API ─────────────────────────────────────────────────────────

    def initialize(self) -> None:
        """Load existing keystore or create a new one with a fresh key."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        if self._store_path.exists():
            self._load()
            print(f"[KeyManager] Loaded keystore from {self._store_path}")
            print(f"[KeyManager] Active key: {self._active_id}")
        else:
            self._generate_first_key()
            print(f"[KeyManager] Created new keystore at {self._store_path}")
            print(f"[KeyManager] Generated key: {self._active_id}")

    @property
    def active_key(self) -> KeyRecord:
        if not self._active_id or self._active_id not in self._keys:
            raise RuntimeError("No active key — call initialize() first")
        return self._keys[self._active_id]

    @property
    def active_he_seed(self) -> int:
        return self.active_key.he_seed

    @property
    def should_rotate(self) -> bool:
        try:
            return self.active_key.needs_rotation
        except RuntimeError:
            return False

    def rotate_key(self) -> KeyRecord:
        """
        Perform key rotation:
        1. Mark current active key as retired
        2. Generate a new AES key + HE seed
        3. Save updated keystore
        Returns the new active KeyRecord.
        """
        if self._active_id and self._active_id in self._keys:
            old = self._keys[self._active_id]
            old.active  = False
            old.retired = time.time()
            print(f"[KeyManager] Retiring key {old.key_id[:20]}…")

        new_key = self._create_key_record()
        self._keys[new_key.key_id] = new_key
        self._active_id = new_key.key_id
        self._save()
        print(f"[KeyManager] Rotated to new key {new_key.key_id}")
        return new_key

    def get_key_by_id(self, key_id: str) -> Optional[KeyRecord]:
        """Retrieve any key (including retired) for decryption of old data."""
        return self._keys.get(key_id)

    def list_keys(self) -> list[dict]:
        """List all keys with metadata (no key material exposed)."""
        return [
            {
                "key_id":   kr.key_id,
                "active":   kr.active,
                "created":  datetime.fromtimestamp(kr.created, timezone.utc).isoformat(),
                "retired":  datetime.fromtimestamp(kr.retired, timezone.utc).isoformat() if kr.retired else None,
                "age_days": round(kr.age_seconds / 86400, 1),
            }
            for kr in self._keys.values()
        ]

    # ── Internal helpers ──────────────────────────────────────────────────

    def _create_key_record(self) -> KeyRecord:
        """Generate a new cryptographically random key."""
        key_data  = os.urandom(KEY_SIZE)
        he_seed   = secrets.randbelow(2**31)
        now       = time.time()
        key_id    = (
            datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            + "-" + secrets.token_hex(4)
        )
        return KeyRecord(key_id=key_id, key_data=key_data, he_seed=he_seed, created=now)

    def _generate_first_key(self) -> None:
        self._salt     = os.urandom(SALT_SIZE)
        record         = self._create_key_record()
        self._keys     = {record.key_id: record}
        self._active_id = record.key_id
        self._save()

    def _derive_store_key(self) -> bytes:
        assert self._salt, "Salt not initialized"
        return _derive_store_key(self._password, self._salt)

    def _save(self) -> None:
        """Serialize and encrypt keystore to disk."""
        store_key = self._derive_store_key()

        serialized_keys = {}
        for kid, kr in self._keys.items():
            # Encrypt the raw key material
            enc_blob = _aes_gcm_encrypt(store_key, kr.key_data)
            # Compute HMAC over the encrypted blob for integrity
            mac      = hmac_lib.new(store_key, enc_blob, hashlib.sha256).digest()
            serialized_keys[kid] = {
                "key_id":    kr.key_id,
                "created":   kr.created,
                "retired":   kr.retired,
                "active":    kr.active,
                "key_data":  base64.b64encode(enc_blob).decode(),
                "hmac":      base64.b64encode(mac).decode(),
                "he_seed":   kr.he_seed,
            }

        store = {
            "version":       1,
            "salt":          base64.b64encode(self._salt).decode(),
            "active_key_id": self._active_id,
            "keys":          serialized_keys,
        }

        tmp = self._store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(store, indent=2))
        tmp.replace(self._store_path)    # atomic write

    def _load(self) -> None:
        """Load and decrypt keystore from disk."""
        raw  = json.loads(self._store_path.read_text())
        if raw.get("version") != 1:
            raise ValueError(f"Unknown keystore version: {raw.get('version')}")

        self._salt     = base64.b64decode(raw["salt"])
        store_key      = self._derive_store_key()
        self._active_id = raw["active_key_id"]

        for kid, entry in raw["keys"].items():
            enc_blob = base64.b64decode(entry["key_data"])
            mac_stored = base64.b64decode(entry["hmac"])
            # Integrity check
            mac_computed = hmac_lib.new(store_key, enc_blob, hashlib.sha256).digest()
            if not hmac_lib.compare_digest(mac_stored, mac_computed):
                raise ValueError(f"HMAC mismatch for key {kid} — keystore may be tampered!")
            key_data = _aes_gcm_decrypt(store_key, enc_blob)
            self._keys[kid] = KeyRecord(
                key_id   = entry["key_id"],
                key_data = key_data,
                he_seed  = entry["he_seed"],
                created  = entry["created"],
                active   = entry["active"],
                retired  = entry.get("retired"),
            )


# ══════════════════════════════════════════════════════════════════════════════
# PART 5 — Windows Certificate Store Integration (simulation)
# ══════════════════════════════════════════════════════════════════════════════

class WinCertStore:
    """
    Simulates the Windows Certificate Store for key protection.

    In production on Windows, replace the store/load methods with:
        import win32crypt
        encrypted = win32crypt.CryptProtectData(key_bytes, None, None, None, None, 0)
        decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, None, 0)[1]

    This simulation uses a local file with DPAPI-like MAC protection.
    The WinCertStore wraps a KeyManager and adds the OS-layer protection.
    """

    STORE_FILE = "keys/wincertstore_sim.bin"

    def __init__(self, km: KeyManager) -> None:
        self._km    = km
        self._path  = Path(self.STORE_FILE)

    def protect_key(self, key_data: bytes) -> bytes:
        """
        DPAPI simulation: 'protect' key bytes with machine-bound entropy.
        Real DPAPI: win32crypt.CryptProtectData(key_data, ..., CRYPTPROTECT_LOCAL_MACHINE)
        """
        machine_entropy = hashlib.sha256(
            b"MACHINE_BOUND:" + os.urandom(8)  # in real DPAPI this comes from the machine SID
        ).digest()
        # Simple XOR with machine entropy for simulation
        protected = bytes(a ^ b for a, b in zip(key_data, machine_entropy * 2))
        mac       = hashlib.sha256(protected + machine_entropy).digest()[:8]
        return protected + mac  # 32 + 8 = 40 bytes

    def store_to_cert_store(self) -> None:
        """
        Simulate exporting the active key to the Windows Certificate Store.
        In production: use certutil.exe or CryptoAPI to store in LocalMachine store.
        """
        active = self._km.active_key
        protected_blob = self.protect_key(active.key_data)
        self._path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            "key_id":         active.key_id,
            "protected_key":  base64.b64encode(protected_blob).decode(),
            "he_seed":        active.he_seed,
            "created":        active.created,
            "store_type":     "SIMULATION_DPAPI",
            "note":           (
                "Production: replace with win32crypt.CryptProtectData / "
                "Windows Cert Store (MY store, LocalMachine). "
                "Simulation uses XOR+MAC for portability."
            ),
        }
        self._path.write_text(json.dumps(record, indent=2))
        print(f"[WinCertStore] Key {active.key_id[:20]}… stored to simulated Windows cert store.")

    def load_from_cert_store(self) -> Optional[bytes]:
        """Load protected key blob from the simulated cert store."""
        if not self._path.exists():
            return None
        record       = json.loads(self._path.read_text())
        protected    = base64.b64decode(record["protected_key"])
        print(f"[WinCertStore] Loaded key from simulated cert store (id={record['key_id'][:20]}…)")
        return protected   # caller decrypts with DPAPI in production

    def windows_api_stub(self) -> str:
        """Return the Windows CryptoAPI code stub for production replacement."""
        return """
# ── Production Windows DPAPI Integration ──────────────────────────────────────
# pip install pywin32  (on Windows)

import win32crypt, win32con

def protect_with_dpapi(key_bytes: bytes) -> bytes:
    \"\"\"Protect key bytes with Windows DPAPI (machine-bound).\"\"\"
    blob = win32crypt.CryptProtectData(
        key_bytes,
        "SecureEyeTrust-HE-Key",    # description
        None,                        # optional entropy
        None,                        # reserved
        None,                        # prompt struct
        win32con.CRYPTPROTECT_LOCAL_MACHINE,
    )
    return blob

def unprotect_with_dpapi(blob: bytes) -> bytes:
    \"\"\"Decrypt a DPAPI-protected blob.\"\"\"
    _, decrypted = win32crypt.CryptUnprotectData(
        blob, None, None, None, None,
        win32con.CRYPTPROTECT_LOCAL_MACHINE,
    )
    return decrypted

def store_in_cert_store(cert_blob: bytes, store_name: str = "MY") -> None:
    \"\"\"Import a certificate/key into the Windows Certificate Store.\"\"\"
    store = win32crypt.CertOpenStore(
        win32crypt.CERT_STORE_PROV_SYSTEM,
        0,
        None,
        win32crypt.CERT_SYSTEM_STORE_LOCAL_MACHINE,
        store_name,
    )
    win32crypt.CertAddEncodedCertificateToStore(
        store, win32crypt.X509_ASN_ENCODING, cert_blob,
        win32crypt.CERT_STORE_ADD_REPLACE_EXISTING,
    )
# ─────────────────────────────────────────────────────────────────────────────
"""
