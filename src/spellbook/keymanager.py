#!/usr/bin/env python3
"""
Spellbook persistent key manager.
Stores the EVM private key encrypted in ~/workspace/.spellbook/key.enc.
The encryption password is provided transiently by the user (never stored).
The decrypted key lives in memory only, never on disk, never in logs.
"""
import os
import sys
import json
import getpass
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

KEY_DIR = Path.home() / "workspace" / ".spellbook"
ENC_FILE = KEY_DIR / "key.enc"
SALT_FILE = KEY_DIR / "key.salt"

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def store_key(privkey_hex: str, password: str) -> None:
    """Encrypt and store the private key. The raw key is never written to disk."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required")
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    privkey_bytes = bytes.fromhex(privkey_hex.replace("0x", ""))
    ct = aesgcm.encrypt(nonce, privkey_bytes, None)
    # Store salt + nonce + ciphertext
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    with open(ENC_FILE, "wb") as f:
        f.write(nonce + ct)
    # Lock down permissions
    os.chmod(ENC_FILE, 0o600)
    os.chmod(SALT_FILE, 0o600)
    print("Key encrypted and stored.")

def load_key(password: str) -> str:
    """Decrypt and return the private key hex. Key lives in memory only."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography package required")
    if not ENC_FILE.exists():
        raise FileNotFoundError("No encrypted key found. Run store first.")
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    with open(ENC_FILE, "rb") as f:
        data = f.read()
    nonce, ct = data[:12], data[12:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    privkey_bytes = aesgcm.decrypt(nonce, ct, None)
    return "0x" + privkey_bytes.hex()

def key_exists() -> bool:
    return ENC_FILE.exists()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: keymanager.py [store|load|exists]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "exists":
        print("yes" if key_exists() else "no")
    elif cmd == "store":
        # Private key and password provided via env (transient, not in argv)
        privkey = os.environ.get("SPELLBOOK_PRIVKEY", "")
        password = os.environ.get("SPELLBOOK_PASSWORD", "")
        if not privkey or not password:
            print("Set SPELLBOOK_PRIVKEY and SPELLBOOK_PASSWORD env vars", file=sys.stderr)
            sys.exit(1)
        store_key(privkey, password)
        # Clear from env (best effort)
        os.environ.pop("SPELLBOOK_PRIVKEY", None)
        os.environ.pop("SPELLBOOK_PASSWORD", None)
    elif cmd == "load":
        password = os.environ.get("SPELLBOOK_PASSWORD", "")
        if not password:
            print("Set SPELLBOOK_PASSWORD env var", file=sys.stderr)
            sys.exit(1)
        # Output to stdout (caller must handle securely, not log it)
        print(load_key(password))
