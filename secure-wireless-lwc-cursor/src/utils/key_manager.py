"""Pre-shared key helpers for lab use only (not a substitute for real provisioning)."""

from __future__ import annotations

import os
from pathlib import Path


def generate_psk(length: int = 16) -> bytes:
    """Return a cryptographically random key (default 128-bit)."""
    if length <= 0:
        raise ValueError("length must be positive")
    return os.urandom(length)


def save_key(path: str | Path, key: bytes) -> None:
    """Write raw key bytes to a file. Lab convenience — protect the file like a secret."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key)
    try:
        os.chmod(p, 0o600)
    except (AttributeError, NotImplementedError, OSError):
        pass


def load_key(path: str | Path) -> bytes:
    """Load raw key bytes from file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    return p.read_bytes()
