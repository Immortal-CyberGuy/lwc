import os
from pathlib import Path


def generate_key(length: int = 16) -> bytes:
    if length <= 0:
        raise ValueError("Key length must be positive.")
    return os.urandom(length)


def save_key(key: bytes, file_path: str) -> None:
    if not key:
        raise ValueError("Key cannot be empty.")
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)


def load_key(file_path: str) -> bytes:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {file_path}")
    data = path.read_bytes()
    if not data:
        raise ValueError("Loaded key is empty.")
    return data
