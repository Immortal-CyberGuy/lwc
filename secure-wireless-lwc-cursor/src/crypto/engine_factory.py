"""Resolve engine name strings for CLI and scripts."""

from __future__ import annotations

from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.base_engine import CryptoEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine

_ENGINES: dict[str, type[CryptoEngine]] = {
    "ascon": AsconEngine,
    "aes": AESEngine,
    "aes-gcm": AESEngine,
    "speck": SpeckEngine,
    "present": PresentEngine,
}


def get_engine(name: str) -> CryptoEngine:
    key = name.strip().lower().replace("_", "-")
    if key not in _ENGINES:
        choices = ", ".join(sorted(_ENGINES))
        raise ValueError(f"unknown engine {name!r}; use one of: {choices}")
    return _ENGINES[key]()


def list_engine_names() -> list[str]:
    return sorted(set(_ENGINES))
