from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path


HKDF_HASH = hashlib.sha256
HKDF_HASH_LEN = HKDF_HASH().digest_size
DEFAULT_ENGINE_KEY_BYTES = 16  # 128-bit symmetric key target.


@dataclass(frozen=True)
class KeyProfile:
    """
    Lightweight key-management profiles.

    All profiles derive 128-bit AEAD engine keys, but differ in root-key size,
    rekey interval, and nonce strategy guidance.
    """

    name: str
    root_key_bytes: int
    engine_key_bytes: int
    rekey_after_messages: int
    nonce_fixed_field_bytes: int
    description: str


_KEY_PROFILES = {
    "minimal": KeyProfile(
        name="minimal",
        root_key_bytes=16,
        engine_key_bytes=16,
        rekey_after_messages=50_000,
        nonce_fixed_field_bytes=8,
        description="Smallest footprint for constrained nodes; 128-bit root key.",
    ),
    "balanced": KeyProfile(
        name="balanced",
        root_key_bytes=16,
        engine_key_bytes=16,
        rekey_after_messages=100_000,
        nonce_fixed_field_bytes=8,
        description="Recommended default for this project: strong + lightweight.",
    ),
    "hardened": KeyProfile(
        name="hardened",
        root_key_bytes=32,
        engine_key_bytes=16,
        rekey_after_messages=20_000,
        nonce_fixed_field_bytes=8,
        description="Longer root key and faster rotation for stricter deployments.",
    ),
}


def recommended_profiles() -> list[KeyProfile]:
    return [_KEY_PROFILES["minimal"], _KEY_PROFILES["balanced"], _KEY_PROFILES["hardened"]]


def _resolve_profile(profile_name: str = "balanced") -> KeyProfile:
    key = profile_name.strip().lower()
    if key not in _KEY_PROFILES:
        choices = ", ".join(sorted(_KEY_PROFILES))
        raise ValueError(f"Unknown key profile '{profile_name}'. Available: {choices}")
    return _KEY_PROFILES[key]


def generate_key(length: int = 16) -> bytes:
    if length <= 0:
        raise ValueError("Key length must be positive.")
    return os.urandom(length)


def generate_root_key(profile_name: str = "balanced") -> bytes:
    profile = _resolve_profile(profile_name)
    return os.urandom(profile.root_key_bytes)


def save_key(key: bytes, file_path: str) -> None:
    if not key:
        raise ValueError("Key cannot be empty.")
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)

    # Best-effort hardening for local key files.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_key(file_path: str) -> bytes:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {file_path}")
    data = path.read_bytes()
    if not data:
        raise ValueError("Loaded key is empty.")
    return data


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not ikm:
        raise ValueError("IKM must not be empty.")
    if not salt:
        salt = b"\x00" * HKDF_HASH_LEN
    return hmac.new(salt, ikm, HKDF_HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not prk:
        raise ValueError("PRK must not be empty.")
    if length <= 0:
        raise ValueError("Requested HKDF length must be positive.")

    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HKDF_HASH).digest()
        out += block
        counter += 1
        if counter > 255:
            raise ValueError("HKDF output length exceeds RFC 5869 limit.")
    return out[:length]


def derive_engine_key(
    root_key: bytes,
    engine_name: str,
    *,
    profile_name: str = "balanced",
    deployment_id: bytes = b"",
    session_id: bytes = b"",
) -> bytes:
    """
    Derive a 128-bit encryption key from a root key with HKDF.

    This keeps per-message work low while still giving domain separation by
    engine/profile/deployment/session context.
    """

    profile = _resolve_profile(profile_name)
    if len(root_key) < profile.root_key_bytes:
        raise ValueError(
            f"Root key too short for profile '{profile.name}': "
            f"expected >= {profile.root_key_bytes} bytes."
        )

    ikm = root_key[: profile.root_key_bytes]
    salt = hashlib.sha256(b"LWC|ROOT-SALT|" + deployment_id).digest()
    prk = hkdf_extract(salt, ikm)

    info = (
        b"LWC|ENGINE-KEY|"
        + engine_name.strip().lower().encode("utf-8")
        + b"|PROFILE|"
        + profile.name.encode("utf-8")
        + b"|DEPLOY|"
        + deployment_id
        + b"|SESSION|"
        + session_id
    )
    return hkdf_expand(prk, info, profile.engine_key_bytes)


def derive_nonce_fixed_field(
    root_key: bytes,
    *,
    profile_name: str = "balanced",
    deployment_id: bytes = b"",
    session_id: bytes = b"",
) -> bytes:
    """
    Derive an 8-byte fixed nonce field.

    Together with a monotonically increasing counter, this supports deterministic
    unique nonce construction per key context.
    """

    profile = _resolve_profile(profile_name)
    ikm = root_key[: profile.root_key_bytes]
    salt = hashlib.sha256(b"LWC|NONCE-SALT|" + deployment_id).digest()
    prk = hkdf_extract(salt, ikm)
    info = b"LWC|NONCE-FIXED|" + profile.name.encode("utf-8") + b"|" + session_id
    return hkdf_expand(prk, info, profile.nonce_fixed_field_bytes)


def build_counter_nonce(seq_num: int, fixed_field: bytes) -> bytes:
    """
    Build a 16-byte nonce: fixed_field(8) || seq_num(8, big-endian).
    """

    if len(fixed_field) != 8:
        raise ValueError("fixed_field must be exactly 8 bytes.")
    if seq_num <= 0 or seq_num > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seq_num must be in [1, 2^64-1].")
    return fixed_field + seq_num.to_bytes(8, "big")


def assess_key_material(key: bytes) -> dict[str, object]:
    """
    Lightweight key-health report suitable for dashboards and checklists.
    """

    if not key:
        raise ValueError("Key must not be empty.")

    bit_length = len(key) * 8
    estimated_strength = min(bit_length, 256)
    issues: list[str] = []

    if len(key) < DEFAULT_ENGINE_KEY_BYTES:
        issues.append("Key shorter than 128 bits.")
    if len(set(key)) <= 2:
        issues.append("Low byte diversity suggests weak/non-random key material.")

    return {
        "bytes": len(key),
        "bits": bit_length,
        "estimated_security_strength_bits": estimated_strength,
        "meets_128_bit_floor": bit_length >= 128,
        "issues": issues,
    }


def should_rekey(message_count: int, profile_name: str = "balanced") -> bool:
    profile = _resolve_profile(profile_name)
    return message_count >= profile.rekey_after_messages
