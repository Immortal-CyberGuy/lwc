import os

from src.utils.key_manager import (
    assess_key_material,
    build_counter_nonce,
    derive_engine_key,
    derive_nonce_fixed_field,
    generate_root_key,
    recommended_profiles,
    should_rekey,
)


def test_profiles_exist():
    names = [p.name for p in recommended_profiles()]
    assert names == ["minimal", "balanced", "hardened"]


def test_derive_engine_key_is_deterministic_for_same_context():
    root = generate_root_key("balanced")
    key_a = derive_engine_key(
        root,
        "ascon",
        profile_name="balanced",
        deployment_id=b"lab-a",
        session_id=b"session-1",
    )
    key_b = derive_engine_key(
        root,
        "ascon",
        profile_name="balanced",
        deployment_id=b"lab-a",
        session_id=b"session-1",
    )
    assert key_a == key_b
    assert len(key_a) == 16


def test_derive_engine_key_changes_with_context():
    root = os.urandom(16)
    key_a = derive_engine_key(root, "ascon", deployment_id=b"lab-a")
    key_b = derive_engine_key(root, "ascon", deployment_id=b"lab-b")
    assert key_a != key_b


def test_nonce_fixed_field_and_counter_nonce():
    root = os.urandom(16)
    fixed = derive_nonce_fixed_field(root, profile_name="balanced", deployment_id=b"lab", session_id=b"s1")
    nonce1 = build_counter_nonce(1, fixed)
    nonce2 = build_counter_nonce(2, fixed)
    assert len(fixed) == 8
    assert len(nonce1) == 16
    assert nonce1 != nonce2


def test_assess_key_material():
    report = assess_key_material(os.urandom(16))
    assert report["meets_128_bit_floor"] is True
    assert report["bits"] == 128
    assert report["issues"] == []


def test_should_rekey_threshold():
    assert should_rekey(100_000, "balanced") is True
    assert should_rekey(99_999, "balanced") is False

