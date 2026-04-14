import os

import pytest

from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine

ENGINES = [AsconEngine(), AESEngine(), SpeckEngine(), PresentEngine()]


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_encrypt_decrypt_roundtrip(engine):
    key = os.urandom(16)
    nonce = os.urandom(16)
    ad = b"test-associated-data"
    for size in [0, 1, 15, 16, 17, 64, 256, 1024]:
        plaintext = os.urandom(size)
        ciphertext, tag = engine.encrypt(key, nonce, ad, plaintext)
        result = engine.decrypt(key, nonce, ad, ciphertext, tag)
        assert result == plaintext, f"{engine.name()} failed roundtrip at size {size}"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_wrong_key_fails(engine):
    key = os.urandom(16)
    nonce = os.urandom(16)
    ad = b"ad"
    plaintext = b"secret"
    ciphertext, tag = engine.encrypt(key, nonce, ad, plaintext)
    wrong_key = os.urandom(16)
    result = engine.decrypt(wrong_key, nonce, ad, ciphertext, tag)
    assert result is None, f"{engine.name()} should fail with wrong key"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_tampered_ciphertext_fails(engine):
    key = os.urandom(16)
    nonce = os.urandom(16)
    ad = b"ad"
    plaintext = b"hello world"
    ciphertext, tag = engine.encrypt(key, nonce, ad, plaintext)
    tampered = bytearray(ciphertext)
    if tampered:
        tampered[0] ^= 0xFF
    else:
        tampered = bytearray(b"\x00")
    result = engine.decrypt(key, nonce, ad, bytes(tampered), tag)
    assert result is None, f"{engine.name()} should detect tampered ciphertext"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_tampered_associated_data_fails(engine):
    key = os.urandom(16)
    nonce = os.urandom(16)
    ad = b"real-ad"
    plaintext = b"message"
    ciphertext, tag = engine.encrypt(key, nonce, ad, plaintext)
    result = engine.decrypt(key, nonce, b"fake-ad", ciphertext, tag)
    assert result is None, f"{engine.name()} should detect tampered associated data"
