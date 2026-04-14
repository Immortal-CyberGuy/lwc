import os

import pytest

from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckCipher, SpeckEngine

ENGINES = [AsconEngine(), AESEngine(), SpeckEngine(), PresentEngine()]


def test_speck_block_roundtrip():
    c = SpeckCipher(os.urandom(16))
    for _ in range(32):
        block = os.urandom(16)
        assert c.decrypt_block(c.encrypt_block(block)) == block


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_encrypt_decrypt_roundtrip(engine):
    key, nonce, ad = os.urandom(16), os.urandom(16), b"test-ad"
    for size in [0, 1, 15, 16, 17, 64, 256, 1024]:
        pt = os.urandom(size)
        ct, tag = engine.encrypt(key, nonce, ad, pt)
        result = engine.decrypt(key, nonce, ad, ct, tag)
        assert result == pt, f"{engine.name()} failed at size {size}"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_wrong_key_fails(engine):
    key, nonce, ad, pt = os.urandom(16), os.urandom(16), b"ad", b"secret"
    ct, tag = engine.encrypt(key, nonce, ad, pt)
    wrong_key = os.urandom(16)
    result = engine.decrypt(wrong_key, nonce, ad, ct, tag)
    assert result is None, f"{engine.name()} should fail with wrong key"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_tampered_ciphertext_fails(engine):
    key, nonce, ad, pt = os.urandom(16), os.urandom(16), b"ad", b"hello world"
    ct, tag = engine.encrypt(key, nonce, ad, pt)
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    result = engine.decrypt(key, nonce, ad, bytes(tampered), tag)
    assert result is None, f"{engine.name()} should detect tampered ciphertext"


@pytest.mark.parametrize("engine", ENGINES, ids=lambda e: e.name())
def test_tampered_ad_fails(engine):
    key, nonce, ad, pt = os.urandom(16), os.urandom(16), b"real-ad", b"msg"
    ct, tag = engine.encrypt(key, nonce, ad, pt)
    result = engine.decrypt(key, nonce, b"fake-ad", ct, tag)
    assert result is None, f"{engine.name()} should detect tampered AD"
