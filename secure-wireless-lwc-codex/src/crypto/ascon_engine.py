import ascon as _ascon

from .base_engine import CryptoEngine


class AsconEngine(CryptoEngine):
    """ASCON-AEAD128 wrapper using the ascon PyPI package API."""

    def encrypt(self, key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        ct_tag = _ascon.encrypt(key, nonce, ad, plaintext)
        return ct_tag[:-16], ct_tag[-16:]

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ad: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes | None:
        return _ascon.decrypt(key, nonce, ad, ciphertext + tag)

    def name(self) -> str:
        return "ASCON-AEAD128"

    @property
    def algo_id(self) -> int:
        return 1
