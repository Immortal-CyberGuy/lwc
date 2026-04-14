from Crypto.Cipher import AES

from .base_engine import CryptoEngine


class AESEngine(CryptoEngine):
    """AES-128-GCM wrapper for baseline comparison."""

    def encrypt(self, key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce[:12])
        cipher.update(ad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ad: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes | None:
        try:
            cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce[:12])
            cipher.update(ad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            return None

    def name(self) -> str:
        return "AES-128-GCM"

    @property
    def algo_id(self) -> int:
        return 2
