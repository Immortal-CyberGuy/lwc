from abc import ABC, abstractmethod


class CryptoEngine(ABC):
    @abstractmethod
    def encrypt(self, key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, auth_tag)."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ad: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes | None:
        """Returns plaintext on success, None on authentication failure."""
        raise NotImplementedError

    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @property
    def algo_id(self) -> int:
        """Unique ID for packet header: 1=ASCON, 2=AES, 3=SPECK, 4=PRESENT."""
        return 0
