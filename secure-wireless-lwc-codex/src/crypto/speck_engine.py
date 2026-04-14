import hashlib
import hmac
import struct

from .base_engine import CryptoEngine


class SpeckCipher:
    """
    SPECK 128/128:
    - block size: 128 bits
    - key size: 128 bits
    - rounds: 32
    """

    ROUNDS = 32
    WORD_SIZE = 64
    MOD = 2**64

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 16:
            raise ValueError("SPECK-128/128 expects a 16-byte key.")
        self.key_schedule = self._expand_key(key_bytes)

    @staticmethod
    def _ror(x: int, r: int) -> int:
        return ((x >> r) | (x << (SpeckCipher.WORD_SIZE - r))) % SpeckCipher.MOD

    @staticmethod
    def _rol(x: int, r: int) -> int:
        return ((x << r) | (x >> (SpeckCipher.WORD_SIZE - r))) % SpeckCipher.MOD

    def _expand_key(self, key_bytes: bytes) -> list[int]:
        l0, k0 = struct.unpack(">QQ", key_bytes)
        k = [k0]
        l = [l0]
        for i in range(self.ROUNDS - 1):
            new_l = (k[i] + self._ror(l[i], 8)) % self.MOD
            new_l ^= i
            new_k = self._rol(k[i], 3) ^ new_l
            l.append(new_l)
            k.append(new_k)
        return k

    def encrypt_block(self, block_bytes: bytes) -> bytes:
        if len(block_bytes) != 16:
            raise ValueError("SPECK block size is 16 bytes.")
        y, x = struct.unpack(">QQ", block_bytes)
        for i in range(self.ROUNDS):
            x = (self._ror(x, 8) + y) % self.MOD
            x ^= self.key_schedule[i]
            y = self._rol(y, 3) ^ x
        return struct.pack(">QQ", y, x)

    def decrypt_block(self, block_bytes: bytes) -> bytes:
        if len(block_bytes) != 16:
            raise ValueError("SPECK block size is 16 bytes.")
        y, x = struct.unpack(">QQ", block_bytes)
        for i in range(self.ROUNDS - 1, -1, -1):
            y = self._ror(y ^ x, 3)
            x = self._rol(((x ^ self.key_schedule[i]) - y) % self.MOD, 8)
        return struct.pack(">QQ", y, x)


class SpeckEngine(CryptoEngine):
    """SPECK-128/128 in CTR mode with HMAC-SHA256 (truncated to 16-byte tag)."""

    BLOCK_SIZE = 16

    def encrypt(self, key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        cipher = SpeckCipher(key[:16])

        ciphertext = bytearray()
        num_blocks = (len(plaintext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter_block = nonce[:8] + struct.pack(">Q", i)
            keystream = cipher.encrypt_block(counter_block)
            start = i * self.BLOCK_SIZE
            block = plaintext[start : start + self.BLOCK_SIZE]
            ciphertext.extend(b ^ k for b, k in zip(block, keystream[: len(block)]))

        tag = hmac.new(key[:16], ad + bytes(ciphertext), hashlib.sha256).digest()[:16]
        return bytes(ciphertext), tag

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ad: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes | None:
        expected_tag = hmac.new(key[:16], ad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return None

        cipher = SpeckCipher(key[:16])
        plaintext = bytearray()
        num_blocks = (len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter_block = nonce[:8] + struct.pack(">Q", i)
            keystream = cipher.encrypt_block(counter_block)
            start = i * self.BLOCK_SIZE
            block = ciphertext[start : start + self.BLOCK_SIZE]
            plaintext.extend(b ^ k for b, k in zip(block, keystream[: len(block)]))
        return bytes(plaintext)

    def name(self) -> str:
        return "SPECK-128/128-CTR-HMAC"

    @property
    def algo_id(self) -> int:
        return 3
