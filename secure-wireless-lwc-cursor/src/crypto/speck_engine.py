import hashlib
import hmac
import struct

from .base_engine import CryptoEngine


class SpeckCipher:
    """SPECK 128/128: 128-bit block, 128-bit key, 32 rounds."""

    ROUNDS = 32
    WORD_SIZE = 64
    MOD = 2**64

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 16:
            raise ValueError("SPECK-128/128 expects a 16-byte key")
        self.key_schedule = self._expand_key(key_bytes)

    def _expand_key(self, key_bytes: bytes):
        b, a = struct.unpack(">QQ", key_bytes)
        k = [a]
        l = [b]
        for i in range(self.ROUNDS - 1):
            new_l = (k[i] + self._ror(l[i], 8)) % self.MOD
            new_l ^= i
            new_k = self._rol(k[i], 3) ^ new_l
            l.append(new_l)
            k.append(new_k)
        return k

    def _ror(self, x: int, r: int) -> int:
        return ((x >> r) | (x << (self.WORD_SIZE - r))) % self.MOD

    def _rol(self, x: int, r: int) -> int:
        return ((x << r) | (x >> (self.WORD_SIZE - r))) % self.MOD

    def encrypt_block(self, block_bytes: bytes) -> bytes:
        y, x = struct.unpack(">QQ", block_bytes)
        for i in range(self.ROUNDS):
            x = (self._ror(x, 8) + y) % self.MOD
            x ^= self.key_schedule[i]
            y = self._rol(y, 3) ^ x
        return struct.pack(">QQ", y, x)

    def decrypt_block(self, block_bytes: bytes) -> bytes:
        y, x = struct.unpack(">QQ", block_bytes)
        for i in range(self.ROUNDS - 1, -1, -1):
            y = self._ror(y ^ x, 3)
            x_temp = x ^ self.key_schedule[i]
            x = self._rol((x_temp - y) % self.MOD, 8)
        return struct.pack(">QQ", y, x)


class SpeckEngine(CryptoEngine):
    """SPECK-128/128 in CTR mode + truncated HMAC-SHA256 tag."""

    BLOCK_SIZE = 16

    def encrypt(self, key, nonce, ad, plaintext):
        cipher = SpeckCipher(key[:16])
        ct = bytearray()
        num_blocks = (len(plaintext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter = nonce[:8] + struct.pack(">Q", i)
            keystream = cipher.encrypt_block(counter)
            start = i * self.BLOCK_SIZE
            block = plaintext[start : start + self.BLOCK_SIZE]
            ct.extend(b ^ k for b, k in zip(block, keystream[: len(block)]))
        mac_data = ad + bytes(ct)
        tag = hmac.new(key[:16], mac_data, hashlib.sha256).digest()[:16]
        return bytes(ct), tag

    def decrypt(self, key, nonce, ad, ciphertext, tag):
        mac_data = ad + ciphertext
        expected_tag = hmac.new(key[:16], mac_data, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return None
        cipher = SpeckCipher(key[:16])
        pt = bytearray()
        num_blocks = (len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter = nonce[:8] + struct.pack(">Q", i)
            keystream = cipher.encrypt_block(counter)
            start = i * self.BLOCK_SIZE
            block = ciphertext[start : start + self.BLOCK_SIZE]
            pt.extend(b ^ k for b, k in zip(block, keystream[: len(block)]))
        return bytes(pt)

    def name(self):
        return "SPECK-128/128-CTR-HMAC"

    @property
    def algo_id(self):
        return 3
