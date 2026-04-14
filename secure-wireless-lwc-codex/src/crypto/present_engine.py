import hashlib
import hmac
import struct

from .base_engine import CryptoEngine

# PRESENT 4-bit S-box and inverse.
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]


def sub_nibbles(state: int) -> int:
    out = 0
    for i in range(16):
        nibble = (state >> (i * 4)) & 0xF
        out |= SBOX[nibble] << (i * 4)
    return out


def p_layer(state: int) -> int:
    out = 0
    for i in range(64):
        if state & (1 << i):
            pos = (i * 16) % 63 if i != 63 else 63
            out |= 1 << pos
    return out


def generate_round_keys(key_80bit: int) -> list[int]:
    """Generate 32 round keys from an 80-bit key register."""
    round_keys = []
    key_reg = key_80bit
    for i in range(1, 33):
        round_keys.append(key_reg >> 16)
        key_reg = ((key_reg << 61) | (key_reg >> 19)) & ((1 << 80) - 1)
        top = SBOX[(key_reg >> 76) & 0xF]
        key_reg = (key_reg & ((1 << 76) - 1)) | (top << 76)
        key_reg ^= i << 15
    return round_keys


def present_encrypt_block(plaintext_64: int, key_80bit: int) -> int:
    round_keys = generate_round_keys(key_80bit)
    state = plaintext_64
    for i in range(31):
        state ^= round_keys[i]
        state = sub_nibbles(state)
        state = p_layer(state)
    state ^= round_keys[31]
    return state


def present_encrypt_block_with_round_keys(plaintext_64: int, round_keys: list[int]) -> int:
    state = plaintext_64
    for i in range(31):
        state ^= round_keys[i]
        state = sub_nibbles(state)
        state = p_layer(state)
    state ^= round_keys[31]
    return state


class PresentEngine(CryptoEngine):
    """
    PRESENT-80 in CTR mode with HMAC-SHA256 (truncated to 16-byte tag).
    Note: PRESENT-80 provides only 80-bit key security.
    """

    BLOCK_SIZE = 8

    def encrypt(self, key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        key_80 = int.from_bytes(key[:10], "big")
        round_keys = generate_round_keys(key_80)

        ciphertext = bytearray()
        num_blocks = (len(plaintext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter = int.from_bytes(nonce[:4] + struct.pack(">I", i), "big")
            keystream = present_encrypt_block_with_round_keys(counter, round_keys).to_bytes(8, "big")
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

        key_80 = int.from_bytes(key[:10], "big")
        round_keys = generate_round_keys(key_80)
        plaintext = bytearray()
        num_blocks = (len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            counter = int.from_bytes(nonce[:4] + struct.pack(">I", i), "big")
            keystream = present_encrypt_block_with_round_keys(counter, round_keys).to_bytes(8, "big")
            start = i * self.BLOCK_SIZE
            block = ciphertext[start : start + self.BLOCK_SIZE]
            plaintext.extend(b ^ k for b, k in zip(block, keystream[: len(block)]))
        return bytes(plaintext)

    def name(self) -> str:
        return "PRESENT-80-CTR-HMAC"

    @property
    def algo_id(self) -> int:
        return 4
