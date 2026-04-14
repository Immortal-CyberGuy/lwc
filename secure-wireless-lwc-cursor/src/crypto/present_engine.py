import hashlib
import hmac
import struct

from .base_engine import CryptoEngine

SBOX = [
    0xC,
    0x5,
    0x6,
    0xB,
    0x9,
    0x0,
    0xA,
    0xD,
    0x3,
    0xE,
    0xF,
    0x8,
    0x4,
    0x7,
    0x1,
    0x2,
]


def sub_nibbles(state: int) -> int:
    result = 0
    for i in range(16):
        nibble = (state >> (i * 4)) & 0xF
        result |= SBOX[nibble] << (i * 4)
    return result


def p_layer(state: int) -> int:
    result = 0
    for i in range(64):
        if state & (1 << i):
            pos = (i * 16) % 63 if i != 63 else 63
            result |= 1 << pos
    return result


def generate_round_keys(key_80bit: int):
    keys = []
    key_reg = key_80bit
    for i in range(1, 33):
        keys.append(key_reg >> 16)
        key_reg = ((key_reg << 61) | (key_reg >> 19)) & ((1 << 80) - 1)
        top = SBOX[(key_reg >> 76) & 0xF]
        key_reg = (key_reg & ((1 << 76) - 1)) | (top << 76)
        key_reg ^= i << 15
    return keys


def present_encrypt_block(plaintext_64: int, key_80bit: int) -> int:
    round_keys = generate_round_keys(key_80bit)
    state = plaintext_64
    for i in range(31):
        state ^= round_keys[i]
        state = sub_nibbles(state)
        state = p_layer(state)
    state ^= round_keys[31]
    return state


class PresentEngine(CryptoEngine):
    """PRESENT-80 in CTR mode + truncated HMAC-SHA256 tag."""

    BLOCK_SIZE = 8

    def encrypt(self, key, nonce, ad, plaintext):
        key_80 = int.from_bytes(key[:10], "big")
        ct = bytearray()
        num_blocks = (len(plaintext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        for i in range(num_blocks):
            ctr_val = int.from_bytes(nonce[:4] + struct.pack(">I", i), "big")
            ks = present_encrypt_block(ctr_val & ((1 << 64) - 1), key_80)
            ks_bytes = ks.to_bytes(8, "big")
            start = i * self.BLOCK_SIZE
            block = plaintext[start : start + self.BLOCK_SIZE]
            ct.extend(b ^ k for b, k in zip(block, ks_bytes[: len(block)]))
        tag = hmac.new(key[:16], ad + bytes(ct), hashlib.sha256).digest()[:16]
        return bytes(ct), tag

    def decrypt(self, key, nonce, ad, ciphertext, tag):
        expected = hmac.new(key[:16], ad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            return None
        key_80 = int.from_bytes(key[:10], "big")
        pt = bytearray()
        for i in range((len(ciphertext) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE):
            ctr_val = int.from_bytes(nonce[:4] + struct.pack(">I", i), "big")
            ks = present_encrypt_block(ctr_val & ((1 << 64) - 1), key_80)
            ks_bytes = ks.to_bytes(8, "big")
            start = i * self.BLOCK_SIZE
            block = ciphertext[start : start + self.BLOCK_SIZE]
            pt.extend(b ^ k for b, k in zip(block, ks_bytes[: len(block)]))
        return bytes(pt)

    def name(self):
        return "PRESENT-80-CTR-HMAC"

    @property
    def algo_id(self):
        return 4
