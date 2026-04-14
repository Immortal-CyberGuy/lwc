from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass(slots=True)
class SecurePacket:
    """Binary secure message layout (version, algo, nonce, seq, ts, AD, ciphertext, tag)."""

    algo_id: int
    nonce: bytes
    seq_num: int
    timestamp: int
    ad: bytes
    ciphertext: bytes
    tag: bytes

    VERSION: ClassVar[int] = 0x01
    # Wire uses uint16 lengths; cap below 65535 for receiver safety.
    MAX_FIELD_LEN: ClassVar[int] = min(65535, 256 * 1024)

    def serialize(self) -> bytes:
        if len(self.nonce) != 16:
            raise ValueError("nonce must be 16 bytes")
        if len(self.tag) != 16:
            raise ValueError("tag must be 16 bytes")
        if len(self.ad) > self.MAX_FIELD_LEN or len(self.ciphertext) > self.MAX_FIELD_LEN:
            raise ValueError("AD or ciphertext exceeds maximum wire size")
        header = struct.pack(">BB", self.VERSION, self.algo_id)
        header += self.nonce
        header += struct.pack(">I", self.seq_num)
        header += struct.pack(">Q", self.timestamp)
        header += struct.pack(">H", len(self.ad)) + self.ad
        header += struct.pack(">H", len(self.ciphertext)) + self.ciphertext
        header += self.tag
        return header

    @staticmethod
    def deserialize(data: bytes) -> SecurePacket:
        min_header = 2 + 16 + 4 + 8 + 2
        if len(data) < min_header:
            raise ValueError("packet too short for header")
        offset = 0
        version, algo_id = struct.unpack_from(">BB", data, offset)
        offset += 2
        if version != SecurePacket.VERSION:
            raise ValueError(f"unsupported protocol version {version}")
        if len(data) < offset + 16 + 4 + 8 + 2:
            raise ValueError("packet truncated before AD length")
        nonce = data[offset : offset + 16]
        offset += 16
        seq_num = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        timestamp = struct.unpack_from(">Q", data, offset)[0]
        offset += 8
        ad_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if ad_len > SecurePacket.MAX_FIELD_LEN:
            raise ValueError("associated data length out of range")
        if len(data) < offset + ad_len + 2:
            raise ValueError("packet truncated in associated data")
        ad = data[offset : offset + ad_len]
        offset += ad_len
        ct_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if ct_len > SecurePacket.MAX_FIELD_LEN:
            raise ValueError("ciphertext length out of range")
        if len(data) < offset + ct_len + 16:
            raise ValueError("packet truncated before authentication tag")
        ct = data[offset : offset + ct_len]
        offset += ct_len
        tag = data[offset : offset + 16]
        return SecurePacket(algo_id, nonce, seq_num, timestamp, ad, ct, tag)
