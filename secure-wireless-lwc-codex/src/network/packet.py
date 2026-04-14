import struct


class SecurePacket:
    VERSION = 0x01
    TAG_SIZE = 16
    NONCE_SIZE = 16

    def __init__(
        self,
        algo_id: int,
        nonce: bytes,
        seq_num: int,
        timestamp: int,
        ad: bytes,
        ciphertext: bytes,
        tag: bytes,
    ):
        self.algo_id = algo_id
        self.nonce = nonce
        self.seq_num = seq_num
        self.timestamp = timestamp
        self.ad = ad
        self.ciphertext = ciphertext
        self.tag = tag

    def serialize(self) -> bytes:
        if len(self.nonce) != self.NONCE_SIZE:
            raise ValueError("Nonce must be 16 bytes.")
        if len(self.tag) != self.TAG_SIZE:
            raise ValueError("Tag must be 16 bytes.")
        if len(self.ad) > 0xFFFF:
            raise ValueError("Associated data is too large for 2-byte length field.")
        if len(self.ciphertext) > 0xFFFF:
            raise ValueError("Ciphertext is too large for 2-byte length field.")

        header = struct.pack(">BB", self.VERSION, self.algo_id)
        header += self.nonce
        header += struct.pack(">I", self.seq_num)
        header += struct.pack(">Q", self.timestamp)
        header += struct.pack(">H", len(self.ad)) + self.ad
        header += struct.pack(">H", len(self.ciphertext)) + self.ciphertext
        header += self.tag
        return header

    @staticmethod
    def deserialize(data: bytes) -> "SecurePacket":
        min_size = 2 + 16 + 4 + 8 + 2 + 2 + 16
        if len(data) < min_size:
            raise ValueError("Packet too short.")

        offset = 0
        version, algo_id = struct.unpack_from(">BB", data, offset)
        offset += 2
        if version != SecurePacket.VERSION:
            raise ValueError(f"Unsupported packet version: {version}")

        nonce = data[offset : offset + 16]
        offset += 16
        seq_num = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        timestamp = struct.unpack_from(">Q", data, offset)[0]
        offset += 8

        ad_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if offset + ad_len > len(data):
            raise ValueError("Invalid associated data length.")
        ad = data[offset : offset + ad_len]
        offset += ad_len

        ct_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        if offset + ct_len + 16 > len(data):
            raise ValueError("Invalid ciphertext length.")
        ciphertext = data[offset : offset + ct_len]
        offset += ct_len

        tag = data[offset : offset + 16]
        offset += 16
        if offset != len(data):
            raise ValueError("Unexpected trailing data in packet.")

        return SecurePacket(algo_id, nonce, seq_num, timestamp, ad, ciphertext, tag)
