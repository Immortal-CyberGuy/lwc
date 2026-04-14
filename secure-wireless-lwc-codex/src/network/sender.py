import os
import socket
import struct
import time

from src.network.packet import SecurePacket


class SecureSender:
    def __init__(self, host: str, port: int, engine, key: bytes):
        self.host = host
        self.port = port
        self.engine = engine
        self.key = key
        self.seq_num = 0

    def send(self, message: str, device_id: str = "SENDER01") -> bytes:
        self.seq_num += 1

        nonce = struct.pack(">Q", self.seq_num) + os.urandom(8)
        timestamp = int(time.time() * 1000)
        ad = device_id.encode("utf-8") + struct.pack(">Q", timestamp)
        plaintext = message.encode("utf-8")

        ciphertext, tag = self.engine.encrypt(self.key, nonce, ad, plaintext)
        packet = SecurePacket(self.engine.algo_id, nonce, self.seq_num, timestamp, ad, ciphertext, tag)
        raw = packet.serialize()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            sock.sendall(struct.pack(">I", len(raw)) + raw)

        return raw
