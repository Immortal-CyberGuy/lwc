import os
import socket
import struct
import time

from src.network.packet import SecurePacket

# Sensible cap for UTF-8 message bodies (independent of wire field limits).
MAX_MESSAGE_UTF8_BYTES = 256 * 1024


class SecureSender:
    def __init__(self, host, port, engine, key, *, verbose: bool = True):
        self.host = host
        self.port = port
        self.engine = engine
        self.key = key
        self.seq_num = 0
        self.verbose = verbose

    def _emit(self, message: str) -> None:
        if self.verbose:
            print(message)

    def send(self, message: str, device_id: str = "SENDER01"):
        plaintext = message.encode("utf-8")
        if len(plaintext) > MAX_MESSAGE_UTF8_BYTES:
            raise ValueError(
                f"message exceeds {MAX_MESSAGE_UTF8_BYTES} UTF-8 bytes after encoding"
            )
        self.seq_num += 1
        nonce = struct.pack(">Q", self.seq_num) + os.urandom(8)
        timestamp = int(time.time() * 1000)
        ad = device_id.encode() + struct.pack(">Q", timestamp)
        ct, tag = self.engine.encrypt(self.key, nonce, ad, plaintext)
        pkt = SecurePacket(
            self.engine.algo_id, nonce, self.seq_num, timestamp, ad, ct, tag
        )
        raw = pkt.serialize()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(struct.pack(">I", len(raw)) + raw)
            self._emit(f"[SENDER] Sent message #{self.seq_num} ({len(raw)} bytes)")
        return raw
