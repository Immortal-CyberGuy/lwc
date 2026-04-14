import os
import socket
import struct
import threading
import time

from src.crypto.ascon_engine import AsconEngine
from src.network.constants import MAX_WIRE_PAYLOAD_BYTES
from src.network.receiver import SecureReceiver


def _ephemeral_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_receiver_rejects_oversized_length_prefix():
    port = _ephemeral_port()
    key = os.urandom(16)
    outcome: dict = {}

    def run_rx():
        rx = SecureReceiver(port, AsconEngine(), key, verbose=False)
        outcome["result"] = rx.listen_once()

    t = threading.Thread(target=run_rx)
    t.start()
    time.sleep(0.35)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack(">I", MAX_WIRE_PAYLOAD_BYTES + 1))
    t.join(timeout=10)
    assert not t.is_alive()
    assert outcome["result"] == (None, "LENGTH_REJECTED")
