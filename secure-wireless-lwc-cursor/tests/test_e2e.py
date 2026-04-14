import os
import socket
import struct
import threading
import time
import pytest

from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine
from src.network.packet import SecurePacket
from src.network.receiver import SecureReceiver
from src.network.sender import SecureSender


def _packet_bytes(
    engine,
    key: bytes,
    seq_num: int,
    plaintext: str,
    device_id: str = "SENDER01",
    tamper_ciphertext: bool = False,
) -> bytes:
    """Build wire-format payload (no length prefix) like SecureSender."""
    nonce = struct.pack(">Q", seq_num) + os.urandom(8)
    timestamp = int(time.time() * 1000)
    ad = device_id.encode() + struct.pack(">Q", timestamp)
    ct, tag = engine.encrypt(key, nonce, ad, plaintext.encode("utf-8"))
    if tamper_ciphertext:
        ct = bytearray(ct)
        if not ct:
            ct = bytearray(b"\x00")
        ct[0] ^= 0xFF
        ct = bytes(ct)
    pkt = SecurePacket(
        engine.algo_id, nonce, seq_num, timestamp, ad, ct, tag
    )
    return pkt.serialize()


def _ephemeral_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.parametrize(
    "engine",
    [
        AsconEngine(),
        AESEngine(),
        SpeckEngine(),
        PresentEngine(),
    ],
    ids=lambda e: e.name(),
)
def test_e2e_encrypt_over_tcp(engine):
    port = _ephemeral_port()
    key = os.urandom(16)
    result = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key)
        result["msg"], result["status"] = rx.listen_once()

    t = threading.Thread(target=run_receiver)
    t.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key)
    tx.send("Hello from secure channel!")
    t.join(timeout=10)
    assert not t.is_alive()
    assert result.get("status") == "OK"
    assert result.get("msg") == "Hello from secure channel!"


def test_replay_same_packet_rejected():
    port = _ephemeral_port()
    key = os.urandom(16)
    engine = AsconEngine()
    results = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key)
        results["pairs"] = rx.listen_count(2)

    t = threading.Thread(target=run_receiver)
    t.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key)
    raw = tx.send("transfer-ok")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack(">I", len(raw)) + raw)
    t.join(timeout=10)
    assert not t.is_alive()
    p1, p2 = results["pairs"]
    assert p1 == ("transfer-ok", "OK")
    assert p2[1] == "REPLAY_REJECTED"


def test_tampered_ciphertext_rejected():
    port = _ephemeral_port()
    key = os.urandom(16)
    engine = AsconEngine()
    results = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key)
        results["pairs"] = rx.listen_count(2)

    t = threading.Thread(target=run_receiver)
    t.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key)
    tx.send("intact")
    tampered = _packet_bytes(
        engine, key, 2, "second", tamper_ciphertext=True
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack(">I", len(tampered)) + tampered)
    t.join(timeout=10)
    assert not t.is_alive()
    p1, p2 = results["pairs"]
    assert p1 == ("intact", "OK")
    assert p2[0] is None
    assert p2[1] == "AUTH_FAILURE"
