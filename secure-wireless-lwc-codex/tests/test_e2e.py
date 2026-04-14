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
from src.network.replay_guard import ReplayGuard
from src.network.sender import SecureSender


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize(
    "engine",
    [AsconEngine(), AESEngine(), SpeckEngine(), PresentEngine()],
    ids=lambda e: e.name(),
)
def test_e2e_single_message(engine):
    port = _free_port()
    key = os.urandom(16)
    result: dict[str, str | None] = {}

    def run_receiver():
        receiver = SecureReceiver(port=port, engine=engine, key=key)
        msg, status = receiver.listen_once()
        result["msg"] = msg
        result["status"] = status

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.2)

    sender = SecureSender("127.0.0.1", port, engine, key)
    sender.send("Hello from secure channel")
    t.join(timeout=3)

    assert result.get("status") == "OK"
    assert result.get("msg") == "Hello from secure channel"


def test_packet_roundtrip_serialization():
    pkt = SecurePacket(
        algo_id=1,
        nonce=os.urandom(16),
        seq_num=123,
        timestamp=1700000000000,
        ad=b"sender01",
        ciphertext=b"\x10\x20\x30",
        tag=os.urandom(16),
    )
    raw = pkt.serialize()
    parsed = SecurePacket.deserialize(raw)

    assert parsed.algo_id == pkt.algo_id
    assert parsed.nonce == pkt.nonce
    assert parsed.seq_num == pkt.seq_num
    assert parsed.timestamp == pkt.timestamp
    assert parsed.ad == pkt.ad
    assert parsed.ciphertext == pkt.ciphertext
    assert parsed.tag == pkt.tag


def test_replay_guard_accepts_fresh_rejects_duplicate():
    guard = ReplayGuard(window_size=64)
    assert guard.check_and_update(1) is True
    assert guard.check_and_update(2) is True
    assert guard.check_and_update(2) is False
    assert guard.check_and_update(1) is False


def test_replay_attack_rejected():
    engine = AsconEngine()
    key = os.urandom(16)
    port = _free_port()
    statuses: list[str] = []

    def receiver_loop():
        guard = ReplayGuard()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(3)

            for _ in range(3):
                conn, _ = sock.accept()
                with conn:
                    length = struct.unpack(">I", conn.recv(4))[0]
                    data = b""
                    while len(data) < length:
                        data += conn.recv(length - len(data))
                    pkt = SecurePacket.deserialize(data)
                    if not guard.check_and_update(pkt.seq_num):
                        statuses.append("REPLAY_REJECTED")
                        continue
                    plaintext = engine.decrypt(key, pkt.nonce, pkt.ad, pkt.ciphertext, pkt.tag)
                    statuses.append("OK" if plaintext is not None else "AUTH_FAILURE")

    t = threading.Thread(target=receiver_loop, daemon=True)
    t.start()
    time.sleep(0.2)

    sender = SecureSender("127.0.0.1", port, engine, key)
    captured_raw = sender.send("Transfer $1000 to Account X")
    time.sleep(0.1)

    for _ in range(2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", port))
            sock.sendall(struct.pack(">I", len(captured_raw)) + captured_raw)
        time.sleep(0.1)

    t.join(timeout=3)
    assert statuses == ["OK", "REPLAY_REJECTED", "REPLAY_REJECTED"]
