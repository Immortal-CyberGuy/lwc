"""
Simulate the three attack stories from the demos, as automated pytest cases:

- Eavesdrop: wire bytes (serialised SecurePacket) must not contain the UTF-8 plaintext.
- Tampering: flip ciphertext bytes, keep original tag → decrypt fails (AUTH_FAILURE).
- Replay / resend: send the same captured payload again → REPLAY_REJECTED.
"""

from __future__ import annotations

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


def _ephemeral_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tampered_packet_serialized(
    engine, key: bytes, seq_num: int, plaintext: str
) -> bytes:
    """Valid encrypt, then flip leading ciphertext bytes; tag unchanged (mitm_demo style)."""
    nonce = struct.pack(">Q", seq_num) + os.urandom(8)
    timestamp = int(time.time() * 1000)
    ad = "SENDER01".encode("utf-8") + struct.pack(">Q", timestamp)
    ct, tag = engine.encrypt(key, nonce, ad, plaintext.encode("utf-8"))
    ct_b = bytearray(ct)
    if not ct_b:
        ct_b = bytearray(b"\x00")
    for i in range(min(4, len(ct_b))):
        ct_b[i] ^= 0xFF
    pkt = SecurePacket(
        engine.algo_id, nonce, seq_num, timestamp, ad, bytes(ct_b), tag
    )
    return pkt.serialize()


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
def test_simulate_eavesdrop_plaintext_not_in_wire_bytes(engine):
    """What a passive tap sees must not include the application message as raw UTF-8."""
    port = _ephemeral_port()
    key = os.urandom(16)
    secret = "Classified payload: project-lwc-9f2a — DO NOT EXPOSE"
    outcome: dict = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key, verbose=False)
        outcome["msg"], outcome["status"] = rx.listen_once()

    th = threading.Thread(target=run_receiver)
    th.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key, verbose=False)
    raw_payload = tx.send(secret)
    th.join(timeout=15)
    assert not th.is_alive()
    assert outcome["status"] == "OK"
    assert outcome["msg"] == secret
    pt_bytes = secret.encode("utf-8")
    assert pt_bytes not in raw_payload
    wire = struct.pack(">I", len(raw_payload)) + raw_payload
    assert pt_bytes not in wire


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
def test_simulate_tampering_auth_failure(engine):
    """Modified ciphertext + original tag → receiver rejects (integrity)."""
    port = _ephemeral_port()
    key = os.urandom(16)
    results: dict = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key, verbose=False)
        results["pairs"] = rx.listen_count(2)

    th = threading.Thread(target=run_receiver)
    th.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key, verbose=False)
    tx.send("first-is-clean")
    tampered = _tampered_packet_serialized(
        engine, key, seq_num=2, plaintext="attacker-forged-body"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
        sk.connect(("127.0.0.1", port))
        sk.sendall(struct.pack(">I", len(tampered)) + tampered)
    th.join(timeout=15)
    assert not th.is_alive()
    p1, p2 = results["pairs"]
    assert p1 == ("first-is-clean", "OK")
    assert p2[0] is None
    assert p2[1] == "AUTH_FAILURE"


def test_simulate_replay_resend_same_wire_rejected():
    """Legitimate delivery once; identical bytes resent twice → both replay-rejected."""
    port = _ephemeral_port()
    key = os.urandom(16)
    engine = AsconEngine()
    results: dict = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key, verbose=False)
        results["pairs"] = rx.listen_count(3)

    th = threading.Thread(target=run_receiver)
    th.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, engine, key, verbose=False)
    captured = tx.send("Pay invoice #5541")
    wire = struct.pack(">I", len(captured)) + captured
    for _ in range(2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
            sk.connect(("127.0.0.1", port))
            sk.sendall(wire)
        time.sleep(0.05)
    th.join(timeout=15)
    assert not th.is_alive()
    rows = results["pairs"]
    assert rows[0] == ("Pay invoice #5541", "OK")
    assert rows[1][1] == "REPLAY_REJECTED"
    assert rows[2][1] == "REPLAY_REJECTED"
