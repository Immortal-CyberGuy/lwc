import os

from src.network.packet import SecurePacket
from src.network.replay_guard import ReplayGuard


def test_secure_packet_roundtrip():
    pkt = SecurePacket(
        algo_id=1,
        nonce=os.urandom(16),
        seq_num=42,
        timestamp=1_700_000_000_000,
        ad=b"device\x00id",
        ciphertext=b"secret-bytes",
        tag=os.urandom(16),
    )
    wire = pkt.serialize()
    out = SecurePacket.deserialize(wire)
    assert out.algo_id == pkt.algo_id
    assert out.nonce == pkt.nonce
    assert out.seq_num == pkt.seq_num
    assert out.timestamp == pkt.timestamp
    assert out.ad == pkt.ad
    assert out.ciphertext == pkt.ciphertext
    assert out.tag == pkt.tag


def test_replay_guard_fresh_and_duplicate():
    g = ReplayGuard(window_size=8)
    assert g.check_and_update(1) is True
    assert g.check_and_update(2) is True
    assert g.check_and_update(2) is False
    assert g.check_and_update(1) is False


def test_replay_guard_rejects_seq_zero():
    g = ReplayGuard()
    assert g.check_and_update(0) is False
