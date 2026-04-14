"""
MITM / tampering: flipping ciphertext bytes breaks the authentication tag.
Run from project root: python -m src.attacks.mitm_demo
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time

from src.crypto.ascon_engine import AsconEngine
from src.network.packet import SecurePacket
from src.network.receiver import SecureReceiver


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _build_payload(
    engine: AsconEngine, key: bytes, seq_num: int, message: str
) -> bytes:
    nonce = struct.pack(">Q", seq_num) + os.urandom(8)
    ts = int(time.time() * 1000)
    device_id = "SENDER01"
    ad = device_id.encode() + struct.pack(">Q", ts)
    ct, tag = engine.encrypt(key, nonce, ad, message.encode("utf-8"))
    pkt = SecurePacket(engine.algo_id, nonce, seq_num, ts, ad, ct, tag)
    return pkt.serialize()


def main() -> None:
    key = os.urandom(16)
    port = _free_port()
    engine = AsconEngine()
    legit_msg = "Authorize payment #7712"

    captured_raw = _build_payload(engine, key, 1, legit_msg)
    pkt = SecurePacket.deserialize(captured_raw)
    ct = bytearray(pkt.ciphertext)
    if not ct:
        ct = bytearray(b"\x00")
    for i in range(min(4, len(ct))):
        ct[i] ^= 0xFF
    tampered_raw = SecurePacket(
        pkt.algo_id,
        pkt.nonce,
        pkt.seq_num,
        pkt.timestamp,
        pkt.ad,
        bytes(ct),
        pkt.tag,
    ).serialize()

    outcome: dict = {}

    def run_receiver():
        rx = SecureReceiver(port, engine, key)
        outcome["msg"], outcome["status"] = rx.listen_once()

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.35)

    print("\n" + "=" * 60)
    print("MITM / TAMPER DEMO")
    print("=" * 60)
    print(f"Legitimate plaintext (offline build): {legit_msg!r}")
    print(f"Legit payload hex (head): {captured_raw.hex()[:80]}...")
    print("Attacker flips bytes in ciphertext; tag left unchanged (classic integrity break).")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack(">I", len(tampered_raw)) + tampered_raw)

    t.join(timeout=15)

    print(f"Receiver outcome: status={outcome.get('status')!r} msg={outcome.get('msg')!r}")
    print("\nRESULT: AEAD verification should fail → AUTH_FAILURE (no trusted plaintext).")


if __name__ == "__main__":
    main()
