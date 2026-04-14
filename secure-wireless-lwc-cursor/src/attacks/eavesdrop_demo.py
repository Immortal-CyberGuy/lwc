"""
Passive eavesdropper: sees ciphertext on the wire, not the application plaintext.
Run from project root: python -m src.attacks.eavesdrop_demo
"""

from __future__ import annotations

import os
import socket
import threading
import time

from src.crypto.ascon_engine import AsconEngine
from src.network.receiver import SecureReceiver
from src.network.sender import SecureSender


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> None:
    key = os.urandom(16)
    port = _free_port()
    secret = "Top secret sensor reading: 42.7 degrees"
    captured: dict = {}

    def run_receiver():
        rx = SecureReceiver(port, AsconEngine(), key)
        captured["plaintext"], captured["status"] = rx.listen_once()

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.35)
    tx = SecureSender("127.0.0.1", port, AsconEngine(), key)
    raw_payload = tx.send(secret)
    captured["raw_payload"] = raw_payload
    t.join(timeout=15)

    print("\n" + "=" * 60)
    print("EAVESDROPPING ANALYSIS (payload bytes = serialized SecurePacket)")
    print("=" * 60)
    print(f"Original message:  {secret}")
    hx = captured["raw_payload"].hex()
    print(f"Captured raw hex (first 120): {hx[:120]}...")
    print(f"Plaintext in raw?: {secret.encode() in captured['raw_payload']}")
    print(f"Decrypted at RX:   {captured.get('plaintext')!r} (status={captured.get('status')})")
    print("\nRESULT: Eavesdropper sees the packet layout; message body is ciphertext + tag.")
    print("The secret string should NOT appear as contiguous bytes in the payload.")


if __name__ == "__main__":
    main()
