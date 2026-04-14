"""
Replay attack: re-sending the same bytes should be rejected by ReplayGuard.
Run from project root: python -m src.attacks.replay_demo
"""

from __future__ import annotations

import os
import socket
import struct
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
    results: dict = {"rows": []}

    def run_receiver():
        rx = SecureReceiver(port, AsconEngine(), key)
        results["rows"] = rx.listen_count(3)

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.35)

    tx = SecureSender("127.0.0.1", port, AsconEngine(), key)
    captured_raw = tx.send("Transfer $1000 to Account X")
    time.sleep(0.15)

    wire = struct.pack(">I", len(captured_raw)) + captured_raw
    for _ in range(2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", port))
            s.sendall(wire)
        time.sleep(0.15)

    t.join(timeout=30)
    rows = results["rows"]

    print("\n" + "=" * 60)
    print("REPLAY ATTACK ANALYSIS")
    print("=" * 60)
    for i, (msg, status) in enumerate(rows, start=1):
        print(f"Connection {i}: status={status!r} msg={msg!r}")
    print("\nRESULT: First delivery should be OK; identical replays should be REPLAY_REJECTED.")


if __name__ == "__main__":
    main()
