import os
import socket
import struct
import threading
import time
from pathlib import Path

from src.crypto.ascon_engine import AsconEngine
from src.network.packet import SecurePacket
from src.network.replay_guard import ReplayGuard
from src.network.sender import SecureSender


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data.")
        data += chunk
    return data


def _write_log(log_path: str, lines: list[str]) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_demo(log_path: str = "results/attack_logs/replay_demo.log") -> dict:
    key = os.urandom(16)
    port = _free_port()
    engine = AsconEngine()
    statuses: list[str] = []

    def receiver_loop(expected_messages: int = 3) -> None:
        guard = ReplayGuard()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(expected_messages)
            for _ in range(expected_messages):
                conn, _addr = sock.accept()
                with conn:
                    msg_len = struct.unpack(">I", _recv_exact(conn, 4))[0]
                    raw = _recv_exact(conn, msg_len)
                    pkt = SecurePacket.deserialize(raw)
                    if not guard.check_and_update(pkt.seq_num):
                        statuses.append("REPLAY_REJECTED")
                        continue
                    pt = engine.decrypt(key, pkt.nonce, pkt.ad, pkt.ciphertext, pkt.tag)
                    statuses.append("OK" if pt is not None else "AUTH_FAILURE")

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

    passed = statuses == ["OK", "REPLAY_REJECTED", "REPLAY_REJECTED"]
    result = {
        "statuses": statuses,
        "result": "PASS" if passed else "FAIL",
    }

    lines = [
        "=" * 60,
        "REPLAY DEMO",
        "=" * 60,
        f"Message 1 status: {statuses[0] if len(statuses) > 0 else 'MISSING'}",
        f"Message 2 status: {statuses[1] if len(statuses) > 1 else 'MISSING'}",
        f"Message 3 status: {statuses[2] if len(statuses) > 2 else 'MISSING'}",
        f"RESULT:           {result['result']}",
    ]
    _write_log(log_path, lines)
    print("\n".join(lines))
    return result


if __name__ == "__main__":
    run_demo()
