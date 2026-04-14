import os
import socket
import struct
import threading
import time
from pathlib import Path

from src.crypto.ascon_engine import AsconEngine
from src.network.packet import SecurePacket
from src.network.receiver import SecureReceiver


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _write_log(log_path: str, lines: list[str]) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _send_raw(host: str, port: int, raw: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(struct.pack(">I", len(raw)) + raw)


def run_demo(log_path: str = "results/attack_logs/mitm_demo.log") -> dict:
    key = os.urandom(16)
    port = _free_port()
    engine = AsconEngine()
    status_result: dict[str, str | None] = {"status": None, "msg": None}

    def run_receiver() -> None:
        receiver = SecureReceiver(port=port, engine=engine, key=key)
        msg, status = receiver.listen_once()
        status_result["status"] = status
        status_result["msg"] = msg

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.2)

    # Build a valid packet first.
    seq_num = 1
    nonce = struct.pack(">Q", seq_num) + os.urandom(8)
    timestamp = int(time.time() * 1000)
    ad = b"SENDER01" + struct.pack(">Q", timestamp)
    plaintext = b"MITM target payload"
    ciphertext, tag = engine.encrypt(key, nonce, ad, plaintext)
    legit_pkt = SecurePacket(engine.algo_id, nonce, seq_num, timestamp, ad, ciphertext, tag)

    # Tamper ciphertext bytes in transit but keep original tag (auth must fail).
    tampered_ct = bytearray(legit_pkt.ciphertext)
    tampered_ct[0] ^= 0xFF
    tampered_pkt = SecurePacket(
        legit_pkt.algo_id,
        legit_pkt.nonce,
        legit_pkt.seq_num,
        legit_pkt.timestamp,
        legit_pkt.ad,
        bytes(tampered_ct),
        legit_pkt.tag,
    )
    _send_raw("127.0.0.1", port, tampered_pkt.serialize())
    t.join(timeout=3)

    passed = status_result["status"] == "AUTH_FAILURE"
    result = {
        "receiver_status": status_result["status"],
        "receiver_message": status_result["msg"],
        "result": "PASS" if passed else "FAIL",
    }

    lines = [
        "=" * 60,
        "MITM TAMPER DEMO",
        "=" * 60,
        f"Receiver status:  {result['receiver_status']}",
        f"Receiver message: {result['receiver_message']}",
        f"RESULT:           {result['result']}",
    ]
    _write_log(log_path, lines)
    print("\n".join(lines))
    return result


if __name__ == "__main__":
    run_demo()
