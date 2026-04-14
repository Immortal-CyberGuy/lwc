import os
import socket
import threading
import time
from pathlib import Path

from src.crypto.ascon_engine import AsconEngine
from src.network.receiver import SecureReceiver
from src.network.sender import SecureSender


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _write_log(log_path: str, lines: list[str]) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_demo(log_path: str = "results/attack_logs/eavesdrop_demo.log") -> dict:
    key = os.urandom(16)
    port = _free_port()
    secret_msg = "Top secret sensor reading: 42.7 degrees"
    result: dict[str, str | bool] = {}

    def run_receiver() -> None:
        receiver = SecureReceiver(port=port, engine=AsconEngine(), key=key)
        msg, status = receiver.listen_once()
        result["receiver_status"] = status
        result["decrypted_message"] = msg or ""

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()
    time.sleep(0.2)

    sender = SecureSender("127.0.0.1", port, AsconEngine(), key)
    raw_packet = sender.send(secret_msg)
    t.join(timeout=3)

    plaintext_in_raw = secret_msg.encode("utf-8") in raw_packet
    result["plaintext_in_raw"] = plaintext_in_raw
    result["raw_packet_hex_prefix"] = raw_packet.hex()[:120]
    result["result"] = "PASS" if (not plaintext_in_raw and result.get("receiver_status") == "OK") else "FAIL"

    lines = [
        "=" * 60,
        "EAVESDROP DEMO",
        "=" * 60,
        f"Original message: {secret_msg}",
        f"Receiver status:  {result.get('receiver_status', '')}",
        f"Decrypted at RX:  {result.get('decrypted_message', '')}",
        f"Captured hex:     {result['raw_packet_hex_prefix']}...",
        f"Plaintext in raw: {plaintext_in_raw}",
        f"RESULT:           {result['result']}",
    ]
    _write_log(log_path, lines)
    print("\n".join(lines))
    return result


if __name__ == "__main__":
    run_demo()
