import socket
import struct

from src.network.packet import SecurePacket
from src.network.replay_guard import ReplayGuard


def _recv_exact(conn: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data.")
        data += chunk
    return data


class SecureReceiver:
    def __init__(self, port: int, engine, key: bytes, host: str = "127.0.0.1"):
        self.host = host
        self.port = port
        self.engine = engine
        self.key = key
        self.replay_guard = ReplayGuard()

    def listen_once(self) -> tuple[str | None, str]:
        """
        Listen for one message and return (plaintext_message, status).
        Status is one of: OK, REPLAY_REJECTED, AUTH_FAILURE, ALGO_MISMATCH, PACKET_ERROR.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(1)
            conn, _addr = sock.accept()
            with conn:
                length_data = _recv_exact(conn, 4)
                msg_len = struct.unpack(">I", length_data)[0]
                raw = _recv_exact(conn, msg_len)

                try:
                    pkt = SecurePacket.deserialize(raw)
                except ValueError:
                    return None, "PACKET_ERROR"

                if pkt.algo_id != self.engine.algo_id:
                    return None, "ALGO_MISMATCH"

                if not self.replay_guard.check_and_update(pkt.seq_num):
                    return None, "REPLAY_REJECTED"

                plaintext = self.engine.decrypt(
                    self.key,
                    pkt.nonce,
                    pkt.ad,
                    pkt.ciphertext,
                    pkt.tag,
                )
                if plaintext is None:
                    return None, "AUTH_FAILURE"

                return plaintext.decode("utf-8"), "OK"
