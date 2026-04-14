import socket
import struct

from src.network.constants import MAX_WIRE_PAYLOAD_BYTES
from src.network.packet import SecurePacket
from src.network.replay_guard import ReplayGuard


class SecureReceiver:
    def __init__(self, port, engine, key, *, verbose: bool = True):
        self.port = port
        self.engine = engine
        self.key = key
        self.replay_guard = ReplayGuard()
        self.verbose = verbose

    def _emit(self, message: str) -> None:
        if self.verbose:
            print(message)

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed before length/payload complete")
            buf += chunk
        return buf

    def _handle_connection(self, conn: socket.socket):
        try:
            length_data = self._recv_exact(conn, 4)
            msg_len = struct.unpack(">I", length_data)[0]
            if msg_len == 0 or msg_len > MAX_WIRE_PAYLOAD_BYTES:
                self._emit("[RECEIVER] Rejected: invalid or oversized length prefix.")
                return None, "LENGTH_REJECTED"
            data = self._recv_exact(conn, msg_len)
            pkt = SecurePacket.deserialize(data)
        except ConnectionError as exc:
            self._emit(f"[RECEIVER] Connection error: {exc}")
            return None, "IO_ERROR"
        except ValueError as exc:
            self._emit(f"[RECEIVER] Parse error: {exc}")
            return None, "PARSE_ERROR"

        if not self.replay_guard.check_and_update(pkt.seq_num):
            self._emit(f"[RECEIVER] REPLAY DETECTED! seq={pkt.seq_num}")
            return None, "REPLAY_REJECTED"
        pt = self.engine.decrypt(
            self.key, pkt.nonce, pkt.ad, pkt.ciphertext, pkt.tag
        )
        if pt is None:
            self._emit("[RECEIVER] AUTH FAILURE! Tag verification failed.")
            return None, "AUTH_FAILURE"
        try:
            msg = pt.decode("utf-8")
        except UnicodeDecodeError:
            self._emit("[RECEIVER] Plaintext is not valid UTF-8.")
            return None, "DECODE_ERROR"
        self._emit(f'[RECEIVER] Decrypted: "{msg}" (seq={pkt.seq_num})')
        return msg, "OK"

    def listen_once(self):
        """Listen for one TCP connection and one length-prefixed packet."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", self.port))
            s.listen(1)
            self._emit(f"[RECEIVER] Listening on port {self.port}...")
            conn, _addr = s.accept()
            with conn:
                return self._handle_connection(conn)

    def listen_count(self, count: int):
        """Accept `count` sequential connections, one packet each (for tests/demos)."""
        results = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", self.port))
            s.listen(count)
            self._emit(
                f"[RECEIVER] Listening on port {self.port} for {count} packet(s)..."
            )
            for _ in range(count):
                conn, _addr = s.accept()
                with conn:
                    results.append(self._handle_connection(conn))
        return results

    def listen_forever(self) -> None:
        """Block accepting messages until KeyboardInterrupt (one packet per connection)."""
        self._emit(
            f"[RECEIVER] Forever mode on port {self.port} (Ctrl+C to stop)..."
        )
        try:
            while True:
                self.listen_once()
        except KeyboardInterrupt:
            self._emit("[RECEIVER] Stopped.")
