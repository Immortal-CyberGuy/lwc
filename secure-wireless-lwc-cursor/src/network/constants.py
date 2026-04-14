"""Wire protocol limits (lab / IoT-friendly)."""

# Max length-prefix payload (serialized SecurePacket); bounds memory on receive.
MAX_WIRE_PAYLOAD_BYTES = 1 * 1024 * 1024  # 1 MiB

DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_CONNECT_HOST = "127.0.0.1"
