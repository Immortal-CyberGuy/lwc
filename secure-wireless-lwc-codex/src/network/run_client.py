import argparse

from src.network.engine_factory import available_engines, create_engine
from src.network.sender import SecureSender


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one-shot secure sender client.")
    parser.add_argument("--host", default="127.0.0.1", help="Receiver host.")
    parser.add_argument("--port", type=int, default=9000, help="Receiver port.")
    parser.add_argument(
        "--engine",
        default="ascon",
        choices=available_engines(),
        help="Crypto engine.",
    )
    parser.add_argument(
        "--key-hex",
        default="00112233445566778899aabbccddeeff",
        help="16-byte key as 32 hex chars.",
    )
    parser.add_argument(
        "--message",
        default="Hello from secure client",
        help="UTF-8 message payload.",
    )
    parser.add_argument("--device-id", default="SENDER01", help="Associated-data device id.")
    return parser


def main() -> None:
    args = _parser().parse_args()
    key = bytes.fromhex(args.key_hex)
    if len(key) != 16:
        raise ValueError("Key must decode to exactly 16 bytes.")

    engine = create_engine(args.engine)
    sender = SecureSender(args.host, args.port, engine, key)
    raw = sender.send(args.message, device_id=args.device_id)
    print(
        f"[CLIENT] Sent message to {args.host}:{args.port} "
        f"with engine={engine.name()} bytes={len(raw)}"
    )


if __name__ == "__main__":
    main()
