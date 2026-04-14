import argparse

from src.network.engine_factory import available_engines, create_engine
from src.network.receiver import SecureReceiver


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one-shot secure receiver server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host.")
    parser.add_argument("--port", type=int, default=9000, help="Bind port.")
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
    return parser


def main() -> None:
    args = _parser().parse_args()
    key = bytes.fromhex(args.key_hex)
    if len(key) != 16:
        raise ValueError("Key must decode to exactly 16 bytes.")

    engine = create_engine(args.engine)
    receiver = SecureReceiver(port=args.port, engine=engine, key=key, host=args.host)
    print(
        f"[SERVER] Listening once on {args.host}:{args.port} "
        f"with engine={engine.name()} (algo_id={engine.algo_id})"
    )
    msg, status = receiver.listen_once()
    print(f"[SERVER] Status={status}")
    print(f"[SERVER] Message={msg}")


if __name__ == "__main__":
    main()
