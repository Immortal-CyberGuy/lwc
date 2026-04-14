"""
Unified entrypoint (post–Phase 6). Run from the project root:

  python main.py verify
  python main.py test
  python main.py benchmark [--quick]
  python main.py visualize [--ensure-csv] [-i path] [-o dir]
  python main.py demo eavesdrop|replay|mitm
  python main.py keygen --out keys/psk.bin
  python main.py serve --port 9000 --key keys/psk.bin
  python main.py send --port 9000 --key keys/psk.bin -m "hello"
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _run_module(mod: str) -> int:
    return subprocess.call([sys.executable, "-m", mod], cwd=ROOT)


def cmd_verify(_args: argparse.Namespace) -> int:
    script = ROOT / "verify_setup.py"
    return subprocess.call([sys.executable, str(script)], cwd=ROOT)


def cmd_test(_args: argparse.Namespace) -> int:
    return subprocess.call(
        [sys.executable, "-m", "pytest", "tests", "-v"],
        cwd=ROOT,
    )


def cmd_benchmark(args: argparse.Namespace) -> int:
    from src.benchmark.bench_runner import main as bench_main

    argv: list[str] = []
    if args.quick:
        argv += ["--quick", "-o", args.output]
    else:
        argv += ["-o", args.output]
    bench_main(argv)
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    from src.benchmark.visualize import main as viz_main

    argv = ["-i", args.input, "-o", args.output_dir]
    if args.ensure_csv:
        argv.append("--ensure-csv")
    viz_main(argv)
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    from src.utils.key_manager import generate_psk, save_key

    key = generate_psk(args.bytes)
    save_key(args.out, key)
    print(f"Wrote {len(key)}-byte PSK to {args.out}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from src.crypto.engine_factory import get_engine
    from src.network.receiver import SecureReceiver
    from src.utils.key_manager import load_key

    key = load_key(args.key)
    engine = get_engine(args.engine)
    rx = SecureReceiver(args.port, engine, key, verbose=not args.quiet)
    if args.once:
        rx.listen_once()
    else:
        rx.listen_forever()
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    from src.crypto.engine_factory import get_engine
    from src.network.sender import SecureSender
    from src.utils.key_manager import load_key

    key = load_key(args.key)
    engine = get_engine(args.engine)
    tx = SecureSender(args.host, args.port, engine, key, verbose=not args.quiet)
    tx.send(args.message, device_id=args.device)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    which = args.which
    mapping = {
        "eavesdrop": "src.attacks.eavesdrop_demo",
        "replay": "src.attacks.replay_demo",
        "mitm": "src.attacks.mitm_demo",
    }
    if which not in mapping:
        print("unknown demo:", which, file=sys.stderr)
        return 2
    return _run_module(mapping[which])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Secure Wireless LWC — lab commands (run from project root)."
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="Run verify_setup.py (Phase 1 gate).")
    p_verify.set_defaults(func=cmd_verify)

    p_test = sub.add_parser("test", help="Run pytest on tests/.")
    p_test.set_defaults(func=cmd_test)

    bp = sub.add_parser("benchmark", help="Run src.benchmark.bench_runner.")
    bp.add_argument("--quick", action="store_true", help="Small iteration run.")
    bp.add_argument(
        "-o",
        "--output",
        default="results/benchmark_results.csv",
        help="Output CSV path.",
    )
    bp.set_defaults(func=cmd_benchmark)

    vp = sub.add_parser("visualize", help="Generate six chart PNGs from CSV.")
    vp.add_argument(
        "-i",
        "--input",
        default="results/benchmark_results.csv",
        help="Input benchmark CSV.",
    )
    vp.add_argument("-o", "--output-dir", default="results", help="PNG output folder.")
    vp.add_argument(
        "--ensure-csv",
        action="store_true",
        help="Create a quick CSV if the input file is missing.",
    )
    vp.set_defaults(func=cmd_visualize)

    dp = sub.add_parser("demo", help="Run an attack demonstration script.")
    dp.add_argument(
        "which",
        choices=("eavesdrop", "replay", "mitm"),
        help="Which demo to run.",
    )
    dp.set_defaults(func=cmd_demo)

    kg = sub.add_parser("keygen", help="Generate a random PSK file (lab use).")
    kg.add_argument(
        "--out",
        default="keys/psk.bin",
        help="Output path for raw key bytes.",
    )
    kg.add_argument(
        "--bytes",
        type=int,
        default=16,
        help="Key length in bytes (default 16 = 128-bit).",
    )
    kg.set_defaults(func=cmd_keygen)

    sv = sub.add_parser(
        "serve",
        help="Listen for one (or many) secure TCP message(s); needs same key as sender.",
    )
    sv.add_argument("-p", "--port", type=int, required=True, help="TCP port to bind.")
    sv.add_argument(
        "--key",
        required=True,
        help="Path to raw PSK file (see: keygen).",
    )
    sv.add_argument(
        "--engine",
        default="ascon",
        help="ascon | aes | speck | present (default: ascon).",
    )
    sv.add_argument(
        "--once",
        action="store_true",
        help="Accept a single message then exit (default: run until Ctrl+C).",
    )
    sv.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress [RECEIVER] console lines.",
    )
    sv.set_defaults(func=cmd_serve)

    sn = sub.add_parser("send", help="Encrypt and send one message to a receiver.")
    sn.add_argument(
        "--host",
        default="127.0.0.1",
        help="Receiver hostname (default: 127.0.0.1).",
    )
    sn.add_argument("-p", "--port", type=int, required=True, help="Receiver TCP port.")
    sn.add_argument("--key", required=True, help="Path to raw PSK file (same as receiver).")
    sn.add_argument(
        "--engine",
        default="ascon",
        help="ascon | aes | speck | present (default: ascon).",
    )
    sn.add_argument("-m", "--message", required=True, help="UTF-8 message body.")
    sn.add_argument(
        "--device",
        default="SENDER01",
        help="Device id embedded in associated data (default: SENDER01).",
    )
    sn.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress [SENDER] console lines.",
    )
    sn.set_defaults(func=cmd_send)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
