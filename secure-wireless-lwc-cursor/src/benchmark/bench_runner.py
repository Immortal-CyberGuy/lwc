"""Benchmark encrypt/decrypt for all engines; write CSV under results/."""

from __future__ import annotations

import argparse
import csv
import os
import time
import tracemalloc
from typing import Iterable

from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine

DEFAULT_ENGINES = [
    AsconEngine(),
    AESEngine(),
    SpeckEngine(),
    PresentEngine(),
]

DEFAULT_PAYLOAD_SIZES = [16, 64, 256, 1024, 4096, 16384]

DEFAULT_ITERATIONS = {
    16: 10_000,
    64: 10_000,
    256: 5_000,
    1024: 2_000,
    4096: 1_000,
    16_384: 500,
}


def run_benchmarks(
    output_csv: str = "results/benchmark_results.csv",
    *,
    engines: Iterable | None = None,
    payload_sizes: list[int] | None = None,
    iterations_map: dict[int, int] | None = None,
) -> list[dict]:
    engines = list(engines or DEFAULT_ENGINES)
    payload_sizes = payload_sizes or list(DEFAULT_PAYLOAD_SIZES)
    iterations_map = iterations_map or dict(DEFAULT_ITERATIONS)

    results: list[dict] = []
    key = os.urandom(16)
    nonce = os.urandom(16)
    ad = b"benchmark-associated-data"

    for engine in engines:
        for size in payload_sizes:
            plaintext = os.urandom(size)
            iters = iterations_map[size]

            tracemalloc.start()
            enc_times: list[int] = []
            ct = tag = b""
            for _ in range(iters):
                start = time.perf_counter_ns()
                ct, tag = engine.encrypt(key, nonce, ad, plaintext)
                end = time.perf_counter_ns()
                enc_times.append(end - start)
            _, enc_peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            tracemalloc.start()
            dec_times: list[int] = []
            for _ in range(iters):
                start = time.perf_counter_ns()
                engine.decrypt(key, nonce, ad, ct, tag)
                end = time.perf_counter_ns()
                dec_times.append(end - start)
            _, dec_peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            avg_enc = sum(enc_times) / len(enc_times) / 1_000
            avg_dec = sum(dec_times) / len(dec_times) / 1_000
            throughput = (size / (avg_enc / 1e6)) / 1024 if avg_enc > 0 else 0.0

            row = {
                "algorithm": engine.name(),
                "payload_bytes": size,
                "iterations": iters,
                "avg_encrypt_us": round(avg_enc, 2),
                "avg_decrypt_us": round(avg_dec, 2),
                "throughput_kbps": round(throughput, 2),
                "enc_peak_mem_kb": round(enc_peak_mem / 1024, 2),
                "dec_peak_mem_kb": round(dec_peak_mem / 1024, 2),
            }
            results.append(row)
            print(
                f"{engine.name():25s} | {size:6d}B | "
                f"Enc: {avg_enc:10.2f}us | {throughput:10.2f} KB/s"
            )

    out_dir = os.path.dirname(output_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to {output_csv}")
    return results


def _quick_config():
    """Small run for smoke tests; PRESENT-in-Python is slow on large payloads."""
    return {
        "payload_sizes": [16, 256],
        "iterations_map": {16: 80, 256: 12},
    }


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="LWC crypto benchmarks → CSV")
    p.add_argument(
        "-o",
        "--output",
        default="results/benchmark_results.csv",
        help="Output CSV path",
    )
    p.add_argument(
        "--quick",
        action="store_true",
        help="Small payload set and few iterations (smoke run)",
    )
    args = p.parse_args(argv)

    if args.quick:
        cfg = _quick_config()
        run_benchmarks(
            args.output,
            payload_sizes=cfg["payload_sizes"],
            iterations_map=cfg["iterations_map"],
        )
    else:
        run_benchmarks(args.output)


if __name__ == "__main__":
    main()
