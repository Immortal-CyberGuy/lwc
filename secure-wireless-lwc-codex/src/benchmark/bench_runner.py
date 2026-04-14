import argparse
import csv
import os
import time
import tracemalloc
from datetime import datetime, timezone

from src.benchmark.metrics import (
    bytes_per_second_to_kilobytes_per_second,
    mean_and_stdev,
    ns_to_us,
)
from src.crypto.aes_engine import AESEngine
from src.crypto.ascon_engine import AsconEngine
from src.crypto.present_engine import PresentEngine
from src.crypto.speck_engine import SpeckEngine

ENGINES = [AsconEngine(), AESEngine(), SpeckEngine(), PresentEngine()]
PAYLOAD_SIZES = [16, 64, 256, 1024, 4096, 16384]
QUICK_PAYLOAD_SIZES = [16, 64, 256]
DEFAULT_ITERATIONS = {
    16: 10000,
    64: 10000,
    256: 5000,
    1024: 2000,
    4096: 1000,
    16384: 500,
}
QUICK_ITERATIONS = {
    16: 20,
    64: 20,
    256: 10,
}


def _nonce_for_iteration(seed: bytes, seq_num: int) -> bytes:
    # 16-byte nonce with counter prefix to avoid accidental nonce reuse during loops.
    return seq_num.to_bytes(8, "big") + seed[8:]


def _benchmark_one(engine, payload_size: int, iterations: int, key: bytes, ad: bytes) -> dict:
    plaintext = os.urandom(payload_size)
    nonce_seed = os.urandom(16)

    enc_times_ns: list[float] = []
    tracemalloc.start()
    last_ct = b""
    last_tag = b""
    last_nonce = b""
    for i in range(iterations):
        nonce = _nonce_for_iteration(nonce_seed, i + 1)
        start = time.perf_counter_ns()
        ct, tag = engine.encrypt(key, nonce, ad, plaintext)
        end = time.perf_counter_ns()
        enc_times_ns.append(end - start)
        last_ct = ct
        last_tag = tag
        last_nonce = nonce
    _, enc_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    dec_times_ns: list[float] = []
    tracemalloc.start()
    for _ in range(iterations):
        start = time.perf_counter_ns()
        _ = engine.decrypt(key, last_nonce, ad, last_ct, last_tag)
        end = time.perf_counter_ns()
        dec_times_ns.append(end - start)
    _, dec_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    avg_enc_ns, std_enc_ns = mean_and_stdev(enc_times_ns)
    avg_dec_ns, std_dec_ns = mean_and_stdev(dec_times_ns)

    avg_enc_us = ns_to_us(avg_enc_ns)
    avg_dec_us = ns_to_us(avg_dec_ns)
    std_enc_us = ns_to_us(std_enc_ns)
    std_dec_us = ns_to_us(std_dec_ns)

    throughput_bps = 0.0
    if avg_enc_ns > 0:
        throughput_bps = payload_size / (avg_enc_ns / 1_000_000_000.0)
    throughput_kbps = bytes_per_second_to_kilobytes_per_second(throughput_bps)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "algorithm": engine.name(),
        "algo_id": engine.algo_id,
        "payload_bytes": payload_size,
        "iterations": iterations,
        "avg_encrypt_us": round(avg_enc_us, 4),
        "std_encrypt_us": round(std_enc_us, 4),
        "avg_decrypt_us": round(avg_dec_us, 4),
        "std_decrypt_us": round(std_dec_us, 4),
        "throughput_kbps": round(throughput_kbps, 4),
        "enc_peak_mem_kb": round(enc_peak_mem / 1024.0, 4),
        "dec_peak_mem_kb": round(dec_peak_mem / 1024.0, 4),
    }


def run_benchmarks(
    output_csv: str = "results/benchmark_results.csv",
    iterations_map: dict[int, int] | None = None,
    payload_sizes: list[int] | None = None,
) -> list[dict]:
    if iterations_map is None:
        iterations_map = DEFAULT_ITERATIONS
    if payload_sizes is None:
        payload_sizes = PAYLOAD_SIZES

    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)

    results: list[dict] = []
    key = os.urandom(16)
    ad = b"benchmark-associated-data"

    for engine in ENGINES:
        for payload_size in payload_sizes:
            if payload_size not in iterations_map:
                raise ValueError(f"Missing iterations for payload size {payload_size}.")
            iters = iterations_map[payload_size]
            row = _benchmark_one(engine, payload_size, iters, key, ad)
            results.append(row)
            print(
                f"{row['algorithm']:25s} | {payload_size:6d}B | "
                f"Enc: {row['avg_encrypt_us']:10.4f}us | "
                f"Dec: {row['avg_decrypt_us']:10.4f}us | "
                f"Thr: {row['throughput_kbps']:10.4f} KB/s"
            )

    with open(output_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"Results saved to {output_csv}")
    return results


def run_repeated_benchmarks(
    runs: int,
    output_dir: str,
    quick: bool = False,
) -> list[str]:
    os.makedirs(output_dir, exist_ok=True)
    iterations_map = QUICK_ITERATIONS if quick else DEFAULT_ITERATIONS
    payload_sizes = QUICK_PAYLOAD_SIZES if quick else PAYLOAD_SIZES
    generated_files = []
    for run_idx in range(1, runs + 1):
        out_file = os.path.join(output_dir, f"run{run_idx}.csv")
        print(f"\n=== Benchmark Run {run_idx}/{runs} -> {out_file} ===")
        run_benchmarks(
            output_csv=out_file,
            iterations_map=iterations_map,
            payload_sizes=payload_sizes,
        )
        generated_files.append(out_file)
    return generated_files


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark cryptographic engines.")
    parser.add_argument(
        "--output",
        default="results/benchmark_results.csv",
        help="Output CSV path for single run.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run with reduced iteration counts for smoke testing.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs. If >1, outputs run1.csv..runN.csv in --output-dir.",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Output directory used when --runs > 1.",
    )
    return parser


def main() -> None:
    args = _build_arg_parser().parse_args()
    if args.runs > 1:
        files = run_repeated_benchmarks(args.runs, args.output_dir, quick=args.quick)
        print("Generated files:")
        for file_path in files:
            print(f"- {file_path}")
        return

    iterations = QUICK_ITERATIONS if args.quick else DEFAULT_ITERATIONS
    payload_sizes = QUICK_PAYLOAD_SIZES if args.quick else PAYLOAD_SIZES
    run_benchmarks(output_csv=args.output, iterations_map=iterations, payload_sizes=payload_sizes)


if __name__ == "__main__":
    main()
