"""Build report charts from benchmark CSV (Phase 6)."""

from __future__ import annotations

import argparse
import os

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


def _read_benchmark_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    for col in (
        "payload_bytes",
        "avg_encrypt_us",
        "avg_decrypt_us",
        "throughput_kbps",
        "enc_peak_mem_kb",
        "dec_peak_mem_kb",
    ):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def _nearest_payload(df: pd.DataFrame, target: int = 1024) -> int:
    sizes = sorted(df["payload_bytes"].dropna().unique().astype(int))
    if not sizes:
        raise ValueError("benchmark CSV has no payload_bytes rows")
    if target in sizes:
        return int(target)
    return int(min(sizes, key=lambda s: abs(s - target)))


def _security_bits(algorithm: str) -> int:
    name = str(algorithm).upper()
    if "PRESENT-80" in name or name.startswith("PRESENT"):
        return 80
    return 128


def generate_all_charts(
    csv_path: str = "results/benchmark_results.csv",
    output_dir: str = "results",
) -> list[str]:
    df = _read_benchmark_csv(csv_path)
    if df.empty:
        raise ValueError(f"no rows in {csv_path}")

    os.makedirs(output_dir, exist_ok=True)
    sns.set_theme(style="whitegrid", palette="deep")
    written: list[str] = []

    # --- Chart 1: throughput vs payload (log2 x) ---
    fig, ax = plt.subplots(figsize=(12, 6))
    for algo in df["algorithm"].unique():
        sub = df[df["algorithm"] == algo].sort_values("payload_bytes")
        ax.plot(
            sub["payload_bytes"],
            sub["throughput_kbps"],
            marker="o",
            linewidth=2,
            label=algo,
        )
    ax.set_xlabel("Payload size (bytes)", fontsize=12)
    ax.set_ylabel("Throughput (KB/s)", fontsize=12)
    ax.set_title("Encryption throughput vs payload size", fontsize=14, fontweight="bold")
    ax.set_xscale("log", base=2)
    ax.legend(fontsize=9, loc="best")
    plt.tight_layout()
    p1 = os.path.join(output_dir, "chart1_throughput.png")
    fig.savefig(p1, dpi=150)
    plt.close(fig)
    written.append(p1)

    # --- Chart 2: encrypt time grouped bars (16 B / ~1 KB / ~16 KB when present) ---
    want = [16, 1024, 16384]
    have = [s for s in want if s in set(df["payload_bytes"].astype(int))]
    if not have:
        have = sorted(df["payload_bytes"].unique().astype(int))[:6]
    df2 = df[df["payload_bytes"].isin(have)].copy()
    df2["size_label"] = df2["payload_bytes"].map(
        lambda b: {16: "16 B", 1024: "1 KB", 16384: "16 KB"}.get(int(b), f"{int(b)} B")
    )
    label_order = (
        df2.drop_duplicates("size_label")
        .sort_values("payload_bytes")["size_label"]
        .tolist()
    )
    fig, ax = plt.subplots(figsize=(12, 6))
    sns.barplot(
        data=df2,
        x="size_label",
        y="avg_encrypt_us",
        hue="algorithm",
        order=label_order,
        ax=ax,
    )
    ax.set_xlabel("Payload", fontsize=12)
    ax.set_ylabel("Avg encrypt time (µs)", fontsize=12)
    ax.set_title("Encryption time by payload size", fontsize=14, fontweight="bold")
    plt.tight_layout()
    p2 = os.path.join(output_dir, "chart2_enc_time.png")
    fig.savefig(p2, dpi=150)
    plt.close(fig)
    written.append(p2)

    # --- Chart 3: peak memory at reference payload (~1 KB) ---
    ref = _nearest_payload(df, 1024)
    mem = df[df["payload_bytes"] == ref].copy()
    mem["peak_kb"] = mem[["enc_peak_mem_kb", "dec_peak_mem_kb"]].max(axis=1)
    mem = mem.sort_values("peak_kb", ascending=True)
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(data=mem, y="algorithm", x="peak_kb", ax=ax, orient="h")
    ax.set_xlabel("Peak traced memory (KB)", fontsize=12)
    ax.set_ylabel("Algorithm", fontsize=12)
    ax.set_title(f"Peak memory (encrypt/decrypt) at {ref} B payload", fontsize=14, fontweight="bold")
    plt.tight_layout()
    p3 = os.path.join(output_dir, "chart3_memory.png")
    fig.savefig(p3, dpi=150)
    plt.close(fig)
    written.append(p3)

    # --- Chart 4: encrypt vs decrypt stacked at reference payload ---
    sub = df[df["payload_bytes"] == ref].set_index("algorithm")
    algos = list(sub.index)
    enc = sub.loc[algos, "avg_encrypt_us"].astype(float).values
    dec = sub.loc[algos, "avg_decrypt_us"].astype(float).values
    x = np.arange(len(algos))
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x, enc, label="Encrypt (µs)")
    ax.bar(x, dec, bottom=enc, label="Decrypt (µs)")
    ax.set_xticks(x)
    ax.set_xticklabels(algos, rotation=20, ha="right")
    ax.set_ylabel("Time (µs)", fontsize=12)
    ax.set_title(f"Encrypt vs decrypt time at {ref} B payload", fontsize=14, fontweight="bold")
    ax.legend()
    plt.tight_layout()
    p4 = os.path.join(output_dir, "chart4_enc_dec.png")
    fig.savefig(p4, dpi=150)
    plt.close(fig)
    written.append(p4)

    # --- Chart 5: throughput vs claimed security level at reference payload ---
    sub5 = df[df["payload_bytes"] == ref].copy()
    sub5["security_bits"] = sub5["algorithm"].map(_security_bits)
    fig, ax = plt.subplots(figsize=(10, 6))
    for _, row in sub5.iterrows():
        ax.scatter(
            row["throughput_kbps"],
            row["security_bits"],
            s=120,
        )
        ax.annotate(
            str(row["algorithm"]),
            (row["throughput_kbps"], row["security_bits"]),
            textcoords="offset points",
            xytext=(6, 4),
            fontsize=8,
        )
    ax.set_xlabel("Throughput (KB/s)", fontsize=12)
    ax.set_ylabel("Security level (key/block strength, bits)", fontsize=12)
    ax.set_title(
        f"Security vs throughput trade-off ({ref} B payload)",
        fontsize=14,
        fontweight="bold",
    )
    plt.tight_layout()
    p5 = os.path.join(output_dir, "chart5_tradeoff.png")
    fig.savefig(p5, dpi=150)
    plt.close(fig)
    written.append(p5)

    # --- Chart 6: attack mitigation (from Phase 5 design targets) ---
    attacks = pd.DataFrame(
        {
            "attack": [
                "Eavesdrop\n(confidentiality)",
                "Replay",
                "MITM / tamper\n(integrity)",
            ],
            "mitigation_pct": [100.0, 100.0, 100.0],
        }
    )
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(data=attacks, x="attack", y="mitigation_pct", ax=ax, color="#4C72B0")
    ax.set_ylim(0, 115)
    ax.set_ylabel("Effective defense (%)", fontsize=12)
    ax.set_xlabel("Threat scenario", fontsize=12)
    ax.set_title("Attack demonstrations — expected mitigation outcome", fontsize=14, fontweight="bold")
    plt.tight_layout()
    p6 = os.path.join(output_dir, "chart6_attacks.png")
    fig.savefig(p6, dpi=150)
    plt.close(fig)
    written.append(p6)

    return written


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Generate benchmark charts (Phase 6)")
    p.add_argument(
        "-i",
        "--input",
        default="results/benchmark_results.csv",
        help="Input CSV from bench_runner",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        default="results",
        help="Directory for PNG outputs",
    )
    p.add_argument(
        "--ensure-csv",
        action="store_true",
        help="If CSV is missing, run a quick benchmark first",
    )
    args = p.parse_args(argv)

    if not os.path.isfile(args.input):
        if args.ensure_csv:
            from src.benchmark.bench_runner import _quick_config, run_benchmarks

            cfg = _quick_config()
            run_benchmarks(
                args.input,
                payload_sizes=cfg["payload_sizes"],
                iterations_map=cfg["iterations_map"],
            )
        else:
            raise SystemExit(
                f"Missing {args.input}. Run: python -m src.benchmark.bench_runner\n"
                f"Or pass --ensure-csv to generate a quick CSV automatically."
            )

    paths = generate_all_charts(args.input, args.output_dir)
    for path in paths:
        print("Wrote", path)


if __name__ == "__main__":
    main()
