import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

SECURITY_BITS = {
    "ASCON-AEAD128": 128,
    "AES-128-GCM": 128,
    "SPECK-128/128-CTR-HMAC": 128,
    "PRESENT-80-CTR-HMAC": 80,
}


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _load_attack_results(log_dir: Path) -> pd.DataFrame:
    attacks = [
        ("Eavesdrop", log_dir / "eavesdrop_demo.log"),
        ("Replay", log_dir / "replay_demo.log"),
        ("MITM/Tamper", log_dir / "mitm_demo.log"),
    ]

    rows: list[dict] = []
    for attack_name, log_path in attacks:
        detected = 0.0
        if log_path.exists():
            content = log_path.read_text(encoding="utf-8", errors="ignore")
            if "RESULT:" in content and "PASS" in content:
                detected = 100.0
        rows.append({"attack_type": attack_name, "detection_percent": detected})
    return pd.DataFrame(rows)


def generate_all_charts(
    benchmark_csv: str = "results/benchmark_results.csv",
    output_dir: str = "results",
    attack_log_dir: str = "results/attack_logs",
) -> list[str]:
    benchmark_path = Path(benchmark_csv)
    if not benchmark_path.exists():
        raise FileNotFoundError(f"Benchmark CSV not found: {benchmark_csv}")

    out_dir = Path(output_dir)
    _ensure_dir(out_dir)
    attack_dir = Path(attack_log_dir)

    df = pd.read_csv(benchmark_path)
    if df.empty:
        raise ValueError("Benchmark CSV is empty.")

    df = df.sort_values(["algorithm", "payload_bytes"]).copy()
    sns.set_theme(style="whitegrid", palette="deep")

    generated: list[str] = []

    # Chart 1: Throughput vs Payload size
    fig, ax = plt.subplots(figsize=(11, 6))
    for algo, subset in df.groupby("algorithm"):
        subset = subset.sort_values("payload_bytes")
        ax.plot(
            subset["payload_bytes"],
            subset["throughput_kbps"],
            marker="o",
            linewidth=2,
            label=algo,
        )
    ax.set_title("Chart 1: Encryption Throughput vs Payload Size")
    ax.set_xlabel("Payload Size (bytes)")
    ax.set_ylabel("Throughput (KB/s)")
    ax.set_xscale("log", base=2)
    ax.legend()
    fig.tight_layout()
    path1 = out_dir / "chart1_throughput.png"
    fig.savefig(path1, dpi=150)
    plt.close(fig)
    generated.append(str(path1))

    # Chart 2: Encryption time grouped bars
    fig, ax = plt.subplots(figsize=(11, 6))
    bar_df = df.copy()
    bar_df["payload_label"] = bar_df["payload_bytes"].astype(str) + " B"
    sns.barplot(
        data=bar_df,
        x="payload_label",
        y="avg_encrypt_us",
        hue="algorithm",
        ax=ax,
    )
    ax.set_title("Chart 2: Encryption Time by Payload Size")
    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Average Encryption Time (us)")
    ax.legend(title="Algorithm", fontsize=8, title_fontsize=9)
    fig.tight_layout()
    path2 = out_dir / "chart2_enc_time.png"
    fig.savefig(path2, dpi=150)
    plt.close(fig)
    generated.append(str(path2))

    # Chart 3: Memory usage at largest available payload
    target_payload = int(df["payload_bytes"].max())
    mem_df = df[df["payload_bytes"] == target_payload].copy()
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(
        data=mem_df,
        x="enc_peak_mem_kb",
        y="algorithm",
        orient="h",
        ax=ax,
    )
    ax.set_title(f"Chart 3: Peak Encryption Memory Usage at {target_payload} B")
    ax.set_xlabel("Peak Memory (KB)")
    ax.set_ylabel("Algorithm")
    fig.tight_layout()
    path3 = out_dir / "chart3_memory.png"
    fig.savefig(path3, dpi=150)
    plt.close(fig)
    generated.append(str(path3))

    # Chart 4: Encryption vs decryption stacked bars (mean across payloads)
    agg = (
        df.groupby("algorithm", as_index=False)[["avg_encrypt_us", "avg_decrypt_us"]]
        .mean()
        .sort_values("algorithm")
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(agg["algorithm"], agg["avg_encrypt_us"], label="Encrypt (us)")
    ax.bar(
        agg["algorithm"],
        agg["avg_decrypt_us"],
        bottom=agg["avg_encrypt_us"],
        label="Decrypt (us)",
    )
    ax.set_title("Chart 4: Mean Encrypt vs Decrypt Time")
    ax.set_xlabel("Algorithm")
    ax.set_ylabel("Time (us)")
    ax.tick_params(axis="x", rotation=15)
    ax.legend()
    fig.tight_layout()
    path4 = out_dir / "chart4_enc_dec.png"
    fig.savefig(path4, dpi=150)
    plt.close(fig)
    generated.append(str(path4))

    # Chart 5: Security vs performance tradeoff
    tradeoff = df.groupby("algorithm", as_index=False)["throughput_kbps"].mean()
    tradeoff["security_bits"] = tradeoff["algorithm"].map(SECURITY_BITS).fillna(0)
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.scatterplot(
        data=tradeoff,
        x="throughput_kbps",
        y="security_bits",
        hue="algorithm",
        s=140,
        ax=ax,
    )
    for _, row in tradeoff.iterrows():
        ax.annotate(row["algorithm"], (row["throughput_kbps"], row["security_bits"]), fontsize=8)
    ax.set_title("Chart 5: Security vs Performance Trade-off")
    ax.set_xlabel("Mean Throughput (KB/s)")
    ax.set_ylabel("Security (bits)")
    fig.tight_layout()
    path5 = out_dir / "chart5_tradeoff.png"
    fig.savefig(path5, dpi=150)
    plt.close(fig)
    generated.append(str(path5))

    # Chart 6: Attack detection rate
    attack_df = _load_attack_results(attack_dir)
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.barplot(data=attack_df, x="attack_type", y="detection_percent", ax=ax)
    ax.set_ylim(0, 100)
    ax.set_title("Chart 6: Attack Detection Rate")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Detection (%)")
    for idx, value in enumerate(attack_df["detection_percent"]):
        ax.text(idx, value + 1, f"{value:.0f}%", ha="center", fontsize=10)
    fig.tight_layout()
    path6 = out_dir / "chart6_attacks.png"
    fig.savefig(path6, dpi=150)
    plt.close(fig)
    generated.append(str(path6))

    # Helpful summary export for report writing.
    summary = (
        df.groupby("algorithm", as_index=False)[
            ["avg_encrypt_us", "avg_decrypt_us", "throughput_kbps", "enc_peak_mem_kb"]
        ]
        .mean()
        .sort_values("algorithm")
    )
    summary_path = out_dir / "benchmark_summary.csv"
    summary.to_csv(summary_path, index=False)
    generated.append(str(summary_path))

    return generated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate benchmark and security charts.")
    parser.add_argument("--input", default="results/benchmark_results.csv", help="Input benchmark CSV path.")
    parser.add_argument("--output-dir", default="results", help="Directory for output charts.")
    parser.add_argument(
        "--attack-log-dir",
        default="results/attack_logs",
        help="Directory containing attack demo logs.",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    generated = generate_all_charts(
        benchmark_csv=args.input,
        output_dir=args.output_dir,
        attack_log_dir=args.attack_log_dir,
    )
    print("Generated artifacts:")
    for item in generated:
        print(f"- {item}")


if __name__ == "__main__":
    main()
