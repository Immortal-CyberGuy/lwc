from pathlib import Path

import pandas as pd

from src.benchmark.visualize import generate_all_charts


def test_generate_all_charts(tmp_path: Path):
    # Minimal benchmark sample with two algorithms and two payload sizes.
    bench_csv = tmp_path / "bench.csv"
    pd.DataFrame(
        [
            {
                "timestamp": "2026-03-23T00:00:00Z",
                "algorithm": "ASCON-AEAD128",
                "algo_id": 1,
                "payload_bytes": 16,
                "iterations": 2,
                "avg_encrypt_us": 10.0,
                "std_encrypt_us": 1.0,
                "avg_decrypt_us": 12.0,
                "std_decrypt_us": 1.2,
                "throughput_kbps": 100.0,
                "enc_peak_mem_kb": 5.0,
                "dec_peak_mem_kb": 5.5,
            },
            {
                "timestamp": "2026-03-23T00:00:01Z",
                "algorithm": "ASCON-AEAD128",
                "algo_id": 1,
                "payload_bytes": 64,
                "iterations": 2,
                "avg_encrypt_us": 20.0,
                "std_encrypt_us": 2.0,
                "avg_decrypt_us": 22.0,
                "std_decrypt_us": 2.2,
                "throughput_kbps": 300.0,
                "enc_peak_mem_kb": 6.0,
                "dec_peak_mem_kb": 6.5,
            },
            {
                "timestamp": "2026-03-23T00:00:02Z",
                "algorithm": "AES-128-GCM",
                "algo_id": 2,
                "payload_bytes": 16,
                "iterations": 2,
                "avg_encrypt_us": 5.0,
                "std_encrypt_us": 0.5,
                "avg_decrypt_us": 6.0,
                "std_decrypt_us": 0.6,
                "throughput_kbps": 500.0,
                "enc_peak_mem_kb": 4.0,
                "dec_peak_mem_kb": 4.5,
            },
            {
                "timestamp": "2026-03-23T00:00:03Z",
                "algorithm": "AES-128-GCM",
                "algo_id": 2,
                "payload_bytes": 64,
                "iterations": 2,
                "avg_encrypt_us": 9.0,
                "std_encrypt_us": 0.9,
                "avg_decrypt_us": 11.0,
                "std_decrypt_us": 1.1,
                "throughput_kbps": 800.0,
                "enc_peak_mem_kb": 4.3,
                "dec_peak_mem_kb": 4.7,
            },
        ]
    ).to_csv(bench_csv, index=False)

    attack_log_dir = tmp_path / "attack_logs"
    attack_log_dir.mkdir(parents=True, exist_ok=True)
    (attack_log_dir / "eavesdrop_demo.log").write_text("RESULT: PASS\n", encoding="utf-8")
    (attack_log_dir / "replay_demo.log").write_text("RESULT: PASS\n", encoding="utf-8")
    (attack_log_dir / "mitm_demo.log").write_text("RESULT: PASS\n", encoding="utf-8")

    output_dir = tmp_path / "out"
    generated = generate_all_charts(
        benchmark_csv=str(bench_csv),
        output_dir=str(output_dir),
        attack_log_dir=str(attack_log_dir),
    )

    assert len(generated) == 7
    expected = [
        output_dir / "chart1_throughput.png",
        output_dir / "chart2_enc_time.png",
        output_dir / "chart3_memory.png",
        output_dir / "chart4_enc_dec.png",
        output_dir / "chart5_tradeoff.png",
        output_dir / "chart6_attacks.png",
        output_dir / "benchmark_summary.csv",
    ]
    for file_path in expected:
        assert file_path.exists()
