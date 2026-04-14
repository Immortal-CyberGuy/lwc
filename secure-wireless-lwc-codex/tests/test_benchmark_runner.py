import csv
from pathlib import Path

from src.benchmark.bench_runner import run_benchmarks


def test_benchmark_runner_quick_output(tmp_path: Path):
    output_file = tmp_path / "benchmark_quick.csv"
    smoke_payloads = [16, 64]
    quick_iters = {16: 2, 64: 2}

    rows = run_benchmarks(
        str(output_file),
        iterations_map=quick_iters,
        payload_sizes=smoke_payloads,
    )
    assert output_file.exists()
    assert len(rows) == 8

    with output_file.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        csv_rows = list(reader)

    assert len(csv_rows) == 8
    for row in csv_rows:
        assert float(row["avg_encrypt_us"]) >= 0.0
        assert float(row["avg_decrypt_us"]) >= 0.0
        assert float(row["throughput_kbps"]) >= 0.0
