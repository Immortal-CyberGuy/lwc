import csv
import os
import tempfile

from src.benchmark.bench_runner import run_benchmarks
from src.crypto.ascon_engine import AsconEngine


def test_run_benchmarks_writes_csv_quick():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bench.csv")
        rows = run_benchmarks(
            path,
            engines=[AsconEngine()],
            payload_sizes=[16, 64],
            iterations_map={16: 50, 64: 50},
        )
        assert len(rows) == 2
        assert all(r["algorithm"] == "ASCON-AEAD128" for r in rows)
        assert os.path.isfile(path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            file_rows = list(reader)
        assert len(file_rows) == 2
        for r in file_rows:
            assert float(r["avg_encrypt_us"]) > 0
            assert float(r["throughput_kbps"]) >= 0
